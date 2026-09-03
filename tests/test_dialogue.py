"""The operator's conversation, as a model.

Pure -- no Textual -- like ``test_flow.py`` and ``test_chat.py``: the record of
what was asked and what came back is asserted on the lines the model produces,
not on a terminal nobody is watching.
"""
from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
from pathlib import Path

from code_analyzer.analysis import AnalysisEvent
from code_analyzer.ask import CONFIRM, SELECT, Answer, Question
from code_analyzer.config import DEFAULTS, validate_config
from code_analyzer.dialogue import Dialogue, ErrorBlock, RunBlock, UserBlock
from code_analyzer.flow import RunFlow
from code_analyzer.journal import Journal, read_session, recent_sessions


def _config() -> dict:
    return validate_config(copy.deepcopy(DEFAULTS))


def _dialogue() -> Dialogue:
    return Dialogue(config=_config())


def _event(phase: str, status: str, message: str = "", **kwargs: object) -> AnalysisEvent:
    return AnalysisEvent(phase, status, message, timestamp=kwargs.pop("timestamp", 0.0), **kwargs)


# --- blocks -----------------------------------------------------------------


def test_an_operator_turn_and_a_run_block_keep_their_order_in_the_transcript() -> None:
    dialogue = _dialogue()
    dialogue.said("/scan ~/fw", reading="scan")
    dialogue.say("预检通过 · 3923 个文件")
    run = dialogue.run("scan", RunFlow(_config()))
    dialogue.said("/pause llm", reading="pause")

    kinds = [block.kind for block in dialogue.blocks]
    assert kinds == ["user", "say", "run", "user"]
    assert isinstance(dialogue.blocks[0], UserBlock)
    assert dialogue.get(run.block_id) is run
    # What the operator typed reads back verbatim, with how it was understood.
    assert dialogue.blocks[0].render() == ["› /scan ~/fw", "  ↳ scan"]


def test_the_events_of_two_runs_land_in_their_own_blocks() -> None:
    """apply returns the block that moved, so one widget repaints, not all."""
    dialogue = _dialogue()
    first = dialogue.run("scan", RunFlow(_config()))
    second = dialogue.run("scan", RunFlow(_config()))

    moved = dialogue.apply(first.block_id, _event("tool", "started", "cppcheck starting", tool="cppcheck"))
    assert moved == first.block_id
    assert first.flow.nodes["cppcheck"].state == "running"
    assert second.flow.nodes["cppcheck"].state == "pending"
    # An event for a block that is not a run changes nothing and says so.
    assert dialogue.apply(dialogue.say("hello").block_id, _event("tool", "started", "x")) is None
    assert dialogue.apply("no-such-block", _event("tool", "started", "x")) is None


def test_an_output_event_costs_the_conversation_nothing() -> None:
    """The same guarantee flow.py makes: half a million of these an hour."""
    dialogue = _dialogue()
    run = dialogue.run("scan", RunFlow(_config()))
    for _index in range(2000):
        dialogue.apply(run.block_id, _event("output", "running", "chunk", tool="cppcheck", unit="u", stream="stdout"))
    assert run.flow.nodes["cppcheck"].state == "pending"


def test_a_finished_run_collapses_to_one_line_and_releases_its_turns() -> None:
    """Ten scans in a session would otherwise hold ten live transcripts."""
    dialogue = _dialogue()
    run = dialogue.run("scan", RunFlow(_config()))
    dialogue.apply(run.block_id, _event("llm", "started", "starting", data={"model": "qwen3.8:27b"}))
    dialogue.apply(run.block_id, _event(
        "unit", "completed", "completed", tool="llm-security", unit="u1",
        data={"index": 1, "total": 1, "finding_count": 2,
              "usage": {"prompt_tokens": 100, "completion_tokens": 20, "requests": 1}},
    ))
    assert run.chat.turns()

    run.settle(0, "扫描完成", Path("/tmp/report/20260903T000000Z-abc"))
    assert run.settled and run.exit_code == 0
    assert run.summary.startswith("✓ 扫描完成 · 退出码 0")
    assert "20260903T000000Z-abc" in run.summary
    # The turns are gone; what the block will show forever is kept.
    assert run.chat.turns() == []
    assert run.final_stats is not None and run.final_stats.answered == 1
    assert run.headline() == run.summary


def test_a_failed_run_is_marked_differently_from_a_partial_one() -> None:
    for exit_code, mark in ((0, "✓"), (10, "◐"), (1, "◐"), (20, "✕"), (130, "✕")):
        run = RunBlock(action="scan", flow=RunFlow(_config()))
        run.settle(exit_code, "扫描结束")
        assert run.summary.startswith(mark), exit_code


def test_at_most_one_run_is_live_and_the_conversation_knows_which() -> None:
    dialogue = _dialogue()
    assert dialogue.live_run() is None
    first = dialogue.run("scan", RunFlow(_config()))
    assert dialogue.live_run() is first
    first.settle(0, "完成")
    assert dialogue.live_run() is None


# --- questions --------------------------------------------------------------


def test_a_question_waits_in_the_conversation_until_it_is_answered() -> None:
    dialogue = _dialogue()
    block = dialogue.ask(Question("compile-db.continue", CONFIRM, "继续？ [y/N] ",
                                  preview=("cmake -S . -B build",)))
    assert dialogue.pending_question() is block and not block.settled
    assert "cmake -S . -B build" in block.render()[0]

    assert dialogue.answer(block.block_id, Answer(text="y"))
    assert block.settled and block.answer.yes
    assert dialogue.pending_question() is None
    # An answered question is not answered twice.
    assert not dialogue.answer(block.block_id, Answer(text="n"))


def test_a_patch_question_shows_every_item_and_what_is_pre_ticked() -> None:
    dialogue = _dialogue()
    block = dialogue.ask(Question(
        "build-context.p1", SELECT, "应用勾选项？ [y/N] ",
        options=("-I src/hal", "-I vendor"), preselected=(0,),
        preview=("构建上下文补丁",), footer=("  影响：只重跑失败的单元",),
    ))
    rendered = block.render()
    assert "  [x] -I src/hal" in rendered and "  [ ] -I vendor" in rendered
    assert rendered.index("  [x] -I src/hal") < rendered.index("  影响：只重跑失败的单元")


# --- the state the parser reads ---------------------------------------------


def test_the_conversation_tells_the_parser_what_subject_it_is_on(tmp_path: Path) -> None:
    dialogue = Dialogue(source=tmp_path, config=_config())
    state = dialogue.state()
    assert state.source == tmp_path and not state.running

    run = dialogue.run("scan", RunFlow(_config()))
    assert dialogue.state().running
    run.settle(0, "完成")
    assert not dialogue.state().running


def test_an_untrusted_path_reaches_a_block_as_text() -> None:
    """Model output and scanned names are untrusted wherever they are drawn."""
    dialogue = _dialogue()
    dialogue.said("[bold red]evil[/].c\x1b[2J")
    dialogue.failed("扫描失败", ["src/\x1b[31mevil.c 打不开"])
    lines = dialogue.lines()
    assert not any("\x1b" in line for line in lines)
    assert any("evil" in line for line in lines)
    assert isinstance(dialogue.blocks[1], ErrorBlock)


def test_the_dialogue_module_never_imports_a_ui() -> None:
    code = (
        "import sys; import code_analyzer.dialogue; "
        "print(sorted({m.split('.')[0] for m in sys.modules} "
        "& {'textual', 'rich', 'http', 'deepseek_harness'}))"
    )
    completed = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "[]"


# --- the session journal ----------------------------------------------------


def test_the_session_journal_records_what_was_asked_and_what_was_answered() -> None:
    with tempfile.TemporaryDirectory() as root:
        journal = Journal(root=Path(root))
        journal.said("/scan ~/fw")
        journal.read_as("action", "scan", ("~/fw",))
        journal.answered("compile-db.continue", "y")
        journal.finished("scan", 10, "/tmp/report/run-1")
        journal.close()

        records = read_session(journal.path)
        assert [record["t"] for record in records] == ["user", "intent", "answer", "result"]
        assert records[0]["text"] == "/scan ~/fw"
        assert records[1]["action"] == "scan" and records[1]["by"] == "parser"
        assert records[2]["question"] == "compile-db.continue" and records[2]["refused"] is False
        assert records[3]["exit_code"] == 10 and records[3]["run"] == "/tmp/report/run-1"
        assert recent_sessions(Path(root)) == [journal.path]


def test_the_journal_is_a_convenience_and_never_stops_a_scan() -> None:
    """A home directory that cannot be written must not be fatal."""
    with tempfile.TemporaryDirectory() as root:
        blocked = Path(root) / "file-not-a-directory"
        blocked.write_text("", encoding="utf-8")
        journal = Journal(blocked / "20260903T000000Z.jsonl")
        assert not journal.enabled and journal.disabled_reason
        # Every method still works, and writes nothing.
        journal.said("/scan ~/fw")
        journal.finished("scan", 0, None)
        journal.close()


def test_an_operators_line_is_bounded_and_carries_no_control_characters() -> None:
    with tempfile.TemporaryDirectory() as root:
        journal = Journal(root=Path(root))
        journal.said("x" * 9000 + "\x1b[2J")
        journal.close()
        record = read_session(journal.path)[0]
        assert len(record["text"]) <= 4000 and "\x1b" not in record["text"]


def test_a_journal_that_cannot_be_read_back_is_empty_rather_than_an_error() -> None:
    with tempfile.TemporaryDirectory() as root:
        path = Path(root) / "broken.jsonl"
        path.write_text('{"t": "user"}\nnot json\n{"t": "result"}\n', encoding="utf-8")
        assert [record["t"] for record in read_session(path)] == ["user", "result"]
        assert read_session(Path(root) / "absent.jsonl") == []


def test_the_session_record_says_whether_the_parser_or_the_model_read_the_line() -> None:
    """Both read lines now, so "was that mine or the model's" needs an answer."""
    with tempfile.TemporaryDirectory() as root:
        journal = Journal(root=Path(root))
        journal.said("/scan ~/fw")
        journal.read_as("action", "scan", ("~/fw",), by="parser")
        journal.said("先体检一下")
        journal.read_as("ask", "", (), by="model")
        journal.proposed([], ["目录里没有 'rm -rf' 这个 action"], "说不准", 24.5, "qwen3.8:27b")
        journal.auto_ran("doctor", None, "auto_run: no writes, no spend, no block")
        journal.close()

        records = read_session(journal.path)
        readings = [r for r in records if r["t"] == "intent"]
        assert [r["by"] for r in readings] == ["parser", "model"]
        proposal = next(r for r in records if r["t"] == "proposal")
        assert proposal["model"] == "qwen3.8:27b" and proposal["seconds"] == 24.5
        assert proposal["dropped"] and proposal["unclear"] == "说不准"
        auto = next(r for r in records if r["t"] == "auto")
        assert auto["action"] == "doctor" and "no writes" in auto["reason"]


def test_a_thinking_block_never_invents_how_long_is_left() -> None:
    from code_analyzer.dialogue import ThinkingBlock

    block = ThinkingBlock(utterance="帮我看看", last_seconds=71.2)
    block.started_at = block.started_at - 24
    rendered = "\n".join(block.render())
    assert "24s" in rendered and "上次 71.2s（本会话测量）" in rendered
    assert "ETA" not in rendered and "剩余" not in rendered
    # The first question of a session has nothing measured to report.
    assert "上次" not in "\n".join(ThinkingBlock(utterance="x").render())

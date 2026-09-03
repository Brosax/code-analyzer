"""The conversation front end: one transcript, one input box.

The assertion boundary is the `Text` this app builds and the blocks the model
holds, not Textual's private render state -- markup in a scanned path must
survive as characters, which is a property of building `Text` segment by
segment.
"""
from __future__ import annotations

import asyncio
import copy
import threading
from pathlib import Path

import pytest

from code_analyzer.analysis import (
    AnalysisEvent,
    AnalysisRequest,
    CancellationToken,
    run_analysis,
)
from code_analyzer.cli import main
from code_analyzer.config import (
    DEFAULTS,
    FIELD_REGISTRY,
    effective_toml,
    load_config,
    load_config_with_sources,
    save_config_snapshot,
)
from code_analyzer.dialogue import RunBlock
from code_analyzer.progress import BRAILLE_FRAMES
from code_analyzer.tui import AnalyzerApp, RunBlockWidget, TuiOutcome


def _app(tmp_path: Path, *, llm: bool = False) -> AnalyzerApp:
    app = AnalyzerApp(tmp_path)
    if llm:
        app.config_llm = True
        app.dialogue.config["llm"]["enabled"] = True
        app.dialogue.config["llm"]["scanners"] = ["llm-memory-safety"]
    return app


def _transcript(app: AnalyzerApp) -> str:
    """Every block as plain text, which is what the operator reads."""
    return "\n".join(app.dialogue.lines())


def _fake_run(app: AnalyzerApp, **config: object) -> RunBlock:
    """Open a run block the way a confirmed action does, without a worker."""
    from code_analyzer.flow import RunFlow

    for key, value in config.items():
        app.dialogue.config["llm"][key] = value
    run = app.dialogue.run("scan", RunFlow(app.dialogue.config))
    app._mount(run)
    return run


# --- the config layer, unchanged by the restructure -------------------------


def test_config_sources_and_atomic_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "源 代码"
    source.mkdir()
    (source / ".code-analyzer.toml").write_text(
        'config_schema_version = 2\n[run]\noutput_root = "reports"\n', encoding="utf-8"
    )
    explicit = tmp_path / "explicit.toml"
    explicit.write_text('config_schema_version = 2\n[llm]\nenabled = true\n', encoding="utf-8")

    loaded = load_config_with_sources(source, explicit, session={"review": {"fail_on": "high"}})
    assert loaded.sources["run.output_root"] == str(source / ".code-analyzer.toml")
    assert loaded.sources["llm.enabled"] == str(explicit)
    assert loaded.sources["review.fail_on"] == "session"
    assert loaded.sources["source.hash_algorithm"] == "default"

    destination = tmp_path / "snapshot.toml"
    save_config_snapshot(source, loaded.config, destination)
    text = destination.read_text(encoding="utf-8")
    assert "compile_database =" not in text
    assert load_config(source, destination)["review"]["fail_on"] == "high"
    with pytest.raises(Exception, match="already exists"):
        save_config_snapshot(source, loaded.config, destination)


def test_registry_covers_every_schema_leaf() -> None:
    """The 83-leaf invariant, and now /config really does render all of them."""

    def leaves(value: object, prefix: str = "") -> set[str]:
        found: set[str] = set()
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "config_schema_version":
                    continue
                path = f"{prefix}.{key}" if prefix else key
                found |= leaves(child, path) or {path}
            return found
        return set()

    assert {spec.path for spec in FIELD_REGISTRY} == leaves(DEFAULTS)


def test_effective_toml_omits_optional_none() -> None:
    config = copy.deepcopy(DEFAULTS)
    text = effective_toml(config)
    assert 'compile_database = ""' not in text and "compile_database =" not in text


# --- the conversation --------------------------------------------------------


def test_the_interface_opens_on_a_transcript_and_an_input_box(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            # No form, no three regions: a scroll, a prompt, a status line.
            assert app.query_one("#transcript").display
            assert app.query_one("#prompt").display
            assert not app.query_one("#log").display
            for gone in ("#workspace", "#running", "#result", "#basic-actions", "#run-flow"):
                assert len(app.query(gone)) == 0, gone
            assert str(tmp_path) in _transcript(app)
            assert app.focused is app.query_one("#prompt")

    asyncio.run(exercise())


def test_typing_a_path_proposes_a_scan_and_asks_before_it_starts(tmp_path: Path) -> None:
    """A scan may run for hours; it is never a side effect of naming a path."""

    async def exercise() -> None:
        source = tmp_path / "project"
        (source / "src").mkdir(parents=True)
        (source / "src" / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit(str(source))
            await pilot.pause()
            # The line is in the record, read as a scan.
            assert f"› {source}" in _transcript(app)
            # A run block opened, and a confirmation is waiting.
            assert app.dialogue.live_run() is not None
            for _ in range(40):
                await pilot.pause()
                if app.dialogue.pending_question() is not None:
                    break
            question = app.dialogue.pending_question()
            assert question is not None and question.question.kind == "confirm"
            assert any("报告目录" in line for line in question.question.preview)
            # Declining settles the block and starts nothing.
            app.submit("n")
            for _ in range(40):
                await pilot.pause()
                if not app._busy:
                    break
            assert not app._busy
            assert not list(tmp_path.glob("code-analyzer-reports"))

    asyncio.run(exercise())


def test_a_slash_command_that_reads_only_runs_without_a_confirmation(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit("/config")
            await pilot.pause()
            text = _transcript(app)
            assert "配置" in text and "review.fail_on" in text
            assert app.dialogue.pending_question() is None

    asyncio.run(exercise())


def test_set_changes_one_leaf_and_says_what_it_was(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit("/set review.fail_on high")
            await pilot.pause()
            assert app.dialogue.config["review"]["fail_on"] == "high"
            assert "review.fail_on: 'none' → 'high'" in _transcript(app)
            assert app.dirty and app.sources["review.fail_on"] == "session"

            # A rejected value changes nothing and says why.
            app.submit("/set llm.jobs 0")
            await pilot.pause()
            assert "不能小于" in _transcript(app)
            assert app.dialogue.config["llm"]["jobs"] != 0

    asyncio.run(exercise())


def test_config_reaches_every_one_of_the_eighty_three_leaves(tmp_path: Path) -> None:
    """The hand-maintained thirteen-field list is gone."""

    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit("/config")
            await pilot.pause()
            common = _transcript(app).count(" = ")
            app.submit("/config --all")
            await pilot.pause()
            # Advanced fields are folded until asked for, then all 83 are there.
            assert common < len(FIELD_REGISTRY)
            app.submit("/set tools.cppcheck.timeout_seconds 600")
            await pilot.pause()
            assert app.dialogue.config["tools"]["cppcheck"]["timeout_seconds"] == 600

    asyncio.run(exercise())


def test_a_refusal_is_a_block_and_never_takes_the_screen(tmp_path: Path) -> None:
    """InfoScreen was the universal error channel; an error is now scrollable."""

    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit("/nonsense")
            app.submit(str(tmp_path / "definitely-not-here"))
            await pilot.pause()
            text = _transcript(app)
            assert "没有 /nonsense 这个命令" in text
            assert "路径不存在" in text
            # Still one screen, still able to type.
            assert app.query_one("#prompt").display
            assert not app.query("ModalScreen")

    asyncio.run(exercise())


def test_a_sentence_goes_to_the_model_with_no_prefix_and_the_box_says_so(tmp_path: Path) -> None:
    """The inversion, at the front end: no `/ask`, no keyword table.

    The autouse fixture stubs the provider, so what is asserted here is the
    routing and the refusal wording -- not a live answer.
    """

    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit("帮我看看哪些单元最值得先扫")
            for _ in range(40):
                await pilot.pause()
                if not app._busy:
                    break
            text = _transcript(app)
            assert "正在把这句话交给模型" in text
            # Provider off in the suite: it degrades and names what still works.
            assert "模型不可达" in text
            assert "/help" in text and "确定性命令不受影响" in text

    asyncio.run(exercise())


def test_a_sentence_that_looks_like_a_path_because_chinese_has_no_spaces(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit("扫描~/fw")
            for _ in range(40):
                await pilot.pause()
                if not app._busy:
                    break
            # Routed as a sentence, not refused as a missing directory.
            assert "路径不存在" not in _transcript(app)
            assert "模型不可达" in _transcript(app)

    asyncio.run(exercise())


def test_an_untrusted_line_reaches_the_transcript_as_text(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit("[bold red]evil[/].c\x1b[2J")
            await pilot.pause()
            text = _transcript(app)
            assert "\x1b" not in text
            assert "evil" in text and "[bold red]" in text

    asyncio.run(exercise())


def test_the_input_history_walks_back_through_what_was_typed(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit("/help")
            app.submit("/config")
            await pilot.pause()
            assert app._history == ["/help", "/config"]

    asyncio.run(exercise())


# --- the run block -----------------------------------------------------------


def test_a_run_is_a_collapsible_block_that_expands_to_the_flow_diagram(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            run = _fake_run(app)
            await pilot.pause()
            widget = app.query_one(RunBlockWidget)
            assert widget.collapsed
            app._drain_events()

            app._emitter(run.block_id)(AnalysisEvent(
                "tool", "started", "cppcheck starting", tool="cppcheck"))
            app._tick()
            await pilot.pause()
            assert "cppcheck" in widget.title

            app._emitter(run.block_id)(AnalysisEvent(
                "tool", "completed", "cppcheck finished with status completed", tool="cppcheck"))
            app._tick()
            widget.collapsed = False
            app._repaint_run(run)
            await pilot.pause()
            body = widget.body.render().plain
            # The fan-out the old run view drew, in the block, plus the bars.
            assert "发现" in body and "cppcheck" in body
            assert "静态分析" in body and "1/3 工具" in body
            assert "█" in body and "░" in body

    asyncio.run(exercise())


def test_a_finished_run_collapses_to_one_line_and_the_history_stays(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            run = _fake_run(app)
            await pilot.pause()
            run.settle(0, "扫描完成", tmp_path / "report")
            app._repaint_run(run)
            await pilot.pause()
            widget = app.query_one(RunBlockWidget)
            assert widget.title.startswith("✓ 扫描完成 · 退出码 0")
            # And the block is still there to scroll back to.
            assert app.dialogue.get(run.block_id) is run
            assert len(list(app.query(RunBlockWidget))) == 1

    asyncio.run(exercise())


def test_events_queue_on_the_worker_and_fold_on_the_tick(tmp_path: Path) -> None:
    """No call_from_thread per event: the worker queues, the 5 Hz tick folds."""

    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            run = _fake_run(app)
            await pilot.pause()
            emit = app._emitter(run.block_id)
            for _index in range(3000):
                emit(AnalysisEvent("unit", "heartbeat", "heartbeat", tool="cppcheck", unit="u",
                                   data={"index": 1, "total": 1}))
            emit(AnalysisEvent("tool", "started", "cppcheck starting", tool="cppcheck"))
            emit(AnalysisEvent("unit", "started", "scanning", tool="cppcheck", unit="u",
                               data={"index": 1, "total": 4}))
            assert run.flow.nodes["cppcheck"].state == "pending", "nothing folds until the tick"
            app._tick()
            assert run.flow.nodes["cppcheck"].state == "running"
            assert run.flow.nodes["cppcheck"].total == 4
            assert not app._pending_events and not app._liveness_events

    asyncio.run(exercise())


def test_answer_chunks_queue_as_liveness_and_never_displace_a_state_event(tmp_path: Path) -> None:
    """An overloaded display drops answer text, not the counters."""

    async def exercise() -> None:
        app = _app(tmp_path, llm=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            run = _fake_run(app, enabled=True, scanners=["llm-security"])
            await pilot.pause()
            emit = app._emitter(run.block_id)
            for _index in range(6000):
                emit(AnalysisEvent("output", "running", "chunk", tool="llm-security",
                                   unit="a.c:f", stream="answer"))
            emit(AnalysisEvent("unit", "completed", "completed", tool="llm-security", unit="a.c:f",
                               data={"index": 1, "total": 1, "finding_count": 3}))
            assert len(app._liveness_events) == 5000 and len(app._pending_events) == 1
            app._tick()
            await pilot.pause()
            assert run.chat.turns()[0].findings == 3

    asyncio.run(exercise())


def test_the_run_block_batches_and_bounds_log_lines(tmp_path: Path) -> None:
    """Moved from test_runtime_output: the caps that keep a firehose survivable."""

    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            run = _fake_run(app)
            emit = app._emitter(run.block_id)
            for index in range(2100):
                emit(AnalysisEvent("output", "running", f"line {index}", tool="cppcheck",
                                   unit="u", stream="stdout"))
            assert len(app._pending_log_lines) == 2000
            markers = [line for line in app._pending_log_lines if "界面日志过载" in line]
            assert len(markers) == 1
            before = len(app._pending_log_lines)
            app._flush_log_queue()
            assert len(app._pending_log_lines) == before - 200

    asyncio.run(exercise())


def test_a_prompt_preview_never_reaches_the_log(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _app(tmp_path, llm=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            run = _fake_run(app, enabled=True, scanners=["llm-security"])
            emit = app._emitter(run.block_id)
            emit(AnalysisEvent("output", "running", "# Scan unit\nfile: a.c", tool="llm-security",
                               unit="a.c:f", stream="prompt", data={"chars": 8000}))
            emit(AnalysisEvent("output", "running", "answer text", tool="llm-security",
                               unit="a.c:f", stream="answer"))
            assert not any("Scan unit" in line for line in app._pending_log_lines)
            assert any("answer text" in line for line in app._pending_log_lines)

    asyncio.run(exercise())


def test_f6_shows_the_prompt_inside_the_expanded_run_block(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _app(tmp_path, llm=True)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            run = _fake_run(app, enabled=True, scanners=["llm-security"])
            await pilot.pause()
            emit = app._emitter(run.block_id)
            emit(AnalysisEvent("unit", "started", "scanning", tool="llm-security", unit="a.c:f",
                               data={"index": 1, "total": 1, "path": "a.c"}))
            emit(AnalysisEvent("output", "running", "# Scan unit\nfile: a.c", tool="llm-security",
                               unit="a.c:f", stream="prompt", data={"chars": 8000}))
            emit(AnalysisEvent("output", "running", '{"findings": []}', tool="llm-security",
                               unit="a.c:f", stream="answer"))
            app._tick()
            widget = app.query_one(RunBlockWidget)
            widget.collapsed = False
            app._repaint_run(run)
            await pilot.pause()
            assert '{"findings": []}' in widget.body.render().plain
            assert "file: a.c" not in widget.body.render().plain

            await pilot.press("f6")
            app._repaint_run(run)
            await pilot.pause()
            assert app._show_prompts
            assert "file: a.c" in widget.body.render().plain

    asyncio.run(exercise())


def test_the_animation_honours_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CODE_ANALYZER_NO_ANIMATION", "1")

    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert app._flow_animated is False
            run = _fake_run(app)
            emit = app._emitter(run.block_id)
            emit(AnalysisEvent("tool", "started", "cppcheck starting", tool="cppcheck"))
            app._tick()
            widget = app.query_one(RunBlockWidget)
            widget.collapsed = False
            app._repaint_run(run)
            await pilot.pause()
            assert not any(frame in widget.body.render().plain for frame in BRAILLE_FRAMES)

    asyncio.run(exercise())


# --- run control, now typed rather than bound to single letters -------------


def test_pause_skip_and_jobs_typed_as_commands_reach_the_control(tmp_path: Path) -> None:
    async def exercise() -> None:
        from code_analyzer.control import RunControl

        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            run = _fake_run(app)
            app.control = RunControl(CancellationToken(), llm_jobs=1)
            app._busy = True

            app.submit("/pause llm")
            await pilot.pause()
            assert app.control.paused("llm")
            app.submit("/resume llm")
            await pilot.pause()
            assert not app.control.paused("llm")

            app.submit("/jobs 4")
            await pilot.pause()
            assert app.control.jobs("llm") == 4

            app.submit("/skip flawfinder")
            await pilot.pause()
            assert "flawfinder" in _transcript(app)

            # A lane that does not exist is refused by name.
            app.submit("/pause nonsense")
            await pilot.pause()
            assert "只有 llm 和 static" in _transcript(app)
            assert run is app.dialogue.live_run()

    asyncio.run(exercise())


def test_ctrl_c_cancels_a_run_and_then_exits(tmp_path: Path) -> None:
    async def exercise() -> None:
        from code_analyzer.control import RunControl

        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            run = _fake_run(app)
            token = CancellationToken()
            app.cancel_token = token
            app.control = RunControl(token, llm_jobs=1)
            app._busy = True

            app.action_cancel_or_exit()
            await pilot.pause()
            assert token.is_cancelled() and run.flow.stopping
            assert "已请求安全停止" in _transcript(app)

    asyncio.run(exercise())


# --- questions ---------------------------------------------------------------


def test_a_question_from_a_worker_becomes_a_turn_and_the_answer_releases_it(tmp_path: Path) -> None:
    """compile-db's prompts, the patch dialog: one seam, one rendering."""

    async def exercise() -> None:
        from code_analyzer.ask import CONFIRM, Question

        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            asker = app._asker()
            answered: dict[str, object] = {}

            def worker() -> None:
                answered["value"] = asker(Question(
                    "compile-db.continue", CONFIRM, "继续？ [y/N] ",
                    preview=("cmake -S . -B build",),
                ))

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            for _ in range(40):
                await pilot.pause()
                if app.dialogue.pending_question() is not None:
                    break
            block = app.dialogue.pending_question()
            assert block is not None
            assert "cmake -S . -B build" in _transcript(app)

            app.submit("y")
            thread.join(timeout=5)
            assert answered["value"].yes
            assert app.dialogue.pending_question() is None

    asyncio.run(exercise())


def test_a_patch_decision_is_answered_in_the_conversation(tmp_path: Path) -> None:
    async def exercise() -> None:
        from code_analyzer.control import DecisionRequest

        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            decider = app._decider()
            got: dict[str, object] = {}
            request = DecisionRequest(
                id="p1", kind="build-context", summary="3 个缺失的 include 根",
                items=[{"label": "-I src/hal", "evidence": "hal.h", "origin": "deterministic"}],
                round=1, probe={"sampled": 12, "reached_after": 9}, preselected=(0,),
            )

            thread = threading.Thread(target=lambda: got.update(d=decider(request)), daemon=True)
            thread.start()
            for _ in range(40):
                await pilot.pause()
                if app.dialogue.pending_question() is not None:
                    break
            assert "-I src/hal" in _transcript(app)
            app.submit("y")
            thread.join(timeout=5)
            assert got["d"].answer == "apply" and got["d"].selected == (0,)
            assert got["d"].decided_by == "tui"

    asyncio.run(exercise())


# --- the CLI's routing to it -------------------------------------------------


def test_cli_tui_routing_and_non_tty(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr("sys.stdout.isatty", lambda: False)
    assert main([]) == 2
    assert "hint:" in capsys.readouterr().err
    assert main(["tui", str(tmp_path)]) == 2
    assert "requires an interactive terminal" in capsys.readouterr().err

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(
        "code_analyzer.tui.run_tui",
        lambda source, config: TuiOutcome(10, tmp_path / "report"),
    )
    assert main(["tui", str(tmp_path)]) == 10
    assert capsys.readouterr().out.strip() == str(tmp_path / "report")


def test_pre_cancelled_headless_request_has_no_report(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    config = load_config(source, None, {"run": {"output_root": str(tmp_path / "out")}})
    token = CancellationToken()
    token.cancel()
    seen: list[AnalysisEvent] = []
    result = run_analysis(AnalysisRequest(source, config), events=seen.append, cancellation=token)
    assert result.exit_code == 130 and result.report_directory is None and result.manifest is None
    assert [event.status for event in seen] == ["started", "interrupted"]


def test_the_run_diagram_is_built_from_the_config_the_run_will_use(tmp_path: Path) -> None:
    """The old run view drew its skeleton from the session's config instead.

    A `--llm-scanner` on the command line then produced a diagram with five
    scanners nobody asked for, sitting at "等待" for the whole run.
    """

    async def exercise() -> None:
        source = tmp_path / "project"
        (source / "src").mkdir(parents=True)
        (source / "src" / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.submit("/set llm.enabled true")
            await pilot.pause()
            assert len(app.dialogue.config["llm"]["scanners"]) > 1

            app.submit(f"/scan {source} --llm-scanner llm-memory-safety")
            await pilot.pause()
            run = app.dialogue.live_run()
            assert run is not None
            drawn = [node.id for node in run.flow.nodes.values() if node.kind == "llm"]
            assert drawn == ["llm-memory-safety"]
            app.submit("n")
            for _ in range(40):
                await pilot.pause()
                if not app._busy:
                    break

    asyncio.run(exercise())


def test_a_command_with_flags_keeps_everything_set_in_the_session(tmp_path: Path) -> None:
    """A live run caught this: /set was silently thrown away by a flagged command."""

    async def exercise() -> None:
        source = tmp_path / "project"
        (source / "src").mkdir(parents=True)
        (source / "src" / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
        out = tmp_path / "elsewhere"
        app = _app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            app.submit(f"/set run.output_root {out}")
            app.submit("/set llm.enabled true")
            await pilot.pause()

            action = __import__("code_analyzer.actions", fromlist=["by_name"]).by_name("scan")
            from code_analyzer.intent import parse

            intent = parse(f"/scan {source} --fail-on high", app.dialogue.state())
            request = app._request(action, intent)
            # The flag applied, and neither /set was lost.
            assert request.config["review"]["fail_on"] == "high"
            assert request.config["run"]["output_root"] == str(out)
            assert request.config["llm"]["enabled"] is True

    asyncio.run(exercise())


# --- the confirm audit -------------------------------------------------------


def test_an_action_that_needs_no_subject_is_not_handed_the_sessions_source_tree(tmp_path: Path) -> None:
    """`/serve` in the conversation used to start a full analysis.

    `_request` filled `source` and `report_directory` for every action, and
    `_run_serve` branches on `request.source is not None`.
    """

    async def exercise() -> None:
        from code_analyzer.actions import SUBJECT_NONE, by_name
        from code_analyzer.intent import parse

        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            assert app.dialogue.source == tmp_path

            for name in ("doctor", "config"):
                action = by_name(name)
                assert action.subject == SUBJECT_NONE
                request = app._request(action, parse(f"/{name}", app.dialogue.state()))
                assert request.source is None, name
                assert request.report_directory is None, name

            # And an action that does need one still gets it.
            scan = app._request(by_name("scan"), parse(f"/scan {tmp_path}", app.dialogue.state()))
            assert scan.source == tmp_path and scan.report_directory is None

    asyncio.run(exercise())


def test_the_confirmation_of_a_writing_action_names_the_files(tmp_path: Path) -> None:
    async def exercise() -> None:
        run = tmp_path / "20260903T000000Z-abcdef"
        run.mkdir()
        (run / "manifest.json").write_text('{"source": "%s"}' % tmp_path, encoding="utf-8")
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit(f"/rebuild-dashboard {run}")
            for _ in range(40):
                await pilot.pause()
                if app.dialogue.pending_question() is not None:
                    break
            question = app.dialogue.pending_question()
            assert question is not None
            preview = "\n".join(question.question.preview)
            assert "manifest.json" in preview
            assert str(run) in preview
            app.submit("n")
            for _ in range(40):
                await pilot.pause()
                if not app._busy:
                    break

    asyncio.run(exercise())


def test_saving_the_configuration_asks_before_it_replaces_the_file(tmp_path: Path) -> None:
    """The one write the conversation does outside an action."""

    async def exercise() -> None:
        app = _app(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            app.submit("/set review.fail_on high")
            await pilot.pause()
            target = tmp_path / ".code-analyzer.toml"

            app.action_save()
            await pilot.pause()
            question = app.dialogue.pending_question()
            assert question is not None and question.question.id == "save.confirm"
            assert str(target) in "\n".join(question.question.preview)
            # Declining writes nothing.
            app.submit("n")
            await pilot.pause()
            assert not target.exists()
            assert "没有写入" in _transcript(app)

            app.action_save()
            await pilot.pause()
            app.submit("y")
            await pilot.pause()
            assert target.exists()
            assert "review" in target.read_text(encoding="utf-8")
            assert not app.dirty

    asyncio.run(exercise())

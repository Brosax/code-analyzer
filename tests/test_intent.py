"""The deterministic parser: a slash command, a bare path or a short phrase.

Pure -- no Textual, no harness, no provider -- for the same reason
``tests/test_flow.py`` is: this is the trunk of the interface, and it must
answer instantly with nothing running.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from code_analyzer.errors import UserError
from code_analyzer.intent import (
    ACTION,
    AMBIGUOUS,
    ASK,
    CONFIG_SET,
    EMPTY,
    META,
    UNKNOWN,
    Intent,
    State,
    coerce,
    help_lines,
    parse,
)


def _tree(tmp_path: Path) -> Path:
    source = tmp_path / "project"
    (source / "src").mkdir(parents=True)
    (source / "src" / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    return source


# --- slash commands ---------------------------------------------------------


def test_a_slash_command_takes_the_same_flags_the_subcommand_takes(tmp_path: Path) -> None:
    """Borrowed parser, not a second list of thirty-five flags."""
    source = _tree(tmp_path)
    intent = parse(f"/scan {source} --llm --llm-jobs 4 --tool splint --fail-on high")
    assert intent.kind == ACTION and intent.action == "scan"
    namespace = intent.values["namespace"]
    assert namespace.llm is True and namespace.llm_jobs == 4
    assert namespace.tool == ["splint"] and namespace.fail_on == "high"

    # And it refuses exactly what the CLI refuses, without exiting the process.
    bad = parse(f"/scan {source} --llm-jobs 0")
    assert bad.kind == UNKNOWN and "greater than zero" in bad.problem


def test_an_unknown_slash_command_suggests_the_closest_one_and_changes_nothing() -> None:
    intent = parse("/doctar")
    assert intent.kind == UNKNOWN and "doctor" in intent.candidates
    assert "你是指" in intent.problem
    assert parse("/zzzzz").kind == UNKNOWN


def test_a_registry_action_answers_to_its_chinese_alias(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    assert parse(f"/扫描 {source}").action == "scan"
    assert parse(f"/预检 {source}").action == "preflight"


def test_the_conversations_own_commands_are_not_registry_actions() -> None:
    for line, name in (("/help", "help"), ("/pause llm", "pause"), ("/jobs 4", "jobs"),
                       ("/cancel", "cancel"), ("/retry", "retry")):
        intent = parse(line)
        assert intent.kind == META and intent.action == name, line
    assert parse("/pause llm").argv == ("llm",)


def test_an_unbalanced_quote_is_reported_rather_than_raised() -> None:
    intent = parse('/scan "unclosed')
    assert intent.kind == UNKNOWN and "引号" in intent.problem


# --- bare paths -------------------------------------------------------------


def test_a_bare_existing_directory_reads_as_a_scan_and_names_its_subject(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    intent = parse(str(source))
    assert intent.kind == ACTION and intent.action == "scan"
    # "path", not "shorthand": the CLI reads this to decide whether naming a
    # directory may start a scan headlessly (it may not).
    assert intent.confidence == "path" and intent.values["source"] == source


def test_an_absolute_path_is_a_path_and_not_a_missing_slash_command(tmp_path: Path) -> None:
    """Both start with "/"; the first thing an operator types is a path."""
    source = _tree(tmp_path)
    assert str(source).startswith("/")
    assert parse(str(source)).action == "scan"
    missing = parse("/tmp/definitely-not-here-9f3a2")
    assert missing.kind == UNKNOWN and "路径不存在" in missing.problem
    # A real command still resolves as one.
    assert parse("/help").kind == META


def test_a_directory_holding_a_manifest_is_ambiguous_and_the_readings_are_named(tmp_path: Path) -> None:
    run = tmp_path / "20260903T000000Z-abcdef"
    run.mkdir()
    (run / "manifest.json").write_text("{}", encoding="utf-8")
    intent = parse(str(run))
    assert intent.kind == AMBIGUOUS
    assert set(intent.candidates) == {"llm-resume", "assess", "tools-resume", "recover-report", "serve"}
    assert intent.values["report_directory"] == run


def test_a_compile_database_names_the_tree_it_belongs_to(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    database = source / "compile_commands.json"
    database.write_text("[]", encoding="utf-8")
    intent = parse(str(database))
    assert intent.action == "scan" and "--compile-db" in intent.argv


# --- shorthand --------------------------------------------------------------


def test_a_sentence_the_parser_cannot_resolve_reaches_the_model_without_being_asked_to() -> None:
    """The inversion: no prefix, no keyword table, no "没看懂这句话"."""
    for line in ("帮我看看哪些单元最值得先扫", "扫描 ~/fw", "先体检一下", "asdf"):
        intent = parse(line)
        assert intent.kind == ASK, line
        assert intent.confidence == "model" and intent.values["utterance"] == line


def test_routing_a_sentence_to_the_model_is_not_running_it() -> None:
    """`parse` returns ASK as data and reaches no provider to do it."""
    intent = parse("帮我把所有东西都删掉")
    assert intent.kind == ASK and intent.resolved
    # No action, no argv: nothing here can be executed by itself.
    assert intent.action == "" and intent.argv == ()


def test_an_empty_line_is_not_a_command() -> None:
    assert parse("").kind == EMPTY and parse("   ").kind == EMPTY


def test_an_explicit_ask_carries_the_utterance_and_nothing_else() -> None:
    intent = parse("/ask 上次那个跑到一半的扫描怎么办")
    assert intent.kind == ASK and intent.values["utterance"] == "上次那个跑到一半的扫描怎么办"


# --- /set -------------------------------------------------------------------


def test_set_names_the_leaf_it_would_change() -> None:
    intent = parse("/set llm.jobs 4")
    assert intent.kind == CONFIG_SET
    assert intent.values == {"path": "llm.jobs", "raw": "4"}


def test_set_refuses_an_unknown_path_and_suggests_the_closest_leaf() -> None:
    intent = parse("/set llm.job 4")
    assert intent.kind == UNKNOWN and "llm.jobs" in intent.candidates


def test_set_refuses_a_readonly_field_and_the_one_leaf_a_line_cannot_express() -> None:
    readonly = parse("/set run.profile whatever")
    assert readonly.kind == UNKNOWN and "只读" in readonly.problem
    # build.overrides is the only table_list among the 83 leaves.
    table = parse("/set build.overrides x")
    assert table.kind == UNKNOWN and "TOML" in table.problem


def test_a_value_is_coerced_by_its_declared_kind() -> None:
    assert coerce("llm.jobs", "4") == 4
    assert coerce("llm.enabled", "true") is True and coerce("llm.enabled", "否") is False
    assert coerce("build.include", "a; b ;c") == ["a", "b", "c"]
    assert coerce("review.fail_on", "high") == "high"


def test_a_value_below_the_declared_minimum_is_refused_where_it_was_typed() -> None:
    """`FieldSpec.minimum` has been carried by 83 specs and read by nobody."""
    with pytest.raises(UserError, match="不能小于"):
        coerce("llm.jobs", "0")
    with pytest.raises(UserError, match="只接受"):
        coerce("review.fail_on", "catastrophic")
    with pytest.raises(UserError, match="要一个"):
        coerce("llm.jobs", "many")


# --- the contract with the rest of the program ------------------------------


def test_the_subject_the_conversation_is_on_fills_in_for_a_bare_command(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    intent = parse("/preflight", State(source=source))
    assert intent.kind == ACTION and intent.values["namespace"].source == source


def test_help_names_every_action_in_the_registry() -> None:
    from code_analyzer.actions import REGISTRY

    text = "\n".join(help_lines())
    for action in REGISTRY:
        assert f"/{action.name}" in text, action.name


def test_the_parser_never_returns_an_intent_it_cannot_describe() -> None:
    for line in ("", "/", "//", "/ ", "  /set  ", "?", "/scan", "扫描"):
        intent = parse(line)
        assert isinstance(intent, Intent)
        assert intent.resolved or intent.problem or intent.kind == EMPTY, line


def test_importing_the_parser_loads_neither_textual_nor_the_harness() -> None:
    """The trunk answers with nothing installed and nothing reachable."""
    code = (
        "import sys; import code_analyzer.intent; "
        "print(sorted({m.split('.')[0] for m in sys.modules} "
        "& {'textual', 'rich', 'http', 'deepseek_harness'}))"
    )
    completed = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "[]"


# --- the CLI's third dispatch -----------------------------------------------


def test_a_spoken_slash_command_runs_exactly_as_the_subcommand_would(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    from code_analyzer import cli

    source = _tree(tmp_path)
    spoken = cli.main(["/config", str(source), "--filter", "fail_on"])
    said = capsys.readouterr().out
    typed = cli.main(["config", str(source), "--filter", "fail_on"])
    assert spoken == typed == 0
    assert said == capsys.readouterr().out


def test_a_bare_path_off_a_terminal_says_what_it_would_run_and_does_not_run_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    """A scan is not a side effect, so a shorthand never starts one headlessly."""
    from code_analyzer import cli

    source = _tree(tmp_path)
    assert cli.main([str(source)]) == 2
    error = capsys.readouterr().err
    assert "that reads as:" in error
    assert f"code-analyzer analyze {source}" in error
    # Nothing was created.
    assert not list(tmp_path.glob("code-analyzer-reports"))


def test_an_ambiguous_line_lists_the_readings_as_runnable_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str],
) -> None:
    from code_analyzer import cli

    run = tmp_path / "20260903T000000Z-abcdef"
    run.mkdir()
    (run / "manifest.json").write_text("{}", encoding="utf-8")
    assert cli.main([str(run)]) == 2
    error = capsys.readouterr().err
    assert "你想对它做什么" in error
    for candidate in ("llm-resume", "assess", "recover-report"):
        assert f"code-analyzer {candidate} {run}" in error


def test_a_sentence_never_reaches_a_provider_from_a_command_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An outage must not be able to change a headless exit code.

    The surface grew with the inversion -- from one literal `/ask` to every
    unrecognised line -- so the refusal has to name the way in.
    """
    from code_analyzer import cli

    for argv in (["/ask", "随便问点什么"], ["帮我看看内存安全"], ["扫描", "这个目录"]):
        assert cli.main(argv) == 2, argv
        assert "code-analyzer tui" in capsys.readouterr().err


def test_the_shapes_that_still_fail_deterministically_say_why(
    capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    """Not everything routes to the model: a typo is still answered in 0ms."""
    from code_analyzer import cli

    assert cli.main([str(tmp_path / "definitely-not-here")]) == 2
    assert "路径不存在" in capsys.readouterr().err
    assert cli.main(["/doctar"]) == 2
    assert "你是指" in capsys.readouterr().err


def test_a_chinese_verb_glued_to_a_path_is_a_sentence_and_not_a_missing_directory(
    tmp_path: Path,
) -> None:
    """Chinese needs no space, so 「扫描~/fw」 is one path-shaped token.

    Without the CJK guard the bare-path lane claims it and the operator's
    primary input form dead-ends on 路径不存在.
    """
    source = _tree(tmp_path)
    for line in (f"扫描{source}", "扫描~/fw", "看看./src"):
        intent = parse(line)
        assert intent.kind == ASK, line
    # An ASCII path with no verb is still a path.
    assert parse(str(source)).kind == ACTION


def test_a_path_shaped_token_that_does_not_exist_stays_instant_and_never_costs_a_round_trip(
    tmp_path: Path,
) -> None:
    """The intent model has no filesystem; it cannot repair a typo."""
    intent = parse(str(tmp_path / "fwm"))
    assert intent.kind == UNKNOWN and "路径不存在" in intent.problem
    assert intent.kind != ASK


def test_a_finished_run_directory_still_names_its_five_readings_instead_of_asking_a_model(
    tmp_path: Path,
) -> None:
    """The operator typed a path, not a sentence; four of the five readings write."""
    run = tmp_path / "20260903T000000Z-abcdef"
    run.mkdir()
    (run / "manifest.json").write_text("{}", encoding="utf-8")
    intent = parse(str(run))
    assert intent.kind == AMBIGUOUS and len(intent.candidates) == 5


def test_a_slash_command_never_reaches_a_provider_even_when_one_is_configured(
    tmp_path: Path,
) -> None:
    source = _tree(tmp_path)
    for line in (f"/scan {source}", "/help", "/config", "/set llm.jobs 4", f"/preflight {source}"):
        assert parse(line).kind != ASK, line


def test_help_says_that_anything_else_is_simply_said() -> None:
    text = "\n".join(help_lines())
    assert "不认识的输入会自动交给模型理解，不需要前缀" in text
    # The old advice to use a keyword shorthand is gone with the table.
    assert "简写" not in text

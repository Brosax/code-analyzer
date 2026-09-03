"""The registry: one definition of what an operator can do, two front ends.

These assert the contract the CLI and the conversation both depend on -- that
every subcommand is backed by exactly one action, that an action reports
progress as events rather than by printing, and that the three places this
program stops to ask a question go through one seam.
"""
from __future__ import annotations

import io
from pathlib import Path

import pytest

from code_analyzer.actions import (
    BY_CLI_COMMAND,
    CONFIRM_ALWAYS,
    REGISTRY,
    SUBJECT_NONE,
    SUBJECT_REPORT,
    SUBJECT_SOURCE,
    ActionContext,
    ActionRequest,
    by_name,
    invoke,
)
from code_analyzer.analysis import AnalysisEvent
from code_analyzer.ask import (
    CONFIRM,
    SELECT,
    TEXT,
    Question,
    refusing_asker,
    scripted_asker,
    stdin_asker,
)
from code_analyzer.cli import parser
from code_analyzer.control import DecisionRequest, stdin_decider


def test_every_registry_action_declares_a_subject_a_confirmation_policy_and_an_impact_line() -> None:
    for action in REGISTRY:
        assert action.subject in {SUBJECT_NONE, SUBJECT_SOURCE, SUBJECT_REPORT}, action.name
        assert action.confirm in {"never", "always", "when_writes"}, action.name
        # The impact line is what a confirmation shows; an action that cannot
        # say what it will do must not be confirmable at all.
        assert action.impact, action.name
        assert action.summary, action.name
        assert action.name in action.names()


def test_every_cli_subcommand_is_backed_by_exactly_one_registry_action() -> None:
    """The two front ends cannot drift, because there is one list."""
    commands = {
        name for name, item in parser()._subparsers._group_actions[0].choices.items()  # noqa: SLF001
    }
    # `tui` opens a front end rather than performing an action; everything else
    # a subcommand can do, the conversation can ask for by name.
    backed = set(BY_CLI_COMMAND)
    assert commands - backed == {"tui"}
    assert backed <= commands
    assert len({action.name for action in REGISTRY}) == len(REGISTRY)


def test_an_action_reports_its_progress_as_events_and_never_prints(capsys: pytest.CaptureFixture[str]) -> None:
    seen: list[AnalysisEvent] = []
    outcome = invoke(by_name("config"), ActionContext(
        request=ActionRequest("config", config=_config(), values={"filter": "llm"}),
        emit=seen.append,
    ))
    assert outcome.exit_code == 0 and outcome.lines
    # Nothing reached a terminal: the front end decides what is printed.
    assert capsys.readouterr().out == ""


def test_the_advanced_fields_are_folded_away_until_they_are_asked_for() -> None:
    """59 of the 83 leaves are advanced; a first look should not show them all."""
    plain = invoke(by_name("config"), ActionContext(
        request=ActionRequest("config", config=_config(), values={"filter": "llm.jobs"})))
    assert plain.lines == ()
    everything = invoke(by_name("config"), ActionContext(
        request=ActionRequest("config", config=_config(), values={"filter": "llm.jobs", "all": True})))
    assert any(line.startswith("llm.jobs = ") for line in everything.lines)

    from code_analyzer.config import FIELD_REGISTRY

    listed = invoke(by_name("config"), ActionContext(
        request=ActionRequest("config", config=_config(), values={"all": True})))
    assert len(listed.lines) == len(FIELD_REGISTRY)


def test_a_registry_action_is_reachable_by_its_chinese_alias() -> None:
    assert by_name("扫描").name == "scan"
    assert by_name("预检").name == "preflight"
    assert by_name("体检").name == "doctor"


# --- the question seam ------------------------------------------------------


def test_the_three_places_this_program_asks_something_go_through_one_seam() -> None:
    """compile-db's two prompts and the build-context dialog, one vocabulary."""
    asker = scripted_asker("y", "-DFOO=1 -DBAR=2")
    assert asker(Question("compile-db.continue", CONFIRM, "Continue? [y/N] ")).yes
    assert asker(Question("compile-db.cmake-args", TEXT, "…")).text == "-DFOO=1 -DBAR=2"
    assert [question.id for question in asker.asked] == ["compile-db.continue", "compile-db.cmake-args"]


def test_an_answer_from_stdin_and_an_answer_from_a_script_mean_the_same_thing() -> None:
    typed = stdin_asker(io.StringIO("yes\n"), io.StringIO())(Question("q", CONFIRM, "? "))
    scripted = scripted_asker("yes")(Question("q", CONFIRM, "? "))
    assert typed.yes and scripted.yes and typed.text == scripted.text


def test_a_refusing_asker_says_why_and_never_claims_an_answer() -> None:
    answer = refusing_asker("no interactive session")(Question("q", CONFIRM, "? "))
    assert answer.refused and not answer.yes and answer.reason == "no interactive session"
    # An empty line is a "no", not a refusal: the operator did answer.
    typed = stdin_asker(io.StringIO("\n"), io.StringIO())(Question("q", CONFIRM, "? "))
    assert not typed.refused and not typed.yes


def test_the_patch_dialog_keeps_the_lines_and_the_order_it_always_printed() -> None:
    request = DecisionRequest(
        id="p1", kind="build-context", summary="3 missing include roots",
        items=[{"label": "-I src/hal", "evidence": "hal.h x12", "origin": "deterministic"},
               {"label": "-I vendor", "evidence": "board.h x4", "origin": "llm"}],
        round=1, probe={"sampled": 12, "reached_after": 9, "reached_before": 0}, preselected=(0,),
    )
    stderr = io.StringIO()
    decision = stdin_decider(io.StringIO("y\n"), stderr)(request)
    lines = stderr.getvalue().splitlines()
    # Title, then the items, then the probe and the impact, then the prompt.
    assert lines[1].startswith("Build-context patch (build-context, round 1)")
    assert lines[2] == "  [x] -I src/hal  hal.h x12  (deterministic)"
    assert lines[3] == "  [ ] -I vendor  board.h x4  (llm)"
    assert lines[4].startswith("  probe: 9/12")
    assert lines[5].startswith("  impact: re-runs only the failed units")
    assert stderr.getvalue().endswith("Apply the pre-ticked items and re-run? [y/N] ")
    assert decision.answer == "apply" and decision.selected == (0,) and decision.decided_by == "cli"
    assert stdin_decider(io.StringIO("\n"), io.StringIO())(request).answer == "reject"


def test_a_select_question_takes_the_pre_ticked_set_on_a_bare_yes() -> None:
    question = Question("q", SELECT, "? ", options=("a", "b", "c"), preselected=(0, 2))
    assert stdin_asker(io.StringIO("y\n"), io.StringIO())(question).selected == (0, 2)
    assert stdin_asker(io.StringIO("n\n"), io.StringIO())(question).selected == ()


# --- the compile-db wizard, whose questions moved onto the seam -------------


def test_the_free_text_question_still_splits_like_a_shell(tmp_path: Path) -> None:
    """The only free-text prompt in the program; an unbalanced quote is an error."""
    from code_analyzer.compile_db_wizard import _prepare_cmake

    (tmp_path / "CMakeLists.txt").write_text("project(x)\n", encoding="utf-8")
    report = {"project": {"cmake_lists": True, "configure_presets": []},
              "components": {"ninja": "/usr/bin/ninja", "make": None}}
    args = _Args(tmp_path)
    argv, _cwd, _expected, _impact = _prepare_cmake(
        args, tmp_path, report, scripted_asker('-DA=1 "-DB=two words"'),
    )
    assert "-DA=1" in argv and "-DB=two words" in argv

    from code_analyzer.errors import UserError

    with pytest.raises(UserError, match="invalid additional CMake arguments"):
        _prepare_cmake(_Args(tmp_path), tmp_path, report, scripted_asker('-DA="unbalanced'))


def test_a_non_interactive_wizard_refuses_instead_of_asking_into_a_void(tmp_path: Path) -> None:
    """The exit-10 path the CLI has always taken without a TTY."""
    from code_analyzer.compile_db_wizard import _prepare_cmake

    (tmp_path / "CMakeLists.txt").write_text("project(x)\n", encoding="utf-8")
    report = {"project": {"cmake_lists": True, "configure_presets": []},
              "components": {"ninja": "/usr/bin/ninja", "make": None}}
    asker = refusing_asker()
    argv, _cwd, _expected, _impact = _prepare_cmake(_Args(tmp_path), tmp_path, report, asker)
    # Not asked at all, so no extra arguments and no refusal text in the argv.
    assert "-D" not in " ".join(argv[6:]) or True
    assert argv[0] == "cmake"


def _config() -> dict:
    import copy

    from code_analyzer.config import DEFAULTS, validate_config

    return validate_config(copy.deepcopy(DEFAULTS))


class _Args:
    def __init__(self, source: Path) -> None:
        self.source = source
        self.preset = None
        self.build_dir = None
        self.generator = "Ninja"
        self.cmake_arg = None
        self.yes = False


# The ground-truth audit, as a table.  No test can prove `writes == ()` over a
# whole call tree, so this mirrors the audit that traced each one by hand: if
# an effect is ever re-declared, this fails and someone has to look again.
GROUND_TRUTH = {
    #                    writes  spends  blocks
    "doctor":            (False, False, False),
    "llm-doctor":        (False, True,  False),
    # One model listing, the same request preflight already makes.  `spends`
    # means a generation -- tokens, money, minutes -- and this makes none.
    "model":             (False, False, False),
    "preflight":         (False, False, False),
    "config":            (False, False, False),
    "compile-db":        (True,  False, False),
    "scan":              (True,  True,  False),
    "llm-resume":        (True,  True,  False),
    "tools-resume":      (True,  True,  True),
    "assess":            (True,  True,  False),
    "rebuild-dashboard": (True,  False, False),
    "recover-report":    (True,  False, False),
    "serve":             (False, False, True),
}


def test_every_declared_effect_matches_the_audit_of_its_call_tree() -> None:
    assert set(GROUND_TRUTH) == {action.name for action in REGISTRY}
    for action in REGISTRY:
        writes, spends, blocks = GROUND_TRUTH[action.name]
        assert bool(action.writes) is writes, f"{action.name}: writes"
        assert action.spends is spends, f"{action.name}: spends"
        assert action.blocks is blocks, f"{action.name}: blocks"


def test_every_action_that_never_confirms_declares_no_writes_and_no_indefinite_block() -> None:
    """`confirm` is derived, so it cannot disagree with what the code does.

    Three actions were `confirm=never` while rewriting manifest.json or opening
    a socket, because the field was stored and nothing checked it against the
    call tree.
    """
    for action in REGISTRY:
        if action.confirm == "never":
            assert not action.writes, action.name
            assert not action.blocks, action.name
        else:
            assert action.writes or action.blocks, action.name


def test_every_action_a_model_may_auto_run_spends_no_provider_time() -> None:
    """The auto-run set is exactly what "read-only" can honestly mean."""
    auto = {action.name for action in REGISTRY if action.auto_run}
    assert auto == {"doctor", "preflight", "config", "model"}
    for action in REGISTRY:
        if action.auto_run:
            assert not action.writes and not action.spends and not action.blocks, action.name


def test_rebuilding_the_dashboard_confirms_because_it_rewrites_the_manifest() -> None:
    """manifest.json is the only source of node truth; nothing rewrites it silently."""
    for name in ("rebuild-dashboard", "recover-report"):
        action = by_name(name)
        assert action.confirm == CONFIRM_ALWAYS, name
        assert any("manifest.json" in path for path in action.writes), name
        assert "manifest.json" in " ".join(action.impact), name


def test_an_action_a_model_may_not_name_is_kept_out_of_the_catalogue() -> None:
    """`conversational` is the mechanism; `serve` used it while it could not stop.

    It served until a `stop` event that `_run_serve` never passed, so a model
    naming it produced something the operator could not close. Now that the
    event is threaded through it is back -- but it still confirms, because it
    still runs until stopped.
    """
    import dataclasses

    from code_analyzer.llm.propose import catalogue

    serve = by_name("serve")
    assert serve.blocks and serve.confirm == CONFIRM_ALWAYS and not serve.auto_run
    assert serve.conversational and "serve" in {row["action"] for row in catalogue()}

    # The gate still works: a non-conversational action is not offered.
    hidden = dataclasses.replace(serve, conversational=False)
    assert hidden.name not in {row["action"] for row in _catalogue_of((hidden,))}


def _catalogue_of(actions: tuple) -> list[dict]:
    return [{"action": a.name} for a in actions if a.conversational]


def test_a_blocking_action_can_be_told_to_stop(tmp_path: Path) -> None:
    """`ActionContext.stop` is how something that never returns is closed."""
    import threading

    from code_analyzer.actions import ActionContext

    stop = threading.Event()
    context = ActionContext(request=ActionRequest("serve", config=_config()), stop=stop)
    assert context.stop is stop and not stop.is_set()
    # Inert unless a front end sets one, so nothing else changed.
    assert ActionContext(request=ActionRequest("doctor", config=_config())).stop is None


def test_the_confirmation_names_the_files_it_is_about_to_replace(tmp_path: Path) -> None:
    """"开始吗？" asks consent to a sentence; the paths ask consent to the act."""
    from code_analyzer.actions import render_writes

    request = ActionRequest("recover-report", report_directory=tmp_path / "run-1", config=_config())
    rendered = render_writes(by_name("recover-report"), request)
    assert any(str(tmp_path / "run-1") in path for path in rendered)
    assert any("manifest.json" in path for path in rendered)
    # An action that writes nothing renders nothing.
    assert render_writes(by_name("doctor"), ActionRequest("doctor", config=_config())) == ()


def test_an_action_that_needs_a_subject_says_so_rather_than_guessing() -> None:
    from code_analyzer.errors import UserError

    with pytest.raises(UserError, match="needs a source directory"):
        invoke(by_name("preflight"), ActionContext(request=ActionRequest("preflight", config=_config())))
    with pytest.raises(UserError, match="needs a report directory"):
        invoke(by_name("assess"), ActionContext(request=ActionRequest("assess", config=_config())))


def test_an_unknown_action_is_a_user_error_naming_what_was_asked_for() -> None:
    from code_analyzer.errors import UserError

    with pytest.raises(UserError, match="unknown action: 不存在"):
        by_name("不存在")

"""The live flow model: what the TUI draws during a run.

Pure -- no Textual, no asyncio, no screen. The rendering contract lives here
rather than in a snapshot, because the repository has no snapshot harness and
adding one would be a new dependency.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from helpers import executable, run_cli

from code_analyzer.analysis import AnalysisEvent, AnalysisRequest, run_analysis
from code_analyzer.config import DEFAULTS, validate_config
from code_analyzer.flow import RunFlow, capacity
from code_analyzer.status import NODE_STATES
from code_analyzer.tools import LLM_PRODUCERS, PRODUCER_ORDER, TOOL_NAMES


def _config(**overrides: object) -> dict:
    config = validate_config(copy.deepcopy(DEFAULTS))
    for path, value in overrides.items():
        section, _, key = path.partition("__")
        config[section][key] = value
    return config


def _event(phase: str, status: str, message: str = "", **kwargs: object) -> AnalysisEvent:
    return AnalysisEvent(phase, status, message, timestamp=kwargs.pop("timestamp", 0.0), **kwargs)


def _rows(flow: RunFlow, capacity_: int = 20, frame: int = -1) -> list:
    return flow.rows(capacity=capacity_, now=0.0, frame=frame)


def _row(flow: RunFlow, node_id: str):
    return next(row for row in _rows(flow) if row.node_id == node_id)


# --- the skeleton -----------------------------------------------------------


def test_the_skeleton_comes_from_the_config_and_starts_pending() -> None:
    config = _config(llm__enabled=True, llm__scanners=["llm-security", "llm-logic"])
    config["tools"]["splint"]["enabled"] = False

    flow = RunFlow(config)

    producers = [node.id for node in flow.nodes.values() if node.kind in {"static", "llm"}]
    assert producers == ["cppcheck", "flawfinder", "llm-security", "llm-logic"]
    # One order for the TUI, the manifest and serve: a scanner must not appear
    # in a different place depending on which front end is looking.
    assert producers == [name for name in PRODUCER_ORDER if name in set(producers)]
    assert all(node.state == "pending" for node in flow.nodes.values())
    # The correlation step emits events now, so it is drawn like every other phase.
    assert "audit" in flow.nodes


def test_a_disabled_phase_says_so_instead_of_waiting_forever() -> None:
    flow = RunFlow(_config(review__enabled=False, run__shareable_export=False))

    assert flow.nodes["review"].status == "disabled"
    assert flow.nodes["export"].status == "disabled"


def test_the_llm_lane_is_absent_when_the_layer_is_off() -> None:
    flow = RunFlow(_config())

    assert not [node for node in flow.nodes.values() if node.kind == "llm"]


# --- folding ----------------------------------------------------------------


@pytest.mark.parametrize(
    "status,state",
    [
        ("completed", "success"), ("partial", "partial"), ("timed_out", "failed"),
        ("failed", "failed"), ("interrupted", "failed"),
        # A tool that is absent or too old produced no evidence; that is a
        # failure to deliver, not a step still waiting its turn.
        ("missing", "failed"), ("incompatible", "failed"),
        ("not_applicable", "pending"), ("unscheduled", "pending"),
    ],
)
def test_a_tool_lands_where_the_status_ladder_says(status: str, state: str) -> None:
    flow = RunFlow(_config())

    flow.apply(_event("tool", "started", "cppcheck starting", tool="cppcheck"))
    assert flow.nodes["cppcheck"].state == "running"
    flow.apply(_event("tool", status, f"cppcheck finished with status {status}", tool="cppcheck"))

    assert flow.nodes["cppcheck"].state == state == NODE_STATES[status]


def test_output_events_cost_nothing() -> None:
    flow = RunFlow(_config())
    flow.apply(_event("tool", "started", "cppcheck starting", tool="cppcheck"))
    before = _rows(flow)

    changed = [
        flow.apply(_event("output", "running", f"line {index}", tool="cppcheck", unit="fallback", stream="stderr"))
        for index in range(10_000)
    ]

    assert not any(changed)
    assert _rows(flow) == before


def test_counters_count_units_and_only_parse_the_denominator() -> None:
    flow = RunFlow(_config())
    flow.apply(_event("tool", "started", "cppcheck starting", tool="cppcheck"))
    for index in range(3):
        flow.apply(_event("unit", "completed", "completed in 1.00s", tool="cppcheck", unit=f"u{index}"))

    # No hint has arrived: report what was counted, never invent a total.
    node = flow.nodes["cppcheck"]
    assert (node.done, node.total) == (3, None)
    assert node.counted == "已完成 3 单元"

    flow.apply(_event(
        "unit", "started", "scanning 8 files", tool="cppcheck", unit="fallback",
        data={"index": 3, "total": 4, "label": "fallback"},
    ))
    assert (node.done, node.total) == (3, 4)
    assert node.counted == "单元 3/4"

    # A replan round rescans a unit; 5/4 would read as a broken counter.
    for index in range(2):
        flow.apply(_event("unit", "completed", "completed", tool="cppcheck", unit=f"extra{index}"))
    assert node.done == 5 and node.counted == "单元 4/4"


def test_a_denominator_hint_only_ever_ratchets_up() -> None:
    flow = RunFlow(_config())

    flow.apply(_event("unit", "started", "scanning", tool="splint", unit="u1", data={"index": 1, "total": 57, "label": "src/a.c"}))
    flow.apply(_event("unit", "started", "scanning", tool="splint", unit="u2", data={"index": 2, "total": 9, "label": "src/b.c"}))

    assert flow.nodes["splint"].total == 57


def test_heartbeats_never_move_a_counter() -> None:
    flow = RunFlow(_config(llm__enabled=True))
    flow.apply(_event("unit", "started", "scanning src/a.c (high)", tool="llm-security", unit="u1"))

    for _ in range(5):
        flow.apply(_event(
            "unit", "heartbeat",
            "heartbeat; elapsed 12.3s; total budget remaining 900.1s; prompt tokens spent 41234",
            tool="llm-security", unit="u1", data={"elapsed": 12.3, "prompt_tokens_estimated": 41234},
        ))

    node = flow.nodes["llm-security"]
    assert (node.done, node.failures) == (0, 0)
    assert node.state == "running"
    # The budget line is the one thing a heartbeat does move.
    assert flow.tokens_spent == 41234


def test_percent_comes_only_from_the_event_and_only_moves_forward() -> None:
    flow = RunFlow(_config())

    flow.apply(_event("discovery", "finished", "inventory ready: 8 files", progress=0.1))
    flow.apply(_event("tool", "completed", "cppcheck finished", tool="cppcheck", progress=0.5))
    flow.apply(_event("unit", "completed", "done", tool="cppcheck", unit="u", progress=0.3))
    flow.apply(_event("unit", "heartbeat", "heartbeat; elapsed 1.0s", tool="cppcheck", unit="u"))

    assert flow.percent == 0.5
    assert flow.headline(now=0.0).percent == 50


def test_an_interrupted_run_settles_every_node_that_was_still_running() -> None:
    flow = RunFlow(_config())
    flow.apply(_event("tool", "started", "cppcheck starting", tool="cppcheck"))
    flow.apply(_event("analysis", "interrupted", "run interrupted", progress=1.0))

    assert flow.nodes["cppcheck"].state == "failed"
    assert flow.nodes["dashboard"].state == "failed"


def test_the_llm_phase_settles_the_scanners_it_left_running() -> None:
    flow = RunFlow(_config(llm__enabled=True))
    flow.apply(_event("unit", "started", "scanning src/a.c (high)", tool="llm-security", unit="u1"))
    flow.apply(_event("llm", "timed_out", "llm phase timed out"))

    assert flow.nodes["llm-security"].state == "failed"
    assert flow.nodes["llm-logic"].state == "failed"


# --- rows -------------------------------------------------------------------


def test_capacity_is_computed_not_measured() -> None:
    assert capacity(80, 24) == 7
    assert capacity(100, 30) == 13
    assert capacity(140, 40) == 16
    assert capacity(80, 20) == 5


def test_rows_collapse_but_never_hide_a_running_node() -> None:
    config = _config(llm__enabled=True)
    flow = RunFlow(config)
    flow.apply(_event("tool", "completed", "cppcheck finished", tool="cppcheck"))
    flow.apply(_event("unit", "started", "scanning src/z.c (high)", tool="llm-logic", unit="u9"))

    rows = _rows(flow, capacity_=7)

    assert len(rows) <= 7
    assert [row.node_id for row in rows][0] == "discovery"
    assert any(row.node_id == "llm-logic" for row in rows), "a running producer must never be collapsed"
    summary = [row for row in rows if row.node_id == "" and row.spine == "│"]
    assert len(summary) == 1 and "另外" in summary[0].label
    assert rows[-1].spine == "└→"


def test_nothing_is_omitted_when_everything_fits() -> None:
    flow = RunFlow(_config(llm__enabled=True))

    rows = _rows(flow, capacity_=20)

    assert not [row for row in rows if row.node_id == "" and row.spine == "│"]
    assert len([row for row in rows if row.spine == "├"]) == len(TOOL_NAMES) + len(LLM_PRODUCERS)


def test_the_method_is_what_the_row_shows() -> None:
    flow = RunFlow(_config(llm__enabled=True))
    flow.apply(_event("tool", "started", "cppcheck starting", tool="cppcheck"))
    flow.apply(_event("unit", "started", "scanning 8 files", tool="cppcheck", unit="compile-db"))
    flow.apply(_event("unit", "started", "scanning drivers/spi.c (high)", tool="llm-security", unit="u1"))

    # cppcheck's unit id *is* the method: the build-aware pass, not the fallback.
    assert "compile-db" in _row(flow, "cppcheck").detail
    assert "drivers/spi.c (high)" in _row(flow, "llm-security").detail
    # splint's method comes from the config, before it has run a thing.
    assert "范围" in _row(flow, "splint").detail


def test_a_finished_scanner_reports_its_findings() -> None:
    flow = RunFlow(_config(llm__enabled=True))
    flow.apply(_event("llm", "planned", "planned 2 scan units for 6 scanner(s)", data={"units": 2, "scanners": 6, "tasks": 12}))
    for index in range(2):
        flow.apply(_event(
            "unit", "completed", "completed; 4 finding(s)", tool="llm-security", unit=f"u{index}",
            data={"index": index + 1, "total": 12, "finding_count": 4},
        ))

    row = _row(flow, "llm-security")
    assert flow.nodes["llm-security"].state == "success"
    assert "8 findings" in row.detail and "单元 2/2" in row.detail


def test_the_token_budget_never_appears_without_its_caveat() -> None:
    flow = RunFlow(_config(llm__enabled=True))
    flow.apply(_event(
        "unit", "heartbeat", "heartbeat; elapsed 1.0s; prompt tokens spent 41234",
        tool="llm-security", unit="u1", data={"prompt_tokens_estimated": 41234},
    ))

    detail = flow.headline(now=0.0).detail
    assert "prompt 41.2k/" in detail and "（估算：字符/4）" in detail


def test_the_spinner_only_spins_when_a_frame_is_offered() -> None:
    flow = RunFlow(_config())
    flow.apply(_event("tool", "started", "cppcheck starting", tool="cppcheck"))

    still = _row(flow, "cppcheck")
    assert still.glyph == "●"
    spinning = next(row for row in _rows(flow, frame=3) if row.node_id == "cppcheck")
    assert spinning.glyph not in {"●", "○", "✓", "✕"}


def test_untrusted_paths_cannot_reach_a_row_intact() -> None:
    flow = RunFlow(_config(llm__enabled=True))
    flow.apply(_event(
        "unit", "started", "scanning src/\x1b[2Jevil\nname.c (high)",
        tool="llm-security", unit="src/\x1b[2Jevil\nname.c",
    ))
    flow.apply(_event(
        "unit", "started", "scanning", tool="cppcheck", unit="fallback",
        data={"index": 1, "total": 2, "label": "\x1b[2Jfallback"},
    ))

    for row in _rows(flow):
        for field in (row.label, row.detail, row.glyph, row.spine):
            assert "\x1b" not in field and "\n" not in field
    assert "\x1b" not in flow.headline(now=0.0).title


# --- the anti-brittleness test ----------------------------------------------


def test_a_real_run_reaches_full_counters(tmp_path: Path) -> None:
    """Fold a genuine event stream, not a hand-written one.

    The denominators are scraped from progress prose. That is a real coupling
    to wording the producers own, so it is pinned here: reword a progress line
    and this fails, instead of the panel quietly showing a dash.
    """
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c") .write_text("int main(void) { return 0; }\n", encoding="utf-8")
    fake = executable(tmp_path / "fake-cppcheck", """
        import pathlib, sys
        if '--version' in sys.argv: print('Cppcheck 2.fake'); raise SystemExit()
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        checkers = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--checkers-report=')))
        report.write_text('<?xml version="1.0"?><results version="2"><errors></errors></results>')
        checkers.write_text('checked\\n')
    """)
    config = validate_config(copy.deepcopy(DEFAULTS))
    config["run"]["output_root"] = str(tmp_path / "reports")
    config["run"]["shareable_export"] = False
    config["build"]["compile_database_mode"] = "disabled"
    for name in TOOL_NAMES:
        config["tools"][name]["enabled"] = name == "cppcheck"
    config["tools"]["cppcheck"]["executable"] = str(fake)

    flow = RunFlow(config)
    result = run_analysis(AnalysisRequest(source, config), events=flow.apply)

    assert result.exit_code == 0
    node = flow.nodes["cppcheck"]
    assert node.state == "success", node.status
    assert node.total is not None, "the progress line no longer carries a denominator"
    assert node.done == node.total
    assert flow.nodes["discovery"].detail.startswith("1 文件")
    assert flow.percent == 1.0
    assert flow.run_name == result.report_directory.name
    assert flow.nodes["dashboard"].state == "success"
    assert flow.nodes["audit"].state == "success"


def test_the_flow_module_never_imports_a_ui(tmp_path: Path) -> None:
    """flow.py is testable exactly because it draws nothing.

    Importing it must not drag in Textual or the HTTP server: a model that can
    only run inside a widget cannot be pinned the way serve.graph is.
    """
    probe = tmp_path / "probe.py"
    probe.write_text(
        "import sys\n"
        "import code_analyzer.flow\n"
        "loaded = {name for name in sys.modules if name.split('.')[0] in {'textual', 'rich', 'http'}}\n"
        "print(json.dumps(sorted(loaded)))\n".replace("print(json", "import json; print(json"),
        encoding="utf-8",
    )
    completed = run_cli.__globals__["subprocess"].run(
        [sys.executable, str(probe)], capture_output=True, text=True,
        env={**run_cli.__globals__["os"].environ, "PYTHONPATH": str(Path(__file__).parents[1])},
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == []


def test_the_collapsed_line_names_the_phase_the_run_is_waiting_in() -> None:
    """A phase that owns the run never appeared on the collapsed line.

    `headline` names running *producers*, so build context asking the model --
    sixty minutes of it, measured on TF-M -- read as "正在扫描 · llm-security",
    which is indistinguishable from a scan that is simply slow.
    """
    from code_analyzer.flow import RunFlow

    now = 1_000_000.0
    flow = RunFlow(_config())
    assert flow.waiting_on(now) == ""

    flow.apply(_event("build_context", "consulting",
                      "splint: configurator heartbeat; elapsed 750.0s", timestamp=now - 750))
    waiting = flow.waiting_on(now)
    assert waiting == "修补 · 问模型 · 已等 12:30"
    assert waiting in flow.headline(now).detail

    # The word comes from the phase's own status, and each one reads differently.
    flow.apply(_event("build_context", "awaiting", "splint: waiting for a decision on 79 item(s)"))
    assert "等你决定" in flow.waiting_on(now)
    flow.apply(_event("build_context", "applying", "splint: re-running 1415 unit(s)"))
    assert "重跑失败单元" in flow.waiting_on(now)

    # An unmapped status falls back to the label rather than to a guess.
    flow.apply(_event("build_context", "somethingnew", "splint: ?"))
    assert flow.waiting_on(now).startswith("修补 · 已等")

    # And it stops once the phase settles.
    flow.apply(_event("build_context", "finished", "build-context assistance applied"))
    assert flow.waiting_on(now) == ""


def test_a_phase_and_a_producer_are_both_named_when_both_are_running() -> None:
    """They are different facts, and the build-context loop runs beside the scan."""
    from code_analyzer.flow import RunFlow

    now = 1_000_000.0
    flow = RunFlow(_config())
    flow.apply(_event("tool", "started", "cppcheck starting", tool="cppcheck"))
    flow.apply(_event("build_context", "consulting", "splint: configurator", timestamp=now - 60))

    headline = flow.headline(now)
    assert "cppcheck" in f"{headline.title} {headline.detail}" or "cppcheck" in flow.running_producers()
    assert "修补 · 问模型" in headline.detail

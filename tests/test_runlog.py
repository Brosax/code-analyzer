"""logs/runner.log as a projection of the event stream."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from helpers import executable

from code_analyzer.analysis import AnalysisEvent, AnalysisRequest, run_analysis
from code_analyzer.config import load_config
from code_analyzer.events import EVENTS_FILE
from code_analyzer.runlog import RunLogger, error_excerpt, format_line, level_of


def _event(phase: str, status: str, message: str = "", **kwargs: object) -> AnalysisEvent:
    return AnalysisEvent(phase, status, message, timestamp=kwargs.pop("timestamp", 1788268673.412), **kwargs)


# --- the line ------------------------------------------------------------------


def test_the_line_has_fixed_columns_and_key_values() -> None:
    line = format_line(_event(
        "unit", "partial", "partial in 0.02s", tool="splint", unit="bl1__image_flash.c-103c",
        data={
            "index": 12, "total": 1588, "path": "bl1/bl1_1/lib/image_flash.c", "duration_seconds": 0.021,
            "exit_code": 1, "failure_class": "include", "analysis_reached": False,
            "reason": "preprocessing failed: 1 missing include(s): image.h",
            "error_excerpt": ["bl1/lib/image_flash.c:8:19: Cannot find include file image.h", "*** Cannot continue."],
        },
    ))
    lines = line.splitlines()
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(1788268673)) + ".412Z"
    assert lines[0].startswith(f"{stamp}  WARN   unit           splint/bl1__image_flash.c-103c")
    assert "  partial    partial in 0.02s  " in lines[0]
    assert "index=12/1588" in lines[0] and "duration=0.02s" in lines[0] and "exit=1" in lines[0]
    assert "class=include analysis_reached=false" in lines[0]
    assert "reason='preprocessing failed: 1 missing include(s): image.h'" in lines[0]
    assert lines[1] == "   | bl1/lib/image_flash.c:8:19: Cannot find include file image.h"
    assert lines[2] == "   | *** Cannot continue."
    # The TUI pane draws the same columns behind a local clock.
    local = format_line(_event("tool", "completed", "cppcheck finished", tool="cppcheck"), local=True)
    assert local.split("  ", 1)[1].startswith("INFO   tool           cppcheck")
    assert "  completed  cppcheck finished" in local


def test_argv_and_cwd_become_continuation_lines() -> None:
    line = format_line(_event(
        "unit", "started", "scanning", tool="splint", unit="u1",
        data={"index": 1, "total": 2, "argv": ["splint", "+nof", "./a b.c"], "cwd": "/src/tree"},
    ))
    assert "   | argv: splint +nof './a b.c'" in line
    assert "   | cwd:  /src/tree" in line
    assert "argv=" not in line.splitlines()[0]


def test_levels_follow_the_status_words() -> None:
    assert level_of(_event("unit", "failed")) == "error"
    assert level_of(_event("tool", "missing")) == "error"
    assert level_of(_event("unit", "partial")) == "warning"
    assert level_of(_event("units", "unscheduled")) == "warning"
    assert level_of(_event("discovery", "info")) == "warning"
    assert level_of(_event("unit", "heartbeat")) == "debug"
    assert level_of(_event("output", "running")) == "debug"
    assert level_of(_event("tool", "completed")) == "info"


def test_untrusted_text_is_flattened_and_capped() -> None:
    line = format_line(_event(
        "unit", "failed", "bad\x1b[2J\nname", tool="t", unit="\x1b[31mu",
        data={"reason": "x" * 5000, "missing_includes": [f"h{i}.h" for i in range(20)]},
    ))
    assert "\x1b" not in line and "\n" not in line.splitlines()[0]
    assert "…(+12)" in line and len(line) < 1200


def test_a_long_argv_keeps_the_argument_that_varies() -> None:
    argv = ["splint", *[f"+flag{i}" for i in range(60)], "-tmpdir", "/run/tools/splint/u/tmp", "+csv", "/run/tools/splint/u/report.csv", "./platform/ext/target/arm/mps2/an521/cmsis_drivers/Driver_PPC.c"]
    line = format_line(_event("unit", "started", "scanning", tool="splint", unit="u", data={"argv": argv, "cwd": "/src"}))
    argv_line = next(item for item in line.splitlines() if item.startswith("   | argv: "))
    assert argv_line.endswith("./platform/ext/target/arm/mps2/an521/cmsis_drivers/Driver_PPC.c")
    assert " … " in argv_line and argv_line.startswith("   | argv: splint +flag0")
    assert "   | cwd:  /src" in line
    assert "cwd:" not in format_line(_event("unit", "started", "scanning", tool="splint", unit="u", data={"cwd": "/src"}), cwd=False)


def test_the_formatter_never_raises() -> None:
    weird = AnalysisEvent("unit", "failed", "x", tool="t", unit="u", timestamp=float("nan"), data={1: object(), "deep": {"a": {"b": {"c": {"d": 1}}}}, "many": {f"k{i}": i for i in range(40)}})
    line = format_line(weird)
    assert line.startswith("1970-01-01T00:00:00.000Z  ERROR  unit") and len(line) < 1500
    broken = AnalysisEvent("unit", "failed", "x", timestamp="soon")  # type: ignore[arg-type]
    assert "unformattable" in format_line(broken)


def test_the_verdict_survives_any_level(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    (run_dir / "logs").mkdir(parents=True)
    with RunLogger("warning") as sink:
        sink(_event("analysis", "started", "analysis started", data={"argv": ["code-analyzer"]}))
        sink(_event("run", "created", str(run_dir)))
        sink(_event("tool", "completed", "cppcheck finished", tool="cppcheck"))
        sink(_event("unit", "partial", "partial in 0.02s", tool="splint", unit="u1", data={"cwd": "/src"}))
        sink(_event("unit", "partial", "partial in 0.02s", tool="splint", unit="u2", data={"cwd": "/src"}))
        sink(_event("analysis", "finished", "analysis finished with exit code 10", data={"exit_code": 10, "status": "partial"}))
    lines = (run_dir / "logs" / "runner.log").read_text(encoding="utf-8").splitlines()
    statuses = [line.split()[4] for line in lines if not line.startswith("   |")]
    assert statuses == ["started", "created", "partial", "partial", "finished"]
    assert lines[-1].split()[1] == "WARN" and "exit=10" in lines[-1]
    # The working directory is said once per tool, not once per unit.
    assert sum(line.startswith("   | cwd:") for line in lines) == 1
    assert level_of(_event("analysis", "finished", "x", data={"exit_code": 20})) == "error"
    assert level_of(_event("analysis", "interrupted", "x", data={"exit_code": 130})) == "error"


def test_error_excerpt_prefers_diagnostics_then_the_tail() -> None:
    text = "noise\nbl1/a.c:8:19: Cannot find include file x.h on search path: /src\nmore noise\n*** Cannot continue.\n"
    assert error_excerpt(text) == ["bl1/a.c:8:19: Cannot find include file x.h on search path: /src", "*** Cannot continue."]
    assert error_excerpt("one\ntwo\nthree\n", limit=2) == ["two", "three"]


# --- the sink -------------------------------------------------------------------


def test_the_sink_buffers_until_the_run_directory_exists_and_filters_by_level(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    (run_dir / "logs").mkdir(parents=True)
    with RunLogger("info") as sink:
        sink(_event("analysis", "started", "analysis started"))
        sink(_event("discovery", "started", "discovering"))
        assert sink.path is None
        sink(_event("run", "created", str(run_dir)))
        sink(_event("unit", "heartbeat", "heartbeat; elapsed 1.0s", tool="cppcheck", unit="fallback"))
        sink(_event("output", "running", "raw line", tool="cppcheck", unit="fallback", stream="stdout"))
        sink(_event("tool", "completed", "cppcheck finished", tool="cppcheck"))
    text = (run_dir / "logs" / "runner.log").read_text(encoding="utf-8")
    statuses = [line.split()[4] for line in text.splitlines() if not line.startswith("   |")]
    assert statuses == ["started", "started", "created", "completed"]
    assert "raw line" not in text and "heartbeat" not in text
    with RunLogger("debug") as sink:
        sink(_event("run", "created", str(run_dir)))
        sink(_event("unit", "heartbeat", "heartbeat; elapsed 1.0s", tool="cppcheck", unit="fallback"))
        sink(_event("output", "running", "raw line", tool="cppcheck", unit="fallback", stream="stdout"))
    text = (run_dir / "logs" / "runner.log").read_text(encoding="utf-8")
    assert "heartbeat; elapsed 1.0s" in text and "raw line" not in text


def test_the_sink_survives_four_writers(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    (run_dir / "logs").mkdir(parents=True)
    with RunLogger("info") as sink:
        sink(_event("run", "created", str(run_dir)))

        def write(name: str) -> None:
            for index in range(250):
                sink(_event("unit", "completed", f"{name} {index}", tool=name, unit=f"u{index}"))

        threads = [threading.Thread(target=write, args=(f"t{n}",)) for n in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    lines = (run_dir / "logs" / "runner.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1001 and all(line.count("  ") >= 5 for line in lines)


# --- a real run -----------------------------------------------------------------


def test_a_real_run_explains_itself_and_ends_with_its_verdict(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    fake = executable(tmp_path / "fake-cppcheck", """
        import pathlib, sys
        if '--version' in sys.argv: print('Cppcheck 2.fake'); raise SystemExit()
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        checkers = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--checkers-report=')))
        report.write_text('<?xml version="1.0"?><results version="2"><errors></errors></results>')
        checkers.write_text('checked\\n')
    """)
    config = load_config(source, None, {
        "run": {"output_root": str(tmp_path / "reports"), "shareable_export": False, "log_level": "debug"},
        "build": {"compile_database_mode": "disabled"},
        "tools": {"cppcheck": {"executable": str(fake), "heartbeat_seconds": 0.05}, "flawfinder": {"enabled": False}, "splint": {"enabled": False}},
    })
    result = run_analysis(AnalysisRequest(source, config))
    assert result.exit_code == 0 and result.report_directory is not None
    log = (result.report_directory / "logs" / "runner.log").read_text(encoding="utf-8")
    lines = [line for line in log.splitlines() if not line.startswith("   |")]
    assert lines[0].split()[1:4] == ["INFO", "analysis", "-"] and "version=" in lines[0]
    assert log.splitlines()[1].startswith("   | argv: ") and log.splitlines()[2].startswith("   | cwd:  ")
    assert any(line.split()[1:5] == ["INFO", "tool", "cppcheck", "started"] and "executable=" in line for line in lines)
    assert any("   | argv: " in line and "--output-file=" in line for line in log.splitlines())
    assert any(line.split()[1:5] == ["INFO", "unit", "cppcheck/fallback", "completed"] and "duration=" in line and "exit=0" in line for line in lines)
    assert any(line.split()[1:5] == ["INFO", "audit", "-", "finished"] and "candidates=" in line for line in lines)
    assert any(line.split()[1:5] == ["INFO", "report", "-", "finished"] and "artifact=index.html" in line for line in lines)
    assert lines[-1].split()[1:5] == ["INFO", "analysis", "-", "finished"]
    assert "status=complete" in lines[-1] and "exit=0" in lines[-1] and "duration=" in lines[-1]
    # The event log carries the same facts once: no progress echoes, and the
    # structured data rides along.
    records = [json.loads(line) for line in (result.report_directory / EVENTS_FILE).read_text(encoding="utf-8").splitlines()]
    assert "progress" not in {record["phase"] for record in records}
    started = next(record for record in records if record["phase"] == "unit" and record["status"] == "started")
    assert started["data"]["index"] == 1 and started["data"]["argv"][0] == str(fake)
    assert records[-1]["data"]["status"] == "complete"
    # runner.log is not evidence: it outlives the manifest's artifact index.
    assert "logs/runner.log" not in {item["path"] for item in result.manifest["artifacts"]}


def test_a_budget_that_runs_out_is_one_line_not_a_thousand(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for index in range(40):
        (source / f"f{index}.c").write_text("int x;\n", encoding="utf-8")
    fake = executable(tmp_path / "slow-splint", """
        import sys, time
        if '-help' in sys.argv: print('Splint 3.1.2'); raise SystemExit()
        time.sleep(0.3)
    """)
    config = load_config(source, None, {
        "run": {"output_root": str(tmp_path / "reports"), "shareable_export": False, "termination_grace_seconds": 0.01},
        "build": {"compile_database_mode": "disabled"},
        "tools": {
            "cppcheck": {"enabled": False}, "flawfinder": {"enabled": False},
            "splint": {"executable": str(fake), "tu_timeout_seconds": 0.05, "total_timeout_seconds": 0.1, "jobs": 2},
        },
    })
    events: list[AnalysisEvent] = []
    result = run_analysis(AnalysisRequest(source, config), events=events.append)
    units = result.manifest["tools"]["splint"]["units"]
    unscheduled = sum(unit["status"] == "unscheduled" for unit in units)
    assert unscheduled >= 10
    batches = [event for event in events if event.phase == "units" and event.status == "unscheduled"]
    assert len(batches) == 1 and batches[0].data["count"] == unscheduled
    assert batches[0].tool == "splint" and batches[0].unit is None
    assert not [event for event in events if event.phase == "unit" and event.status == "unscheduled"]
    counts = result.manifest["tools"]["splint"]["unit_counts"]
    assert counts["planned"] == counts["started"] + counts["unscheduled"]
    progress = [event.progress for event in events if event.progress is not None]
    assert progress == sorted(progress)
    time.sleep(0)

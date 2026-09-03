"""Run-level events.jsonl, static-tool heartbeats and the `running` placeholder."""
from __future__ import annotations

import copy
import json
import threading
import zipfile
from pathlib import Path
from typing import Any

import pytest
from helpers import executable, run_cli
from test_core import fake_tools, write_config

from code_analyzer.analysis import (
    AnalysisEvent,
    AnalysisRequest,
    CancellationToken,
    run_analysis,
)
from code_analyzer.config import (
    DEFAULTS,
    effective_toml,
    load_config,
    save_config_snapshot,
)
from code_analyzer.events import EVENTS_FILE, JsonlEventSink, event_record, fan_out
from code_analyzer.llm import scan as llm_scan
from code_analyzer.persist import jsonl_bytes
from code_analyzer.runner import _finish_interrupted, _running_state
from code_analyzer.sanitize import EVENT_LOG_REASON


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    return source


def _slow_cppcheck(tmp_path: Path, sleep: float) -> Path:
    return executable(tmp_path / "cppcheck", f"""
        import pathlib, sys, time
        if '--version' in sys.argv: print('Cppcheck test'); raise SystemExit()
        report = pathlib.Path(next(v.split('=', 1)[1] for v in sys.argv if v.startswith('--output-file=')))
        time.sleep({sleep})
        report.write_text('<results><errors/></results>')
        print('checking\\x1b[31m main.c\\t(fake)')
    """)


def _slow_flawfinder(tmp_path: Path, sleep: float) -> Path:
    return executable(tmp_path / "flawfinder", f"""
        import json, sys, time
        if '--version' in sys.argv: print('Flawfinder test'); raise SystemExit()
        time.sleep({sleep})
        print(json.dumps({{'version': '2.1.0', 'runs': [{{'tool': {{'driver': {{'name': 'Flawfinder'}}}}, 'results': []}}]}}))
    """)


def _config(source: Path, tmp_path: Path, tools: dict[str, Path], **run: Any) -> dict[str, Any]:
    return load_config(source, None, {
        "run": {"output_root": str(tmp_path / "reports"), "shareable_export": False, **run},
        "review": {"enabled": False},
        "build": {"compile_database_mode": "disabled"},
        "tools": {
            name: {"enabled": name in tools, **({"executable": str(tools[name])} if name in tools else {})}
            for name in ("cppcheck", "flawfinder", "splint")
        },
    })


def _lines(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    assert text.endswith("\n")
    return [json.loads(line) for line in text.splitlines()]


def _statuses(value: Any) -> set[str]:
    """Every `status` value anywhere in a manifest."""
    found: set[str] = set()
    if isinstance(value, dict):
        if isinstance(value.get("status"), str):
            found.add(value["status"])
        for child in value.values():
            found |= _statuses(child)
    elif isinstance(value, list):
        for child in value:
            found |= _statuses(child)
    return found


# --- events.jsonl -----------------------------------------------------------


def test_headless_run_writes_ordered_events_log_into_the_run_directory(tmp_path: Path) -> None:
    source = _source(tmp_path)
    config = _config(source, tmp_path, {"cppcheck": _slow_cppcheck(tmp_path, 0)})
    seen: list[AnalysisEvent] = []

    result = run_analysis(AnalysisRequest(source, config), events=seen.append)

    assert result.exit_code == 0 and result.report_directory is not None
    records = _lines(result.report_directory / EVENTS_FILE)
    assert set(records[0]) == {"phase", "status", "message", "tool", "unit", "progress", "timestamp", "stream", "data"}
    # Progress strings are the CLI's channel; the headless service never echoes them.
    assert "progress" not in {item["phase"] for item in records}
    structured = list(records)
    keys = [(item["phase"], item["status"]) for item in structured]
    # The first two fire before the run directory exists; they are buffered, not lost.
    assert keys[:2] == [("analysis", "started"), ("discovery", "started")]
    created = keys.index(("run", "created"))
    completed = keys.index(("tool", "completed"))
    assert 1 < created < completed
    assert structured[created]["message"] == str(result.report_directory)
    assert structured[completed]["tool"] == "cppcheck"
    assert keys[-1] == ("analysis", "finished")
    progress = [item["progress"] for item in records if item["progress"] is not None]
    assert progress == sorted(progress) and progress[0] == 0.0 and progress[-1] == 1.0
    # The file mirrors what the caller's own sink received, minus control
    # characters: analyzer output is untrusted and the file gets tailed.
    assert [(e.phase, e.status) for e in seen] == [(i["phase"], i["status"]) for i in records]
    raw = next(e for e in seen if e.phase == "output" and e.stream == "stdout")
    assert raw.message == "checking\x1b[31m main.c\t(fake)"
    logged = next(i for i in records if i["phase"] == "output" and i["stream"] == "stdout")
    assert logged["message"] == "checking [31m main.c (fake)"
    # A progress log that is appended to after the index is final cannot be evidence.
    assert result.manifest is not None
    assert EVENTS_FILE not in {item["path"] for item in result.manifest["artifacts"]}


def test_events_file_setting_relocates_the_log_and_round_trips(tmp_path: Path) -> None:
    source = _source(tmp_path)
    target = tmp_path / "elsewhere" / "run.jsonl"
    config = _config(source, tmp_path, {"cppcheck": _slow_cppcheck(tmp_path, 0)}, events_file=str(target))

    target.parent.mkdir()
    target.write_text('{"stale": true}\n', encoding="utf-8")
    result = run_analysis(AnalysisRequest(source, config))

    assert result.report_directory is not None
    assert not (result.report_directory / EVENTS_FILE).exists()
    records = _lines(target)
    # One run per file, like <run_dir>/events.jsonl: a stale file is replaced.
    assert "stale" not in records[0]
    assert (records[0]["phase"], records[0]["status"]) == ("analysis", "started")
    assert (records[-1]["phase"], records[-1]["status"]) == ("analysis", "finished")

    assert f'events_file = "{target}"' in effective_toml(config)
    snapshot = save_config_snapshot(source, config, tmp_path / "snapshot.toml")
    assert load_config(source, snapshot)["run"]["events_file"] == str(target)
    relative = tmp_path / "relative.toml"
    relative.write_text('config_schema_version = 2\n[run]\nevents_file = "logs/run.jsonl"\n', encoding="utf-8")
    assert load_config(source, relative)["run"]["events_file"] == str(tmp_path / "logs" / "run.jsonl")
    assert effective_toml(copy.deepcopy(DEFAULTS)).count('events_file = ""') == 1


def test_cli_analyze_writes_the_events_log(tmp_path: Path) -> None:
    source = _source(tmp_path)
    tools = fake_tools(tmp_path)
    config = write_config(tmp_path / "config.toml", tools, export=False)

    completed = run_cli("analyze", source, "--config", config, "--output-root", tmp_path / "out", "--no-compile-db")

    assert completed.returncode == 0, completed.stderr
    records = _lines(Path(completed.stdout.strip()) / EVENTS_FILE)
    keys = [(item["phase"], item["status"]) for item in records]
    assert keys[0] == ("analysis", "started") and keys[-1] == ("analysis", "finished")
    assert ("tool", "completed") in keys
    # The CLI consumes progress strings directly: none may be echoed as events.
    assert "progress" not in {item["phase"] for item in records}

    target = tmp_path / "moved" / "events.jsonl"
    completed = run_cli(
        "analyze", source, "--config", config, "--output-root", tmp_path / "out",
        "--no-compile-db", "--events-file", target,
    )
    assert completed.returncode == 0, completed.stderr
    assert not (Path(completed.stdout.strip()) / EVENTS_FILE).exists()
    assert _lines(target)[0]["status"] == "started"


def test_events_log_stays_out_of_the_shareable_archive_with_a_reason(tmp_path: Path) -> None:
    source = _source(tmp_path)
    tools = fake_tools(tmp_path)
    config = write_config(tmp_path / "config.toml", tools, export=True)

    completed = run_cli("analyze", source, "--config", config, "--output-root", tmp_path / "out", "--no-compile-db")

    assert completed.returncode == 0, completed.stderr
    run_dir = Path(completed.stdout.strip())
    assert (run_dir / EVENTS_FILE).is_file()
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["export"]["status"] == "completed"
    with zipfile.ZipFile(run_dir / manifest["export"]["archive"]) as bundle:
        assert EVENTS_FILE not in bundle.namelist()
        report = json.loads(bundle.read("redaction-report.json"))
    entry = next(item for item in report["omitted_artifacts"] if item["entry"] == EVENTS_FILE)
    assert entry["status"] == "excluded" and entry["reason"] == EVENT_LOG_REASON
    assert entry in manifest["export"]["omitted_artifacts"]


def test_sink_serialises_concurrent_writers_line_by_line(tmp_path: Path) -> None:
    target = tmp_path / "events.jsonl"
    writers, per_writer = 4, 250
    with JsonlEventSink(target) as sink:
        def emit(worker: int) -> None:
            for index in range(per_writer):
                sink(AnalysisEvent("unit", "heartbeat", f"worker {worker} event {index} " + "x" * 512, tool=f"w{worker}"))
        threads = [threading.Thread(target=emit, args=(worker,)) for worker in range(writers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    records = _lines(target)
    assert len(records) == writers * per_writer
    assert sorted((item["tool"], item["message"]) for item in records) == sorted(
        (f"w{worker}", f"worker {worker} event {index} " + "x" * 512)
        for worker in range(writers) for index in range(per_writer)
    )


def test_fan_out_delivers_in_order_and_skips_none() -> None:
    first: list[str] = []
    second: list[str] = []
    sink = fan_out(lambda event: first.append("a" + event.status), None, lambda event: second.append("b" + event.status))
    sink(AnalysisEvent("analysis", "started", "x"))
    assert first == ["astarted"] and second == ["bstarted"]


# --- heartbeats ----------------------------------------------------------------


@pytest.mark.parametrize("name", ["cppcheck", "flawfinder"])
def test_static_tools_heartbeat_while_a_unit_runs(tmp_path: Path, name: str) -> None:
    source = _source(tmp_path)
    tool = {"cppcheck": _slow_cppcheck, "flawfinder": _slow_flawfinder}[name](tmp_path, 0.8)
    config = _config(source, tmp_path, {name: tool})
    config["tools"][name]["heartbeat_seconds"] = 0.2
    events: list[AnalysisEvent] = []

    result = run_analysis(AnalysisRequest(source, config), events=events.append)

    assert result.exit_code == 0, result.manifest
    beats = [e for e in events if e.phase == "unit" and e.status == "heartbeat"]
    assert beats and all(e.tool == name for e in beats)
    assert all(e.message.startswith("heartbeat; elapsed ") and "s; unit timeout " in e.message for e in beats)
    assert all(e.progress is None for e in beats)
    finished = next(i for i, e in enumerate(events) if e.phase == "tool" and e.status == "completed")
    assert events.index(beats[0]) < finished


# --- `running` placeholder --------------------------------------------------------


def test_running_placeholder_is_visible_on_tool_start_and_gone_at_the_end(tmp_path: Path) -> None:
    source = _source(tmp_path)
    config = _config(source, tmp_path, {"cppcheck": _slow_cppcheck(tmp_path, 0), "flawfinder": _slow_flawfinder(tmp_path, 0)})
    snapshots: dict[str, dict[str, Any]] = {}
    run_dir: list[Path] = []

    def sink(event: AnalysisEvent) -> None:
        if (event.phase, event.status) == ("run", "created"):
            run_dir.append(Path(event.message))
        if (event.phase, event.status) == ("tool", "started"):
            manifest = json.loads((run_dir[0] / "manifest.json").read_text(encoding="utf-8"))
            snapshots[str(event.tool)] = manifest["tools"][str(event.tool)]

    result = run_analysis(AnalysisRequest(source, config), events=sink)

    assert result.exit_code == 0 and result.manifest is not None
    assert set(snapshots) == {"cppcheck", "flawfinder"}
    for name, record in snapshots.items():
        assert record["requested"] is True and record["status"] == "running"
        assert record["executable"] == config["tools"][name]["executable"]
        assert record["units"] == [] and record["unit_counts"]["planned"] == 0
    assert "running" not in _statuses(result.manifest)
    assert result.manifest["tools"]["cppcheck"]["status"] == "completed"


def test_cancelling_on_tool_start_leaves_no_running_state(tmp_path: Path) -> None:
    source = _source(tmp_path)
    config = _config(source, tmp_path, {"cppcheck": _slow_cppcheck(tmp_path, 5), "flawfinder": _slow_flawfinder(tmp_path, 0)})
    config["run"]["termination_grace_seconds"] = 0.1
    token = CancellationToken()

    def sink(event: AnalysisEvent) -> None:
        if (event.phase, event.status, event.tool) == ("tool", "started", "cppcheck"):
            token.cancel()

    result = run_analysis(AnalysisRequest(source, config), events=sink, cancellation=token)

    assert result.exit_code == 130 and result.manifest is not None
    assert result.manifest["status"] == "interrupted"
    assert result.manifest["tools"]["cppcheck"]["status"] == "interrupted"
    assert result.manifest["tools"]["flawfinder"]["status"] == "interrupted"
    assert "running" not in _statuses(result.manifest)
    assert result.report_directory is not None
    persisted = json.loads((result.report_directory / "manifest.json").read_text(encoding="utf-8"))
    assert "running" not in _statuses(persisted)


def test_finish_interrupted_rewrites_running_placeholders(tmp_path: Path) -> None:
    """The guard for a placeholder that is still on the manifest at interruption."""
    source = _source(tmp_path)
    config = _config(source, tmp_path, {"cppcheck": _slow_cppcheck(tmp_path, 0)})
    result = run_analysis(AnalysisRequest(source, config))
    assert result.report_directory is not None and result.manifest is not None
    inventory = json.loads((result.report_directory / "inputs" / "source-inventory.json").read_text(encoding="utf-8"))["files"]
    manifest = result.manifest
    manifest["tools"]["cppcheck"] = _running_state(inventory, "cppcheck", "/usr/bin/cppcheck", "Cppcheck 9")
    manifest["llm"] = llm_scan.running(config["llm"])
    assert manifest["llm"]["status"] == "running" and manifest["llm"]["requested"] is True

    exit_code, _ = _finish_interrupted(
        result.report_directory, manifest, inventory, ["cppcheck"], lambda _m: None, lambda *_a, **_k: None
    )

    assert exit_code == 130
    assert "running" not in _statuses(manifest)
    cppcheck = manifest["tools"]["cppcheck"]
    assert cppcheck["status"] == "interrupted" and cppcheck["requested"] is True
    assert (cppcheck["executable"], cppcheck["version"]) == ("/usr/bin/cppcheck", "Cppcheck 9")
    assert manifest["llm"]["status"] == "interrupted" and manifest["llm"]["reason"] == "run interrupted"
    persisted = json.loads((result.report_directory / "manifest.json").read_text(encoding="utf-8"))
    assert persisted["tools"]["cppcheck"]["status"] == "interrupted" and persisted["llm"]["status"] == "interrupted"


def test_the_models_half_of_the_conversation_is_recorded_faithfully() -> None:
    """The live page reads this file, not the objects the TUI folds."""
    answer = AnalysisEvent(
        "output", "running", '{\n  "findings": [\x1b[2J{"cwe": "CWE-787"}]\n}',
        tool="llm-security", unit="u1", stream="answer",
    )
    record = event_record(answer)
    # Indentation and newlines kept -- they are the only structure a JSON
    # answer has -- and the escape sequence gone all the same.
    assert record["message"] == '{\n  "findings": [ [2J{"cwe": "CWE-787"}]\n}'
    # The encoder escapes the newline, so a tail -f still sees one line.
    assert b"\\n" in jsonl_bytes(record) and jsonl_bytes(record).count(b"\n") == 1

    # Every other message is still collapsed to one line, as the log needs.
    noisy = AnalysisEvent("output", "running", "a\n  b\tc", tool="cppcheck", unit="u1", stream="stdout")
    assert event_record(noisy)["message"] == "a b c"
    unit = AnalysisEvent("unit", "completed", "completed;\n  2 finding(s)", tool="llm-security", unit="u1")
    assert event_record(unit)["message"] == "completed; 2 finding(s)"

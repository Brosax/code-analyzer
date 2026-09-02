"""RunControl: pause, skip, jobs and decisions, cooperatively and journalled."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from helpers import executable

from code_analyzer.analysis import (
    AnalysisEvent,
    AnalysisRequest,
    CancellationToken,
    run_analysis,
)
from code_analyzer.config import load_config
from code_analyzer.control import (
    CANCELLED,
    RUN,
    SKIP_PRODUCER,
    AdjustableSemaphore,
    Decision,
    DecisionRequest,
    RunControl,
)


def test_the_semaphore_limit_moves_while_workers_hold_it() -> None:
    gate = AdjustableSemaphore(2)
    assert gate.acquire() and gate.acquire()
    done = threading.Event()

    def third() -> None:
        gate.acquire()
        done.set()

    threading.Thread(target=third, daemon=True).start()
    assert not done.wait(0.2), "a third worker must wait at limit 2"
    gate.set_limit(3)
    assert done.wait(2.0)
    assert gate.active == 3
    gate.set_limit(1)
    for _ in range(3):
        gate.release()
    assert gate.active == 0 and gate.limit == 1
    # A cancelled wait returns instead of hanging.
    blocked = AdjustableSemaphore(1)
    blocked.acquire()
    assert blocked.acquire(cancelled=lambda: True) is False


def test_a_paused_lane_holds_the_checkpoint_until_resumed_or_cancelled() -> None:
    journal: list[tuple[str, str]] = []
    control = RunControl(listener=lambda phase, status, text, data: journal.append((phase, status)))
    control.pause("static")
    answers: list[str] = []
    thread = threading.Thread(target=lambda: answers.append(control.checkpoint("static", "splint", "u1", poll=0.05)), daemon=True)
    thread.start()
    time.sleep(0.2)
    assert not answers, "the checkpoint waits while the lane is paused"
    control.resume("static")
    thread.join(2.0)
    assert answers == [RUN]
    control.pause("llm")
    other = threading.Thread(target=lambda: answers.append(control.checkpoint("llm", "llm-security", None, poll=0.05)), daemon=True)
    other.start()
    time.sleep(0.1)
    control.cancel()
    other.join(2.0)
    assert answers[-1] == CANCELLED
    assert control.paused("llm") and control.cancelled
    assert journal == [("control", "paused"), ("control", "resumed"), ("control", "paused"), ("control", "cancel")]


def test_skips_and_jobs_are_answered_and_journalled() -> None:
    journal: list[dict] = []
    control = RunControl(listener=lambda phase, status, text, data: journal.append({"phase": phase, "status": status, **data}), llm_jobs=2)
    control.skip("flawfinder")
    assert control.checkpoint("static", "flawfinder", None) == SKIP_PRODUCER
    assert control.checkpoint("static", "splint", "u1") == RUN
    control.skip_unit("splint", "u9")
    assert control.checkpoint("static", "splint", "u9") == "skip_unit"
    assert control.set_jobs("llm", 5) == 5 and control.jobs("llm") == 5
    assert control.set_jobs("llm", 99) == 8, "the LLM pool has a ceiling"
    assert control.set_jobs("llm", 0) == 1
    assert control.toggle_pause("llm") is True and control.toggle_pause("llm") is False
    assert control.state()["lanes"]["llm"] == {"paused": False, "jobs": 1}
    assert control.state()["skipped"] == ["flawfinder"]
    statuses = [item["status"] for item in journal]
    assert statuses == ["skipped", "skipped", "jobs", "jobs", "jobs", "paused", "resumed"]
    assert journal[2]["value"] == 5 and journal[3]["value"] == 8


def test_decisions_cross_threads_time_out_and_yield_to_cancel() -> None:
    journal: list[tuple[str, str, dict]] = []
    control = RunControl(listener=lambda phase, status, text, data: journal.append((phase, status, data)))
    request = DecisionRequest("d1", "build_context_patch", "apply 3 include dirs", items=({"op": "add_include"},))
    answers: list[Decision] = []
    thread = threading.Thread(target=lambda: answers.append(control.request_decision(request)), daemon=True)
    thread.start()
    time.sleep(0.1)
    assert [item.id for item in control.pending()] == ["d1"]
    assert control.decide("nope", "apply") is False
    assert control.decide("d1", "apply", selected=(0,), decided_by="tui", note="ok") is True
    thread.join(2.0)
    assert answers == [Decision("apply", (0,), "tui", "ok")] and not control.pending()
    expired = control.request_decision(DecisionRequest("d2", "retry", "retry?"), timeout=0.2)
    assert expired.answer == "reject" and expired.decided_by == "timeout"
    control.cancel()
    cancelled = control.request_decision(DecisionRequest("d3", "retry", "retry?"))
    assert cancelled.answer == "reject" and cancelled.note == "run cancelled"
    kinds = [(phase, status) for phase, status, _data in journal]
    assert kinds[:2] == [("decision", "requested"), ("decision", "decided")]
    assert ("decision", "expired") in kinds
    auto = RunControl(decider=lambda req: Decision("apply", decided_by="auto"))
    assert auto.request_decision(request).decided_by == "auto"


# --- through a real run ---------------------------------------------------------


def _slow_splint(tmp_path: Path, seconds: float) -> Path:
    return executable(tmp_path / "slow-splint", f"""
        import pathlib, sys, time
        if '-help' in sys.argv: print('Splint 3.1.2'); raise SystemExit()
        time.sleep({seconds})
        report = pathlib.Path(sys.argv[sys.argv.index('+csv') + 1])
        report.write_text('file,line,message\\\\na.c,1,warning\\\\n')
        print('Finished checking --- 1 code warning', file=sys.stderr)
        raise SystemExit(1)
    """)


def _config(tmp_path: Path, splint: Path, **splint_settings: object) -> dict:
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    return load_config(source, None, {
        "run": {"output_root": str(tmp_path / "reports"), "shareable_export": False},
        "build": {"compile_database_mode": "disabled"},
        "review": {"enabled": False},
        "tools": {
            "cppcheck": {"enabled": False}, "flawfinder": {"enabled": False},
            "splint": {"executable": str(splint), "jobs": 1, **splint_settings},
        },
    })


def test_pausing_the_static_lane_holds_the_next_unit_and_is_journalled(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for index in range(3):
        (source / f"f{index}.c").write_text("int x;\n", encoding="utf-8")
    config = _config(tmp_path, _slow_splint(tmp_path, 0.3))
    control = RunControl(CancellationToken(), llm_jobs=1)
    events: list[AnalysisEvent] = []
    resumed_at: list[float] = []

    def sink(event: AnalysisEvent) -> None:
        events.append(event)
        if event.phase == "unit" and event.status == "started" and len([e for e in events if e.phase == "unit" and e.status == "started"]) == 1:
            control.pause("static", "test")
            threading.Timer(1.0, lambda: (resumed_at.append(time.monotonic()), control.resume("static", "test"))).start()

    result = run_analysis(AnalysisRequest(source, config), events=sink, control=control)
    assert result.exit_code == 0, result.manifest["tools"]["splint"]
    starts = [e.timestamp for e in events if e.phase == "unit" and e.status == "started"]
    assert len(starts) == 3
    # The second unit started only after the resume, not while paused.
    assert starts[1] - starts[0] >= 0.9
    statuses = [(e.phase, e.status) for e in events if e.phase == "control"]
    assert statuses == [("control", "paused"), ("control", "resumed")]
    log = (result.report_directory / "logs" / "runner.log").read_text(encoding="utf-8")
    assert "  control        -" in log and "paused" in log and "resumed" in log
    records = [json.loads(line) for line in (result.report_directory / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [r["status"] for r in records if r["phase"] == "control"] == ["paused", "resumed"]


def test_skipping_a_producer_unschedules_its_units_and_marks_the_tool(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    for index in range(4):
        (source / f"f{index}.c").write_text("int x;\n", encoding="utf-8")
    config = _config(tmp_path, _slow_splint(tmp_path, 0.2))
    config["tools"]["flawfinder"]["enabled"] = True
    config["tools"]["flawfinder"]["executable"] = str(executable(tmp_path / "flawfinder", """
        import json, sys
        if '--version' in sys.argv: print('flawfinder 2.0.20'); raise SystemExit()
        print(json.dumps({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'Flawfinder'}}, 'results': []}]}))
    """))
    control = RunControl(CancellationToken(), llm_jobs=1)
    control.skip("flawfinder", "test")
    events: list[AnalysisEvent] = []

    def sink(event: AnalysisEvent) -> None:
        events.append(event)
        if event.phase == "unit" and event.status == "started" and event.tool == "splint" and event.data["index"] == 2:
            control.skip("splint", "test")

    result = run_analysis(AnalysisRequest(source, config), events=sink, control=control)
    manifest = result.manifest
    assert manifest["tools"]["flawfinder"]["status"] == "skipped"
    assert manifest["tools"]["flawfinder"]["reason"] == "skipped by operator"
    splint = manifest["tools"]["splint"]
    statuses = [unit["status"] for unit in splint["units"]]
    assert statuses.count("completed") == 2 and statuses.count("unscheduled") == 2
    assert all(unit["reason"] == "skipped by operator" for unit in splint["units"] if unit["status"] == "unscheduled")
    counts = splint["unit_counts"]
    assert counts["planned"] == counts["started"] + counts["unscheduled"]
    assert result.exit_code == 10
    tool_events = [(e.tool, e.status) for e in events if e.phase == "tool" and e.status in {"skipped", "partial"}]
    assert ("flawfinder", "skipped") in tool_events and ("splint", "partial") in tool_events
    batches = [e for e in events if e.phase == "units" and e.status == "unscheduled"]
    assert len(batches) == 1 and batches[0].data == {"count": 2, "reason": "skipped by operator", "first_index": 3, "last_index": 4, "total": 4}

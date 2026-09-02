"""The LLM lane says why it failed, refunds what it never spent, and stops hammering a dead endpoint."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from fake_harness import FakeHarness, fixture, response, steps, transport_failed

from code_analyzer.analysis import AnalysisEvent, AnalysisRequest, run_analysis
from code_analyzer.config import DEFAULTS, validate_config
from code_analyzer.harness.runtime import (
    RETRYABLE_FAILURE_CODES,
    HarnessRunFailed,
    RunOutcome,
    provider_failure,
    timeline,
)
from code_analyzer.llm import scan
from code_analyzer.llm.resume import resumable
from code_analyzer.tools import TOOL_NAMES

FINDING = {
    "file": "src/parser.c", "line_range": [118, 121], "symbol": "parse_packet", "category": "unsafe-copy",
    "severity": "high", "confidence": 0.8, "message": "dst is written past its end", "evidence": "memcpy(dst, src, n);",
    "description": "n comes from the packet header and is never checked against sizeof dst.",
}


class _Runtime:
    """A harness runtime bound to one (producer, unit), backed by the fake."""

    def __init__(self, fake: FakeHarness, producer: str, unit_id: str, settings: dict[str, Any]) -> None:
        self.fake, self.producer, self.unit_id, self.settings = fake, producer, unit_id, settings

    def __enter__(self) -> _Runtime:
        return self

    def __exit__(self, *_exception: object) -> None:
        return None

    def run(self, prompt: Any, *, session_id: str | None = None, on_event: Any = None) -> RunOutcome:
        try:
            result = self.fake.run(producer=self.producer, unit_id=self.unit_id, prompt=prompt)
        except AssertionError:
            raise
        except Exception as exc:
            raise HarnessRunFailed("failed", f"agent runtime error: {type(exc).__name__}: {exc}") from exc
        if on_event is not None:
            for event in [*result.events, *result.notifications]:
                on_event(event)
        return RunOutcome(
            session_id=result.session_id, final_response=result.final_response, finish_reason=result.finish_reason,
            events=list(result.events), notifications=list(result.notifications), duration_seconds=0.5,
        )


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeHarness:
    harness = FakeHarness()
    real = scan.run

    def patched(*args: Any, **kwargs: Any) -> dict[str, Any]:
        kwargs["open_runtime"] = lambda producer, unit_id, settings: _Runtime(harness, producer, unit_id, settings)
        return real(*args, **kwargs)

    monkeypatch.setattr(scan, "run", patched)
    return harness


def _tree(tmp_path: Path, files: int = 1) -> Path:
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    for index in range(files):
        (source / f"unit{index}.c").write_text(
            f"int parse_packet{index}(char *dst, const char *src, int n) {{ for (int i = 0; i < n; i++) dst[i] = src[i]; return n; }}\n",
            encoding="utf-8",
        )
    return source


def _config(tmp_path: Path, **llm: Any) -> dict[str, Any]:
    config = validate_config(copy.deepcopy(DEFAULTS))
    config["run"].update({"output_root": str(tmp_path / "reports"), "shareable_export": False})
    config["build"]["compile_database_mode"] = "disabled"
    config["review"]["enabled"] = False
    for name in TOOL_NAMES:
        config["tools"][name]["enabled"] = False
    config["llm"].update({
        "enabled": True, "endpoint": "http://127.0.0.1:9/v1", "scanners": ["llm-memory-safety"],
        "cache": False, "jobs": 1, "heartbeat_seconds": 0.05, **llm,
    })
    return config


def _run(tmp_path: Path, config: dict[str, Any]) -> tuple[dict[str, Any], list[AnalysisEvent]]:
    events: list[AnalysisEvent] = []
    result = run_analysis(AnalysisRequest(_tree(tmp_path), config), events=events.append)
    assert result.manifest is not None
    return result.manifest, events


# --- what the provider said ------------------------------------------------------


def test_provider_failure_reads_the_sdk_stream() -> None:
    recorded = fixture("transport-failed")
    failure = provider_failure(list(recorded.events))
    assert failure == {"code": "TRANSPORT", "message": "Connection error.", "requests": 6, "retries": 5, "class": "transport"}
    assert provider_failure(list(fixture("well-formed").events)) is None
    assert provider_failure([]) is None
    assert "TRANSPORT" in RETRYABLE_FAILURE_CODES
    steps_seen = [item["step"] for item in timeline(list(recorded.events))]
    assert steps_seen[:3] == ["waiting", "finish", "retry"] and steps_seen[-1] == "turn_end"


def test_a_transport_failure_is_named_and_resumable(tmp_path: Path, fake: FakeHarness) -> None:
    fake.script_default(transport_failed())
    manifest, events = _run(tmp_path, _config(tmp_path, consecutive_failure_limit=0))
    unit = manifest["llm"]["scanners"]["llm-memory-safety"]["units"][0]
    assert unit["status"] == "failed"
    assert unit["reason"] == "provider TRANSPORT: Connection error. (6 requests, 5 retries)"
    assert unit["failure_class"] == "transport" and unit["provider_failure"]["code"] == "TRANSPORT"
    assert resumable(unit) and not resumable({"status": "failed", "failure_class": "parse"})
    run_dir = Path(manifest["run_directory"])
    directory = run_dir / "llm" / "sessions" / "llm-memory-safety" / unit["id"]
    assert sorted(path.name for path in directory.iterdir()) == [
        "events.jsonl", "findings.json", "meta.json", "request.json", "response.json",
    ]
    meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
    assert meta["provider_failure"]["retries"] == 5 and meta["timeline"][0]["step"] == "waiting"
    terminal = next(e for e in events if e.phase == "unit" and e.status == "failed")
    assert terminal.data["failure_class"] == "transport" and terminal.data["provider_code"] == "TRANSPORT"
    # The budget the session never spent came back.
    budget = manifest["llm"]["budget"]
    assert budget["completion_tokens_reserved"] == 0 and budget["refunded"]["completion_tokens"] == 2000
    assert budget["refunded"]["prompt_tokens"] > 0 and budget["prompt_tokens_spent"] == 0


def test_the_breaker_opens_and_unschedules_the_rest_at_once(tmp_path: Path, fake: FakeHarness) -> None:
    fake.script_default(transport_failed())
    _tree(tmp_path, files=6)
    manifest, events = _run(tmp_path, _config(tmp_path, consecutive_failure_limit=2))
    record = manifest["llm"]
    units = record["scanners"]["llm-memory-safety"]["units"]
    failed = [unit for unit in units if unit["status"] == "failed"]
    unscheduled = [unit for unit in units if unit["status"] == "unscheduled"]
    assert len(failed) == 2 and len(unscheduled) == len(units) - 2
    assert all(unit["reason"].startswith("provider unreachable: TRANSPORT Connection error. (circuit breaker after 2") for unit in unscheduled)
    assert record["reason"].startswith("provider unreachable")
    assert len(fake.calls) == 2, "the endpoint is not asked again once the breaker is open"
    opened = [e for e in events if e.phase == "llm" and e.status == "breaker_open"]
    assert len(opened) == 1 and opened[0].data["consecutive"] == 2
    batches = [e for e in events if e.phase == "units" and e.status == "unscheduled"]
    assert len(batches) == 1 and batches[0].data["count"] == len(unscheduled)
    counts = record["unit_counts"]
    assert counts["planned"] == counts["started"] + counts["unscheduled"]


def test_a_refund_makes_the_next_unit_affordable(tmp_path: Path, fake: FakeHarness) -> None:
    """Budget for exactly one reservation: the second unit runs only if the first refunded."""
    _tree(tmp_path, files=2)
    fake.script_default(transport_failed())
    config = _config(tmp_path, consecutive_failure_limit=0, total_completion_tokens=2000, max_completion_tokens=2000)
    manifest, _events = _run(tmp_path, config)
    units = manifest["llm"]["scanners"]["llm-memory-safety"]["units"]
    assert [unit["status"] for unit in units] == ["failed", "failed"]
    assert len(fake.calls) == 2


def test_the_endpoint_is_checked_before_planning(tmp_path: Path) -> None:
    """No fake: the real phase must refuse a closed port in seconds, before any unit is planned."""
    manifest, events = _run(tmp_path, _config(tmp_path))
    record = manifest["llm"]
    assert record["status"] == "failed" and record["reason"].startswith("endpoint unreachable:")
    assert record.get("planned_units", 0) == 0
    assert not (Path(manifest["run_directory"]) / "llm" / "index.json").exists()
    terminal = next(e for e in events if e.phase == "llm" and e.status == "failed")
    assert terminal.data["reason"].startswith("endpoint unreachable:")


# --- where a unit is --------------------------------------------------------------


def test_steps_and_output_follow_the_session(tmp_path: Path, fake: FakeHarness) -> None:
    scripted = steps("turn/start", "llm/retry", "assistant/chunk", "tool/call", "turn/end", text="{\"findings\": [")
    fake.script_default(response(json.dumps({"findings": [FINDING]}), notifications=scripted))
    manifest, events = _run(tmp_path, _config(tmp_path))
    unit = manifest["llm"]["scanners"]["llm-memory-safety"]["units"][0]
    assert unit["status"] == "completed" and unit["failure_class"] is None and unit["cache"]["hit"] is False
    step_events = [e for e in events if e.phase == "unit" and e.status == "step"]
    assert [e.data["step"] for e in step_events] == [
        "prompting", "waiting", "retry", "streaming", "reading", "parsing", "validating",
    ]
    assert step_events[2].data["detail"] == "1/5 TRANSPORT" and step_events[4].data["detail"] == "read"
    assert all(e.progress is None for e in step_events)
    outputs = [e.message for e in events if e.phase == "output" and e.stream == "agent"]
    assert any(message.startswith("assistant/chunk: {\"findings\": [") for message in outputs)
    assert any(message == "tool/call: tool read" for message in outputs)
    assert not any("turn/start" in message for message in outputs)


def test_heartbeats_carry_rate_and_eta_once_a_session_finished(tmp_path: Path, fake: FakeHarness) -> None:
    _tree(tmp_path, files=3)
    usage = ({"type": "assistant/chunk", "data": {"chunk": {"type": "usage", "usage": {"inputTokens": 900, "outputTokens": 120}}}},)
    fake.script_default(response(json.dumps({"findings": [FINDING]}), events=usage, delay=0.2))
    manifest, events = _run(tmp_path, _config(tmp_path, heartbeat_seconds=0.05))
    beats = [e for e in events if e.phase == "unit" and e.status == "heartbeat"]
    assert beats, "a 0.2 s session must heartbeat at 0.05 s"
    first = beats[0].data
    assert {"elapsed", "remaining_budget_seconds", "prompt_tokens_estimated", "measured", "jobs", "tok_s", "eta_seconds", "basis"} <= set(first)
    later = [beat.data for beat in beats if beat.data["eta_seconds"] is not None]
    assert later, "after the first session the ETA is known"
    assert later[-1]["basis"].startswith("mean of the last") and later[-1]["tok_s"] is not None
    assert manifest["llm"]["budget"]["measured"]["completion_tokens"] == 120 * 3


def test_a_cache_replay_is_marked_on_the_record(tmp_path: Path, fake: FakeHarness) -> None:
    fake.script_default(response(json.dumps({"findings": [FINDING]})))
    config = _config(tmp_path, cache=True, cache_directory=str(tmp_path / "cache"))
    first, _ = _run(tmp_path, config)
    second, events = _run(tmp_path, config)
    unit = second["llm"]["scanners"]["llm-memory-safety"]["units"][0]
    assert unit["cache"] == {"hit": True, "source_run": Path(first["run_directory"]).name}
    terminal = next(e for e in events if e.phase == "unit" and e.status == "completed")
    assert terminal.data["cache_hit"] is True and terminal.data["source_run"] == unit["cache"]["source_run"]
    started = next(e for e in events if e.phase == "unit" and e.status == "started")
    assert started.message.startswith("cached (") and started.data["cached"] is True
    assert [e.data["step"] for e in events if e.phase == "unit" and e.status == "step"][0] == "replaying"


# --- the operator's retry -------------------------------------------------------------


def test_an_operator_retry_reruns_the_transport_failures_as_its_own_round(tmp_path: Path, fake: FakeHarness) -> None:
    from code_analyzer.analysis import CancellationToken
    from code_analyzer.control import RunControl

    fake.script_default(transport_failed())
    config = _config(tmp_path, consecutive_failure_limit=0)
    control = RunControl(CancellationToken(), llm_jobs=1)
    events: list[AnalysisEvent] = []

    def sink(event: AnalysisEvent) -> None:
        events.append(event)
        # The operator presses `r` the moment the transport failure lands --
        # and the provider is back by the time the retry round runs.
        if event.phase == "unit" and event.status == "failed" and (event.data or {}).get("failure_class") == "transport":
            fake.script_default("well-formed")
            control.request_retry("llm", None, "test")

    result = run_analysis(AnalysisRequest(_tree(tmp_path), config), events=sink, control=control)
    manifest = result.manifest
    block = manifest["llm"]["scanners"]["llm-memory-safety"]
    assert [unit["status"] for unit in block["units"]] == ["failed", "completed"]
    unit_id = block["units"][0]["id"]
    plan = json.loads((result.report_directory / "llm" / "plan.json").read_text(encoding="utf-8"))
    operator = [entry for entry in plan["rounds"] if entry.get("decided_by") == "operator"]
    assert len(operator) == 1 and operator[0]["action"] == "retry" and operator[0]["scheduled"] == 1
    assert operator[0]["targets"] == [unit_id]
    assert list((result.report_directory / "llm/sessions/llm-memory-safety").glob("*/r1/findings.json"))
    assert [e.status for e in events if e.phase == "control"] == ["retry_requested"]
    assert any(e.phase == "llm" and e.status == "retry" for e in events)
    assert len(fake.calls_for("llm-memory-safety")) == 2

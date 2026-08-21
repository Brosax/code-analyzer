"""The fake harness is test infrastructure, so it carries its own tests.

Every LLM test in this suite trusts the fake to script responses, record
calls and land evidence.  An untested fake would let those tests pass for
reasons that have nothing to do with the code under test.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest
from fake_harness import (
    FIXTURE_UNIT,
    FIXTURES,
    FakeHarness,
    HarnessTimeout,
    HarnessUnavailable,
    fixture,
    fixture_names,
    install,
    response,
    timed_out,
    unavailable,
)

from code_analyzer.persist import json_bytes


def _payload(text: str) -> dict:
    return json.loads(text)


@pytest.mark.parametrize("name", fixture_names())
def test_every_recorded_envelope_is_canonical_json_and_loads_as_a_response(name: str) -> None:
    path = FIXTURES / f"{name}.json"
    raw = path.read_bytes()
    # Checked-in fixtures obey the same one JSON representation as artifacts.
    assert json_bytes(json.loads(raw)) == raw
    scripted = fixture(name)
    assert isinstance(scripted.final_response, str)
    assert scripted.finish_reason
    assert len(scripted.session_id) == 16
    assert all(isinstance(event, dict) and "type" in event for event in scripted.events)


def test_recorded_envelopes_cover_the_parser_hazards() -> None:
    well_formed = fixture("well-formed").final_response
    assert _payload(well_formed)["findings"][0]["symbol"] == FIXTURE_UNIT["symbol"]

    fenced = fixture("fenced").final_response
    assert fenced.startswith("```json") and fenced.rstrip().endswith("```")
    assert _payload(fenced.split("\n", 1)[1].rsplit("```", 1)[0]) == _payload(well_formed)

    prose = fixture("prose-prefixed").final_response
    with pytest.raises(json.JSONDecodeError):
        _payload(prose)
    assert _payload(prose[prose.index("{"):]) == _payload(well_formed)

    truncated = fixture("truncated")
    with pytest.raises(json.JSONDecodeError):
        _payload(truncated.final_response)
    assert truncated.finish_reason == "max-tokens"

    empty = fixture("empty")
    assert empty.final_response == "" and empty.finish_reason == "error"

    stray = _payload(fixture("line-out-of-range").final_response)["findings"][0]
    assert stray["line_start"] > FIXTURE_UNIT["line_end"]
    assert stray["line_end"] > FIXTURE_UNIT["line_end"]


def test_responses_are_served_in_order_per_unit_and_every_call_is_recorded() -> None:
    fake = FakeHarness()
    fake.script("llm-memory-safety", "u1", "well-formed", "truncated")
    fake.script("llm-security", "u1", "empty")

    first = fake.run(producer="llm-memory-safety", unit_id="u1", prompt="a")
    second = fake.run(producer="llm-memory-safety", unit_id="u1", prompt="b")
    third = fake.run(producer="llm-security", unit_id="u1", prompt="c")

    assert [item.finish_reason for item in (first, second, third)] == [
        "completed", "max-tokens", "error",
    ]
    assert first.session_id == fixture("well-formed").session_id
    assert [(call.producer, call.unit_id, call.attempt) for call in fake.calls] == [
        ("llm-memory-safety", "u1", 1), ("llm-memory-safety", "u1", 2), ("llm-security", "u1", 1),
    ]
    assert [call.request["prompt"] for call in fake.calls] == ["a", "b", "c"]
    assert [call.outcome for call in fake.calls] == ["completed", "max-tokens", "error"]
    assert len(fake.calls_for("llm-memory-safety")) == 2
    assert fake.remaining() == {}


def test_an_unscripted_unit_fails_loudly_until_a_default_is_set() -> None:
    fake = FakeHarness()
    with pytest.raises(AssertionError, match="unscripted harness call for llm-security/u9"):
        fake.run(producer="llm-security", unit_id="u9")

    fake.script_default(response("{}"))
    assert fake.run(producer="llm-security", unit_id="u9").final_response == "{}"
    # The refused call is still recorded: the scheduler did make it.
    assert [call.outcome for call in fake.calls] == ["unscripted", "completed"]


def test_transport_failures_raise_and_still_record_the_attempt(tmp_path: Path) -> None:
    fake = FakeHarness(tmp_path / "sessions")
    fake.script("llm-memory-safety", "slow", timed_out())
    fake.script("llm-memory-safety", "dead", unavailable())

    with pytest.raises(HarnessTimeout, match="request_timeout_seconds"):
        fake.run(producer="llm-memory-safety", unit_id="slow")
    with pytest.raises(HarnessUnavailable, match="dsh runtime"):
        fake.run(producer="llm-memory-safety", unit_id="dead")

    assert [call.outcome for call in fake.calls] == ["HarnessTimeout", "HarnessUnavailable"]
    assert all(call.finished_at is not None for call in fake.calls)
    # A torn-down session leaves whatever it already streamed and no envelope.
    torn = tmp_path / "sessions/llm-memory-safety/slow"
    assert torn.is_dir() and not (torn / "response.json").exists()


def test_injected_delay_is_real_so_budget_tests_can_starve_the_schedule() -> None:
    fake = FakeHarness()
    fake.script("llm-security", "u1", response("{}", delay=0.05))
    started = time.monotonic()
    fake.run(producer="llm-security", unit_id="u1")
    call = fake.calls[0]
    assert time.monotonic() - started >= 0.05
    assert call.finished_at is not None and call.finished_at - call.started_at >= 0.05


def test_parallel_units_are_served_without_losing_calls() -> None:
    fake = FakeHarness()
    units = [f"u{index}" for index in range(8)]
    for unit in units:
        fake.script("llm-firmware-concurrency", unit, response("{}", delay=0.05))

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(
            lambda unit: fake.run(producer="llm-firmware-concurrency", unit_id=unit), units,
        ))

    assert len(results) == len(units)
    assert sorted(call.unit_id for call in fake.calls) == sorted(units)
    assert len({call.index for call in fake.calls}) == len(units)
    windows = sorted((call.started_at, call.finished_at) for call in fake.calls)
    assert any(later[0] < earlier[1] for earlier, later in zip(windows, windows[1:], strict=False))


def test_session_evidence_matches_the_recorded_envelope_byte_for_byte(tmp_path: Path) -> None:
    fake = FakeHarness(tmp_path / "run/llm/sessions")
    fake.script("llm-memory-safety", FIXTURE_UNIT["unit_id"], "well-formed")
    result = fake.run(producer="llm-memory-safety", unit_id=FIXTURE_UNIT["unit_id"])

    assert result.session_root == tmp_path / "run/llm/sessions/llm-memory-safety" / FIXTURE_UNIT["unit_id"]
    assert result.session_root is not None
    envelope = (result.session_root / "response.json").read_bytes()
    assert envelope == (FIXTURES / "well-formed.json").read_bytes()
    events = (result.session_root / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["type"] for line in events] == [
        "session.started", "tool.call", "session.finished",
    ]


def test_derived_session_ids_are_stable_across_runs() -> None:
    def once() -> str:
        fake = FakeHarness()
        fake.script("llm-security", "u1", response("{}"))
        return fake.run(producer="llm-security", unit_id="u1").session_id

    assert once() == once()


def test_install_patches_a_callable_or_a_session_factory(monkeypatch: pytest.MonkeyPatch) -> None:
    module = SimpleNamespace(run_unit=None, Session=None)
    fake = install(monkeypatch, module, "run_unit")
    fake.script("llm-security", "u1", "well-formed")
    assert module.run_unit(producer="llm-security", unit_id="u1").finish_reason == "completed"

    factory_fake = install(monkeypatch, module, "Session", as_factory=True)
    factory_fake.script("llm-security", "u2", "empty")
    with module.Session(endpoint="http://127.0.0.1:1/v1") as session:
        assert session.run(producer="llm-security", unit_id="u2").final_response == ""
    assert factory_fake.constructions == [
        {"args": [], "kwargs": {"endpoint": "http://127.0.0.1:1/v1"}}
    ]
    # Leaving the context closes the session, exactly as the SDK does.
    assert factory_fake.closed
    with pytest.raises(HarnessUnavailable, match="session is closed"):
        factory_fake.run(producer="llm-security", unit_id="u2")

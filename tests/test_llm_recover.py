"""Rebuilding the LLM phase from the evidence a killed run already wrote.

`recover-report` rebuilds the static lane by re-reading each analyzer's report
off disk. The LLM lane had no such path: its per-unit evidence lands the moment
a unit settles, but the index of it is only written when the whole phase ends,
and `build_review` walks the manifest rather than the directory. So a run
killed mid-phase kept every finding on disk and showed none of them.
"""
from __future__ import annotations

import json
from pathlib import Path

from code_analyzer.llm.recover import recover_phase, unfinished


def _unit(run: Path, producer: str, unit_id: str, *, findings: list[dict] | None = None,
          status: str = "completed") -> None:
    directory = run / "llm" / "sessions" / producer / unit_id
    directory.mkdir(parents=True)
    (directory / "meta.json").write_text(json.dumps({
        "unit_id": unit_id, "producer": producer, "status": status,
        "finding_count": len(findings or []), "malformed_count": 0,
        "finish_reason": "completed", "duration_seconds": 12.5,
        "cache": {"hit": False, "source_run": None},
        "usage_measured": {"prompt_tokens": 5300, "completion_tokens": 44, "requests": 1},
    }), encoding="utf-8")
    (directory / "request.json").write_text(json.dumps({
        "unit_id": unit_id, "producer": producer, "model": "qwen3.8:27b",
        "skill_version": "1.0.0", "unit_sha256": "abc123",
    }), encoding="utf-8")
    (directory / "findings.json").write_text(json.dumps({
        "producer": producer, "unit_id": unit_id, "valid_report": True,
        "findings": findings or [],
    }), encoding="utf-8")


def _run(tmp_path: Path) -> Path:
    run = tmp_path / "20260904T000000Z-abcdef"
    (run / "llm").mkdir(parents=True)
    (run / "llm" / "index.json").write_text(json.dumps({
        "files": {"bl1/main.c": {"size": 900, "readable": True}},
        "units": [{"unit_id": "u1", "path": "bl1/main.c", "name": "boot",
                   "risk_tier": "critical", "unit_sha256": "abc123",
                   "start_byte": 0, "end_byte": 900, "byte_length": 900,
                   "kind": "function", "is_header": False}],
        "totals": {"parse_confidence_low": 0},
    }), encoding="utf-8")
    return run


def test_a_phase_that_never_wrote_its_index_is_rebuilt_from_its_units(tmp_path: Path) -> None:
    run = _run(tmp_path)
    _unit(run, "llm-security", "u1", findings=[
        {"severity": "high", "category": "input-validation", "message": "unchecked key id"}])
    _unit(run, "llm-memory-safety", "u1")
    manifest = {"llm": {"enabled": True, "requested": True, "status": "running",
                        "scanners": {}, "planned_units": 0, "model": "qwen3.8:27b"}}

    assert unfinished(manifest) is True
    phase = recover_phase(run, manifest)
    assert phase is not None

    assert sorted(phase["scanners"]) == ["llm-memory-safety", "llm-security"]
    assert phase["recovered"] is True
    assert phase["unit_counts"]["completed"] == 2
    assert phase["planned_units"] == 1

    unit = phase["scanners"]["llm-security"]["units"][0]
    assert unit["id"] == "u1" and unit["producer"] == "llm-security"
    assert unit["valid_report"] is True and unit["finding_count"] == 1
    assert unit["risk_tier"] == "critical" and unit["symbol"] == "boot"
    assert unit["input_files"] == ["bl1/main.c"]
    # The artifacts are hashed off disk, the same way the run would have.
    paths = {item["path"] for item in unit["artifacts"]}
    assert "llm/sessions/llm-security/u1/findings.json" in paths
    assert all(item["sha256"] and item["size"] for item in unit["artifacts"])
    # Facts about an execution that is over, and its evidence does not carry
    # them: said, not guessed.
    assert phase["budget"] == {"status": "recovered-from-unit-evidence"}


def test_only_scanners_become_scanners(tmp_path: Path) -> None:
    """The configurator and the validator share the sessions tree.

    Listing either as a scanner puts a producer with no findings into the
    review's scanner table and into llm_coverage.
    """
    run = _run(tmp_path)
    _unit(run, "llm-security", "u1")
    _unit(run, "build-context-configurator", "r1")
    _unit(run, "llm-validator", "c1")

    phase = recover_phase(run, {"llm": {"enabled": True, "scanners": {}}})
    assert phase is not None
    assert list(phase["scanners"]) == ["llm-security"]


def test_a_finished_phase_is_left_exactly_as_the_run_wrote_it(tmp_path: Path) -> None:
    """The run's own accounting wins wherever it exists."""
    manifest = {"llm": {"enabled": True, "scanners": {
        "llm-security": {"producer": "llm-security", "units": [{"id": "u1", "status": "completed"}]}}}}
    assert unfinished(manifest) is False
    assert unfinished({"llm": {"enabled": False}}) is False
    assert unfinished({}) is False


def test_a_run_with_no_sessions_recovers_nothing(tmp_path: Path) -> None:
    run = _run(tmp_path)
    assert recover_phase(run, {"llm": {"enabled": True, "scanners": {}}}) is None

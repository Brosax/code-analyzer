"""Rebuild the LLM phase of a run from the evidence it already wrote.

``recover-report`` rebuilds the static lane by re-reading each analyzer's own
report off disk, and that is what lets a killed run keep its findings. The LLM
lane had no such path: its per-unit evidence is written the moment each unit
settles, but the *index* of it -- ``manifest["llm"]["scanners"][…]["units"]`` --
is only written when the whole phase finishes. A run interrupted mid-phase
therefore kept every ``findings.json`` on disk and showed none of them in the
report, because ``review.build_review`` walks the manifest, not the directory.

Measured on Trusted Firmware-M (2026-09-04): 540 unit results, 91 units and 52
findings -- seventeen of them high, seven hours of GPU time -- sat in
``llm/sessions/`` while the rebuilt review said ``llm: {}``.

So this reads the sessions back and rebuilds the block, from the same three
files an auditor would read: the unit plan the phase saved, each unit's
``request.json`` (what was asked) and its ``meta.json`` (what happened). It
invokes nothing and reaches no endpoint -- the same promise the rest of
recovery makes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..status import aggregate_units, counts
from ..tools import LLM_PRODUCERS
from ..tools.common import artifact
from .units import coverage_report

SESSIONS = ("llm", "sessions")
# What the run itself computed and this cannot: a budget is spent as the phase
# runs and a cache hit rate is a property of that run's execution, not of its
# evidence. Reported as recovered rather than invented.
RECOVERED = "recovered-from-unit-evidence"


def _read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def unfinished(manifest: dict[str, Any]) -> bool:
    """Whether the manifest's LLM block is missing the units it should index.

    The run's own record wins whenever it exists: a finished phase already
    counted its units, and re-deriving them would only add a way for the two to
    disagree.
    """
    phase = manifest.get("llm")
    if not isinstance(phase, dict) or not phase.get("enabled"):
        return False
    scanners = phase.get("scanners")
    if isinstance(scanners, dict) and any(
        isinstance(block, dict) and block.get("units") for block in scanners.values()
    ):
        return False
    return True


def _unit_record(directory: Path, run_dir: Path, planned: dict[str, Any]) -> dict[str, Any] | None:
    """One unit, from the three files it left behind."""
    meta = _read(directory / "meta.json")
    request = _read(directory / "request.json")
    if not meta and not request:
        return None
    unit_id = str(meta.get("unit_id") or request.get("unit_id") or directory.name)
    producer = str(meta.get("producer") or request.get("producer") or directory.parent.name)
    report = directory / "findings.json"
    findings = _read(report)
    plan = planned.get(unit_id) or {}
    artifacts = [artifact(item, run_dir) for item in sorted(directory.iterdir()) if item.is_file()]
    parameters = request.get("parameters") if isinstance(request.get("parameters"), dict) else {}
    return {
        "id": unit_id,
        "producer": producer,
        # A unit whose evidence is on disk but whose meta.json never landed was
        # cut off mid-write; `interrupted` is what the ladder calls that.
        "status": str(meta.get("status") or "interrupted"),
        "valid_report": bool(findings.get("valid_report", bool(findings))),
        "finding_count": int(meta.get("finding_count") or len(findings.get("findings") or [])),
        "malformed_count": int(meta.get("malformed_count") or 0),
        "finish_reason": str(meta.get("finish_reason") or ""),
        "reason": meta.get("reason"),
        "failure_class": meta.get("failure_class"),
        "provider_failure": meta.get("provider_failure"),
        "duration_seconds": meta.get("duration_seconds"),
        "usage_measured": meta.get("usage_measured") or meta.get("usage") or {},
        "cache": meta.get("cache") or {"hit": False, "source_run": None},
        "evidence_context": str(meta.get("evidence_context") or "source-only"),
        "model": str(request.get("model") or ""),
        "skill_version": str(request.get("skill_version") or meta.get("skill_version") or ""),
        "skill_sha256": str(request.get("skill_sha256") or meta.get("skill_sha256") or ""),
        "unit_sha256": str(request.get("unit_sha256") or plan.get("unit_sha256") or ""),
        "risk_tier": str(plan.get("risk_tier") or ""),
        "symbol": str(plan.get("name") or ""),
        "input_files": [plan["path"]] if plan.get("path") else [],
        "artifacts": artifacts,
        "recovered": True,
        **({"parameters": parameters} if parameters else {}),
    }


def recover_phase(run_dir: Path, manifest: dict[str, Any]) -> dict[str, Any] | None:
    """The ``llm`` block rebuilt from ``llm/sessions``, or None when there is none.

    Returns a block shaped exactly like the one the phase writes for itself, so
    every consumer -- the review, the dashboard, SARIF, the export -- reads it
    without knowing it was recovered.
    """
    run_dir = Path(run_dir)
    sessions = run_dir.joinpath(*SESSIONS)
    if not sessions.is_dir():
        return None
    phase = dict(manifest.get("llm") or {})
    plan = _read(run_dir / "llm" / "index.json")
    planned = {
        str(unit.get("unit_id")): unit
        for unit in plan.get("units") or []
        if isinstance(unit, dict) and unit.get("unit_id")
    }

    scanners: dict[str, dict[str, Any]] = {}
    every_unit: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    for producer_dir in sorted(sessions.iterdir()):
        # Scanners only.  The build-context configurator and the validator
        # write their sessions to the same tree, and neither is a first-layer
        # producer: listing them here would put a "scanner" with no findings
        # into the review's scanner table and into llm_coverage.
        if not producer_dir.is_dir() or producer_dir.name not in LLM_PRODUCERS:
            continue
        units = [
            record
            for record in (
                _unit_record(unit_dir, run_dir, planned)
                for unit_dir in sorted(producer_dir.iterdir())
                if unit_dir.is_dir()
            )
            if record is not None
        ]
        if not units:
            continue
        name = producer_dir.name
        analyzed = sum(bool(unit["valid_report"]) for unit in units)
        attempted = sum(unit["status"] != "unscheduled" for unit in units)
        scanners[name] = {
            "producer": name,
            "requested": True,
            "status": aggregate_units(units, applicable=True),
            "reason": None,
            "version": next((unit["model"] for unit in units if unit["model"]), str(phase.get("model") or "")),
            "executable": None,
            "skill_version": next((unit["skill_version"] for unit in units if unit["skill_version"]), ""),
            "skill_sha256": next((unit["skill_sha256"] for unit in units if unit["skill_sha256"]), ""),
            "units": units,
            "valid_reports": analyzed,
            "coverage": {
                "metric": "llm_unit_coverage", "covered": analyzed, "total": len(units),
                "attempted": attempted, "analyzed": analyzed, "excluded": 0,
                "effective_total": len(units), "ratio": analyzed / len(units) if units else None,
            },
            "excluded_files": [],
            "unit_counts": counts(units),
            "recovered": True,
        }
        every_unit.extend(units)
        results.extend({"unit_id": unit["id"], "producer": name, "status": unit["status"]} for unit in units)

    if not scanners:
        return None
    coverage = coverage_report(plan, results, scanners=sorted(scanners)) if planned else {}
    return {
        **phase,
        "enabled": True,
        "requested": True,
        "status": aggregate_units(every_unit, applicable=True),
        "scanners": scanners,
        "unit_counts": counts(every_unit),
        "coverage": coverage,
        "planned_units": len(planned) or len(every_unit),
        # Said, not guessed: these are facts about an execution that is over,
        # and its evidence does not carry them.
        "budget": {"status": RECOVERED},
        "cache": {"status": RECOVERED},
        "recovered": True,
        "reason": (
            f"rebuilt from {len(every_unit)} unit result(s) on disk: the run stopped before it "
            "wrote its own LLM accounting"
        ),
    }

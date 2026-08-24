"""``llm-resume``: scan the units a run could not afford, into the same run.

A scan that hits its token budget or its deadline does not fail -- it records
the units it never dispatched as ``unscheduled`` and reports honest coverage.
This command finishes those, plus anything ``interrupted`` by Ctrl-C, and
re-derives the review from the enlarged evidence.

It is deliberately **not** ``recover-report``.  That command's contract is that
it never invokes an analyzer (``recovery.py`` stamps
``analyzers_invoked = False``); this one exists precisely to invoke one, so it
writes new session evidence and says so.

Two things it refuses to do quietly:

* **Re-plan.**  The units come from the run's own ``llm/index.json`` and their
  prompts from ``llm/units/<unit_id>.json`` -- the exact bytes the original
  scan would have sent.  Re-planning against today's source would silently
  scan different code under the same unit ids.
* **Pretend the scanner is unchanged.**  If a skill has been edited since the
  run, the resumed units are scanned by a different scanner than their
  siblings, so the difference is reported and recorded per unit.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ..audit import (
    assessment_summary,
    build_assessment,
    carry_verdicts,
    load_assessment,
    write_assessment,
)
from ..dashboard import rebuild_dashboard
from ..errors import UserError
from ..harness.cordis import cordis_document, tool_allowlist, write_cordis_config
from ..harness.runtime import harness_available, redact_credential
from ..persist import json_bytes
from ..review import build_review, write_review
from ..sarif import build_sarif, write_sarif
from ..status import (
    EXIT_COMPLETE,
    EXIT_INTERRUPTED,
    EXIT_PARTIAL,
    aggregate_units,
    counts,
)
from ..tools import LLM_PRODUCERS
from ..tools.common import artifact_index
from .scan import OpenRuntime, _Cache, _Phase, _scanner_record
from .skills import Skill, load_skill, skills_directory
from .units import coverage_report

# A unit in one of these states was never given to the model, or was cut off
# before it answered: both are resumable.  "failed" is not -- the model
# answered and the answer was unusable, and repeating it is not resumption.
RESUMABLE = ("unscheduled", "interrupted")


def run_resume(
    report_directory: Path,
    config: dict[str, Any],
    *,
    progress: Callable[[str], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    open_runtime: OpenRuntime | None = None,
) -> dict[str, Any]:
    """Scan the resumable units of one run and re-derive its review.

    Returns the ``llm`` block written back into manifest.json, with the exit
    code the command should return under ``exit_code``.
    """
    progress = progress or (lambda _message: None)
    run_dir = Path(report_directory).expanduser().resolve()
    manifest = _read(run_dir / "manifest.json", "manifest")
    phase = manifest.get("llm")
    if not isinstance(phase, dict) or not phase.get("enabled"):
        raise UserError(f"{run_dir} has no LLM phase to resume: run analyze with --llm first")
    plan = _read(run_dir / "llm" / "index.json", "unit plan", hint="the run kept no unit plan to resume from")
    source = Path(str(manifest.get("source") or ""))

    blocks = {name: dict(block) for name, block in (phase.get("scanners") or {}).items() if isinstance(block, dict)}
    pending = [
        (name, unit)
        for name in sorted(blocks, key=_producer_order)
        for unit in blocks[name].get("units", [])
        if isinstance(unit, dict) and unit.get("status") in RESUMABLE
    ]
    if not pending:
        progress("resume: every unit already carries a result; nothing to scan")
        return {**phase, "exit_code": EXIT_COMPLETE, "resumed": 0}
    if open_runtime is None and not harness_available():
        raise UserError("the deepseek-harness runtime is not importable; install it before running llm-resume")

    settings = config["llm"]
    skills: dict[str, Skill] = {}
    prompts: dict[str, list[dict[str, Any]]] = {}
    tasks: list[tuple[int, str, dict[str, Any]]] = []
    unreadable: dict[tuple[str, str], str] = {}
    for index, (name, record) in enumerate(pending, 1):
        unit_id = str(record.get("id") or "")
        if name not in skills:
            skills[name] = load_skill(name)
        stored = _unit_payload(run_dir, unit_id)
        if stored is None:
            unreadable[(name, unit_id)] = "the run kept no rendered prompt for this unit"
            continue
        prompts[unit_id] = stored["prompt"]
        tasks.append((index, name, stored["unit"]))
    progress(
        f"resume: {len(pending)} unit(s) left {' or '.join(RESUMABLE)}; "
        f"{len(tasks)} replayable, {len(unreadable)} without a stored prompt"
    )
    for name, block in blocks.items():
        declared = str(block.get("skill_version") or "")
        if name in skills and declared and declared != skills[name].skill_version:
            progress(
                f"resume: {name} is now version {skills[name].skill_version}, the run used {declared}; "
                f"resumed units are scanned by the newer scanner"
            )

    records: list[dict[str, Any]] = []
    if tasks:
        with skills_directory() as skill_dir:
            session_root = run_dir / "llm" / "dsh-sessions"
            session_root.mkdir(parents=True, exist_ok=True)
            cordis_path = write_cordis_config(
                run_dir / "llm" / "resume",
                cordis_document(
                    settings, skill_dir=skill_dir, session_root=session_root,
                    tools=tool_allowlist(skills.values()),
                ),
            )
            state = _Phase(
                source=source,
                run_dir=run_dir,
                settings=settings,
                grace=float(config["run"]["termination_grace_seconds"]),
                cordis_path=cordis_path,
                session_root=session_root,
                skills=skills,
                prompts=prompts,
                cache=_Cache(config, run_dir),
                progress=progress,
                unit_event=lambda *_args: None,
                output_event=None,
                cancelled=cancelled,
                open_runtime=open_runtime,
            )
            records.extend(state.execute_all(tasks))

    resumed = {(record["producer"], record["id"]): record for record in records}
    resolved = sum(record["status"] not in RESUMABLE for record in records)
    for name, block in blocks.items():
        units = [
            resumed.get((name, str(unit.get("id") or "")), unit)
            for unit in block.get("units", [])
            if isinstance(unit, dict)
        ]
        blocks[name] = {**block, **_scanner_record(name, skills[name], settings, units)} if name in skills else block

    phase = dict(phase)
    phase["scanners"] = blocks
    every_unit = [unit for block in blocks.values() for unit in block.get("units", [])]
    phase["unit_counts"] = counts(every_unit)
    phase["status"] = aggregate_units(every_unit, applicable=bool(every_unit))
    phase["coverage"] = coverage_report(
        plan,
        [
            {"unit_id": unit.get("id"), "producer": name, "status": unit.get("status")}
            for name, block in blocks.items() for unit in block.get("units", [])
        ],
        scanners=sorted(blocks, key=_producer_order),
    )
    # The original budget was spent by the original run; this one has its own.
    phase["resume"] = {
        "runs": int((phase.get("resume") or {}).get("runs", 0)) + 1,
        "resumed": len(records),
        "resolved": resolved,
        "unreadable": sorted(f"{name}/{unit_id}" for name, unit_id in unreadable),
        "budget": state.budget_state() if tasks else None,
        "analyzers_invoked": True,
    }
    manifest["llm"] = redact_credential(phase, settings)
    exit_code = _exit_code(every_unit, records)
    _rederive(run_dir, manifest, config, progress)
    progress(f"resume: {resolved} of {len(records)} resumed unit(s) now carry a result")
    return {**manifest["llm"], "exit_code": exit_code, "resumed": len(records)}


def _rederive(run_dir: Path, manifest: dict[str, Any], config: dict[str, Any], progress: Callable[[str], None]) -> None:
    """Rebuild every derived artifact from the enlarged evidence."""
    inventory = list((_read_optional(run_dir / "inputs" / "source-inventory.json") or {}).get("files") or [])
    source = Path(str(manifest.get("source") or ""))
    review = build_review(source, run_dir, manifest, inventory)
    write_review(run_dir, review, int(config["review"]["max_markdown_findings"]))
    manifest["review"] = {
        **(manifest.get("review") or {}),
        "status": "completed", "error": None,
        "findings": review["total_findings"], "diagnostics": review["total_diagnostics"],
    }
    write_sarif(run_dir, build_sarif(review, manifest))
    # Verdicts were bought with model time and survive a re-derivation; the
    # correlation around them is deterministic and is rebuilt.
    assessment = carry_verdicts(build_assessment(review), load_assessment(run_dir))
    write_assessment(run_dir, assessment)
    manifest["audit"] = {**(manifest.get("audit") or {}), **assessment_summary(assessment), "error": None}
    manifest["artifacts"] = artifact_index(run_dir)
    (run_dir / "manifest.json").write_bytes(json_bytes(manifest))
    rebuild_dashboard(run_dir)
    progress(f"resume: review re-derived; {review['total_findings']} findings")


def _unit_payload(run_dir: Path, unit_id: str) -> dict[str, Any] | None:
    """The unit and the prompt the original run rendered for it."""
    if not unit_id:
        return None
    payload = _read_optional(run_dir / "llm" / "units" / f"{unit_id}.json")
    if not isinstance(payload, dict):
        return None
    unit, prompt = payload.get("unit"), payload.get("prompt")
    if not isinstance(unit, dict) or not isinstance(prompt, list) or not prompt:
        return None
    return {"unit": unit, "prompt": prompt}


def _exit_code(every_unit: list[dict[str, Any]], records: list[dict[str, Any]]) -> int:
    if any(record["status"] == "interrupted" for record in records):
        return EXIT_INTERRUPTED
    return EXIT_COMPLETE if not any(unit.get("status") in RESUMABLE for unit in every_unit) else EXIT_PARTIAL


def _producer_order(name: str) -> tuple[int, str]:
    return (LLM_PRODUCERS.index(name) if name in LLM_PRODUCERS else len(LLM_PRODUCERS), name)


def _read(path: Path, label: str, *, hint: str | None = None) -> dict[str, Any]:
    value = _read_optional(path)
    if not isinstance(value, dict):
        raise UserError(f"no usable {label} at {path}" + (f": {hint}" if hint else ""))
    return value


def _read_optional(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

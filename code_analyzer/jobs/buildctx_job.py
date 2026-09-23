"""Build context, driven from the conversation: diagnose, propose a patch, apply it on a click.

The pieces are the proven ones from build_context.py -- the per-unit diagnosis
the adapters record, the deterministic ``infer_patch``, ``validate_config``
underneath ``ConfigPatch.apply``, the Splint probe on a dozen failed units --
without the old in-run loop that stopped a scan and waited for a decision.
Here each step is a separate, visible act:

* ``diagnose`` reads counts from the last call's evidence (no process runs);
* ``propose`` infers a patch, probes it, stores it as ``buildctx/patches/P-n.json``
  and returns an approval card -- nothing is applied;
* ``apply`` (only after a human click on that card) writes the next build
  context version, re-runs only the units that failed, merges the new attempt
  into the call's evidence (old units are marked superseded, never
  overwritten), and rebuilds the list.  No model call anywhere in the loop.
"""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from ..build_context import (
    ConfigPatch,
    PatchItem,
    diagnose_units,
    infer_patch,
    probe_patch,
    select_probe_files,
    write_round,
    write_stubs,
)
from ..compile_db import filter_database, resolve_compile_db
from ..errors import UserError
from ..evidence.analyze import current_buildctx, reindex, static_config
from ..evidence.buildctx_schema import buildctx_sha, buildctx_text
from ..evidence.workspace import Workspace, _atomic
from ..persist import json_bytes
from ..tools import CompileDatabase, OutputBudget, RunContext, adapter
from ..tools.common import merge_attempt

RECONFIGURABLE = ("splint", "cppcheck")
PROBE_UNITS = 12


def last_call(workspace: Workspace) -> tuple[dict[str, Any], Path]:
    calls = [r for r in workspace.ledger.of("call_finished") if r.get("run_dir") and r.get("exit_code") != 130]
    if not calls:
        raise UserError("no tool run yet; run_tools first")
    return calls[-1], workspace.root / calls[-1]["run_dir"]


def _evidence(run_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    inventory = json.loads((run_dir / "inputs" / "source-inventory.json").read_text(encoding="utf-8"))
    return manifest, [item for item in inventory.get("files") or [] if isinstance(item, dict)]


def diagnose(workspace: Workspace) -> dict[str, Any]:
    """Counts only: which units failed and why, which headers are missing and where they could be."""
    _, run_dir = last_call(workspace)
    manifest, inventory = _evidence(run_dir)
    out: dict[str, Any] = {}
    for tool in RECONFIGURABLE:
        record = manifest.get("tools", {}).get(tool)
        if not isinstance(record, dict) or not record.get("units"):
            continue
        diagnosis = diagnose_units(record, inventory, tool=tool)
        out[tool] = {
            **diagnosis.counts, "classes": diagnosis.classes,
            "top_missing": [{"header": h.name, "units": h.units, "kind": h.kind, "candidates": list(h.candidates[:3])}
                            for h in diagnosis.missing_headers[:12]],
            "error_directives": len(diagnosis.error_directives),
        }
    return out


def propose(workspace: Workspace, tool: str = "splint") -> dict[str, Any]:
    """Infer and probe a patch; store it; return what the approval card shows."""
    if tool not in RECONFIGURABLE:
        raise UserError(f"build context patches apply to {' or '.join(RECONFIGURABLE)}")
    call, run_dir = last_call(workspace)
    manifest, inventory = _evidence(run_dir)
    record = manifest.get("tools", {}).get(tool)
    if not isinstance(record, dict) or not record.get("units"):
        raise UserError(f"{tool} did not run in {call['call_id']}")
    diagnosis = diagnose_units(record, inventory, tool=tool)
    if not diagnosis.units_failed:
        return {"patch": None, "reason": f"no {tool} unit failed for lack of build context"}
    config = static_config(current_buildctx(workspace), output_root=run_dir.parent)
    number = len(workspace.ledger.of("patch_proposed")) + 1
    round_index = 100 + number   # rounds above any the old in-run loop recorded
    patch = infer_patch(diagnosis, config, source=workspace.source, round=round_index)
    if not patch.items:
        return {"patch": None, "reason": "nothing the tree proves could fix the failed units; "
                                         "a compilation database or the vendor's defines are needed"}
    preselected = [index for index, item in enumerate(patch.items) if item.preselected]
    probe = None
    executable = shutil.which(str(record.get("executable") or config["tools"][tool]["executable"]))
    if tool == "splint" and preselected and executable:
        sample = select_probe_files(diagnosis, record, PROBE_UNITS)
        try:
            trial = patch.apply(config, run_dir, workspace.source, preselected)
            probe = probe_patch(executable, workspace.source, run_dir, trial, sample, round=round_index)
        except UserError as error:
            probe = {"sampled": 0, "reached_before": 0, "reached_after": 0, "error": str(error)}
        probe = {k: v for k, v in probe.items() if k != "per_file"}
    write_round(run_dir, round_index, diagnosis=diagnosis.as_dict(), patch=patch.as_dict(), probe=probe)
    document = {"patch_id": f"P-{number}", "tool": tool, "call_id": call["call_id"], "round": round_index,
                "items": [item.as_dict() for item in patch.items], "labels": [item.label() for item in patch.items],
                "preselected": preselected, "probe": probe, "failed_units": diagnosis.units_failed,
                "buildctx_sha": buildctx_sha(current_buildctx(workspace))}
    data = json_bytes(document)
    directory = workspace.root / "buildctx" / "patches"
    directory.mkdir(parents=True, exist_ok=True)
    _atomic(directory / f"P-{number}.json", data)
    sha = hashlib.sha256(data).hexdigest()
    workspace.ledger.append("patch_proposed", patch_id=f"P-{number}", tool=tool, sha256=sha, items=len(patch.items),
                            preselected=len(preselected), probe=probe)
    return {"patch": document, "sha256": sha}


def apply(workspace: Workspace, patch_id: str, selected: list[int], *, progress: Any = lambda _l: None,
          cancelled: Any = lambda: False) -> dict[str, Any]:
    """Apply an approved patch: new build context version, re-run the failed units, rebuild the list."""
    document = json.loads((workspace.root / "buildctx" / "patches" / f"{patch_id}.json").read_text(encoding="utf-8"))
    if document["buildctx_sha"] != buildctx_sha(current_buildctx(workspace)):
        raise UserError(f"{patch_id} was proposed against an older build context; propose again")
    call, run_dir = last_call(workspace)
    if call["call_id"] != document["call_id"]:
        raise UserError(f"{patch_id} belongs to {document['call_id']}, not the latest run; propose again")
    tool = document["tool"]
    patch = ConfigPatch(document["round"], [PatchItem(**item) for item in document["items"]])
    config = static_config(current_buildctx(workspace), output_root=run_dir.parent)
    patched = patch.apply(config, run_dir, workspace.source, selected)
    stubs = patch.selected_stubs(selected)
    if stubs:
        write_stubs(run_dir, document["round"], stubs, run_id=run_dir.name)
    context = {"build": patched["build"], "tools": patched["tools"]}
    number, sha = workspace.save_version("buildctx", buildctx_text(context))
    workspace.ledger.append("buildctx_version", version=number, sha256=buildctx_sha(context), by=f"patch {patch_id}")
    manifest, inventory = _evidence(run_dir)
    record = manifest["tools"][tool]
    diagnosis = diagnose_units(record, inventory, tool=tool)
    files = sorted({f for unit in record.get("units") or [] if str(unit.get("id")) in set(diagnosis.failed_unit_ids)
                    for f in unit.get("input_files") or []})
    declared = adapter(tool)
    executable = shutil.which(str(record.get("executable") or patched["tools"][tool]["executable"]))
    if declared.rerun is None or executable is None:
        raise UserError(f"{tool} cannot be re-run here")
    attempt = document["round"] + 1
    progress(f"{tool}: re-running {len(files)} failed file(s) with build context v{number}")
    # The run's compilation database comes along: re-running a build-aware unit without it
    # would demote its evidence to source-only (the old tools-resume did exactly that).
    compile_path, entries, _degraded, _discovery = resolve_compile_db(workspace.source, patched)
    filtered, covered = filter_database(workspace.source, inventory, entries)
    run_context = RunContext(source=workspace.source, run_dir=run_dir, inventory=inventory,
                             compile_db=CompileDatabase(entries=filtered, covered=frozenset(covered),
                                                        present=compile_path is not None),
                             config=patched, progress=lambda message: progress(f"{tool}: {message}"),
                             cancelled=cancelled, unit_event=lambda *_args, **_kwargs: None,
                             output_budget=OutputBudget(64 * 1024 * 1024), attempt=attempt)
    result = declared.rerun(executable, run_context, files)
    result["executable"] = executable
    merged = merge_attempt(record, result, attempt=attempt)
    manifest["tools"][tool] = merged
    _atomic(run_dir / "manifest.json", json_bytes(manifest))
    after = diagnose_units(merged, inventory, tool=tool)
    outcome = {"patch_id": patch_id, "tool": tool, "buildctx_version": number, "rerun_files": len(files),
               "failed_before": diagnosis.units_failed, "failed_after": after.units_failed,
               "reached_before": diagnosis.units_analysis_reached, "reached_after": after.units_analysis_reached}
    workspace.ledger.append("patch_applied", **outcome)
    reindex(workspace, progress=progress)
    return outcome

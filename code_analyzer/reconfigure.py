"""The build-context loop as one function, run inside `analyze` or over a finished run.

`runner.run_static` calls `run_loop` after the tools; `tools-resume` rebuilds
the same context from a run directory -- manifest, inventory, effective
configuration -- and calls it again, so a run whose patch was only recorded
(a headless run without ``--build-assist-yes``, a rejected dialog) can be
completed later without re-running the tools that already succeeded.
"""
from __future__ import annotations

import shutil
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .build_context import (
    applied_config_toml,
    diagnose_units,
    infer_patch,
    manifest_block,
    probe_patch,
    relative_to_run,
    select_probe_files,
    suggested_toml,
    write_round,
    write_stubs,
)
from .control import Decision, DecisionRequest, RunControl
from .errors import UserError
from .includes import include_index
from .llm import configure
from .tools import TOOL_NAMES, CompileDatabase, OutputBudget, RunContext, adapter
from .tools.common import merge_attempt

Emit = Callable[..., None]


@dataclass
class LoopContext:
    """Everything the loop reads or writes; the runner and tools-resume both build one."""

    source: Path
    run_dir: Path
    run_id: str
    inventory: list[dict[str, Any]]
    config: dict[str, Any]
    manifest: dict[str, Any]
    manifest_lock: threading.RLock
    save_manifest: Callable[[], None]
    requested_names: list[str]
    resolved_tools: dict[str, tuple[str, str | None]]
    compile_db: CompileDatabase
    output_budget: OutputBudget
    control: RunControl
    # `emit(phase, status, message, *, tool=None, unit=None, stream=None, data=None)`:
    # the static lane's event channel, already positioned at its full share.
    emit: Emit
    progress: Callable[[str], None] = lambda _message: None
    live_events: bool = False
    # Rounds already recorded in the manifest (tools-resume continues them).
    first_round: int = 1
    previous_rounds: list[dict[str, Any]] = field(default_factory=list)

    @property
    def cancelled(self) -> Callable[[], bool]:
        return self.control.cancellation.is_cancelled


def run_loop(ctx: LoopContext) -> str:
    """Diagnose -> infer -> consult -> probe -> decide -> re-run, tool by tool.

    Returns the outcome word written to ``manifest["build_context"]``.  Every
    round leaves its evidence under inputs/build-context/r<N>/.
    """
    config = ctx.config
    assist = str(config["build"]["assist"])
    rounds: list[dict[str, Any]] = list(ctx.previous_rounds)
    outcome, why = "skipped", "no unit needed a different build context"
    if assist == "off":
        return "off"
    rounds_limit = int(config["build"]["assist_rounds"])
    current = config
    configurator_gate: tuple[bool, str | None] | None = None
    manifest, source, run_dir, control = ctx.manifest, ctx.source, ctx.run_dir, ctx.control
    inventory, progress = ctx.inventory, ctx.progress

    def bc(state: str, message: str, **data: Any) -> None:
        ctx.emit("build_context", state, message, data={"assist": assist, **data})
        progress(f"build-context: {message}")

    bc("started", f"build-context assistance ({assist})" + (f", continuing at round {ctx.first_round}" if ctx.first_round > 1 else ""))
    for name in ctx.requested_names:
        declared = adapter(name)
        if declared.rerun is None or name not in ctx.resolved_tools:
            continue
        resolved, version = ctx.resolved_tools[name]
        for round_index in range(ctx.first_round, ctx.first_round + rounds_limit):
            if ctx.cancelled():
                return outcome
            record = manifest["tools"][name]
            unit_ids = declared.reconfigurable(record)
            if not unit_ids:
                break
            files = _unit_files(record, unit_ids)
            diagnosis = diagnose_units(record, inventory, tool=name)
            bc("diagnosed", f"{name}: {diagnosis.units_failed}/{diagnosis.units_total} unit(s) could not be preprocessed; {len(diagnosis.missing_headers)} distinct missing header(s)", tool=name, round=round_index, **diagnosis.counts)
            patch = infer_patch(diagnosis, current, source=source, round=round_index)
            if not patch.items:
                why = f"{name}: nothing the tree can prove -- {len(diagnosis.missing_headers)} header(s), none resolvable"
                bc("skipped", why, tool=name, round=round_index)
                write_round(run_dir, round_index, diagnosis=diagnosis.as_dict())
                rounds.append({"round": round_index, "tool": name, "diagnosis": diagnosis.counts, "items": 0, "applied": False, "reason": why})
                break
            labels = [item.label() for item in patch.items]
            bc("inferred", f"{name}: {len(patch.items)} patch item(s): " + "; ".join(labels[:4]) + (" …" if len(labels) > 4 else ""), tool=name, round=round_index, items=labels)
            # The model adds what the tree alone cannot prove -- whenever its
            # endpoint answers, whether or not the scan lane is on.
            if configurator_gate is None:
                configurator_gate = configure.gate(config)
            llm_block: dict[str, Any]
            if configurator_gate[0]:
                model = str(config["llm"].get("model") or "")
                counts = diagnosis.counts
                bc("consulting", f"{name}: asking {model} to complete the build context ({counts['external']} header(s) the tree lacks, {counts['ambiguous']} ambiguous, {counts['error_directives']} #error)", tool=name, round=round_index, model=model)
                by_unit = {str(u.get("id")): u for u in record.get("units") or []}
                samples = [f"{unit_id}: " + ", ".join((by_unit.get(unit_id) or {}).get("missing_includes") or [])[:200] for unit_id in diagnosis.failed_unit_ids[:configure.MAX_SAMPLES]]

                def consult_event(
                    producer: str, unit_id: str, status: str, message: str, value: float | None,
                    data: dict[str, Any] | None = None, *, phase: str = "unit", tool_name: str = name, r: int = round_index,
                ) -> None:
                    bc("consulting", f"{tool_name}: configurator {message}", tool=tool_name, round=r, llm_status=status,
                       **{k: v for k, v in (data or {}).items() if k not in {"tool", "round", "assist"}})

                proposal = configure.propose(
                    source, run_dir, config, diagnosis=diagnosis, deterministic=patch, inventory=inventory,
                    index=include_index(inventory), round_no=round_index, samples=samples,
                    progress=lambda message, tool_name=name: progress(f"build-context {tool_name}: {message}"),
                    unit_event=consult_event,
                    output_event=(lambda producer, unit_id, stream, message: ctx.emit("output", "running", message, tool=producer, unit=unit_id, stream=stream)) if ctx.live_events else None,
                    cancelled=ctx.cancelled,
                )
                llm_block = proposal.as_dict()
                public = {k: v for k, v in llm_block.items() if k not in {"problems", "unresolved"}}
                if proposal.used:
                    # Both lists are already capped; the union is not capped
                    # again, or a tree with 64 proven roots would silently
                    # drop every item the model added (seen live).
                    patch.items = patch.items + proposal.items
                    bc("consulted", f"{name}: {model} proposed {len(proposal.items)} item(s) ({len(proposal.problems)} dropped, {len(proposal.unresolved)} left unresolved)" + (f"; {proposal.reason}" if proposal.reason and not proposal.items else ""), tool=name, round=round_index, **public)
                else:
                    bc("consulted", f"{name}: configurator {proposal.status}: {proposal.reason}; the deterministic patch proceeds alone", tool=name, round=round_index, **public)
            else:
                llm_block = {"used": False, "status": "skipped", "reason": configurator_gate[1]}
                bc("consulted", f"{name}: configurator skipped: {configurator_gate[1]}", tool=name, round=round_index, **llm_block)
            preselected = tuple(index for index, item in enumerate(patch.items) if item.preselected)
            probe = None
            if name == "splint" and preselected:
                sample = select_probe_files(diagnosis, record, int(config["build"]["assist_probe_units"]))
                bc("probing", f"{name}: trying the patch on {len(sample)} failed unit(s)", tool=name, round=round_index, sampled=len(sample))
                try:
                    trial = patch.apply(current, run_dir, source, preselected)
                    probe = probe_patch(resolved, source, run_dir, trial, sample, round=round_index, cancelled=ctx.cancelled)
                except UserError as exc:
                    probe = {"sampled": 0, "reached_before": 0, "reached_after": 0, "per_file": [], "error": str(exc)}
                bc("probed", f"{name}: {probe['reached_after']}/{probe['sampled']} sampled unit(s) now reach Finished checking", tool=name, round=round_index, **{k: v for k, v in probe.items() if k != "per_file"})
            llm_items = [index for index, item in enumerate(patch.items) if item.origin == "llm"]
            if llm_items and probe is not None and probe["reached_after"] <= probe["reached_before"]:
                # A proposal the probe could not confirm is shown, not ticked.
                preselected = tuple(index for index in preselected if index not in set(llm_items))
            evidence = write_round(run_dir, round_index, diagnosis=diagnosis.as_dict(), patch=patch.as_dict(), probe=probe, llm=llm_block)
            summary = f"{name}: round {round_index}: {len(patch.items)} item(s)"
            if llm_items:
                summary += f", {len(llm_items)} from {llm_block.get('model') or 'the model'}"
            if probe is not None:
                summary += f"; probe {probe['reached_after']}/{probe['sampled']} now preprocess"
            if llm_block.get("third_party"):
                summary += "; third-party endpoint: the diagnosis (header and directory names) left this machine"
            request = DecisionRequest(
                id=control.new_request_id("bc"), kind="build_context_patch", summary=summary,
                items=tuple({**item.as_dict(), "label": item.label()} for item in patch.items),
                round=round_index, probe=probe, evidence_path=relative_to_run(evidence, run_dir), preselected=preselected,
            )
            improved = probe is None or probe["reached_after"] > probe["reached_before"]
            deterministic = all(patch.items[index].origin == "deterministic" for index in preselected)
            if assist == "auto" and improved and deterministic:
                decision = control.auto_decide(request, Decision("apply", preselected, "auto", "deterministic patch; probe improved"))
            else:
                bc("awaiting", f"{name}: waiting for a decision on {len(patch.items)} item(s)", tool=name, round=round_index, decision=request.id)
                timeout = float(config["build"]["approval_timeout_seconds"]) or None
                decision = control.request_decision(request, timeout=timeout)
            write_round(run_dir, round_index, decision={"answer": decision.answer, "selected": list(decision.selected), "decided_by": decision.decided_by, "note": decision.note})
            if decision.answer != "apply" or not decision.selected:
                outcome, why = "rejected", f"{name}: round {round_index} {decision.answer} by {decision.decided_by}" + (f" ({decision.note})" if decision.note else "")
                bc("rejected", why, tool=name, round=round_index, decision=request.id)
                rounds.append({"round": round_index, "tool": name, "diagnosis": diagnosis.counts, "items": len(patch.items), "llm": llm_block, "probe": probe, "decision": decision.answer, "decided_by": decision.decided_by, "applied": False})
                break
            try:
                patched = patch.apply(current, run_dir, source, decision.selected)
            except UserError as exc:
                outcome, why = "failed", f"{name}: the patch did not validate: {exc}"
                bc("failed", why, tool=name, round=round_index)
                rounds.append({"round": round_index, "tool": name, "items": len(patch.items), "applied": False, "reason": why})
                break
            stubs = patch.selected_stubs(decision.selected)
            if stubs:
                write_stubs(run_dir, round_index, stubs, run_id=ctx.run_id)
            write_round(run_dir, round_index, applied_config=applied_config_toml(patched))
            attempt = round_index + 1
            bc("applying", f"{name}: re-running {len(files)} unit(s) with the patch (attempt {attempt})", tool=name, round=round_index, units=len(files), stubs=len(stubs))

            def rerun_unit(
                unit: str | None, status: str, message: str, value: float | None,
                data: dict[str, Any] | None = None, *, phase: str = "unit", tool_name: str = name, attempt_no: int = attempt,
            ) -> None:
                ctx.emit(phase, status, message, tool=tool_name, unit=unit, data=data)
                if data and "index" in data and status != "info":
                    progress(f"build-context attempt {attempt_no} {tool_name}: unit {data['index']}/{data['total']} {data.get('label', unit)}: {message}")

            context = RunContext(
                source=source, run_dir=run_dir, inventory=inventory, compile_db=ctx.compile_db,
                config=patched, progress=lambda message, tool_name=name: progress(f"build-context {tool_name}: {message}"),
                cancelled=ctx.cancelled, unit_event=rerun_unit,
                output_event=(lambda unit, stream, message, tool_name=name: ctx.emit("output", "running", message, tool=tool_name, unit=unit, stream=stream)) if ctx.live_events else None,
                output_budget=ctx.output_budget, control=control, attempt=attempt,
            )
            before = {"failed": diagnosis.units_failed, "analysis_reached": diagnosis.units_analysis_reached}
            try:
                result = declared.rerun(resolved, context, files)
            except Exception as exc:
                outcome, why = "failed", f"{name}: re-run failed: {exc}"
                bc("failed", why, tool=name, round=round_index)
                rounds.append({"round": round_index, "tool": name, "items": len(patch.items), "applied": False, "reason": why})
                break
            result["executable"], result["version"] = resolved, version
            merged = merge_attempt(record, result, attempt=attempt)
            with ctx.manifest_lock:
                manifest["tools"][name] = merged
                ctx.save_manifest()
            after_diag = diagnose_units(merged, inventory, tool=name)
            after = {"failed": after_diag.units_failed, "analysis_reached": after_diag.units_analysis_reached}
            rounds.append({
                "round": round_index, "tool": name, "diagnosis": diagnosis.counts, "items": len(patch.items),
                "llm": llm_block, "selected": list(decision.selected), "probe": probe, "decision": decision.answer,
                "decided_by": decision.decided_by, "applied": True, "attempt": attempt,
                "rerun_units": len(files), "before": before, "after": after, "status": merged["status"],
            })
            outcome, why = "applied", None
            current = patched
            (run_dir / "suggested-config.toml").write_text(suggested_toml(config, patched, source), encoding="utf-8")
            bc("applied", f"{name}: attempt {attempt} {merged['status']}; analysis reached {after['analysis_reached']}/{merged['unit_counts']['planned']} (was {before['analysis_reached']}); {merged['unit_counts'].get('superseded', 0)} unit(s) superseded", tool=name, round=round_index, before=before, after=after, tool_status=merged["status"], superseded=merged["unit_counts"].get("superseded", 0))
            if after["failed"] >= before["failed"]:
                break
    with ctx.manifest_lock:
        manifest["build_context"] = manifest_block(assist, outcome, rounds, reason=why)
        ctx.save_manifest()
    bc("finished", f"build-context assistance {outcome}" + (f": {why}" if why else ""), outcome=outcome, rounds=len(rounds))
    return outcome


def _unit_files(record: dict[str, Any], unit_ids: list[str]) -> list[str]:
    wanted = set(unit_ids)
    files: list[str] = []
    for unit in record.get("units") or []:
        if str(unit.get("id")) in wanted:
            for path in unit.get("input_files") or []:
                if path not in files:
                    files.append(str(path))
    return files


# --- tools-resume ------------------------------------------------------------------------


def run_tools_resume(
    report_directory: Path, *, tool: str | None = None, assist: str | None = None,
    decider: Callable[[DecisionRequest], Decision] | None = None,
    progress: Callable[[str], None] | None = None, event_sink: Callable[[Any], None] | None = None,
    cancellation: Any = None,
) -> dict[str, Any]:
    """Re-enter a finished run's build-context loop and re-derive its review.

    Reads what the run left -- manifest, inventory, effective configuration,
    the rounds already recorded -- and continues from the next round with the
    tools resolved afresh.  Returns the ``build_context`` block with the
    outcome; the review, SARIF and dashboard are rebuilt from the merged
    evidence by ``recover_report``.
    """
    from .analysis import AnalysisEvent, CancellationToken
    from .persist import write_json
    from .recovery import _read_object, _recovery_config, recover_report
    from .runner import _read_manifest, _version

    progress = progress or (lambda _message: None)
    run_dir = Path(report_directory).expanduser().resolve()
    manifest = _read_manifest(run_dir)
    if manifest is None:
        raise UserError(f"{run_dir} has no manifest.json to resume from")
    inventory_document = _read_object(run_dir / "inputs" / "source-inventory.json", "source inventory")
    inventory = [item for item in inventory_document.get("files") or [] if isinstance(item, dict)]
    source = Path(str(inventory_document.get("source") or manifest.get("source") or "")).expanduser().resolve()
    if not source.is_dir():
        raise UserError(f"the run's source tree is gone: {source}")
    config = _recovery_config(run_dir, source)
    if assist is not None:
        config["build"]["assist"] = assist
    if config["build"]["assist"] == "off":
        raise UserError("build.assist is off; pass --build-assist propose or auto to resume the loop")
    names = [
        name for name in TOOL_NAMES
        if (tool is None or name == tool) and isinstance(manifest.get("tools", {}).get(name), dict)
        and manifest["tools"][name].get("units")  # the tool ran: it left units to reconfigure
    ]
    resolved_tools: dict[str, tuple[str, str | None]] = {}
    for name in names:
        declared = adapter(name)
        if declared.rerun is None:
            continue
        record = manifest["tools"][name]
        executable = str(record.get("executable") or config["tools"][name]["executable"])
        resolved = shutil.which(executable)
        if not resolved:
            raise UserError(f"{name}: executable not found: {executable}")
        resolved_tools[name] = (resolved, _version(name, resolved))
    if not resolved_tools:
        raise UserError("no reconfigurable tool in this run (splint or cppcheck)")
    previous = manifest.get("build_context") if isinstance(manifest.get("build_context"), dict) else {}
    previous_rounds = [dict(item) for item in previous.get("rounds") or [] if isinstance(item, dict)]
    first_round = 1 + max([int(item.get("round") or 0) for item in previous_rounds] or [0])
    control = RunControl(cancellation or CancellationToken(), decider=decider)
    sink = event_sink or (lambda _event: None)
    control.attach(lambda phase, status, message, data: sink(AnalysisEvent(phase, status, message, data=data)))
    lock = threading.RLock()

    def emit(phase: str, status: str, message: str, *, tool: str | None = None, unit: str | None = None, stream: str | None = None, data: dict[str, Any] | None = None) -> None:
        sink(AnalysisEvent(phase, status, message, tool=tool, unit=unit, stream=stream, data=data))

    def save() -> None:
        manifest["resumed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        write_json(run_dir / "manifest.json", manifest)

    ctx = LoopContext(
        source=source, run_dir=run_dir, run_id=str(manifest.get("run_id") or run_dir.name), inventory=inventory,
        config=config, manifest=manifest, manifest_lock=lock, save_manifest=save, requested_names=list(resolved_tools),
        resolved_tools=resolved_tools, compile_db=CompileDatabase(entries=[], covered=frozenset(), present=False),
        output_budget=OutputBudget(64 * 1024 * 1024), control=control, emit=emit, progress=progress,
        first_round=first_round, previous_rounds=previous_rounds,
    )
    emit("run", "resumed", f"tools-resume: continuing the build-context loop at round {first_round}", data={"run_dir": str(run_dir), "tools": list(resolved_tools)})
    outcome = run_loop(ctx)
    if outcome == "applied":
        progress("tools-resume: re-deriving the review from the merged evidence")
        recover_report(run_dir)
    block = dict(manifest.get("build_context") or {})
    block["outcome"] = outcome
    return block

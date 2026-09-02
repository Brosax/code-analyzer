from __future__ import annotations

import hashlib
import json
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .analysis import AnalysisEvent, CancellationToken, EventSink
from .audit import (
    assessment_summary,
    build_assessment,
    load_assessment,
    write_assessment,
)
from .compile_db import filter_database, resolve_compile_db
from .config import effective_toml
from .doctor import verify_canary
from .errors import UserError
from .html_report import render
from .inventory import discover, git_state, source_slug
from .llm import scan as llm_scan
from .persist import json_bytes
from .persist import write_json as _write_json
from .progress import ProgressDisplay
from .review import REVIEW_SCHEMA_VERSION, build_review, should_fail, write_review
from .sanitize import ExportError, export_shareable
from .sarif import build_sarif, write_sarif
from .status import overall
from .tools import TOOL_NAMES, CompileDatabase, OutputBudget, RunContext, adapter
from .tools.common import artifact_index

# The whole run's share of disk for tool output.  Generous: flawfinder's native
# report is its stdout, so this has to sit far above any real report and act
# only against a runaway.
RUN_OUTPUT_BYTES = 2 * 1024 * 1024 * 1024


class AnalysisCancelled(Exception):
    """Cancellation observed before a report directory exists."""


# --- the concurrent window --------------------------------------------------
#
# The static adapters and the LLM scan phase run at the same time, so neither
# of them owns a progress segment any more.  One window covers both, and inside
# it progress is *work-proportional*: each side reports the fraction of its own
# work that is finished, and the reported value is
#
#     WINDOW_START + (WINDOW_END - WINDOW_START) * (w_static * f_static + w_llm * f_llm)
#
# Each fraction is individually non-decreasing, so the weighted sum is too.
# Wall clock is deliberately never an input: a value derived from elapsed time
# is unrepeatable, and the progress column of events.jsonl would stop being a
# statement about work and become a timing measurement.
WINDOW_START = 0.1
# The window ends exactly where the stability rescan starts, so the ladder past
# it (stability 0.85, review 0.86-0.92, export 0.93+) is untouched.
WINDOW_END = 0.85
# Equal weights.  The runner cannot know which side dominates -- static cost
# scales with the file count, LLM cost with model latency -- and finding out
# would mean timing them, which is the one input this model excludes.  Half
# each therefore claims nothing about the ratio.  With the LLM phase disabled
# the static side takes the whole window, which reproduces the pre-concurrency
# ladder for every static-only run.
WEIGHTS_WITH_LLM = (0.5, 0.5)
WEIGHTS_STATIC_ONLY = (1.0, 0.0)
STATIC, LLM = 0, 1

# The serial control path.  "Concurrency changes no evidence" is only a real
# claim while the serial result can still be produced on demand and compared,
# which is what tests/test_concurrency.py does with this flag.  Not a config
# key: an operator has no reason to choose, and a run that differs by it would
# be a bug rather than an option.
CONCURRENT_PHASES = True


class _Window:
    """The progress segment the static adapters and the LLM phase share.

    The lock covers the emission, not just the arithmetic.  Two threads that
    each computed a value and then emitted it could still emit them out of
    order, and the event log -- which is read in file order -- would show the
    bar walking backwards even though neither fraction ever did.
    """

    def __init__(self, emit: Callable[..., None], *, llm: bool) -> None:
        self._emit = emit
        self._weights = WEIGHTS_WITH_LLM if llm else WEIGHTS_STATIC_ONLY
        self._done = [0.0, 0.0]
        self._lock = threading.Lock()

    def event(
        self, side: int, fraction: float | None, phase: str, status: str, message: str, **fields: Any
    ) -> None:
        """Advance one side and announce it; a None fraction reports no work."""
        with self._lock:
            value = None
            if fraction is not None:
                # Clamped as well as ratcheted: the weights sum to 1, so two
                # fractions that cannot exceed 1 cannot put the value past
                # WINDOW_END, where the stability phase's literal 0.85 waits.
                self._done[side] = max(self._done[side], min(1.0, fraction))
                # Rounded only to keep binary-float noise (0.10375000000000001)
                # out of the event log; round() is non-decreasing, so it cannot
                # disturb the ordering the lock above is protecting.
                value = round(WINDOW_START + (WINDOW_END - WINDOW_START) * sum(
                    weight * done for weight, done in zip(self._weights, self._done, strict=True)
                ), 6)
            self._emit(phase, status, message, value=value, **fields)

    def finish(self, side: int) -> None:
        """This side has no work left; the next event carries its whole share.

        Nothing is emitted: a side that ends without an event of its own (no
        requested tools, a disabled phase) must still not strand its weight
        below the window's end.
        """
        with self._lock:
            self._done[side] = 1.0


def _run_together(
    static: Callable[[], None], llm: Callable[[], None], cancel: Callable[[], None]
) -> None:
    """Run both sides at once, keep both outcomes, re-raise the first failure.

    The static side stays on the calling thread so a Ctrl-C still lands where
    the interpreter delivers it.  A crash on one side is held until the other
    has finished writing its half of the manifest: an exception must cost the
    run one producer's results, never both.
    """
    failures: list[BaseException] = []

    def guarded() -> None:
        try:
            llm()
        except BaseException as exc:
            failures.append(exc)

    worker = threading.Thread(target=guarded, name="llm-phase")
    worker.start()
    try:
        static()
    except BaseException as exc:
        failures.append(exc)
        if not isinstance(exc, Exception):
            # KeyboardInterrupt and SystemExit are stop signals, not bugs: the
            # other side has to hear one or the join below waits out a full LLM
            # scan.  An ordinary exception is one producer's problem and must
            # not cost the other producer the results it already has.
            cancel()
    finally:
        worker.join()
    if failures:
        raise failures[0]


def analyze(
    source: Path, config: dict[str, Any], *, event_sink: EventSink | None = None
) -> tuple[int, Path]:
    """Terminal entry point: progress strings to stderr, structured events to the sink."""
    sink = event_sink or (lambda _event: None)
    sink(AnalysisEvent("analysis", "started", "analysis started", progress=0.0))
    with ProgressDisplay(sys.stderr) as display:
        exit_code, run_dir = _analyze(source, config, display.emit, event_sink=event_sink)
    status = "interrupted" if exit_code == 130 else "finished"
    sink(AnalysisEvent("analysis", status, f"analysis finished with exit code {exit_code}", progress=1.0))
    return exit_code, run_dir


def _analyze(
    source: Path,
    config: dict[str, Any],
    progress: Callable[[str], None],
    *,
    cancellation: CancellationToken | None = None,
    event_sink: EventSink | None = None,
) -> tuple[int, Path]:
    cancellation = cancellation or CancellationToken()
    live_events = event_sink is not None
    event_sink = event_sink or (lambda _event: None)

    def event(
        phase: str,
        status: str,
        message: str,
        *,
        tool: str | None = None,
        unit: str | None = None,
        stream: str | None = None,
        value: float | None = None,
    ) -> None:
        event_sink(AnalysisEvent(
            phase, status, message, tool=tool, unit=unit, stream=stream, progress=value
        ))

    source = source.expanduser().resolve()
    if not source.is_dir():
        raise UserError(f"source is not a directory: {source}")
    output_root = Path(config["run"]["output_root"]).expanduser().resolve()
    if output_root == source:
        raise UserError("output root must not be identical to source")
    # A first-round LLM scanner is blind by construction: its cwd is the
    # scanned tree and its only input is one scan unit.  The default output
    # root is relative, so `analyze .` would drop the run directory -- with
    # tools/*/report.xml, tools/*/report.sarif and the sanitizer map in it --
    # straight into that tree, and the LLM-only measurement stops meaning
    # anything.  Static-only runs are unaffected: nothing there reads back.
    if config["llm"]["enabled"] and output_root.is_relative_to(source):
        raise UserError(
            f"output root {output_root} is inside the scanned tree {source}: an LLM scanner runs "
            f"with that tree as its working directory and would be able to read the static "
            f"analyzers' reports it is supposed to be independent of. Point [run] output_root "
            f"(or --output-root) at a directory outside the source, or set [llm] enabled = false"
        )
    progress("discovering source files and build context")
    event("discovery", "started", "discovering source files and build context")
    compile_path, compile_entries, degraded, compile_discovery = resolve_compile_db(source, config)
    if cancellation.cancelled:
        raise AnalysisCancelled()
    if compile_path is None and config["build"]["compile_database_mode"] == "auto":
        progress("no valid compile database found; continuing with reduced build context")
        progress("next step: " + shlex.join(["code-analyzer", "compile-db", str(source)]))
    try:
        output_root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise UserError(f"cannot create output root {output_root}: {exc}") from exc
    try:
        inventory = discover(source, config, output_root, cancelled=cancellation.is_cancelled)
    except InterruptedError as exc:
        raise AnalysisCancelled() from exc
    if cancellation.cancelled:
        raise AnalysisCancelled()
    filtered_db, db_covered = filter_database(source, inventory, compile_entries)
    progress(
        f"inventory ready: {len(inventory)} files; "
        f"compile database entries: {len(filtered_db)}"
    )
    run_id = uuid.uuid4().hex[:12]
    timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_dir = output_root / source_slug(source) / f"{timestamp}-{run_id}"
    try:
        (run_dir / "inputs").mkdir(parents=True)
        (run_dir / "logs").mkdir()
        (run_dir / "tools").mkdir()
    except OSError as exc:
        raise UserError(f"cannot create run directory {run_dir}: {exc}") from exc
    # The message is the path itself: the event log sink opens
    # <run_dir>/events.jsonl on this event and flushes what came before.
    event("run", "created", str(run_dir))

    config_path_values: list[Path] = [Path(value) for value in config.get("_config_paths", [])]
    config_path_values.extend(Path(item["path"]) for item in compile_discovery["candidates"])
    _write_inputs(run_dir, inventory, config, filtered_db, source, output_root, config_path_values)
    requested = {name: bool(config["tools"][name]["enabled"]) for name in TOOL_NAMES}
    manifest: dict[str, Any] = {
        "manifest_schema_version": 2,
        "analyzer_version": __version__,
        "run_id": run_id,
        "status": "running",
        "exit_code": None,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "finished_at": None,
        "source": str(source),
        "output_root": str(output_root),
        "run_directory": str(run_dir),
        "analysis_context": "full" if compile_path else "degraded",
        "analysis_context_reasons": degraded,
        "compile_database": {
            "path": str(compile_path) if compile_path else None,
            "entries": len(compile_entries),
            "filtered_entries": len(filtered_db),
            "discovery": compile_discovery,
        },
        "source_options": {"include": config["source"]["include"], "exclude": config["source"]["exclude"]},
        "source_inventory": {"total": len(inventory), "sha256": _inventory_digest(inventory), "git": git_state(source), "stable": None, "changes": {}},
        "tools": {name: _not_requested(inventory, name) for name in requested},
        # A new top-level key, never inside manifest["tools"]: status.overall()
        # walks the tools, so a model timeout must not be able to turn a
        # complete/0 run into a partial/10 one.
        "llm": llm_scan.not_requested(),
        "export": {"enabled": bool(config["run"]["shareable_export"]), "status": "pending" if config["run"]["shareable_export"] else "disabled", "archive": None, "error": None},
        "review": {
            "enabled": bool(config["review"]["enabled"]),
            "status": "pending" if config["review"]["enabled"] else "disabled",
            "schema_version": REVIEW_SCHEMA_VERSION if config["review"]["enabled"] else None,
            "summary": "review/summary.json" if config["review"]["enabled"] else None,
            "error": None,
        },
        "gate": {"policy": config["review"]["fail_on"], "triggered": False},
        "audit": {"status": "pending" if config["review"]["enabled"] else "disabled", "path": None, "error": None},
        "artifacts": [],
    }
    _save_manifest(run_dir, manifest)
    _log(run_dir, f"run {run_id} started; {len(inventory)} source files")
    event("discovery", "finished", f"inventory ready: {len(inventory)} files", value=WINDOW_START)

    # From here to the join below, two threads publish into one manifest: the
    # static side owns manifest["tools"], the LLM side owns manifest["llm"].
    # The lock spans the read-modify-write, not just the write -- a
    # serialisation running while the other side swaps a subtree would persist
    # a torn snapshot -- and it is reentrant so that a mutation region can save
    # without unlocking.  Outside the window there is exactly one thread and
    # the lock is uncontended.
    manifest_lock = threading.RLock()
    # One ceiling for the whole run, not one per invocation: splint calls
    # run_process once per translation unit, so a large tree could otherwise
    # fill a disk one bounded unit at a time.
    output_budget = OutputBudget(RUN_OUTPUT_BYTES)
    llm_enabled = bool(config["llm"]["enabled"])
    window = _Window(event, llm=llm_enabled)

    def save_manifest() -> None:
        with manifest_lock:
            _save_manifest(run_dir, manifest)

    interrupted = cancellation.cancelled
    requested_names = [name for name in TOOL_NAMES if requested[name]]
    tool_count = max(1, len(requested_names))

    def run_static() -> None:
        nonlocal interrupted
        for tool_index, name in enumerate(requested_names, 1):
            tool_prefix = f"tool {tool_index}/{len(requested_names)} {name}"
            started_fraction = (tool_index - 1) / tool_count
            finished_fraction = tool_index / tool_count
            if interrupted or cancellation.cancelled:
                interrupted = True
                with manifest_lock:
                    manifest["tools"][name] = _preflight_state("interrupted", inventory, name, "run interrupted before tool start")
                progress(f"{tool_prefix}: interrupted before start")
                window.event(STATIC, finished_fraction, "tool", "interrupted", "run interrupted before tool start", tool=name)
                continue
            executable = config["tools"][name]["executable"]
            resolved = shutil.which(executable)
            if not resolved:
                with manifest_lock:
                    manifest["tools"][name] = _preflight_state("missing", inventory, name, f"executable not found: {executable}")
                    save_manifest()
                _log(run_dir, f"{name}: missing executable {executable}")
                progress(f"{tool_prefix}: missing executable")
                window.event(STATIC, finished_fraction, "tool", "missing", f"executable not found: {executable}", tool=name)
                continue
            incompatibility = _incompatibility(name, resolved)
            if incompatibility:
                with manifest_lock:
                    manifest["tools"][name] = _preflight_state("incompatible", inventory, name, incompatibility)
                    manifest["tools"][name]["executable"] = resolved
                    manifest["tools"][name]["version"] = _version(name, resolved)
                    save_manifest()
                _log(run_dir, f"{name}: incompatible: {incompatibility}")
                progress(f"{tool_prefix}: incompatible")
                window.event(STATIC, finished_fraction, "tool", "incompatible", incompatibility, tool=name)
                continue
            _log(run_dir, f"{name}: starting {resolved}")
            progress(f"{tool_prefix}: starting")
            version = _version(name, resolved)
            # Persisted before the event so that whoever reacts to `tool started`
            # already finds the placeholder on disk.
            with manifest_lock:
                manifest["tools"][name] = _running_state(inventory, name, resolved, version)
                save_manifest()
            window.event(STATIC, started_fraction, "tool", "started", f"{name} starting", tool=name)
            def unit_progress(message: str, prefix: str = tool_prefix, tool_name: str = name) -> None:
                progress(f"{prefix}: {message}")
            def structured_unit(
                unit: str, status: str, message: str, value: float | None,
                tool_name: str = name, index: int = tool_index,
            ) -> None:
                fraction = None if value is None else (index - 1 + value) / tool_count
                window.event(STATIC, fraction, "unit", status, message, tool=tool_name, unit=unit)
            def streamed_output(unit: str, stream: str, message: str, tool_name: str = name) -> None:
                event("output", "running", message, tool=tool_name, unit=unit, stream=stream)
            context = RunContext(
                source=source, run_dir=run_dir, inventory=inventory,
                compile_db=CompileDatabase(
                    entries=filtered_db, covered=frozenset(db_covered), present=compile_path is not None,
                ),
                config=config, progress=unit_progress, cancelled=cancellation.is_cancelled,
                unit_event=structured_unit, output_event=streamed_output if live_events else None,
                output_budget=output_budget,
            )
            try:
                result = adapter(name).run(resolved, context)
            except Exception as exc:
                result = _preflight_state("failed", inventory, name, f"adapter failure: {exc}")
            result["executable"] = resolved
            result["version"] = version
            with manifest_lock:
                manifest["tools"][name] = result
                save_manifest()
            interrupted = result["status"] == "interrupted"
            _log(run_dir, f"{name}: {result['status']}")
            progress(f"{tool_prefix}: finished with status {result['status']}")
            window.event(
                STATIC, finished_fraction, "tool", result["status"],
                f"{name} finished with status {result['status']}", tool=name,
            )
        # A run with no requested tools still has to hand the static weight on,
        # or the window could never reach its end.
        window.finish(STATIC)

    def run_llm() -> None:
        progress("llm: starting semantic scan")
        with manifest_lock:
            manifest["llm"] = llm_scan.running(config["llm"])
            save_manifest()
        window.event(LLM, 0.0, "llm", "started", "starting LLM semantic scan")
        def llm_unit(producer: str, unit: str, status: str, message: str, value: float | None) -> None:
            window.event(LLM, value, "unit", status, message, tool=producer, unit=unit)
        def llm_output(producer: str, unit: str, stream: str, message: str) -> None:
            event("output", "running", message, tool=producer, unit=unit, stream=stream)
        try:
            record = llm_scan.run(
                source, run_dir, inventory, config, progress,
                cancelled=cancellation.is_cancelled, unit_event=llm_unit,
                output_event=llm_output if live_events else None,
            )
        except InterruptedError:
            record = llm_scan.failed(config["llm"], "run interrupted")
            record["status"] = "interrupted"
        except Exception as exc:
            record = llm_scan.failed(config["llm"], f"llm phase failure: {exc}")
        with manifest_lock:
            manifest["llm"] = record
            save_manifest()
        _log(run_dir, f"llm: {record['status']}")
        progress(f"llm: finished with status {record['status']}")
        window.event(
            LLM, 1.0, "llm", record["status"],
            f"LLM scan finished with status {record['status']}",
        )

    # The two sides share only the manifest, the event sink and the
    # cancellation token, each of which is serialised above; everything else
    # they touch is disjoint (tools/ against llm/, CPU against network).
    # Running them together also *strengthens* the first-round blindness rule:
    # while a scanner runs, tools/*/report.* has not been written yet, so there
    # is nothing for it to peek at.  The output_root guard above stays exactly
    # as it was -- blindness must not come to depend on a race.
    if llm_enabled and CONCURRENT_PHASES:
        _run_together(run_static, run_llm, cancellation.cancel)
    else:
        run_static()
        if llm_enabled:
            run_llm()

    if interrupted or cancellation.cancelled or manifest["llm"].get("status") == "interrupted":
        return _finish_interrupted(run_dir, manifest, inventory, requested_names, progress, event)

    progress("verifying source stability")
    # The concurrent window ends here; a lower value would walk progress
    # backwards on every run that enables the LLM phase.
    event("stability", "started", "verifying source stability", value=WINDOW_END)
    try:
        after = discover(source, config, output_root, cancelled=cancellation.is_cancelled)
    except InterruptedError:
        return _finish_interrupted(run_dir, manifest, inventory, requested_names, progress, event)
    if cancellation.cancelled:
        return _finish_interrupted(run_dir, manifest, inventory, requested_names, progress, event)
    before_by_path = {item["path"]: item["sha256"] for item in inventory}
    after_by_path = {item["path"]: item["sha256"] for item in after}
    changes = {
        "added": sorted(after_by_path.keys() - before_by_path.keys()),
        "deleted": sorted(before_by_path.keys() - after_by_path.keys()),
        "changed": sorted(path for path in before_by_path.keys() & after_by_path.keys() if before_by_path[path] != after_by_path[path]),
    }
    stable = not any(changes.values())
    event("stability", "finished", "source is stable" if stable else "source changed during analysis", value=0.85)
    manifest["source_inventory"]["stable"] = stable
    manifest["source_inventory"]["changes"] = changes
    # Compute the intended final state before deriving and exporting reports,
    # without persisting export success ahead of the export actually running.
    intended_export = "completed" if config["run"]["shareable_export"] else manifest["export"]["status"]
    status, exit_code = overall(manifest["tools"], stable, intended_export)
    manifest["status"], manifest["exit_code"] = status, exit_code
    manifest["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    review_summary: dict[str, Any] | None = None
    if config["review"]["enabled"]:
        progress("deriving non-authoritative review findings")
        event("review", "started", "deriving non-authoritative review findings", value=0.86)
        try:
            review_summary = build_review(
                source, run_dir, manifest, inventory, cancelled=cancellation.is_cancelled
            )
            write_review(
                run_dir, review_summary, int(config["review"]["max_markdown_findings"]),
                cancelled=cancellation.is_cancelled,
            )
        except Exception as exc:
            manifest["review"].update({"status": "failed", "error": str(exc)})
            if exit_code in {0, 1}:
                manifest["status"], manifest["exit_code"] = "partial", 10
            _log(run_dir, f"review derivation failed: {exc}")
            progress("review derivation failed; native evidence was retained")
            event("review", "failed", str(exc), value=0.92)
        else:
            review_status = review_summary.get("report_integrity", {}).get("status", "complete")
            manifest["review"].update({
                "status": "partial" if review_status == "partial" else "completed", "error": None,
                "findings": review_summary["total_findings"],
                "diagnostics": review_summary["total_diagnostics"],
            })
            if review_status == "partial" and manifest["exit_code"] in {0, 1}:
                manifest["status"], manifest["exit_code"] = "partial", 10
                manifest["gate"]["triggered"] = False
            _log(run_dir, f"review completed; {review_summary['total_findings']} findings")
            event("review", "finished", f"review completed; {review_summary['total_findings']} findings", value=0.92)
            # Deterministic and zero-model, so it belongs on the spine: the
            # static-only / llm-only / both split is available without assess.
            try:
                write_sarif(run_dir, build_sarif(review_summary, manifest))
            except Exception as exc:
                _log(run_dir, f"SARIF export failed: {exc}")
            try:
                assessment = build_assessment(review_summary)
                write_assessment(run_dir, assessment)
            except Exception as exc:
                manifest["audit"] = {"status": "failed", "error": str(exc), "path": None}
                _log(run_dir, f"correlation failed: {exc}")
            else:
                manifest["audit"] = {**assessment_summary(assessment), "error": None}
                _log(run_dir, f"correlation completed; {manifest['audit']['candidates']} candidates")
    if cancellation.cancelled:
        return _finish_interrupted(run_dir, manifest, inventory, requested_names, progress, event)
    gate_includes_llm = bool(config["review"]["gate_includes_llm"])
    if manifest["exit_code"] == 0 and review_summary is not None and should_fail(
        review_summary, config["review"]["fail_on"], include_generated=gate_includes_llm
    ):
        manifest["gate"]["triggered"] = True
        manifest["exit_code"] = 1
    artifact_cache: dict[str, tuple[int, int, dict[str, Any]]] = {}
    manifest["artifacts"] = artifact_index(run_dir, artifact_cache)
    save_manifest()

    if config["run"]["shareable_export"] and exit_code != 130:
        progress("creating redacted shareable export")
        event("export", "started", "creating redacted shareable export", value=0.93)
        try:
            export_shareable(
                run_dir, manifest, config, config_path_values, cancelled=cancellation.is_cancelled
            )
        except (ExportError, OSError, ValueError, json.JSONDecodeError) as exc:
            manifest["export"].update({"status": "failed", "archive": None, "error": str(exc)})
            _log(run_dir, f"shareable export failed: {exc}")
            status, exit_code = overall(manifest["tools"], stable, "failed", manifest["review"]["status"])
            manifest["status"], manifest["exit_code"] = status, exit_code
            manifest["gate"]["triggered"] = False
            progress("shareable export failed; private evidence was retained")
            event("export", "failed", str(exc), value=0.98)
        else:
            status, exit_code = overall(
                manifest["tools"], stable, manifest["export"]["status"], manifest["review"]["status"]
            )
            if manifest["gate"].get("triggered") and status == "complete":
                exit_code = 1
            elif status != "complete":
                manifest["gate"]["triggered"] = False
            manifest["status"], manifest["exit_code"] = status, exit_code
            export_message = f"shareable export {manifest['export']['status']}"
            _log(run_dir, export_message)
            progress(export_message)
            event("export", "finished", export_message, value=0.98)
    elif exit_code == 130 and config["run"]["shareable_export"]:
        manifest["export"].update({"status": "failed", "archive": None, "error": "run interrupted"})
    if cancellation.cancelled:
        return _finish_interrupted(run_dir, manifest, inventory, requested_names, progress, event)
    (run_dir / "index.html").write_text(render(manifest, review_summary, load_assessment(run_dir)), encoding="utf-8")
    manifest["artifacts"] = artifact_index(run_dir, artifact_cache)
    save_manifest()
    try:
        _update_latest(run_dir.parent, manifest)
    except OSError as exc:
        _log(run_dir, f"latest.json publication failed: {exc}")
        if manifest["exit_code"] in {0, 1}:
            manifest["status"], manifest["exit_code"] = "partial", 10
            manifest["gate"]["triggered"] = False
        manifest["publication_error"] = str(exc)
        (run_dir / "index.html").write_text(render(manifest, review_summary, load_assessment(run_dir)), encoding="utf-8")
        manifest["artifacts"] = artifact_index(run_dir, artifact_cache)
        save_manifest()
        progress("latest.json publication failed; unique run evidence was retained")
    progress(f"run finished: status {manifest['status']}, exit code {manifest['exit_code']}")
    return int(manifest["exit_code"]), run_dir


def _finish_interrupted(
    run_dir: Path,
    manifest: dict[str, Any],
    inventory: list[dict[str, Any]],
    requested_names: list[str],
    progress: Callable[[str], None],
    event: Callable[..., None],
) -> tuple[int, Path]:
    """Publish inspectable partial evidence after cooperative cancellation."""
    for name in requested_names:
        current = manifest["tools"][name]
        if current.get("status") in {"not_requested", "running"}:
            manifest["tools"][name] = {
                **_preflight_state("interrupted", inventory, name, "run interrupted before tool start"),
                "executable": current.get("executable"), "version": current.get("version"),
            }
    if manifest["llm"].get("status") == "running":
        manifest["llm"].update({"status": "interrupted", "reason": "run interrupted"})
    manifest["status"] = "interrupted"
    manifest["exit_code"] = 130
    manifest["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest["source_inventory"]["stable"] = None
    manifest["source_inventory"]["changes"] = {}
    if manifest["review"]["enabled"]:
        manifest["review"].update({"status": "interrupted", "error": "run interrupted"})
    if manifest["export"]["enabled"]:
        manifest["export"].update({"status": "failed", "archive": None, "error": "run interrupted"})
    manifest["gate"]["triggered"] = False
    artifact_cache: dict[str, tuple[int, int, dict[str, Any]]] = {}
    manifest["artifacts"] = artifact_index(run_dir, artifact_cache)
    _save_manifest(run_dir, manifest)
    (run_dir / "index.html").write_text(render(manifest, None), encoding="utf-8")
    manifest["artifacts"] = artifact_index(run_dir, artifact_cache)
    _save_manifest(run_dir, manifest)
    try:
        _update_latest(run_dir.parent, manifest)
    except OSError as exc:
        manifest["publication_error"] = str(exc)
        _log(run_dir, f"latest.json publication failed: {exc}")
        _save_manifest(run_dir, manifest)
    progress("run finished: status interrupted, exit code 130")
    event("analysis", "interrupted", "run safely stopped; partial evidence retained", value=1.0)
    return 130, run_dir


def _not_requested(inventory: list[dict[str, Any]], name: str) -> dict[str, Any]:
    total = len([item for item in inventory if Path(item["path"]).suffix == ".c"]) if name == "splint" else len(inventory)
    metric = "tu_report_coverage" if name == "splint" else "input_coverage"
    coverage: dict[str, Any] = {"metric": metric, "covered": 0, "total": total, "attempted": 0, "analyzed": 0, "excluded": 0, "effective_total": total, "ratio": None}
    if name == "splint":
        coverage.update({"analysis_reached": 0, "analysis_ratio": None})
    return {"requested": False, "status": "not_requested", "executable": None, "version": None, "units": [], "valid_reports": 0, "coverage": coverage, "unit_counts": {"planned": 0, "started": 0, "completed": 0, "failed": 0, "timed_out": 0, "unscheduled": 0}}


def _preflight_state(state: str, inventory: list[dict[str, Any]], name: str, reason: str) -> dict[str, Any]:
    value = _not_requested(inventory, name)
    value.update({"requested": True, "status": state, "reason": reason})
    return value


def _running_state(inventory: list[dict[str, Any]], name: str, executable: str, version: str | None) -> dict[str, Any]:
    """Transient placeholder published while a tool runs; never a final record."""
    value = _not_requested(inventory, name)
    value.update({"requested": True, "status": "running", "executable": executable, "version": version})
    return value


def _write_inputs(run_dir: Path, inventory: list[dict[str, Any]], config: dict[str, Any], filtered_db: list[dict[str, Any]], source: Path, output_root: Path, extra: list[Path]) -> None:
    inputs = run_dir / "inputs"
    (inputs / "effective-config.toml").write_text(effective_toml(config), encoding="utf-8")
    (inputs / "source-files.txt").write_text("".join(item["path"] + "\n" for item in inventory), encoding="utf-8")
    _write_json(inputs / "source-inventory.json", {"source": str(source), "files": inventory})
    if filtered_db:
        _write_json(inputs / "compile_commands.filtered.json", filtered_db)
    mapping = {
        "source": str(source), "output_root": str(output_root), "run_directory": str(run_dir),
        "cwd": str(Path.cwd().resolve()), "home": str(Path.home().resolve()), "hostname": socket.gethostname(),
        "additional_paths": [str(path.resolve()) for path in extra],
    }
    _write_json(inputs / "sanitizer-map.private.json", mapping)


def _save_manifest(run_dir: Path, manifest: dict[str, Any]) -> None:
    target = run_dir / "manifest.json"
    temporary = run_dir / ".manifest.json.tmp"
    temporary.write_bytes(json_bytes(manifest))
    temporary.replace(target)


def _log(run_dir: Path, message: str) -> None:
    with (run_dir / "logs" / "runner.log").open("a", encoding="utf-8") as stream:
        stream.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + message + "\n")


def _inventory_digest(inventory: list[dict[str, Any]]) -> str:
    canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _update_latest(source_root: Path, manifest: dict[str, Any]) -> None:
    payload = {
        "manifest_schema_version": manifest["manifest_schema_version"],
        "run_id": manifest["run_id"],
        "run_directory": manifest["run_directory"],
        "status": manifest["status"],
        "exit_code": manifest["exit_code"],
        "finished_at": manifest["finished_at"],
    }
    target = source_root / "latest.json"
    temporary = source_root / f".latest.{manifest['run_id']}.tmp"
    try:
        temporary.write_bytes(json_bytes(payload))
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def _version(name: str, executable: str) -> str | None:
    argv = adapter(name).version_argv(executable)
    try:
        completed = subprocess.run(argv, capture_output=True, timeout=10, shell=False)
        text = (completed.stdout + completed.stderr).decode("utf-8", errors="replace").strip()
        return text.splitlines()[0] if text else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _incompatibility(name: str, executable: str) -> str | None:
    """Return a capability error, or None when compatible/indeterminate.

    An indeterminate help command is left to the adapter.  This keeps wrappers
    and test doubles usable while still rejecting a real, recognizable help
    page that lacks capabilities required by the v1 argv contract.
    """
    declared = adapter(name)
    if declared.help_topics:
        missing = []
        for topic in declared.help_topics:
            result = _help([executable, "-help", topic])
            if result is not None and not result.strip():
                missing.append(topic)
        if missing:
            verified, reason = verify_canary(name, executable)
            return None if verified else "missing help topics: " + ", ".join(missing) + (f"; canary: {reason}" if reason else "")
        return None
    required = declared.required_capabilities
    text = _help([executable, "--help"])
    if text is None or text.lstrip().startswith(("{", "<")):
        return None
    plausible = "usage" in text.lower() or "options" in text.lower() or any(flag in text for flag in required)
    if not plausible:
        return None
    missing = [flag for flag in required if flag not in text]
    if missing:
        verified, reason = verify_canary(name, executable)
        return None if verified else "missing required capabilities: " + ", ".join(missing) + (f"; canary: {reason}" if reason else "")
    return None


def _help(argv: list[str]) -> str | None:
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return (completed.stdout + completed.stderr).decode("utf-8", errors="replace")

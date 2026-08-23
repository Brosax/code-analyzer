from __future__ import annotations

import hashlib
import json
import shlex
import shutil
import socket
import subprocess
import sys
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
from .status import overall
from .tools import TOOL_NAMES, cppcheck, flawfinder, splint
from .tools.common import artifact_index


class AnalysisCancelled(Exception):
    """Cancellation observed before a report directory exists."""


def analyze(source: Path, config: dict[str, Any]) -> tuple[int, Path]:
    with ProgressDisplay(sys.stderr) as display:
        return _analyze(source, config, display.emit)


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
    event("discovery", "finished", f"inventory ready: {len(inventory)} files", value=0.1)

    interrupted = cancellation.cancelled
    requested_names = [name for name in TOOL_NAMES if requested[name]]
    tool_count = max(1, len(requested_names))
    for tool_index, name in enumerate(requested_names, 1):
        tool_prefix = f"tool {tool_index}/{len(requested_names)} {name}"
        tool_start_progress = 0.1 + 0.7 * (tool_index - 1) / tool_count
        tool_finish_progress = 0.1 + 0.7 * tool_index / tool_count
        if not requested[name]:
            continue
        if interrupted or cancellation.cancelled:
            interrupted = True
            manifest["tools"][name] = _preflight_state("interrupted", inventory, name, "run interrupted before tool start")
            progress(f"{tool_prefix}: interrupted before start")
            event("tool", "interrupted", "run interrupted before tool start", tool=name, value=tool_finish_progress)
            continue
        executable = config["tools"][name]["executable"]
        resolved = shutil.which(executable)
        if not resolved:
            manifest["tools"][name] = _preflight_state("missing", inventory, name, f"executable not found: {executable}")
            _log(run_dir, f"{name}: missing executable {executable}")
            progress(f"{tool_prefix}: missing executable")
            event("tool", "missing", f"executable not found: {executable}", tool=name, value=tool_finish_progress)
            _save_manifest(run_dir, manifest)
            continue
        incompatibility = _incompatibility(name, resolved)
        if incompatibility:
            manifest["tools"][name] = _preflight_state("incompatible", inventory, name, incompatibility)
            manifest["tools"][name]["executable"] = resolved
            manifest["tools"][name]["version"] = _version(name, resolved)
            _log(run_dir, f"{name}: incompatible: {incompatibility}")
            progress(f"{tool_prefix}: incompatible")
            event("tool", "incompatible", incompatibility, tool=name, value=tool_finish_progress)
            _save_manifest(run_dir, manifest)
            continue
        _log(run_dir, f"{name}: starting {resolved}")
        progress(f"{tool_prefix}: starting")
        event("tool", "started", f"{name} starting", tool=name, value=tool_start_progress)
        def unit_progress(message: str, prefix: str = tool_prefix, tool_name: str = name) -> None:
            progress(f"{prefix}: {message}")
        def structured_unit(
            unit: str, status: str, message: str, value: float | None,
            tool_name: str = name, tool_start: float = tool_start_progress,
        ) -> None:
            overall_value = None if value is None else tool_start + 0.7 * value / tool_count
            event("unit", status, message, tool=tool_name, unit=unit, value=overall_value)
        def streamed_output(unit: str, stream: str, message: str, tool_name: str = name) -> None:
            event("output", "running", message, tool=tool_name, unit=unit, stream=stream)
        try:
            if name == "cppcheck":
                result = cppcheck.run(
                    resolved, source, run_dir, inventory, filtered_db, db_covered, config, unit_progress,
                    cancelled=cancellation.is_cancelled, unit_event=structured_unit,
                    output_event=streamed_output if live_events else None,
                )
            elif name == "flawfinder":
                result = flawfinder.run(
                    resolved, source, run_dir, inventory, config, unit_progress,
                    cancelled=cancellation.is_cancelled, unit_event=structured_unit,
                    output_event=streamed_output if live_events else None,
                )
            else:
                result = splint.run(
                    resolved, source, run_dir, inventory, filtered_db, config, unit_progress,
                    compile_db_present=compile_path is not None, cancelled=cancellation.is_cancelled,
                    unit_event=structured_unit, output_event=streamed_output if live_events else None,
                )
        except Exception as exc:
            result = _preflight_state("failed", inventory, name, f"adapter failure: {exc}")
        result["executable"] = resolved
        result["version"] = _version(name, resolved)
        manifest["tools"][name] = result
        interrupted = result["status"] == "interrupted"
        _log(run_dir, f"{name}: {result['status']}")
        progress(f"{tool_prefix}: finished with status {result['status']}")
        event(
            "tool", result["status"], f"{name} finished with status {result['status']}",
            tool=name, value=tool_finish_progress,
        )
        _save_manifest(run_dir, manifest)

    if interrupted or cancellation.cancelled:
        return _finish_interrupted(run_dir, manifest, inventory, requested_names, progress, event)

    if config["llm"]["enabled"]:
        progress("llm: starting semantic scan")
        event("llm", "started", "starting LLM semantic scan", value=0.8)
        def llm_unit(producer: str, unit: str, status: str, message: str, value: float | None) -> None:
            # Rounded so the last unit (0.8 + 0.04 * 1.0 = 0.8400000000000001)
            # cannot land above the phase's own 0.84 completion value.
            event("unit", status, message, tool=producer, unit=unit, value=None if value is None else round(0.8 + 0.04 * value, 6))
        def llm_output(producer: str, unit: str, stream: str, message: str) -> None:
            event("output", "running", message, tool=producer, unit=unit, stream=stream)
        try:
            manifest["llm"] = llm_scan.run(
                source, run_dir, inventory, config, progress,
                cancelled=cancellation.is_cancelled, unit_event=llm_unit,
                output_event=llm_output if live_events else None,
            )
        except InterruptedError:
            manifest["llm"] = llm_scan.failed(config["llm"], "run interrupted")
            manifest["llm"]["status"] = "interrupted"
        except Exception as exc:
            manifest["llm"] = llm_scan.failed(config["llm"], f"llm phase failure: {exc}")
        llm_status = manifest["llm"]["status"]
        _log(run_dir, f"llm: {llm_status}")
        progress(f"llm: finished with status {llm_status}")
        event("llm", llm_status, f"LLM scan finished with status {llm_status}", value=0.84)
        _save_manifest(run_dir, manifest)
        if llm_status == "interrupted" or cancellation.cancelled:
            return _finish_interrupted(run_dir, manifest, inventory, requested_names, progress, event)

    progress("verifying source stability")
    # The LLM phase ends at 0.84; a lower value here would walk progress
    # backwards on every run that enables it.
    event("stability", "started", "verifying source stability", value=0.84)
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
    if manifest["exit_code"] == 0 and review_summary is not None and should_fail(review_summary, config["review"]["fail_on"]):
        manifest["gate"]["triggered"] = True
        manifest["exit_code"] = 1
    artifact_cache: dict[str, tuple[int, int, dict[str, Any]]] = {}
    manifest["artifacts"] = artifact_index(run_dir, artifact_cache)
    _save_manifest(run_dir, manifest)

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
    _save_manifest(run_dir, manifest)
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
        _save_manifest(run_dir, manifest)
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
        if current.get("status") == "not_requested":
            manifest["tools"][name] = _preflight_state(
                "interrupted", inventory, name, "run interrupted before tool start"
            )
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
    return {"requested": False, "status": "not_requested", "executable": None, "version": None, "units": [], "valid_reports": 0, "coverage": {"metric": metric, "covered": 0, "total": total, "attempted": 0, "analyzed": 0, "excluded": 0, "effective_total": total, "ratio": None}, "unit_counts": {"planned": 0, "started": 0, "completed": 0, "failed": 0, "timed_out": 0, "unscheduled": 0}}


def _preflight_state(state: str, inventory: list[dict[str, Any]], name: str, reason: str) -> dict[str, Any]:
    value = _not_requested(inventory, name)
    value.update({"requested": True, "status": state, "reason": reason})
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
    argv = [executable, "-help", "version"] if name == "splint" else [executable, "--version"]
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
    if name == "splint":
        missing = []
        for topic in ("nof", "csv", "tmpdir", "modes", "ITS4"):
            result = _help([executable, "-help", topic])
            if result is not None and not result.strip():
                missing.append(topic)
        if missing:
            verified, reason = verify_canary(name, executable)
            return None if verified else "missing help topics: " + ", ".join(missing) + (f"; canary: {reason}" if reason else "")
        return None
    required = {
        "cppcheck": ("--xml-version", "--output-file", "--project", "--file-list", "--check-level", "--check-library", "--checkers-report", "--cppcheck-build-dir"),
        "flawfinder": ("--sarif", "--minlevel", "--columns", "--neverignore"),
    }[name]
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

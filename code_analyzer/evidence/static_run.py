"""One static call: discover the tree, run cppcheck, flawfinder and splint, check the tree held still.

This is the static path of the old runner (runner.py ``_analyze``) and nothing
else: the same discovery and compile-database resolution, the same adapters
and argv, the same capability checks, the same stability rescan and the same
exit-code algebra (status.overall), writing the same manifest the evidence
layer reads.  The old run's LLM scan, review, audit, SARIF, dashboard, HTML
report and shareable archive are gone -- the list, the index and the export
own those jobs now.

A run directory is ``<output_root>/<source slug>/<UTC stamp>-<run id>/`` with
``inputs/`` (the inventory, the filtered compile database, the effective
configuration), ``tools/<tool>/<unit>/`` (native reports, never rewritten) and
``manifest.json`` (written atomically after every step, so an interrupted run
leaves an honest record: status ``interrupted``, exit code 130).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .. import __version__
from ..compile_db import filter_database, resolve_compile_db
from ..config import effective_toml
from ..core.cancel import CancellationToken
from ..errors import UserError
from ..inventory import (
    Discovery,
    discover,
    git_state,
    scope_sentence,
    scope_summary,
    source_slug,
)
from ..persist import json_bytes
from ..status import overall
from ..tools import TOOL_NAMES, CompileDatabase, OutputBudget, RunContext, adapter

# The whole run's share of disk for tool output: far above any real report, a guard against a runaway.
RUN_OUTPUT_BYTES = 2 * 1024 * 1024 * 1024
MANIFEST_SCHEMA_VERSION = 2


class Cancelled(Exception):
    """Cancellation observed before a run directory exists."""


def run(source: Path, config: dict[str, Any], progress: Callable[[str], None], *,
        cancellation: CancellationToken | None = None) -> tuple[int, Path]:
    """Run the enabled analyzers once; returns (exit code, run directory)."""
    cancellation = cancellation or CancellationToken()
    source = source.expanduser().resolve()
    if not source.is_dir():
        raise UserError(f"source is not a directory: {source}")
    output_root = Path(config["run"]["output_root"]).expanduser().resolve()
    if output_root == source:
        raise UserError("output root must not be identical to source")
    progress("discovering source files and build context")
    compile_path, compile_entries, degraded, compile_discovery = resolve_compile_db(source, config)
    if cancellation.cancelled:
        raise Cancelled()
    if compile_path is None and config["build"]["compile_database_mode"] == "auto":
        progress("no valid compile database found; continuing with reduced build context")
    try:
        output_root.mkdir(parents=True, exist_ok=True)
        discovered = discover(source, config, output_root, cancelled=cancellation.is_cancelled)
    except InterruptedError as error:
        raise Cancelled() from error
    except OSError as error:
        raise UserError(f"cannot create output root {output_root}: {error}") from error
    if cancellation.cancelled:
        raise Cancelled()
    inventory = discovered.files
    scope = scope_summary(discovered)
    filtered_db, db_covered = filter_database(source, inventory, compile_entries)
    progress(f"inventory ready: {len(inventory)} files; compile database entries: {len(filtered_db)}")
    if not discovered.complete:
        progress(scope_sentence(len(inventory), scope))
    run_id = uuid.uuid4().hex[:12]
    run_dir = output_root / source_slug(source) / f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{run_id}"
    try:
        for sub in ("inputs", "logs", "tools"):
            (run_dir / sub).mkdir(parents=True)
    except OSError as error:
        raise UserError(f"cannot create run directory {run_dir}: {error}") from error
    _write_inputs(run_dir, discovered, config, filtered_db, source)
    requested = [name for name in TOOL_NAMES if config["tools"][name]["enabled"]]
    manifest: dict[str, Any] = {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION, "analyzer_version": __version__, "run_id": run_id,
        "status": "running", "exit_code": None,
        "started_at": _now(), "finished_at": None,
        "source": str(source), "output_root": str(output_root), "run_directory": str(run_dir),
        "analysis_context": "full" if compile_path else "degraded", "analysis_context_reasons": degraded,
        "compile_database": {"path": str(compile_path) if compile_path else None, "entries": len(compile_entries),
                             "filtered_entries": len(filtered_db), "discovery": compile_discovery},
        "source_options": {"include": config["source"]["include"], "exclude": config["source"]["exclude"]},
        "source_inventory": {"total": len(inventory), "sha256": inventory_digest(inventory),
                             "git": git_state(source), "stable": None, "changes": {}, "scope": scope},
        "tools": {name: _not_requested(inventory, name) for name in TOOL_NAMES},
    }
    _save(run_dir, manifest)
    database = CompileDatabase(entries=filtered_db, covered=frozenset(db_covered), present=compile_path is not None)
    budget = OutputBudget(RUN_OUTPUT_BYTES)
    interrupted = False
    try:
        for index, name in enumerate(requested, 1):
            prefix = f"tool {index}/{len(requested)} {name}"
            if interrupted or cancellation.cancelled:
                interrupted = True
                manifest["tools"][name] = _state("interrupted", inventory, name, "run interrupted before tool start")
                progress(f"{prefix}: interrupted before start")
                continue
            executable = config["tools"][name]["executable"]
            resolved = shutil.which(executable)
            if not resolved:
                manifest["tools"][name] = _state("missing", inventory, name, f"executable not found: {executable}")
                _save(run_dir, manifest)
                progress(f"{prefix}: missing executable")
                continue
            version = _version(name, resolved)
            problem = incompatibility(name, resolved)
            if problem:
                manifest["tools"][name] = {**_state("incompatible", inventory, name, problem),
                                           "executable": resolved, "version": version}
                _save(run_dir, manifest)
                progress(f"{prefix}: incompatible ({problem})")
                continue
            progress(f"{prefix}: starting")
            manifest["tools"][name] = {**_state("running", inventory, name, ""), "executable": resolved,
                                       "version": version}
            _save(run_dir, manifest)
            context = RunContext(
                source=source, run_dir=run_dir, inventory=inventory, compile_db=database, config=config,
                progress=lambda message, p=prefix: progress(f"{p}: {message}"),
                cancelled=cancellation.is_cancelled,
                unit_event=lambda unit, status, message, value, data=None, *, phase="unit", p=prefix:
                    _unit_line(progress, p, unit, status, message, data, phase),
                output_budget=budget)
            try:
                result = adapter(name).run(resolved, context)
            except Exception as error:  # noqa: BLE001 - one adapter's bug must not cost the others' evidence
                result = _state("failed", inventory, name, f"adapter failure: {error}")
            result.update(executable=resolved, version=version)
            manifest["tools"][name] = result
            _save(run_dir, manifest)
            interrupted = result["status"] == "interrupted"
            progress(f"{prefix}: finished with status {result['status']}")
    except KeyboardInterrupt:
        cancellation.cancel()
        interrupted = True
    if interrupted or cancellation.cancelled:
        return _interrupted(run_dir, manifest, inventory, requested, progress)

    progress("verifying source stability")
    try:
        after = discover(source, config, output_root, cancelled=cancellation.is_cancelled)
    except InterruptedError:
        return _interrupted(run_dir, manifest, inventory, requested, progress)
    if cancellation.cancelled:
        return _interrupted(run_dir, manifest, inventory, requested, progress)
    stable, changes, scope = stability(discovered, after)
    manifest["source_inventory"].update(stable=stable, changes=changes, scope=scope)
    _write_json(run_dir / "inputs" / "source-inventory.json", _inventory_document(source, discovered, after))
    if not scope["complete"]:
        progress(scope_sentence(len(inventory), scope))
    status, exit_code = overall(manifest["tools"], stable, "disabled", scope_complete=bool(scope["complete"]))
    manifest.update(status=status, exit_code=exit_code, finished_at=_now())
    _save(run_dir, manifest)
    progress(f"run finished: status {status}, exit code {exit_code}")
    return exit_code, run_dir


def stability(before: Discovery, after: Discovery) -> tuple[bool | None, dict[str, list[str]], dict[str, Any]]:
    """Did the tree hold still?  True, False, or None when part of it could not be looked at."""
    before_by_path = {item["path"]: item["sha256"] for item in before.files}
    after_by_path = {item["path"]: item["sha256"] for item in after.files}
    # A path one walk could not read is missing from that walk for a reason that is not a source change.
    vanished = _unverified(before_by_path.keys() - after_by_path.keys(), after.anomalies)
    appeared = _unverified(after_by_path.keys() - before_by_path.keys(), before.anomalies)
    unverified = sorted({*vanished, *appeared})
    changes = {
        "added": sorted(after_by_path.keys() - before_by_path.keys() - set(appeared)),
        "deleted": sorted(before_by_path.keys() - after_by_path.keys() - set(vanished)),
        "changed": sorted(p for p in before_by_path.keys() & after_by_path.keys() if before_by_path[p] != after_by_path[p]),
        "unverified": unverified,
    }
    moved = any(changes[key] for key in ("added", "deleted", "changed"))
    stable = False if moved else (True if after.complete and not unverified else None)
    return stable, changes, scope_summary(before, after)


def incompatibility(name: str, executable: str) -> str | None:
    """A capability error, or None when compatible or indeterminate (the adapter then decides).

    Help text is advisory -- distro builds and wrappers implement options they do not list -- so a
    recognisable help page that lacks a required option is confirmed with a canary run before refusing.
    """
    declared = adapter(name)
    if declared.help_topics:
        missing = [topic for topic in declared.help_topics
                   if (text := _help([executable, "-help", topic])) is not None and not text.strip()]
        if not missing:
            return None
        verified, reason = canary(name, executable)
        return None if verified else "missing help topics: " + ", ".join(missing) + (f"; canary: {reason}" if reason else "")
    text = _help([executable, "--help"])
    if text is None or text.lstrip().startswith(("{", "<")):
        return None
    required = declared.required_capabilities
    if not ("usage" in text.lower() or "options" in text.lower() or any(flag in text for flag in required)):
        return None
    missing = [flag for flag in required if flag not in text]
    if not missing:
        return None
    verified, reason = canary(name, executable)
    return None if verified else "missing required capabilities: " + ", ".join(missing) + (f"; canary: {reason}" if reason else "")


def canary(name: str, executable: str) -> tuple[bool, str | None]:
    """Run the tool over a minimal source file and check its native report."""
    try:
        with tempfile.TemporaryDirectory(prefix=f"code-analyzer-{name}-canary-") as temporary:
            root = Path(temporary)
            (root / "canary.c").write_text("int main(void) { int value; return value; }\n", encoding="utf-8")
            valid, reason = adapter(name).canary(executable, root)
            return (True, None) if valid else (False, reason or f"minimal {name} canary did not produce a valid native report")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, ET.ParseError, subprocess.TimeoutExpired) as error:
        return False, str(error)


def inventory_digest(inventory: list[dict[str, Any]]) -> str:
    return hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# -- helpers ------------------------------------------------------------------------------------------

def _unit_line(progress: Callable[[str], None], prefix: str, unit: str | None, status: str, message: str,
               data: dict[str, Any] | None, phase: str) -> None:
    if phase == "units":
        progress(f"{prefix}: {message}")
    elif data and "index" in data and status != "info":
        progress(f"{prefix}: unit {data['index']}/{data['total']} {data.get('label', unit)}: {message}")


def _interrupted(run_dir: Path, manifest: dict[str, Any], inventory: list[dict[str, Any]], requested: list[str],
                 progress: Callable[[str], None]) -> tuple[int, Path]:
    """An honest record of a stopped run: every unfinished tool says interrupted, the exit code is 130."""
    for name in requested:
        current = manifest["tools"][name]
        if current.get("status") in {"not_requested", "running"}:
            manifest["tools"][name] = {**_state("interrupted", inventory, name, "run interrupted before tool start"),
                                       "executable": current.get("executable"), "version": current.get("version")}
    manifest.update(status="interrupted", exit_code=130, finished_at=_now())
    manifest["source_inventory"].update(stable=None, changes={})
    _save(run_dir, manifest)
    progress("run finished: status interrupted, exit code 130")
    return 130, run_dir


def _not_requested(inventory: list[dict[str, Any]], name: str) -> dict[str, Any]:
    total = len([i for i in inventory if Path(i["path"]).suffix == ".c"]) if name == "splint" else len(inventory)
    coverage: dict[str, Any] = {"metric": "tu_report_coverage" if name == "splint" else "input_coverage",
                                "covered": 0, "total": total, "attempted": 0, "analyzed": 0, "excluded": 0,
                                "effective_total": total, "ratio": None}
    if name == "splint":
        coverage.update(analysis_reached=0, analysis_ratio=None)
    return {"requested": False, "status": "not_requested", "executable": None, "version": None, "units": [],
            "valid_reports": 0, "coverage": coverage,
            "unit_counts": {"planned": 0, "started": 0, "completed": 0, "failed": 0, "timed_out": 0, "unscheduled": 0}}


def _state(state: str, inventory: list[dict[str, Any]], name: str, reason: str) -> dict[str, Any]:
    value = _not_requested(inventory, name)
    value.update(requested=True, status=state, reason=reason)
    return value


def _write_inputs(run_dir: Path, discovered: Discovery, config: dict[str, Any], filtered_db: list[dict[str, Any]],
                  source: Path) -> None:
    inputs = run_dir / "inputs"
    (inputs / "effective-config.toml").write_text(effective_toml(config), encoding="utf-8")
    (inputs / "source-files.txt").write_text("".join(item["path"] + "\n" for item in discovered.files), encoding="utf-8")
    _write_json(inputs / "source-inventory.json", _inventory_document(source, discovered, None))
    if filtered_db:
        _write_json(inputs / "compile_commands.filtered.json", filtered_db)


def _inventory_document(source: Path, initial: Discovery, recheck: Discovery | None) -> dict[str, Any]:
    """The files analysed and every gap in them; ``recheck`` is null until the stability walk ran."""
    record = lambda d: {"complete": d.complete, "anomalies": [a.as_dict() for a in d.anomalies]}  # noqa: E731
    return {"source": str(source), "files": initial.files, "discovery": record(initial),
            "recheck": None if recheck is None else record(recheck)}


def _unverified(missing: Any, anomalies: Any) -> list[str]:
    unreadable = {item.path for item in anomalies if item.operation in {"read", "stat"}}
    unwalked = {item.path for item in anomalies if item.operation == "walk"}
    return sorted(path for path in missing if path in unreadable
                  or any(d == "." or path.startswith(d + "/") for d in unwalked))


def _save(run_dir: Path, manifest: dict[str, Any]) -> None:
    temporary = run_dir / ".manifest.json.tmp"
    temporary.write_bytes(json_bytes(manifest))
    temporary.replace(run_dir / "manifest.json")


def _write_json(path: Path, value: Any) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(json_bytes(value))
    temporary.replace(path)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _version(name: str, executable: str) -> str | None:
    try:
        completed = subprocess.run(adapter(name).version_argv(executable), capture_output=True, timeout=10, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (completed.stdout + completed.stderr).decode("utf-8", errors="replace").strip()
    return text.splitlines()[0] if text else None


def _help(argv: list[str]) -> str | None:
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   timeout=10, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return (completed.stdout + completed.stderr).decode("utf-8", errors="replace")

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from ..control import CANCELLED, RUN, SKIP_PRODUCER, SKIP_UNIT
from ..process import run_process
from ..runlog import error_excerpt
from ..status import aggregate_units, counts
from .adapter import Adapter, RunContext
from .common import (
    announce_never_ran,
    attach_artifacts,
    output_room,
    unit_outcome,
    utf8_validation,
)


def shard_files(files: list[str], prefix_bytes: int = 200) -> list[list[str]]:
    shards: list[list[str]] = []
    current: list[str] = []
    size = prefix_bytes
    for path in sorted(files):
        encoded = len(path.encode("utf-8")) + 1
        if current and (len(current) >= 1000 or size + encoded > 256 * 1024):
            shards.append(current)
            current, size = [], prefix_bytes
        current.append(path)
        size += encoded
    if current:
        shards.append(current)
    return shards


def run(
    executable: str,
    source: Path,
    run_dir: Path,
    inventory: list[dict[str, Any]],
    config: dict[str, Any],
    progress: Callable[[str], None] | None = None,
    *,
    cancelled: Callable[[], bool] | None = None,
    unit_event: Callable[[str, str, str, float | None], None] | None = None,
    output_budget: Any = None,
    output_event: Callable[[str, str, str], None] | None = None,
    control: Any = None,
) -> dict[str, Any]:
    progress = progress or (lambda _message: None)
    unit_event = unit_event or (lambda *_args, **_kwargs: None)
    files = [item["path"] for item in inventory]
    compatible: list[str] = []
    excluded: list[dict[str, Any]] = []
    for relative in files:
        valid_encoding, error = utf8_validation(source / relative)
        if valid_encoding:
            compatible.append(relative)
        else:
            detail = error or {"byte_offset": None, "reason": "UTF-8 validation failed"}
            excluded.append({
                "path": relative,
                "byte_offset": detail.get("byte_offset"),
                "reason": detail.get("reason"),
                "category": "encoding",
            })
    if excluded:
        # Itemised once, up front: the files the lexical scan will never see,
        # and why.  The tool's own reason names the count below.
        unit_event(
            None, "info", f"{len(excluded)} file(s) excluded: encoding", None,
            data={"count": len(excluded), "reason": "encoding", "excluded": excluded[:20]}, phase="units",
        )
    shards = shard_files(compatible)
    units: list[dict[str, Any]] = []
    deadline = time.monotonic() + float(config["tools"]["flawfinder"]["timeout_seconds"])
    heartbeat_seconds = float(config["tools"]["flawfinder"]["heartbeat_seconds"])
    grace = float(config["run"]["termination_grace_seconds"])
    for index, paths in enumerate(shards, 1):
        name = f"shard-{index:04d}"
        facts = {"index": index, "total": len(shards), "label": name, "files": len(paths)}
        action = control.checkpoint("static", "flawfinder", name) if control is not None else RUN
        if action in {SKIP_PRODUCER, SKIP_UNIT}:
            units.append({"id": name, "status": "unscheduled", "input_files": paths, "valid_report": False, "reason": "skipped by operator", "evidence_context": "source-only", "artifacts": []})
            continue
        if (cancelled is not None and cancelled()) or action == CANCELLED:
            units.append({"id": name, "status": "interrupted", "input_files": paths, "valid_report": False, "reason": "run interrupted", "evidence_context": "source-only", "artifacts": []})
            break
        directory = run_dir / "tools" / "flawfinder" / name
        directory.mkdir(parents=True, exist_ok=True)
        stdout, stderr, report = directory / "stdout.raw", directory / "stderr.raw", directory / "report.sarif"
        if time.monotonic() >= deadline:
            units.append({"id": name, "status": "unscheduled", "input_files": paths, "valid_report": False, "reason": "total budget exhausted", "evidence_context": "source-only", "artifacts": []})
            continue
        argv = [executable, "--sarif", "--minlevel=0", "--neverignore", "--columns", "--omittime", "--quiet", "--", *paths]
        unit_timeout = max(0.001, deadline - time.monotonic())
        unit_event(name, "started", f"scanning {len(paths)} files", (index - 1) / max(1, len(shards)), data={
            **facts, "argv": argv, "cwd": str(source), "timeout_seconds": round(unit_timeout, 3), "attempt": 1,
            "evidence_context": "source-only",
        })
        unit_event(name, "info", "机器输出已隐藏并保存至 report.sarif", None)

        def beat(
            elapsed: float, unit: str = name, timeout: float = unit_timeout, unit_facts: dict[str, Any] = facts,
        ) -> None:
            message = f"heartbeat; elapsed {elapsed:.1f}s; unit timeout {timeout:.1f}s"
            unit_event(unit, "heartbeat", message, None, data={
                **unit_facts, "elapsed": round(elapsed, 1), "timeout_seconds": round(timeout, 1),
            })

        process = run_process(
            argv, source, stdout, stderr, unit_timeout, grace,
            heartbeat=beat, heartbeat_seconds=heartbeat_seconds, cancelled=cancelled,
            output=(
                (lambda stream, line, unit=name: output_event(unit, stream, line))
                if output_event is not None else None
            ),
            output_streams=("stderr",),
            max_output_bytes=output_room(output_budget),
        )
        if output_budget is not None:
            output_budget.spend(process)
        report.unlink(missing_ok=True)
        valid, reason = _validate(stdout)
        if valid:
            # A .sarif name is only assigned after the native stdout has
            # passed the SARIF 2.1.0 contract.
            shutil.copyfile(stdout, report)
        state, reason = unit_outcome(
            process, valid, process.exit_code == 0 and valid, reason,
            f"unexpected exit status {process.exit_code}",
        )
        unit = {
            "id": name, "status": state, "input_files": paths,
            "valid_report": valid, "process": process.as_dict(), "reason": reason,
            "evidence_context": "source-only",
        }
        attach_artifacts(unit, directory, run_dir)
        units.append(unit)
        unit_event(name, state, f"{state} in {process.duration_seconds:.2f}s", index / max(1, len(shards)), data={
            **facts, "duration_seconds": process.duration_seconds, "exit_code": process.exit_code,
            "reason": reason, "valid_report": valid, "attempt": 1, "dir": str(directory.relative_to(run_dir)),
            "error_excerpt": error_excerpt(stderr.read_text(encoding="utf-8", errors="replace")) if state != "completed" and stderr.is_file() else None,
        })
        if process.interrupted:
            break
    if units and units[-1]["status"] == "interrupted":
        for index in range(len(units) + 1, len(shards) + 1):
            paths = shards[index - 1]
            units.append({"id": f"shard-{index:04d}", "status": "interrupted", "input_files": paths, "valid_report": False, "reason": "run interrupted", "evidence_context": "source-only", "artifacts": []})
    announce_never_ran(unit_event, units, len(shards))
    attempted = {path for unit in units if "process" in unit for path in unit["input_files"]}
    analyzed = {path for unit in units if unit.get("valid_report") for path in unit["input_files"]}
    status = aggregate_units(units, applicable=bool(compatible))
    if excluded and status not in {"interrupted", "failed", "timed_out"}:
        status = "partial"
    effective_total = len(files) - len(excluded)
    return {
        "requested": True, "status": status, "units": units,
        "valid_reports": sum(bool(unit.get("valid_report")) for unit in units),
        "reason": f"{len(excluded)} file(s) excluded: encoding" if excluded else None,
        "excluded_files": excluded,
        "coverage": {
            "metric": "input_coverage", "total": len(files), "attempted": len(attempted),
            "analyzed": len(analyzed), "excluded": len(excluded), "covered": len(analyzed),
            "ratio": len(analyzed) / effective_total if effective_total else None,
            "effective_total": effective_total,
        },
        "unit_counts": counts(units),
    }


def _validate(path: Path) -> tuple[bool, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return False, f"invalid Flawfinder SARIF: {exc}"
    if not isinstance(data, dict) or data.get("version") != "2.1.0":
        return False, "Flawfinder report is not SARIF 2.1.0"
    if not isinstance(data.get("runs"), list) or not all(isinstance(run, dict) for run in data["runs"]):
        return False, "invalid Flawfinder SARIF: runs must be an array of objects"
    return True, None


# --- the adapter ------------------------------------------------------------


def _run(executable: str, ctx: RunContext) -> dict[str, Any]:
    return run(
        executable, ctx.source, ctx.run_dir, ctx.inventory, ctx.config, ctx.progress,
        cancelled=ctx.cancelled, unit_event=ctx.unit_event, output_event=ctx.output_event,
        output_budget=ctx.output_budget, control=ctx.control,
    )


def _parse(source: Path, run_dir: Path, execution: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from ..review import _parse_flawfinder_units  # late-bound; see cppcheck._parse

    return _parse_flawfinder_units(source, run_dir, execution)


def _severity(raw: str, scale: str | None = None) -> str:
    value = str(raw or "").strip().lower()
    try:
        numeric = float(value)
    except ValueError:
        return {"error": "high", "warning": "medium", "note": "info", "none": "unknown"}.get(value, "unknown")
    if scale == "security-severity":
        # SARIF security-severity is a CVSS-like 0-10 scale.
        if numeric >= 9:
            return "critical"
        if numeric >= 7:
            return "high"
        if numeric >= 4:
            return "medium"
    else:
        # Flawfinder's native risk level is a 0-5 scale.
        if numeric >= 5:
            return "critical"
        if numeric >= 4:
            return "high"
        if numeric >= 3:
            return "medium"
    if numeric > 0:
        return "low"
    return "info" if numeric == 0 else "unknown"


def _canary(executable: str, root: Path) -> tuple[bool, str | None]:
    argv = [executable, "--sarif", "--minlevel=0", "--columns", "--neverignore", "--omittime", "--quiet", "--", "canary.c"]
    completed = subprocess.run(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, shell=False)
    data = json.loads(completed.stdout.decode("utf-8", errors="strict"))
    valid = completed.returncode in {0, 1} and data.get("version") == "2.1.0"
    return (True, None) if valid else (False, None)


ADAPTER = Adapter(
    name="flawfinder",
    run=_run,
    parse=_parse,
    severity=_severity,
    version_argv=lambda executable: [executable, "--version"],
    required_capabilities=("--sarif", "--minlevel", "--columns", "--neverignore"),
    canary=_canary,
    apt_package="flawfinder",
)

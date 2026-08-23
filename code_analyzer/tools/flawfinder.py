from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any, Callable

from ..process import run_process
from ..status import aggregate_units, counts
from .common import attach_artifacts, unit_outcome, utf8_validation


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
    output_event: Callable[[str, str, str], None] | None = None,
) -> dict[str, Any]:
    progress = progress or (lambda _message: None)
    unit_event = unit_event or (lambda _unit, _status, _message, _progress: None)
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
    shards = shard_files(compatible)
    units: list[dict[str, Any]] = []
    deadline = time.monotonic() + float(config["tools"]["flawfinder"]["timeout_seconds"])
    heartbeat_seconds = float(config["tools"]["flawfinder"]["heartbeat_seconds"])
    grace = float(config["run"]["termination_grace_seconds"])
    for index, paths in enumerate(shards, 1):
        name = f"shard-{index:04d}"
        if cancelled is not None and cancelled():
            units.append({"id": name, "status": "interrupted", "input_files": paths, "valid_report": False, "reason": "run interrupted", "evidence_context": "source-only", "artifacts": []})
            unit_event(name, "interrupted", "run interrupted", index / max(1, len(shards)))
            break
        directory = run_dir / "tools" / "flawfinder" / name
        directory.mkdir(parents=True, exist_ok=True)
        stdout, stderr, report = directory / "stdout.raw", directory / "stderr.raw", directory / "report.sarif"
        if time.monotonic() >= deadline:
            units.append({"id": name, "status": "unscheduled", "input_files": paths, "valid_report": False, "reason": "total budget exhausted", "evidence_context": "source-only", "artifacts": []})
            progress(f"unit {index}/{len(shards)} {name}: unscheduled (budget exhausted)")
            unit_event(name, "unscheduled", "total budget exhausted", index / max(1, len(shards)))
            continue
        progress(f"unit {index}/{len(shards)} {name}: scanning {len(paths)} files")
        unit_event(name, "started", f"scanning {len(paths)} files", (index - 1) / max(1, len(shards)))
        unit_event(name, "info", "机器输出已隐藏并保存至 report.sarif", None)
        argv = [executable, "--sarif", "--minlevel=0", "--neverignore", "--columns", "--omittime", "--quiet", "--", *paths]
        unit_timeout = max(0.001, deadline - time.monotonic())

        def beat(
            elapsed: float, unit: str = name, timeout: float = unit_timeout,
            prefix: str = f"unit {index}/{len(shards)} {name}",
        ) -> None:
            message = f"heartbeat; elapsed {elapsed:.1f}s; unit timeout {timeout:.1f}s"
            progress(f"{prefix}: {message}")
            unit_event(unit, "heartbeat", message, None)

        process = run_process(
            argv, source, stdout, stderr, unit_timeout, grace,
            heartbeat=beat, heartbeat_seconds=heartbeat_seconds, cancelled=cancelled,
            output=(
                (lambda stream, line, unit=name: output_event(unit, stream, line))
                if output_event is not None else None
            ),
            output_streams=("stderr",),
        )
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
        progress(f"unit {index}/{len(shards)} {name}: {state} in {process.duration_seconds:.2f}s")
        unit_event(name, state, f"{state} in {process.duration_seconds:.2f}s", index / max(1, len(shards)))
        if process.interrupted:
            break
    if units and units[-1]["status"] == "interrupted":
        for index in range(len(units) + 1, len(shards) + 1):
            paths = shards[index - 1]
            units.append({"id": f"shard-{index:04d}", "status": "interrupted", "input_files": paths, "valid_report": False, "reason": "run interrupted", "evidence_context": "source-only", "artifacts": []})
    attempted = {path for unit in units if "process" in unit for path in unit["input_files"]}
    analyzed = {path for unit in units if unit.get("valid_report") for path in unit["input_files"]}
    status = aggregate_units(units, applicable=bool(compatible))
    if excluded and status not in {"interrupted", "failed", "timed_out"}:
        status = "partial"
    effective_total = len(files) - len(excluded)
    return {
        "requested": True, "status": status, "units": units,
        "valid_reports": sum(bool(unit.get("valid_report")) for unit in units),
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

from __future__ import annotations

import csv
import hashlib
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from ..compile_db import splint_flags
from ..process import run_process
from ..status import aggregate_units, counts
from .adapter import Adapter, RunContext
from .common import attach_artifacts, unit_outcome

Plan = tuple[int, str, str, list[str], str]


def run(
    executable: str,
    source: Path,
    run_dir: Path,
    inventory: list[dict[str, Any]],
    filtered_db: list[dict[str, Any]],
    config: dict[str, Any],
    progress: Callable[[str], None] | None = None,
    *,
    compile_db_present: bool = False,
    cancelled: Callable[[], bool] | None = None,
    unit_event: Callable[[str, str, str, float | None], None] | None = None,
    output_event: Callable[[str, str, str], None] | None = None,
) -> dict[str, Any]:
    progress = progress or (lambda _message: None)
    unit_event = unit_event or (lambda _unit, _status, _message, _progress: None)
    c_files = [item["path"] for item in inventory if Path(item["path"]).suffix.lower() == ".c"]
    by_file: dict[str, list[dict[str, Any]]] = {}
    for entry in filtered_db:
        try:
            relative = Path(entry["file"]).resolve().relative_to(source.resolve()).as_posix()
        except ValueError:
            continue
        if relative in c_files:
            by_file.setdefault(relative, []).append(entry)

    settings = config["tools"]["splint"]
    requested_scope = settings["scope"]
    scope = "build" if requested_scope == "auto" and compile_db_present else (
        "inventory" if requested_scope == "auto" else requested_scope
    )
    selected = sorted(by_file) if scope == "build" else c_files
    not_in_build = sorted(set(c_files) - set(by_file)) if compile_db_present else []
    if compile_db_present:
        (run_dir / "inputs" / "splint-not-in-build.txt").write_text(
            "".join(path + "\n" for path in not_in_build), encoding="utf-8"
        )

    build = config["build"]
    fallback_flags = [
        *(f"-I{x}" for x in build["include"]),
        *(f"-I{x}" for x in build["system_include"]),
        *(f"-D{x}" for x in build["define"]),
        *(f"-U{x}" for x in build["undefine"]),
    ]
    raw_plans: list[tuple[str, str, list[str], str]] = []
    for relative in selected:
        entries = by_file.get(relative)
        configurations = [splint_flags(entry) for entry in entries] if entries else [list(fallback_flags)]
        for flags in configurations:
            fingerprint = hashlib.sha256((relative + "\0" + "\0".join(flags)).encode()).hexdigest()[:12]
            safe = relative.replace("/", "__").replace("\\", "__")
            safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in safe)
            raw_plans.append((
                f"{safe[:80]}-{fingerprint}", relative, flags,
                "build-aware" if entries else "source-only",
            ))
    plans: list[Plan] = [(index, *item) for index, item in enumerate(raw_plans, 1)]

    deadline = time.monotonic() + float(settings["total_timeout_seconds"])
    per_tu = float(settings["tu_timeout_seconds"])
    grace = float(config["run"]["termination_grace_seconds"])
    heartbeat_seconds = float(settings["heartbeat_seconds"])
    cancel = threading.Event()

    def is_cancelled() -> bool:
        return cancel.is_set() or (cancelled is not None and cancelled())

    def execute(plan: Plan) -> tuple[int, dict[str, Any], list[str]]:
        index, unit_id, relative, flags, evidence_context = plan
        if is_cancelled():
            unit_event(unit_id, "interrupted", "run interrupted", index / max(1, len(plans)))
            return index, _unstarted(unit_id, relative, "interrupted", "run interrupted", evidence_context), []
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            progress(f"unit {index}/{len(plans)} {relative}: unscheduled (budget exhausted)")
            unit_event(unit_id, "unscheduled", "total budget exhausted", index / max(1, len(plans)))
            return index, _unstarted(unit_id, relative, "unscheduled", "total budget exhausted", evidence_context), []
        directory = run_dir / "tools" / "splint" / unit_id
        directory.mkdir(parents=True, exist_ok=True)
        tmp = directory / "tmp"
        tmp.mkdir(exist_ok=True)
        stdout, stderr, report = directory / "stdout.raw", directory / "stderr.raw", directory / "report.csv"
        unit_timeout = min(per_tu, max(0.001, remaining))
        progress(f"unit {index}/{len(plans)} {relative}: scanning")
        unit_event(unit_id, "started", f"scanning {relative}", (index - 1) / max(1, len(plans)))
        argv = [
            executable, "+nof", "-strict", "+unixlib", "+showsummary", "+its4mostrisky", "+its4veryrisky",
            "+its4risky", "+its4moderate", "+its4low", "-tmpdir", str(tmp), "+csvoverwrite", "+csv", str(report),
            *flags, "./" + relative,
        ]

        def beat(elapsed: float) -> None:
            total_remaining = max(0.0, deadline - time.monotonic())
            message = (
                f"unit {index}/{len(plans)} {relative}: heartbeat; elapsed {elapsed:.1f}s; "
                f"unit timeout {unit_timeout:.1f}s; total budget remaining {total_remaining:.1f}s"
            )
            progress(message)
            unit_event(
                unit_id,
                "heartbeat",
                f"heartbeat; elapsed {elapsed:.1f}s; unit timeout {unit_timeout:.1f}s; "
                f"total budget remaining {total_remaining:.1f}s",
                None,
            )

        process = run_process(
            argv, source, stdout, stderr, unit_timeout, grace,
            heartbeat=beat, heartbeat_seconds=heartbeat_seconds, cancelled=is_cancelled,
            output=(
                (lambda stream, line: output_event(unit_id, stream, line))
                if output_event is not None else None
            ),
        )
        valid, csv_cells, reason = _validate_csv(report)
        text = _combined_text(stdout, stderr)
        lowered = text.lower()
        finished = "finished checking" in lowered
        fatal = any(marker in lowered for marker in ("cannot continue", "internal bug"))
        fatal |= not finished and any(marker in lowered for marker in ("parse error", "preprocessing error"))
        normal = process.exit_code in {0, 1} and finished and valid and not fatal
        state, reason = unit_outcome(
            process, valid, normal, reason,
            "Splint did not reach Finished checking" if not finished else f"unexpected exit status {process.exit_code}",
        )
        unit = {
            "id": unit_id, "status": state, "input_files": [relative], "valid_report": valid,
            "process": process.as_dict(), "reason": reason, "evidence_context": evidence_context,
        }
        attach_artifacts(unit, directory, run_dir)
        progress(f"unit {index}/{len(plans)} {relative}: {state} in {process.duration_seconds:.2f}s")
        unit_event(unit_id, state, f"{state} in {process.duration_seconds:.2f}s", index / max(1, len(plans)))
        return index, unit, csv_cells

    completed: dict[int, tuple[dict[str, Any], list[str]]] = {}
    jobs = min(int(settings["jobs"]), max(1, len(plans)))
    if jobs == 1:
        for plan in plans:
            if is_cancelled():
                cancel.set()
            index, unit, cells = execute(plan)
            completed[index] = (unit, cells)
            if unit["status"] == "interrupted":
                cancel.set()
    elif plans:
        executor = ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="splint")
        futures = {executor.submit(execute, plan): plan[0] for plan in plans}
        try:
            for future in as_completed(futures):
                if is_cancelled():
                    cancel.set()
                index, unit, cells = future.result()
                completed[index] = (unit, cells)
                if unit["status"] == "interrupted":
                    cancel.set()
        except KeyboardInterrupt:
            cancel.set()
            for future in futures:
                if not future.done():
                    future.cancel()
            for future, index in futures.items():
                if future.cancelled():
                    plan = plans[index - 1]
                    completed[index] = (_unstarted(plan[1], plan[2], "interrupted", "run interrupted", plan[4]), [])
                elif future.done():
                    try:
                        _, unit, cells = future.result()
                        completed[index] = (unit, cells)
                    except Exception:
                        plan = plans[index - 1]
                        completed[index] = (_unstarted(plan[1], plan[2], "interrupted", "run interrupted", plan[4]), [])
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

    units: list[dict[str, Any]] = []
    valid_files: set[str] = set()
    headers: set[str] = set()
    for index, unit_id, relative, _, evidence_context in plans:
        unit, cells = completed.get(index, (_unstarted(unit_id, relative, "interrupted", "run interrupted", evidence_context), []))
        units.append(unit)
        if unit.get("valid_report"):
            valid_files.add(relative)
            for item in inventory:
                if item["is_header"] and any(
                    item["path"] in cell or str((source / item["path"]).resolve()) in cell for cell in cells
                ):
                    headers.add(item["path"])

    attempted_files = {unit["input_files"][0] for unit in units if "process" in unit}
    excluded_count = len(not_in_build) if scope == "build" else 0
    effective_total = len(c_files) - excluded_count
    status = aggregate_units(units, applicable=bool(selected))
    if excluded_count and status not in {"interrupted", "failed", "timed_out"}:
        status = "partial"
    return {
        "requested": True,
        "status": status,
        "scope": scope,
        "requested_scope": requested_scope,
        "jobs": jobs,
        "not_in_build": len(not_in_build),
        "units": units,
        "valid_reports": sum(bool(unit.get("valid_report")) for unit in units),
        "coverage": {
            "metric": "tu_report_coverage", "covered": len(valid_files), "total": len(c_files),
            "attempted": len(attempted_files), "analyzed": len(valid_files), "excluded": excluded_count,
            "effective_total": effective_total,
            "ratio": len(valid_files) / effective_total if effective_total else None,
            "inventory_c_files": len(c_files), "not_in_build": len(not_in_build),
            "headers_seen_via_tu": len(headers),
        },
        "unit_counts": counts(units),
    }


def _unstarted(unit_id: str, relative: str, state: str, reason: str, evidence_context: str = "source-only") -> dict[str, Any]:
    return {
        "id": unit_id, "status": state, "input_files": [relative], "valid_report": False,
        "reason": reason, "evidence_context": evidence_context, "artifacts": [],
    }


def _validate_csv(path: Path) -> tuple[bool, list[str], str | None]:
    try:
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            return False, [], "invalid Splint CSV: report is empty"
        if "\x00" in text:
            return False, [], "invalid Splint CSV: NUL byte"
        rows = [row for row in csv.reader(text.splitlines(), strict=True) if any(cell.strip() for cell in row)]
    except (OSError, UnicodeError, csv.Error) as exc:
        return False, [], f"invalid Splint CSV: {exc}"
    if not rows or len(rows[0]) < 2:
        return False, [], "invalid Splint CSV: expected comma-separated columns"
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        return False, [], "invalid Splint CSV: inconsistent or truncated rows"
    return True, [cell for row in rows for cell in row], None


def _combined_text(*paths: Path) -> str:
    result = []
    for path in paths:
        try:
            result.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return "\n".join(result)


# --- the adapter ------------------------------------------------------------


def _run(executable: str, ctx: RunContext) -> dict[str, Any]:
    return run(
        executable, ctx.source, ctx.run_dir, ctx.inventory, ctx.compile_db.entries, ctx.config, ctx.progress,
        compile_db_present=ctx.compile_db.present, cancelled=ctx.cancelled,
        unit_event=ctx.unit_event, output_event=ctx.output_event,
    )


def _parse(source: Path, run_dir: Path, execution: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from ..review import _parse_splint_units  # late-bound; see cppcheck._parse

    return _parse_splint_units(source, run_dir, execution)


def _severity(_raw: str, _scale: str | None = None) -> str:
    # splint's own levels are not a severity ladder, and the gate treats its
    # findings as "unknown" on purpose; inventing a mapping here would give
    # them a rank they have not earned.
    return "unknown"


def _canary(executable: str, root: Path) -> tuple[bool, str | None]:
    report, tmp = root / "report.csv", root / "tmp"
    tmp.mkdir()
    argv = [executable, "+nof", "-tmpdir", str(tmp), "+csvoverwrite", "+csv", str(report), "./canary.c"]
    completed = subprocess.run(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, shell=False)
    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace").lower()
    valid = (
        completed.returncode in {0, 1} and report.is_file()
        and report.stat().st_size > 0 and "finished checking" in output
    )
    return (True, None) if valid else (False, None)


def _reported_version(text: str) -> str | None:
    match = re.search(r"^Splint\s+([0-9][^\s]*)", text, re.MULTILINE)
    return match.group(1) if match else None


ADAPTER = Adapter(
    name="splint",
    run=_run,
    parse=_parse,
    severity=_severity,
    version_argv=lambda executable: [executable, "-help", "version"],
    reported_version=_reported_version,
    help_topics=("nof", "csv", "tmpdir", "modes", "ITS4"),
    canary=_canary,
    apt_package="splint",
)

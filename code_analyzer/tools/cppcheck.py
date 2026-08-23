from __future__ import annotations

import os
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

from ..process import run_process
from ..status import aggregate_units, counts
from .common import attach_artifacts, unit_outcome


def run(
    executable: str,
    source: Path,
    run_dir: Path,
    inventory: list[dict[str, Any]],
    filtered_db: list[dict[str, Any]],
    covered: set[str],
    config: dict[str, Any],
    progress: Callable[[str], None] | None = None,
    *,
    cancelled: Callable[[], bool] | None = None,
    unit_event: Callable[[str, str, str, float | None], None] | None = None,
    output_event: Callable[[str, str, str], None] | None = None,
) -> dict[str, Any]:
    progress = progress or (lambda _message: None)
    unit_event = unit_event or (lambda _unit, _status, _message, _progress: None)
    tool_dir = run_dir / "tools" / "cppcheck"
    timeout = float(config["tools"]["cppcheck"]["timeout_seconds"])
    heartbeat_seconds = float(config["tools"]["cppcheck"]["heartbeat_seconds"])
    grace = float(config["run"]["termination_grace_seconds"])
    jobs = min(4, os.cpu_count() or 1)
    passes: list[tuple[str, list[str], list[str]]] = []
    if filtered_db:
        db_path = run_dir / "inputs" / "compile_commands.filtered.json"
        passes.append(("compile-db", [f"--project={db_path}"], sorted(covered)))
    fallback = [item["path"] for item in inventory if item["path"] not in covered]
    if fallback:
        passes.append(("fallback", [], fallback))
    units: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout
    for index, (name, pass_args, files) in enumerate(passes, 1):
        evidence_context = "build-aware" if name == "compile-db" else "source-only"
        if cancelled is not None and cancelled():
            units.append({"id": name, "status": "interrupted", "input_files": files, "valid_report": False, "reason": "run interrupted", "evidence_context": evidence_context, "artifacts": []})
            unit_event(name, "interrupted", "run interrupted", index / max(1, len(passes)))
            for later_name, _, later_files in passes[index:]:
                units.append({"id": later_name, "status": "interrupted", "input_files": later_files, "valid_report": False, "reason": "run interrupted", "evidence_context": "build-aware" if later_name == "compile-db" else "source-only", "artifacts": []})
            break
        directory = tool_dir / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "build").mkdir(exist_ok=True)
        report = directory / "report.xml"
        checkers = directory / "checkers.txt"
        stdout = directory / "stdout.raw"
        stderr = directory / "stderr.raw"
        if time.monotonic() >= deadline:
            units.append({"id": name, "status": "unscheduled", "input_files": files, "valid_report": False, "reason": "total budget exhausted", "evidence_context": evidence_context, "artifacts": []})
            progress(f"unit {index}/{len(passes)} {name}: unscheduled (budget exhausted)")
            unit_event(name, "unscheduled", "total budget exhausted", index / max(1, len(passes)))
            continue
        progress(f"unit {index}/{len(passes)} {name}: scanning {len(files)} files")
        unit_event(name, "started", f"scanning {len(files)} files", (index - 1) / max(1, len(passes)))
        argv = [
            executable, "--enable=all", "--inconclusive", "--check-level=exhaustive", "--check-library",
            "--max-ctu-depth=10", "--xml", "--xml-version=2", f"--output-file={report}",
            f"--checkers-report={checkers}", f"--cppcheck-build-dir={directory / 'build'}",
            f"--relative-paths={source.resolve()}", "--quiet", "-j", str(jobs),
        ]
        argv.extend(pass_args)
        if name == "fallback":
            argv.append("--force")
            build = config["build"]
            standard = build.get("cpp_standard") or build.get("c_standard")
            if standard:
                argv.append(f"--std={standard}")
            if build.get("cppcheck_platform"):
                argv.append(f"--platform={build['cppcheck_platform']}")
            for path in build["include"] + build["system_include"]:
                argv.append(f"-I{path}")
            for value in build["define"]:
                argv.append(f"-D{value}")
            for value in build["undefine"]:
                argv.append(f"-U{value}")
            file_list = run_dir / "inputs" / "cppcheck-fallback-files.txt"
            file_list.write_text("".join(path + "\n" for path in files), encoding="utf-8")
            argv.append(f"--file-list={file_list}")
        unit_timeout = max(0.001, deadline - time.monotonic())

        def beat(
            elapsed: float, unit: str = name, timeout: float = unit_timeout,
            prefix: str = f"unit {index}/{len(passes)} {name}",
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
        )
        valid, reason = _validate(report)
        state, reason = unit_outcome(
            process, valid, process.exit_code == 0 and valid, reason,
            f"unexpected exit status {process.exit_code}",
        )
        unit = {"id": name, "status": state, "input_files": files, "valid_report": valid, "process": process.as_dict(), "reason": reason, "evidence_context": evidence_context}
        attach_artifacts(unit, directory, run_dir)
        units.append(unit)
        progress(f"unit {index}/{len(passes)} {name}: {state} in {process.duration_seconds:.2f}s")
        unit_event(name, state, f"{state} in {process.duration_seconds:.2f}s", index / max(1, len(passes)))
        if process.interrupted:
            for later_name, _, later_files in passes[len(units):]:
                units.append({"id": later_name, "status": "interrupted", "input_files": later_files, "valid_report": False, "reason": "run interrupted", "evidence_context": "build-aware" if later_name == "compile-db" else "source-only", "artifacts": []})
            break
    attempted_files = {path for unit in units if "process" in unit for path in unit["input_files"]}
    analyzed_files = {path for unit in units if unit.get("valid_report") for path in unit["input_files"]}
    return _result(units, len(attempted_files), len(analyzed_files), len(inventory))


def _validate(path: Path) -> tuple[bool, str | None]:
    if not path.is_file():
        return False, "report.xml was not produced"
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        return False, f"invalid Cppcheck XML: {exc}"
    return (True, None) if root.tag == "results" else (False, "Cppcheck XML root is not results")


def _result(units: list[dict[str, Any]], attempted: int, analyzed: int, total: int) -> dict[str, Any]:
    return {
        "requested": True,
        "status": aggregate_units(units, applicable=bool(total)),
        "units": units,
        "valid_reports": sum(bool(unit.get("valid_report")) for unit in units),
        "coverage": {
            "metric": "input_coverage", "covered": analyzed, "total": total,
            "attempted": attempted, "analyzed": analyzed, "excluded": 0,
            "effective_total": total, "ratio": analyzed / total if total else None,
        },
        "unit_counts": counts(units),
    }

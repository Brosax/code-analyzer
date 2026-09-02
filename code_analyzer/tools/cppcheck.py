from __future__ import annotations

import os
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Sequence

from ..control import CANCELLED, RUN, SKIP_PRODUCER, SKIP_UNIT
from ..process import run_process
from ..runlog import error_excerpt
from ..status import aggregate_units, counts
from .adapter import Adapter, RunContext
from .common import announce_never_ran, attach_artifacts, output_room, unit_outcome


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
    output_budget: Any = None,
    output_event: Callable[[str, str, str], None] | None = None,
    control: Any = None,
    only_files: Sequence[str] | None = None,
    attempt: int = 1,
) -> dict[str, Any]:
    progress = progress or (lambda _message: None)
    unit_event = unit_event or (lambda *_args, **_kwargs: None)
    tool_dir = run_dir / "tools" / "cppcheck"
    timeout = float(config["tools"]["cppcheck"]["timeout_seconds"])
    heartbeat_seconds = float(config["tools"]["cppcheck"]["heartbeat_seconds"])
    grace = float(config["run"]["termination_grace_seconds"])
    jobs = min(4, os.cpu_count() or 1)
    passes: list[tuple[str, list[str], list[str]]] = []
    if only_files is not None:
        # A build-context re-run: the fallback pass again, over the same
        # files, under the patched [build], into a directory of its own.
        passes.append((f"fallback-r{attempt}", [], sorted(only_files)))
    else:
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
        facts = {"index": index, "total": len(passes), "label": name, "files": len(files)}
        action = control.checkpoint("static", "cppcheck", name) if control is not None else RUN
        if action in {SKIP_PRODUCER, SKIP_UNIT}:
            units.append({"id": name, "status": "unscheduled", "input_files": files, "valid_report": False, "reason": "skipped by operator", "evidence_context": evidence_context, "artifacts": []})
            continue
        if (cancelled is not None and cancelled()) or action == CANCELLED:
            units.append({"id": name, "status": "interrupted", "input_files": files, "valid_report": False, "reason": "run interrupted", "evidence_context": evidence_context, "artifacts": []})
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
            continue
        argv = [
            executable, "--enable=all", "--inconclusive", "--check-level=exhaustive", "--check-library",
            "--max-ctu-depth=10", "--xml", "--xml-version=2", f"--output-file={report}",
            f"--checkers-report={checkers}", f"--cppcheck-build-dir={directory / 'build'}",
            f"--relative-paths={source.resolve()}", "--quiet", "-j", str(jobs),
        ]
        argv.extend(pass_args)
        if name.startswith("fallback"):
            argv.append("--force")
            build = config["build"]
            standard = build.get("cpp_standard") or build.get("c_standard")
            if standard:
                argv.append(f"--std={standard}")
            if build.get("cppcheck_platform"):
                argv.append(f"--platform={build['cppcheck_platform']}")
            includes, defines, undefines = override_union(build)
            for path in includes:
                argv.append(f"-I{path}")
            for value in defines:
                argv.append(f"-D{value}")
            for value in undefines:
                argv.append(f"-U{value}")
            file_list = run_dir / "inputs" / ("cppcheck-fallback-files.txt" if name == "fallback" else f"cppcheck-{name}-files.txt")
            file_list.write_text("".join(path + "\n" for path in files), encoding="utf-8")
            argv.append(f"--file-list={file_list}")
        unit_timeout = max(0.001, deadline - time.monotonic())
        unit_event(name, "started", f"scanning {len(files)} files", (index - 1) / max(1, len(passes)), data={
            **facts, "argv": argv, "cwd": str(source), "timeout_seconds": round(unit_timeout, 3), "attempt": attempt,
            "evidence_context": evidence_context,
        })

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
            max_output_bytes=output_room(output_budget),
        )
        if output_budget is not None:
            output_budget.spend(process)
        valid, reason = _validate(report)
        state, reason = unit_outcome(
            process, valid, process.exit_code == 0 and valid, reason,
            f"unexpected exit status {process.exit_code}",
        )
        unit = {
            "id": name, "status": state, "input_files": files, "valid_report": valid,
            "process": process.as_dict(), "reason": reason, "evidence_context": evidence_context,
            "attempt": attempt, "diagnosis": diagnose_report(report) if valid else None,
        }
        if only_files is not None:
            unit["supersedes"] = "fallback"
        attach_artifacts(unit, directory, run_dir)
        units.append(unit)
        diagnosis = unit["diagnosis"] or {}
        unit_event(name, state, f"{state} in {process.duration_seconds:.2f}s", index / max(1, len(passes)), data={
            **facts, "duration_seconds": process.duration_seconds, "exit_code": process.exit_code,
            "reason": reason, "valid_report": valid, "attempt": attempt, "findings": diagnosis.get("findings"),
            "failure_class": diagnosis.get("category"), "diagnosis": diagnosis.get("counts"),
            "dir": str(directory.relative_to(run_dir)),
            "error_excerpt": error_excerpt(_combined_text(stdout, stderr)) if state != "completed" else None,
        })
        if process.interrupted:
            for later_name, _, later_files in passes[len(units):]:
                units.append({"id": later_name, "status": "interrupted", "input_files": later_files, "valid_report": False, "reason": "run interrupted", "evidence_context": "build-aware" if later_name == "compile-db" else "source-only", "artifacts": []})
            break
    announce_never_ran(unit_event, units, len(passes))
    attempted_files = {path for unit in units if "process" in unit for path in unit["input_files"]}
    analyzed_files = {path for unit in units if unit.get("valid_report") for path in unit["input_files"]}
    return _result(units, len(attempted_files), len(analyzed_files), len(inventory))


def override_union(build: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    """The global ``[build]`` lists plus every ``[[build.overrides]]`` entry, deduplicated.

    Cppcheck's fallback pass is one invocation over every file, so a per-path
    override cannot be applied per path here; the union is the honest
    approximation, and the order keeps the global lists first.
    """
    includes = [*build["include"], *build["system_include"]]
    defines = list(build["define"])
    undefines = list(build["undefine"])
    for override in build.get("overrides") or []:
        includes.extend(override.get("include") or [])
        includes.extend(override.get("system_include") or [])
        defines.extend(override.get("define") or [])
        undefines.extend(override.get("undefine") or [])
    return list(dict.fromkeys(includes)), list(dict.fromkeys(defines)), list(dict.fromkeys(undefines))


# Cppcheck's own ids for "I could not see the code": the counts a build-context
# diagnosis reads instead of re-parsing a 50 MB report.
DIAGNOSIS_IDS: tuple[str, ...] = ("missingInclude", "missingIncludeSystem", "preprocessorErrorDirective", "syntaxError")


def diagnose_report(path: Path) -> dict[str, Any]:
    """Count the diagnostic ids in a valid report, streaming."""
    counts_by_id = {name: 0 for name in DIAGNOSIS_IDS}
    findings = 0
    try:
        for _event, element in ET.iterparse(path, events=("end",)):
            if element.tag == "error":
                findings += 1
                identity = element.get("id", "")
                if identity in counts_by_id:
                    counts_by_id[identity] += 1
                element.clear()
    except (OSError, ET.ParseError):
        return {"category": None, "findings": findings, "counts": counts_by_id, "error": "report could not be re-read"}
    category = None
    if counts_by_id["missingInclude"] or counts_by_id["missingIncludeSystem"]:
        category = "include"
    elif counts_by_id["preprocessorErrorDirective"]:
        category = "configuration"
    elif counts_by_id["syntaxError"]:
        category = "parsing"
    return {"category": category, "findings": findings, "counts": counts_by_id}


def _combined_text(*paths: Path) -> str:
    result = []
    for path in paths:
        try:
            result.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return "\n".join(result)


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


# --- the adapter ------------------------------------------------------------


def _run(executable: str, ctx: RunContext) -> dict[str, Any]:
    return run(
        executable, ctx.source, ctx.run_dir, ctx.inventory, ctx.compile_db.entries,
        ctx.compile_db.covered_set, ctx.config, ctx.progress,
        cancelled=ctx.cancelled, unit_event=ctx.unit_event, output_event=ctx.output_event,
        output_budget=ctx.output_budget, control=ctx.control, attempt=ctx.attempt,
    )


def _rerun(executable: str, ctx: RunContext, files: Sequence[str]) -> dict[str, Any]:
    return run(
        executable, ctx.source, ctx.run_dir, ctx.inventory, ctx.compile_db.entries,
        ctx.compile_db.covered_set, ctx.config, ctx.progress,
        cancelled=ctx.cancelled, unit_event=ctx.unit_event, output_event=ctx.output_event,
        output_budget=ctx.output_budget, control=ctx.control, only_files=list(files), attempt=ctx.attempt,
    )


def reconfigurable(record: dict[str, Any]) -> list[str]:
    """The fallback pass, when its report says headers were missing."""
    from .common import effective_units

    for unit in effective_units(record.get("units") or []):
        counts = (unit.get("diagnosis") or {}).get("counts") or {}
        if str(unit.get("id", "")).startswith("fallback") and unit.get("valid_report") and (
            counts.get("missingInclude") or counts.get("missingIncludeSystem")
        ):
            return [str(unit["id"])]
    return []


def _parse(source: Path, run_dir: Path, execution: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    # Imported here, not at module scope: parsing a native report produces
    # review rows, so it lives in the review layer, and that layer imports this
    # package.  Late binding keeps the dependency one-way.
    from ..review import _parse_cppcheck_units

    return _parse_cppcheck_units(source, run_dir, execution)


def _severity(raw: str, _scale: str | None = None) -> str:
    return {
        "error": "high", "warning": "medium", "style": "low", "performance": "low",
        "portability": "low", "information": "info", "debug": "info",
    }.get(str(raw or "").strip().lower(), "unknown")


def _canary(executable: str, root: Path) -> tuple[bool, str | None]:
    report, checkers, files, build = root / "report.xml", root / "checkers.txt", root / "files.txt", root / "build"
    files.write_text("canary.c\n", encoding="utf-8")
    build.mkdir()
    argv = [
        executable, "--xml", "--xml-version=2", f"--output-file={report}",
        f"--checkers-report={checkers}", f"--cppcheck-build-dir={build}",
        "--check-level=exhaustive", "--check-library", f"--file-list={files}", "--quiet",
    ]
    completed = subprocess.run(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, shell=False)
    valid = completed.returncode in {0, 1} and report.is_file() and ET.parse(report).getroot().tag == "results"
    return (True, None) if valid else (False, None)


ADAPTER = Adapter(
    name="cppcheck",
    run=_run,
    parse=_parse,
    severity=_severity,
    version_argv=lambda executable: [executable, "--version"],
    required_capabilities=(
        "--xml-version", "--output-file", "--project", "--file-list",
        "--check-level", "--check-library", "--checkers-report", "--cppcheck-build-dir",
    ),
    canary=_canary,
    apt_package="cppcheck",
    rerun=_rerun,
    reconfigurable=reconfigurable,
)

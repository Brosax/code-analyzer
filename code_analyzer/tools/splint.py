from __future__ import annotations

import fnmatch
import hashlib
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from ..compile_db import splint_flags
from ..process import run_process
from ..runlog import error_excerpt
from ..status import aggregate_units, counts
from .adapter import Adapter, RunContext
from .common import attach_artifacts, is_diagnostic, output_room, unit_outcome
from .splint_csv import splint_rows

Plan = tuple[int, str, str, list[str], str]

# The predefined check modes Splint 3.1.2 answers to (`splint -help modes`).
MODES: tuple[str, ...] = ("strict", "checks", "standard", "weak")

# Why a unit did not analyse anything, in decision order.  A word, not a
# sentence: the sentence is `explain_failure`, the word is what a re-run,
# the flow panel and the build-context diagnosis branch on.  A unit the
# runner killed (timed out, interrupted) carries no class: it did not fail
# for an analysis reason, and its status word already says what happened.
FAILURE_CLASSES: tuple[str, ...] = ("csv", "include", "configuration", "parsing", "tool")

# `\s*`, not `\s+`: the log fallback joins wrapped lines with no space so a
# header name split mid-word survives, and the wrap can fall right after
# "include file".  The name still ends at the next space, `>` or quote.
_MISSING_INCLUDE = re.compile(r"Cannot find include file\s*<?([^\s>\"]+)>?", re.I)
_ERROR_DIRECTIVE = re.compile(r"#error\s+(.+)")
# `(?!s)`: Splint's own hint, "(For help on parse errors, see ...)", follows
# every parse error on the same line and must not count as a second one.
_PARSE_ERROR = re.compile(r"parse error(?!s)", re.I)
# Sentence-anchored: the hint under every reserved-name warning ("External
# name is reserved for system use ...") would otherwise count it twice.
_RESERVED_NAME = re.compile(r"\bName .+? is (?:in the implementation name space|reserved for)", re.I)
_RESERVED_FLAGS = ("isoreserved", "isoreservedinternal")
MAX_MISSING_INCLUDES = 200
MAX_NAMED_INCLUDES = 20


def option_flags(settings: Mapping[str, Any]) -> list[str]:
    """The typed ``[tools.splint]`` options as Splint flags.

    Every spelling here was checked against ``splint -help <flag>`` on 3.1.2.
    The set is closed on purpose: README says arbitrary analyzer arguments are
    unavailable, and a build-context proposal may only pick from this list.
    """
    mode = str(settings.get("mode") or "strict")
    flags = [f"-{mode}"]
    if settings.get("report_reserved_names", True) is False:
        flags.append("-isoreserved")
    if settings.get("try_to_recover"):
        flags.append("+trytorecover")
    if settings.get("skip_system_headers"):
        flags.append("-skipsysheaders")
    directories = [str(item) for item in settings.get("system_dirs") or []]
    if directories:
        flags.extend(["-systemdirs", ":".join(directories)])
    return flags


def matching_overrides(build: Mapping[str, Any], relative: str) -> list[dict[str, Any]]:
    """The ``[[build.overrides]]`` entries whose ``match`` glob names this file."""
    return [
        dict(item) for item in build.get("overrides") or []
        if isinstance(item, Mapping) and fnmatch.fnmatchcase(relative, str(item.get("match", "")))
    ]


def build_flags(build: Mapping[str, Any], relative: str | None = None) -> list[str]:
    """The ``[build]`` flags a source-only translation unit receives.

    The global lists come first; every matching override appends its own, in
    the order the overrides are written, so a later override can add a more
    specific directory after a general one.
    """
    include = list(build["include"])
    system = list(build["system_include"])
    define = list(build["define"])
    undefine = list(build["undefine"])
    if relative is not None:
        for override in matching_overrides(build, relative):
            include.extend(override.get("include") or [])
            system.extend(override.get("system_include") or [])
            define.extend(override.get("define") or [])
            undefine.extend(override.get("undefine") or [])
    return [
        *(f"-I{x}" for x in include),
        *(f"-I{x}" for x in system),
        *(f"-D{x}" for x in define),
        *(f"-U{x}" for x in undefine),
    ]


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
    output_budget: Any = None,
    output_event: Callable[[str, str, str], None] | None = None,
) -> dict[str, Any]:
    progress = progress or (lambda _message: None)
    unit_event = unit_event or (lambda *_args, **_kwargs: None)
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
    options = option_flags(settings)
    raw_plans: list[tuple[str, str, list[str], str]] = []
    for relative in selected:
        entries = by_file.get(relative)
        configurations = [splint_flags(entry) for entry in entries] if entries else [build_flags(build, relative)]
        for flags in configurations:
            # The options are part of the identity: a re-run with a different
            # mode or a reserved-name switch must land in its own directory.
            fingerprint = hashlib.sha256(
                (relative + "\0" + "\0".join([*options, *flags])).encode()
            ).hexdigest()[:12]
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

    total = max(1, len(plans))

    def execute(plan: Plan) -> tuple[int, dict[str, Any], list[str]]:
        index, unit_id, relative, flags, evidence_context = plan
        if is_cancelled():
            # Announced once for the whole batch after the pool drains.
            return index, _unstarted(unit_id, relative, "interrupted", "run interrupted", evidence_context), []
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return index, _unstarted(unit_id, relative, "unscheduled", "total budget exhausted", evidence_context), []
        directory = run_dir / "tools" / "splint" / unit_id
        directory.mkdir(parents=True, exist_ok=True)
        tmp = directory / "tmp"
        tmp.mkdir(exist_ok=True)
        stdout, stderr, report = directory / "stdout.raw", directory / "stderr.raw", directory / "report.csv"
        unit_timeout = min(per_tu, max(0.001, remaining))
        argv = [
            executable, "+nof", *options, "+unixlib", "+showsummary", "+its4mostrisky", "+its4veryrisky",
            "+its4risky", "+its4moderate", "+its4low", "-tmpdir", str(tmp), "+csvoverwrite", "+csv", str(report),
            *flags, "./" + relative,
        ]
        facts = {"index": index, "total": total, "label": relative, "path": relative}
        unit_event(unit_id, "started", "scanning", (index - 1) / total, data={
            **facts, "argv": argv, "cwd": str(source), "timeout_seconds": round(unit_timeout, 3),
            "attempt": 1, "evidence_context": evidence_context,
        })

        def beat(elapsed: float) -> None:
            total_remaining = max(0.0, deadline - time.monotonic())
            unit_event(
                unit_id,
                "heartbeat",
                f"heartbeat; elapsed {elapsed:.1f}s; unit timeout {unit_timeout:.1f}s; "
                f"total budget remaining {total_remaining:.1f}s",
                None,
                data={
                    **facts, "elapsed": round(elapsed, 1), "timeout_seconds": round(unit_timeout, 1),
                    "remaining_budget_seconds": round(total_remaining, 1),
                },
            )

        process = run_process(
            argv, source, stdout, stderr, unit_timeout, grace,
            heartbeat=beat, heartbeat_seconds=heartbeat_seconds, cancelled=is_cancelled,
            output=(
                (lambda stream, line: output_event(unit_id, stream, line))
                if output_event is not None else None
            ),
            max_output_bytes=output_room(output_budget),
        )
        if output_budget is not None:
            output_budget.spend(process)
        valid, rows, csv_cells, recovered, reason = _validate_csv(report)
        text = _combined_text(stdout, stderr)
        lowered = text.lower()
        finished = "finished checking" in lowered
        fatal = any(marker in lowered for marker in ("cannot continue", "internal bug"))
        fatal |= not finished and any(marker in lowered for marker in ("parse error", "preprocessing error"))
        normal = process.exit_code in {0, 1} and finished and valid and not fatal
        diagnosis = diagnose(text, rows)
        diagnosis["csv_recovered_rows"] = recovered
        killed = process.timed_out or process.interrupted
        failure_class = None if normal or killed else classify_failure(valid, reason, diagnosis, lowered)
        diagnosis["category"] = failure_class
        state, reason = unit_outcome(
            process, valid, normal, reason,
            explain_failure(failure_class, diagnosis, finished, process.exit_code),
        )
        missing = diagnosis["missing_includes"]
        unit = {
            "id": unit_id, "status": state, "input_files": [relative], "valid_report": valid,
            "process": process.as_dict(), "reason": reason, "evidence_context": evidence_context,
            # "Finished checking" is the discriminator: a preprocessing death
            # never reaches it, and a unit that did may still carry only
            # preproc rows (a #warning), which is an analysis all the same.
            "analysis_reached": finished and not fatal,
            "failure_class": failure_class,
            "missing_includes": missing[:MAX_NAMED_INCLUDES],
            "missing_includes_more": max(0, len(missing) - MAX_NAMED_INCLUDES),
            "csv_recovered_rows": recovered,
            "attempt": 1,
            "diagnosis": diagnosis,
        }
        attach_artifacts(unit, directory, run_dir)
        unit_event(unit_id, state, f"{state} in {process.duration_seconds:.2f}s", index / total, data={
            **facts, "duration_seconds": process.duration_seconds, "exit_code": process.exit_code,
            "reason": reason, "failure_class": failure_class, "missing_includes": missing[:MAX_NAMED_INCLUDES],
            "analysis_reached": unit["analysis_reached"], "valid_report": valid, "attempt": 1,
            "csv_recovered_rows": recovered, "dir": str(directory.relative_to(run_dir)),
            "error_excerpt": error_excerpt(text) if state != "completed" else None,
        })
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
    reached_files: set[str] = set()
    headers: set[str] = set()
    header_forms = header_path_forms(inventory, source)
    for index, unit_id, relative, _, evidence_context in plans:
        unit, cells = completed.get(index, (_unstarted(unit_id, relative, "interrupted", "run interrupted", evidence_context), []))
        units.append(unit)
        if unit.get("valid_report"):
            valid_files.add(relative)
            credit_headers(headers, header_forms, cells)
        if unit.get("analysis_reached"):
            reached_files.add(relative)
    announce_batches(unit_event, plans_by_index={plan[0]: plan for plan in plans}, units=units, total=total)

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
            # A parseable report is not an analysis: a unit that died at its
            # first #include still writes a valid CSV of preprocessing rows
            # and never prints "Finished checking".  `ratio` keeps its
            # historical meaning (and the exit code with it); this pair says
            # how many units Splint actually checked.
            "analysis_reached": len(reached_files),
            "analysis_ratio": len(reached_files) / effective_total if effective_total else None,
            "inventory_c_files": len(c_files), "not_in_build": len(not_in_build),
            "headers_seen_via_tu": len(headers),
        },
        "unit_counts": counts(units),
    }


def announce_batches(
    unit_event: Callable[..., None], *, plans_by_index: Mapping[int, Plan], units: Sequence[Mapping[str, Any]],
    total: int,
) -> None:
    """One event per (state, reason) for the units that never ran.

    A budget that runs out with a thousand units left used to emit a thousand
    rows; the manifest still records every unit, the stream records the fact.
    """
    batches: dict[tuple[str, str], list[int]] = {}
    for index, unit in enumerate(units, 1):
        if "process" in unit or unit.get("status") not in {"unscheduled", "interrupted"}:
            continue
        batches.setdefault((str(unit["status"]), str(unit.get("reason") or "")), []).append(index)
    for (state, reason), indexes in batches.items():
        unit_event(
            None, state, f"{len(indexes)} unit(s) {state}: {reason}", max(indexes) / max(1, total),
            data={"count": len(indexes), "reason": reason, "first_index": min(indexes), "last_index": max(indexes), "total": total},
            phase="units",
        )


def _unstarted(unit_id: str, relative: str, state: str, reason: str, evidence_context: str = "source-only") -> dict[str, Any]:
    return {
        "id": unit_id, "status": state, "input_files": [relative], "valid_report": False,
        "reason": reason, "evidence_context": evidence_context, "artifacts": [],
        "analysis_reached": False, "failure_class": None, "attempt": 1,
    }


# --- what went wrong, in words ----------------------------------------------


def _unwrap(text: str, joiner: str) -> str:
    """Join Splint's four-space continuation lines back onto their message.

    Splint wraps at 80 columns and indents the rest, sometimes mid-word
    (``trusted-fir`` / ``mware-m``).  Callers choose the joiner: an empty one
    restores a split identifier, a space restores prose.
    """
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("    ") and lines:
            lines[-1] += joiner + line.strip()
        else:
            lines.append(line)
    return "\n".join(lines)


def _ordered_unique(values: Sequence[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return list(seen)


def diagnose(text: str, rows: Sequence[Sequence[str]]) -> dict[str, Any]:
    """Aggregate one unit's output into the facts a reconfiguration needs.

    The CSV rows are preferred over the logs because their text is not
    wrapped; the logs are the fallback for a unit whose CSV never got written.
    Everything here is counts and identifiers -- never a source line -- so it
    can travel into the manifest, the flow panel and a model prompt as-is.
    """
    header = [cell.strip().lower() for cell in rows[0]] if rows else []
    flag_column = header.index("flag name") if "flag name" in header else None
    text_column = header.index("warning text") if "warning text" in header else None
    messages = [row[text_column] for row in rows[1:] if text_column is not None and len(row) > text_column]
    flag_names = [row[flag_column] for row in rows[1:] if flag_column is not None and len(row) > flag_column]
    joined = "\n".join(messages)
    missing = _ordered_unique(_MISSING_INCLUDE.findall(joined))
    if not missing:
        missing = _ordered_unique(_MISSING_INCLUDE.findall(_unwrap(text, "")))
    prose = _unwrap(text, " ")
    directives = _ordered_unique(
        [item.strip()[:200] for item in _ERROR_DIRECTIVE.findall(joined + "\n" + prose)]
    )
    parse_errors = len(_PARSE_ERROR.findall(prose))
    reserved = sum(1 for name in flag_names if name.strip().lower() in _RESERVED_FLAGS)
    if not flag_names:
        reserved = len(_RESERVED_NAME.findall(prose))
    first_error = next(
        (line.strip()[:300] for line in [*messages, *prose.splitlines()] if is_diagnostic(line)), "",
    )
    return {
        "category": None,
        "first_error": first_error,
        "missing_includes": missing[:MAX_MISSING_INCLUDES],
        "error_directives": directives[:20],
        "parse_errors": parse_errors,
        "reserved_name_warnings": reserved,
        "preproc_only": bool(flag_names) and all(name.strip().lower() == "preproc" for name in flag_names),
        "csv_recovered_rows": 0,
    }


def classify_failure(valid: bool, csv_error: str | None, diagnosis: Mapping[str, Any], lowered: str) -> str:
    """One word for why the unit analysed nothing; see FAILURE_CLASSES."""
    if not valid and csv_error:
        return "csv"
    if diagnosis["missing_includes"]:
        return "include"
    if diagnosis["error_directives"]:
        return "configuration"
    if diagnosis["parse_errors"] or "cannot continue" in lowered or "parse error" in lowered:
        return "parsing"
    return "tool"


def explain_failure(
    failure_class: str | None, diagnosis: Mapping[str, Any], finished: bool, exit_code: int | None
) -> str:
    """The human sentence for a unit that did not complete."""
    if failure_class == "include":
        names = list(diagnosis["missing_includes"])
        shown = ", ".join(names[:5]) + (f", …(+{len(names) - 5})" if len(names) > 5 else "")
        return f"preprocessing failed: {len(names)} missing include(s): {shown}"
    if failure_class == "configuration":
        return f"preprocessing failed: #error {diagnosis['error_directives'][0]}"[:300]
    if failure_class == "parsing":
        first = diagnosis.get("first_error") or ""
        return f"parse error after preprocessing: {first}"[:300] if first else "Splint could not parse the translation unit"
    if not finished:
        return "Splint did not reach Finished checking"
    return f"unexpected exit status {exit_code}"


def header_path_forms(
    inventory: Sequence[Mapping[str, Any]], source: Path
) -> tuple[tuple[str, str], ...]:
    """Both spellings of every header path, resolved exactly once.

    splint names an included header either as the path it was given or as an
    absolute one, so a match has to be tried both ways.  Neither form depends
    on the unit being examined, and resolving inside the unit loop is what made
    header attribution quadratic: on trusted-firmware-m that is 1588 units by
    2335 headers -- 3.7 million filesystem calls -- and the run sat at 94% CPU
    for 42 minutes *after* every unit had already been scanned, on course for
    255 minutes.
    """
    return tuple(
        (str(item["path"]), str((source / str(item["path"])).resolve()))
        for item in inventory if item.get("is_header")
    )


def credit_headers(
    headers: set[str], header_forms: Sequence[tuple[str, str]], cells: Sequence[str]
) -> None:
    """Record the headers one unit's report names, in place.

    One haystack per unit rather than one pass per header, and a header already
    credited is never searched for again.  Joining on a newline cannot invent a
    match that scanning the cells separately would miss: no path contains one.
    """
    if not cells:
        return
    blob = "\n".join(cells)
    for relative_header, absolute_header in header_forms:
        if relative_header in headers:
            continue
        if relative_header in blob or absolute_header in blob:
            headers.add(relative_header)


def _validate_csv(path: Path) -> tuple[bool, list[list[str]], list[str], int, str | None]:
    """Read the report through the shared reader: ``(valid, rows, cells, recovered, reason)``."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return False, [], [], 0, f"invalid Splint CSV: {exc}"
    rows, recovered, error = splint_rows(text)
    if error is not None:
        return False, [], [], 0, error
    return True, rows, [cell for row in rows for cell in row], recovered, None


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
        unit_event=ctx.unit_event, output_event=ctx.output_event, output_budget=ctx.output_budget,
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

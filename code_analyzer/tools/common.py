from __future__ import annotations

import codecs
import hashlib
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..events import EVENTS_FILE

# Where the runner's narrative log lives, relative to the run directory; the
# writer is runlog.RunLogger, named here so the artifact index can skip it
# without importing the writer.
RUN_LOG_FILE = "logs/runner.log"

# The vocabulary of analyzer *diagnostics* -- lines that say the tool could not
# do its job, as opposed to findings about the code.  Shared by the review
# layer (which files them apart from findings) and the adapters (which use
# them to say why a unit analysed nothing), so both agree on what a
# diagnostic is.
_DIAGNOSTIC = re.compile(
    r"parse.?error|syntax.?error|preprocess(?:or|ing)?(?:.?error)?|cannot (?:continue|parse)|internal.?(?:bug|error)|"
    r"cannot (?:find|open|read).*include|include file .*not found|missing.?include|configuration.?error|"
    r"unrecognized (?:option|flag|identifier)|unknown option|no valid configuration",
    re.I,
)
_FATAL = re.compile(r"fatal|parse.?error|syntax.?error|cannot (?:continue|parse)|internal.?(?:bug|error)", re.I)


def is_diagnostic(value: str) -> bool:
    return bool(_DIAGNOSTIC.search(value))


def is_fatal(value: str) -> bool:
    return bool(_FATAL.search(value))


def diagnostic_category(value: str) -> str:
    if re.search(r"parse|syntax|cannot continue|internal|unrecognized identifier", value, re.I):
        return "parsing"
    if re.search(r"include", value, re.I):
        return "include"
    if re.search(r"preprocess|configuration|macro|option|flag", value, re.I):
        return "configuration"
    return "tool"


def utf8_validation(path: Path, chunk_size: int = 1024 * 1024) -> tuple[bool, dict[str, Any] | None]:
    """Validate UTF-8 without loading a potentially large source file in memory."""
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    offset = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(chunk_size):
                pending = decoder.getstate()[0]
                try:
                    decoder.decode(chunk, final=False)
                except UnicodeDecodeError as exc:
                    return False, {
                        "byte_offset": offset - len(pending) + exc.start,
                        "reason": str(exc),
                    }
                offset += len(chunk)
            try:
                pending = decoder.getstate()[0]
                decoder.decode(b"", final=True)
            except UnicodeDecodeError as exc:
                return False, {
                    "byte_offset": offset - len(pending) + exc.start,
                    "reason": str(exc),
                }
    except OSError as exc:
        return False, {"byte_offset": None, "reason": str(exc)}
    return True, None


# How a re-run's outcome ranks against the unit it would replace.
UNIT_RANK: dict[str, int] = {
    "completed": 3, "partial": 2, "timed_out": 1, "failed": 1, "unscheduled": 0, "interrupted": 0,
}


def effective_units(units: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The units that stand: every unit minus those a later attempt superseded."""
    return [dict(unit) for unit in units if not unit.get("superseded_by")]


def merge_attempt(previous: dict[str, Any], rerun: dict[str, Any], *, attempt: int) -> dict[str, Any]:
    """Fold a re-run's units into a tool record without touching the old ones.

    Every previous unit stays, verbatim; each re-run unit is appended with
    its attempt number and, when it did at least as well as the unit it
    re-ran (``UNIT_RANK``, ties broken by ``analysis_reached``), the old unit
    is marked ``superseded_by`` it.  A worse re-run is kept as evidence but
    supersedes nothing.  Status, coverage and counts are recomputed over the
    effective set, so the exit code follows what actually stands.
    """
    from ..status import aggregate_units, counts

    record = dict(previous)
    units = [dict(unit) for unit in previous.get("units") or []]
    by_file: dict[str, dict[str, Any]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    for unit in units:
        if unit.get("superseded_by"):
            continue
        by_id[str(unit.get("id"))] = unit
        files = unit.get("input_files") or []
        if len(files) == 1:
            by_file[str(files[0])] = unit
    for new in rerun.get("units") or []:
        new = dict(new)
        new["attempt"] = attempt
        files = new.get("input_files") or []
        # An adapter that re-ran a many-file unit names what it re-ran; a
        # one-file unit is matched by its file.
        old = by_id.get(str(new.get("supersedes"))) if new.get("supersedes") else None
        if old is None and len(files) == 1:
            old = by_file.get(str(files[0]))
        if old is not None:
            better = UNIT_RANK.get(str(new.get("status")), 0) > UNIT_RANK.get(str(old.get("status")), 0)
            same = UNIT_RANK.get(str(new.get("status")), 0) == UNIT_RANK.get(str(old.get("status")), 0)
            if better or (same and bool(new.get("analysis_reached")) >= bool(old.get("analysis_reached"))):
                old["superseded_by"] = new["id"]
                new["supersedes"] = old["id"]
                by_file[str(files[0])] = new
            else:
                new["superseded_by"] = old["id"]
                new["supersedes"] = old["id"]
        units.append(new)
    effective = [unit for unit in units if not unit.get("superseded_by")]
    coverage = dict(previous.get("coverage") or {})
    valid_files = {unit["input_files"][0] for unit in effective if unit.get("valid_report") and unit.get("input_files")}
    reached_files = {unit["input_files"][0] for unit in effective if unit.get("analysis_reached") and unit.get("input_files")}
    attempted = {unit["input_files"][0] for unit in effective if "process" in unit and unit.get("input_files")}
    effective_total = coverage.get("effective_total") or len(effective) or None
    coverage.update({
        "covered": len(valid_files), "analyzed": len(valid_files), "attempted": len(attempted),
        "ratio": len(valid_files) / effective_total if effective_total else None,
    })
    if "analysis_reached" in coverage:
        coverage.update({
            "analysis_reached": len(reached_files),
            "analysis_ratio": len(reached_files) / effective_total if effective_total else None,
        })
    tally = counts(effective)
    tally["superseded"] = sum(1 for unit in units if unit.get("superseded_by"))
    record.update({
        "units": units, "status": aggregate_units(effective, applicable=bool(effective)),
        "valid_reports": sum(bool(unit.get("valid_report")) for unit in effective),
        "coverage": coverage, "unit_counts": tally, "attempts": attempt,
    })
    return record


def announce_never_ran(unit_event: Any, units: Sequence[Mapping[str, Any]], total: int) -> None:
    """One event per (status, reason) for the units that never ran.

    A budget that runs out with a thousand units left used to emit a thousand
    rows; the manifest still records every unit, the stream records the fact.
    """
    batches: dict[tuple[str, str], list[int]] = {}
    for index, unit in enumerate(units, 1):
        if "process" in unit or unit.get("status") not in {"unscheduled", "interrupted", "skipped"}:
            continue
        batches.setdefault((str(unit["status"]), str(unit.get("reason") or "")), []).append(index)
    for (state, reason), indexes in batches.items():
        unit_event(
            None, state, f"{len(indexes)} unit(s) {state}: {reason}", max(indexes) / max(1, total),
            data={
                "count": len(indexes), "reason": reason, "first_index": min(indexes), "last_index": max(indexes),
                "total": total,
            },
            phase="units",
        )


def output_room(budget: Any) -> int:
    """Bytes this invocation may store, from the run-level budget.

    ``None`` means no run-level budget (a direct adapter call in a test, or a
    caller that does not care), in which case ``run_process``'s own per-call
    ceiling is the only limit -- exactly the behaviour before the budget
    existed.
    """
    from ..process import MAX_OUTPUT_BYTES

    return MAX_OUTPUT_BYTES if budget is None else min(MAX_OUTPUT_BYTES, budget.remaining())


def unit_outcome(
    process: Any, valid: bool, succeeded: bool, reason: str | None, failure_reason: str
) -> tuple[str, str | None]:
    """Shared per-unit status ladder for every analyzer adapter."""
    if process.interrupted:
        return "interrupted", _with_truncation(reason, process)
    if process.timed_out:
        return ("partial" if valid else "timed_out"), _with_truncation(reason, process)
    if succeeded:
        return "completed", _with_truncation(reason, process)
    return ("partial" if valid else "failed"), _with_truncation(reason or failure_reason, process)


def _with_truncation(reason: str | None, process: Any) -> str | None:
    """Name the output ceiling when it is why a report will not parse.

    flawfinder's native report *is* its stdout, so a tool that ran past the
    ceiling produces a JSON parse error whose real cause is invisible.  The
    number is already in ``ProcessResult``; without this it has no reader, and
    the unit's reason says "invalid report" rather than what happened.
    """
    dropped = {
        stream: count for stream, count in (getattr(process, "truncated_bytes", None) or {}).items()
        if isinstance(count, int) and count > 0
    }
    if not dropped:
        return reason
    detail = "; ".join(f"{count} byte(s) of {stream} dropped at the output ceiling" for stream, count in sorted(dropped.items()))
    return f"{reason}; {detail}" if reason else detail


def artifact(path: Path, run_dir: Path, chunk_size: int = 1024 * 1024) -> dict:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
            size += len(chunk)
    return {
        "path": path.relative_to(run_dir).as_posix(),
        "size": size,
        "sha256": digest.hexdigest(),
    }


def artifact_index(
    run_dir: Path, cache: dict[str, tuple[int, int, dict[str, Any]]] | None = None
) -> list[dict[str, Any]]:
    """Index evidence files under a report directory.

    Skips the manifest and writer temporaries (both the runner's and the
    recovery command's), the two run-level logs (``events.jsonl`` and
    ``logs/runner.log`` are still being appended to after the final index is
    taken -- the last line of each is the run's own verdict -- so their hash
    could never be verified) and the per-unit analyzer scratch directories
    (cppcheck ``build/``, splint ``tmp/``), which are caches, not evidence.
    Both logs still travel in the shareable export, as of the moment it was
    made.  The optional cache avoids re-hashing files whose size and mtime are
    unchanged between successive index rebuilds within one run.
    """
    result = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in {"manifest.json", ".manifest.json.tmp"} or path.name.startswith(".recover-"):
            continue
        relative = path.relative_to(run_dir)
        if relative.as_posix() in {EVENTS_FILE, RUN_LOG_FILE}:
            continue
        parts = relative.parts
        if len(parts) >= 5 and parts[0] == "tools" and parts[3] in {"build", "tmp"}:
            continue
        if cache is None:
            result.append(artifact(path, run_dir))
            continue
        key = relative.as_posix()
        stat = path.stat()
        cached = cache.get(key)
        if cached is not None and cached[0] == stat.st_size and cached[1] == stat.st_mtime_ns:
            result.append(cached[2])
            continue
        item = artifact(path, run_dir)
        cache[key] = (stat.st_size, stat.st_mtime_ns, item)
        result.append(item)
    return result


def attach_artifacts(unit: dict, directory: Path, run_dir: Path) -> None:
    unit["artifacts"] = [artifact(path, run_dir) for path in sorted(directory.iterdir()) if path.is_file()]

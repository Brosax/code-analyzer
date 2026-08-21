"""Scan-unit planning and coverage accounting (design doc 4.5, 5.6, 9.2).

One invariant governs this module:

    every byte of every in-scope file lands in exactly one scan unit.

Depth-0 regions no function claimed become ``module-scope`` units; whatever
the parser could not classify becomes a ``raw-span`` unit.  Nothing is
dropped, because the coverage denominator is only honest if the plan covers
the whole tree — a risk tier lowers the effort a unit gets, never whether it
is planned at all.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .index import (
    LOW_CONFIDENCE,
    Parser,
    build_index,
    decode_source,
    line_of,
    line_starts,
    source_text,
)
from .risk import RISK_TIERS, RiskProfile, classify, profile_from_config

UNIT_KINDS: tuple[str, ...] = ("function", "module-scope", "raw-span")

_IDENT = re.compile(r"[A-Za-z_]\w*")

# A module-scope or raw span longer than this is split at a line boundary:
# one unit has to fit in a prompt alongside its context.
MAX_UNIT_BYTES = 16384

# Context lists are bounded here as well as in the prompt builder, so that
# llm/index.json stays a plan rather than a copy of the repository.
MAX_CONTEXT_NAMES = 32
MAX_CALLEES = 64

_UNSCANNED_REASONS: tuple[str, ...] = (
    "unscheduled", "failed", "timed_out", "interrupted", "no_result",
    "parse_confidence_low", "unreadable",
)


def build_plan(
    source: Path,
    inventory: Sequence[dict[str, Any]],
    *,
    config: Mapping[str, Any] | None = None,
    parser: Parser | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Index the tree and plan its scan units.  This is ``llm/index.json``."""
    profile = profile_from_config(config)
    index = build_index(source, inventory, parser=parser, cancelled=cancelled)
    units = plan_units(index, source, profile=profile)
    plan = {
        **index,
        "units": units,
        "risk": {
            "profile": profile.profile,
            "min_tier": profile.min_tier,
            "overrides": [f"{pattern}={tier}" for pattern, tier in profile.overrides],
        },
    }
    plan["coverage"] = coverage_report(plan)
    return plan


def plan_units(
    index: Mapping[str, Any], source: Path, *, profile: RiskProfile | None = None
) -> list[dict[str, Any]]:
    """Tile every indexed file with scan units, in file then offset order."""
    profile = profile or RiskProfile()
    units: list[dict[str, Any]] = []
    for path in sorted(index.get("files", {})):
        record = index["files"][path]
        if not record.get("readable", True):
            continue
        try:
            raw = decode_source((source / path).read_bytes())
        except OSError:
            continue
        starts = line_starts(raw)
        ordinals: dict[tuple[str, str], int] = {}
        for kind, start, end, symbol in _segments(record, raw):
            for begin, stop in _chunks(raw, start, end, kind):
                units.append(
                    _unit(index, record, raw, starts, ordinals, kind, begin, stop, symbol, profile)
                )
    return units


def unit_source(source: Path, unit: Mapping[str, Any]) -> str:
    """Read one unit's own source, decoded for a model rather than for offsets."""
    with (source / unit["path"]).open("rb") as handle:
        handle.seek(int(unit["start_byte"]))
        return source_text(handle.read(int(unit["end_byte"]) - int(unit["start_byte"])))


def coverage_gaps(plan: Mapping[str, Any]) -> dict[str, dict[str, list[list[int]]]]:
    """Bytes not claimed by exactly one unit.  Empty means the plan is complete.

    This is the executable form of the completeness invariant; callers and
    tests assert it rather than trusting the segmentation.
    """
    problems: dict[str, dict[str, list[list[int]]]] = {}
    by_path: dict[str, list[tuple[int, int]]] = {}
    for unit in plan.get("units", ()):
        by_path.setdefault(unit["path"], []).append((int(unit["start_byte"]), int(unit["end_byte"])))
    for path, record in sorted(plan.get("files", {}).items()):
        if not record.get("readable", True):
            continue
        size = int(record.get("size", 0))
        spans = sorted(by_path.get(path, ()))
        gaps: list[list[int]] = []
        overlaps: list[list[int]] = []
        cursor = 0
        for start, end in spans:
            if start > cursor:
                gaps.append([cursor, start])
            elif start < cursor:
                overlaps.append([start, min(cursor, end)])
            cursor = max(cursor, end)
        if cursor < size:
            gaps.append([cursor, size])
        if cursor > size:
            overlaps.append([size, cursor])
        if gaps or overlaps:
            problems[path] = {"gaps": gaps, "overlaps": overlaps}
    return problems


def coverage_report(
    plan: Mapping[str, Any],
    results: Iterable[Mapping[str, Any]] = (),
    *,
    scanners: Sequence[str] = (),
) -> dict[str, Any]:
    """Build the ``llm_coverage`` object of design doc 9.2.

    ``results`` are per-unit outcomes ``{"unit_id", "producer", "status"}``
    using the existing unit status vocabulary.  A unit counts as scanned once
    any producer completed it; a file counts as scanned only when every one of
    its units did, because a partially scanned file is not a scanned file.
    """
    units = list(plan.get("units", ()))
    files = plan.get("files", {})
    by_id = {unit["unit_id"]: unit for unit in units}
    outcomes: dict[str, list[str]] = {}
    per_scanner: dict[str, dict[str, int]] = {
        name: {"units": 0, "functions": 0, "bytes": 0, "files": 0} for name in scanners
    }
    scanner_files: dict[str, set[str]] = {name: set() for name in scanners}
    completed: set[str] = set()
    for result in results:
        unit_id = str(result.get("unit_id", ""))
        unit = by_id.get(unit_id)
        if unit is None:
            continue
        status = str(result.get("status", ""))
        outcomes.setdefault(unit_id, []).append(status)
        if status != "completed":
            continue
        completed.add(unit_id)
        producer = str(result.get("producer", ""))
        bucket = per_scanner.setdefault(producer, {"units": 0, "functions": 0, "bytes": 0, "files": 0})
        bucket["units"] += 1
        bucket["functions"] += int(unit["kind"] == "function")
        bucket["bytes"] += int(unit["byte_length"])
        scanner_files.setdefault(producer, set()).add(unit["path"])
    for producer, paths in scanner_files.items():
        per_scanner[producer]["files"] = len(paths)

    functions = [unit for unit in units if unit["kind"] == "function"]
    planned_paths: dict[str, list[dict[str, Any]]] = {}
    for unit in units:
        planned_paths.setdefault(unit["path"], []).append(unit)
    scanned_files = sum(
        1 for path, group in planned_paths.items()
        if all(unit["unit_id"] in completed for unit in group)
    )
    tiers = {tier: {"planned": 0, "scanned": 0} for tier in RISK_TIERS}
    for unit in units:
        bucket = tiers.setdefault(unit["risk_tier"], {"planned": 0, "scanned": 0})
        bucket["planned"] += 1
        bucket["scanned"] += int(unit["unit_id"] in completed)
    reasons = {name: 0 for name in _UNSCANNED_REASONS}
    for unit in units:
        if unit["unit_id"] not in completed:
            reasons[_reason(outcomes.get(unit["unit_id"], ()))] += 1
        if float(unit.get("parse_confidence", 1.0)) < LOW_CONFIDENCE:
            reasons["parse_confidence_low"] += 1
    reasons["unreadable"] = sum(1 for record in files.values() if not record.get("readable", True))
    return {
        "files": _ratio(scanned_files, len(files)),
        "functions": _ratio(sum(1 for unit in functions if unit["unit_id"] in completed), len(functions)),
        "bytes": _ratio(
            sum(int(unit["byte_length"]) for unit in units if unit["unit_id"] in completed),
            sum(int(record.get("size", 0)) for record in files.values()),
        ),
        "by_scanner": {name: dict(bucket) for name, bucket in sorted(per_scanner.items())},
        "risk_tiers": {tier: dict(tiers[tier]) for tier in sorted(tiers, key=RISK_TIERS.index)},
        "unscanned_reasons": reasons,
    }


def _segments(
    record: Mapping[str, Any], raw: str
) -> list[tuple[str, int, int, Mapping[str, Any] | None]]:
    size = len(raw)
    unparsed = record.get("unparsed_from")
    limit = size if unparsed is None else max(0, min(int(unparsed), size))
    claimed: list[tuple[str, int, int, Mapping[str, Any] | None]] = []
    cursor = 0
    for symbol in sorted(record.get("functions", ()), key=lambda item: item["start_byte"]):
        start, end = int(symbol["start_byte"]), int(symbol["end_byte"])
        # Defensive: an extent that overlaps its predecessor or leaves the file
        # would break the invariant, so it forfeits its claim to those bytes.
        if start < cursor or end > limit or end <= start:
            continue
        if start > cursor:
            claimed.append(("module-scope", cursor, start, None))
        claimed.append(("function", start, end, symbol))
        cursor = end
    if limit > cursor:
        claimed.append(("module-scope", cursor, limit, None))
        cursor = limit
    if size > cursor:
        claimed.append(("raw-span", cursor, size, None))
    return _absorb_blank(claimed, raw, size)


def _absorb_blank(
    segments: Sequence[tuple[str, int, int, Mapping[str, Any] | None]], raw: str, size: int
) -> list[tuple[str, int, int, Mapping[str, Any] | None]]:
    """Fold whitespace-only gaps into a neighbour; every byte still lands once."""
    result: list[list[Any]] = []
    pending: int | None = None
    for kind, start, end, symbol in segments:
        if symbol is None and not raw[start:end].strip():
            if result:
                result[-1][2] = end
                continue
            pending = start if pending is None else pending
            continue
        if pending is not None:
            start, pending = pending, None
        result.append([kind, start, end, symbol])
    if pending is not None:
        result.append(["module-scope", pending, size, None])
    return [(kind, start, end, symbol) for kind, start, end, symbol in result]


def _chunks(raw: str, start: int, end: int, kind: str) -> list[tuple[int, int]]:
    if kind == "function" or end - start <= MAX_UNIT_BYTES:
        return [(start, end)]
    result: list[tuple[int, int]] = []
    cursor = start
    while end - cursor > MAX_UNIT_BYTES:
        split = raw.rfind("\n", cursor, cursor + MAX_UNIT_BYTES)
        split = split + 1 if split > cursor else cursor + MAX_UNIT_BYTES
        result.append((cursor, split))
        cursor = split
    result.append((cursor, end))
    return result


def _unit(
    index: Mapping[str, Any],
    record: Mapping[str, Any],
    raw: str,
    starts: Sequence[int],
    ordinals: dict[tuple[str, str], int],
    kind: str,
    start: int,
    end: int,
    symbol: Mapping[str, Any] | None,
    profile: RiskProfile,
) -> dict[str, Any]:
    path = record["path"]
    name = str(symbol["name"]) if symbol else ""
    ordinal = ordinals.get((kind, name), 0)
    ordinals[(kind, name)] = ordinal + 1
    body = raw[start:end]
    unit = {
        "unit_id": unit_id(path, kind, name, ordinal),
        "kind": kind,
        "path": path,
        "name": name,
        "language": record.get("language", "c"),
        "is_header": bool(record.get("is_header")),
        "start_byte": start,
        "end_byte": end,
        "byte_length": end - start,
        "line_start": line_of(starts, start),
        "line_end": line_of(starts, max(end - 1, start)),
        "unit_sha256": hashlib.sha256(body.encode("latin-1")).hexdigest(),
        "file_sha256": record.get("sha256", ""),
        "parse_confidence": record.get("parse_confidence", 1.0),
        "signature": str(symbol["signature"]) if symbol else "",
        "conditional": str(symbol["conditional"]) if symbol else _condition(record, start),
        "dead": bool(symbol["dead"]) if symbol else _dead(record, start, end),
        "kr_style": bool(symbol["kr_style"]) if symbol else False,
        "macro_header": bool(symbol["macro_header"]) if symbol else False,
        "callees": _callees(index, symbol),
        "callers": _callers(index, name) if symbol else [],
        "types": _referenced(body, index.get("types", {})),
        "macros": _referenced(body, index.get("macros", {})),
        "globals": _referenced(body, index.get("globals", {})),
    }
    tier, reasons = classify(unit, profile=profile)
    unit["risk_tier"] = tier
    unit["risk_reasons"] = list(reasons)
    return unit


def unit_id(path: str, kind: str, name: str, ordinal: int) -> str:
    """Stable identity for a unit, following the splint unit-id convention.

    Offsets are deliberately absent: an edit above a function must not change
    the identity of the unit below it, or the cross-run cache never hits.
    """
    safe = path.replace("/", "__").replace("\\", "__")
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in safe)
    fingerprint = hashlib.sha256(
        "\0".join((path, kind, name, str(ordinal))).encode()
    ).hexdigest()[:12]
    return f"{safe[:80]}-{fingerprint}"


def _callees(index: Mapping[str, Any], symbol: Mapping[str, Any] | None) -> list[str]:
    if symbol is None:
        return []
    symbols = index.get("symbols", {})
    return [name for name in symbol.get("calls", ())[:MAX_CALLEES] if name in symbols]


def _callers(index: Mapping[str, Any], name: str) -> list[str]:
    keys = index.get("call_graph", {}).get("callers", {}).get(name, ())
    return sorted({key.rpartition("::")[2] for key in keys})[:MAX_CONTEXT_NAMES]


def _referenced(body: str, table: Mapping[str, Any]) -> list[str]:
    if not table:
        return []
    result: list[str] = []
    seen: set[str] = set()
    for match in _IDENT.finditer(body):
        name = match.group(0)
        if name in seen or name not in table:
            continue
        seen.add(name)
        result.append(name)
        if len(result) == MAX_CONTEXT_NAMES:
            break
    return result


def _condition(record: Mapping[str, Any], offset: int) -> str:
    labels = [
        f"#{arm['kind']} {arm['condition']}".strip()
        for arm in record.get("conditionals", ())
        if arm["body_start"] <= offset < arm["body_end"]
    ]
    return " && ".join(labels)


def _dead(record: Mapping[str, Any], start: int, end: int) -> bool:
    """True when the unit overlaps an inactive branch: a module-scope unit can
    span both the ``#if 0`` and the live code around it."""
    return any(start < stop and begin < end for begin, stop in record.get("dead_spans", ()))


def _reason(statuses: Sequence[str]) -> str:
    for candidate in ("interrupted", "failed", "timed_out", "unscheduled"):
        if candidate in statuses:
            return candidate
    return "no_result" if not statuses else "failed"


def _ratio(scanned: int, total: int) -> dict[str, Any]:
    return {"scanned": scanned, "total": total, "ratio": round(scanned / total, 4) if total else 0.0}

"""Native evidence, read back: each analyzer's report parsed into finding rows, and what every row carries.

This is the parsing half of the old review layer (review.py), kept byte for byte where it matters: the
fingerprint formula, severity normalisation, the reference review level (the RT700 test plan's grading), the
report integrity checks, and the late-bound parsers each tool adapter calls.  The rest of the old review --
the overlap groups, the summary, the Markdown report -- was replaced by the index and the list (v3 M9).
"""
from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

from ..tools import adapters
from ..tools.common import diagnostic_category, is_diagnostic, is_fatal
from ..tools.splint_csv import splint_rows
from .grading import (
    GRADING_MAPPING_VERSION,
    REVIEW_LEVEL_RANK,
    reference_review_level,
)

SEVERITY_MAPPING_VERSION = 2


SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}


def enrich_row(item: dict[str, Any], cached_canonical: Callable[[Any], str]) -> dict[str, Any]:
    """The derived fields every parsed finding row carries, in place.

    Shared by the review (this module) and the v3 evidence store
    (evidence/findings.py), so a row means the same thing in both.
    """
    item["canonical_path"] = cached_canonical(item.get("file", ""))
    engine = "llm" if item.get("engine") == "llm" else "static"
    item["engine"] = engine
    item["producer"] = str(item.get("producer") or item["tool"])
    item["evidence_class"] = "generated" if engine == "llm" else "native"
    # A hallucinated critical must never be able to fail somebody's build.
    item["gate_eligible"] = engine == "static"
    item["severity"] = _normalize_severity(
        item["tool"], item.get("original_severity", ""), item.get("severity_scale"), engine=engine
    )
    # Splint deliberately remains unknown: its native output has no stable
    # severity scale that can support an authoritative gate.
    if item["tool"] == "splint":
        item["severity"] = "unknown"
    item["severity_mapping_version"] = SEVERITY_MAPPING_VERSION
    item["rank"] = SEVERITY_RANK[item["severity"]]
    item["review_level"] = reference_review_level(item.get("original_severity", ""))
    item["review_level_mapping_version"] = GRADING_MAPPING_VERSION
    item["review_level_rank"] = REVIEW_LEVEL_RANK[item["review_level"]]
    item["fingerprint"] = _fingerprint(item)
    return item


def should_fail(summary: dict[str, Any], policy: str, *, include_generated: bool = False) -> bool:
    """Does this review trip the quality gate?

    Generated findings are excluded by default and that default is the
    charter: a hallucinated critical must not be able to fail somebody's
    pipeline.  ``include_generated`` is the opt-in for a team that has decided
    otherwise for its own repository -- an explicit choice in their config,
    never something a scan turns on for them.
    """
    if policy == "none":
        return False
    minimum = SEVERITY_RANK[policy]
    return any(
        int(item.get("rank", 0)) >= minimum
        and (include_generated or item.get("gate_eligible", True))
        for item in summary.get("findings", [])
    )


def canonical_path(file_value: str, source: Path) -> str:
    if not file_value:
        return ""
    value = urllib.parse.unquote(str(file_value))
    if value.startswith("file://"):
        value = urllib.parse.urlparse(value).path
    path = Path(value)
    absolute = path if path.is_absolute() else source / path
    try:
        return absolute.resolve(strict=False).relative_to(source.resolve()).as_posix()
    except ValueError:
        return absolute.resolve(strict=False).as_posix()


def _scanner_executions(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Per-scanner execution records from the new top-level manifest["llm"]."""
    llm = manifest.get("llm")
    scanners = llm.get("scanners") if isinstance(llm, dict) else None
    if not isinstance(scanners, dict):
        return {}
    return {
        str(name): dict(execution)
        for name, execution in scanners.items()
        if isinstance(execution, dict)
    }


def _parse_cppcheck_units(source: Path, run_dir: Path, tool: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for unit in tool.get("units", []):
        report = run_dir / "tools" / "cppcheck" / unit["id"] / "report.xml"
        context = _evidence_context("cppcheck", unit, tool)
        integrity = _report_integrity(unit, report, run_dir, "cppcheck", _validate_cppcheck_report, tool)
        if integrity is not None:
            diagnostics.append(integrity)
            continue
        artifact = report.relative_to(run_dir).as_posix()
        try:
            errors = (
                element for _event, element in ET.iterparse(report, events=("end",))
                if element.tag == "error"
            )
            for error in errors:
                rule = error.get("id", "")
                message = error.get("msg", "") or error.get("verbose", "")
                severity = error.get("severity", "")
                locations = error.findall("location") or [None]
                is_diagnostic = _is_diagnostic(rule + " " + message)
                for location in locations:
                    common = {
                        "tool": "cppcheck", "message": message,
                        "file": location.get("file", "") if location is not None else "",
                        "line": location.get("line", "") if location is not None else "",
                        "column": location.get("column", "") if location is not None else "",
                        "source_artifact": artifact,
                        "evidence_context": context,
                    }
                    if is_diagnostic:
                        diagnostics.append({
                            **common, "severity": "error" if severity == "error" else "warning",
                            "category": _diagnostic_category(rule + " " + message), "fatal": severity == "error",
                        })
                    else:
                        findings.append({
                            **common, "original_severity": severity or "unknown", "rule_id": rule,
                            "cwe": f"CWE-{error.get('cwe')}" if error.get("cwe") else _extract_cwe(message),
                        })
                error.clear()
        except (OSError, ET.ParseError) as exc:
            diagnostics.append(_integrity_diagnostic("cppcheck", unit, report, run_dir, f"Cppcheck XML parse failed: {exc}", context))
            continue
    return findings, diagnostics


def _parse_flawfinder_units(source: Path, run_dir: Path, tool: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = [
        {
            "tool": "flawfinder", "severity": "warning", "category": "encoding-exclusion",
            "message": str(item.get("reason") or "source is not valid UTF-8"),
            "file": str(item.get("path", "")), "line": "", "column": "",
            "byte_offset": item.get("byte_offset"), "fatal": False,
            "source_artifact": "", "evidence_context": "source-only",
        }
        for item in tool.get("excluded_files", []) if isinstance(item, dict)
    ]
    for unit in tool.get("units", []):
        report = run_dir / "tools" / "flawfinder" / unit["id"] / "report.sarif"
        context = _evidence_context("flawfinder", unit, tool)
        integrity = _report_integrity(unit, report, run_dir, "flawfinder", _validate_flawfinder_report, tool)
        if integrity is not None:
            diagnostics.append(integrity)
            diagnostics.extend(_flawfinder_encoding_diagnostics(run_dir, unit, context))
            continue
        artifact = report.relative_to(run_dir).as_posix()
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            diagnostics.append(_integrity_diagnostic("flawfinder", unit, report, run_dir, f"Flawfinder SARIF parse failed: {exc}", context))
            continue
        for run in data.get("runs", []):
            rules = {
                str(rule.get("id", "")): rule
                for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
                if isinstance(rule, dict)
            }
            for result in run.get("results", []):
                rule_id = str(result.get("ruleId", ""))
                rule = rules.get(rule_id, {})
                message_value = result.get("message", {})
                message = str(message_value.get("text", "")) if isinstance(message_value, dict) else str(message_value)
                locations = result.get("locations") or [{}]
                raw, severity_scale = _sarif_raw_severity(result, rule)
                cwe = _extract_cwe(" ".join((rule_id, message, json.dumps(rule, ensure_ascii=False))))
                for location in locations:
                    physical = location.get("physicalLocation", {})
                    region = physical.get("region", {})
                    uri = physical.get("artifactLocation", {}).get("uri", "")
                    common = {
                        "tool": "flawfinder", "message": message, "file": uri,
                        "line": str(region.get("startLine", "")), "column": str(region.get("startColumn", "")),
                        "source_artifact": artifact,
                        "evidence_context": context,
                    }
                    if _is_diagnostic(rule_id + " " + message):
                        diagnostics.append({**common, "severity": "warning", "category": _diagnostic_category(message), "fatal": False})
                    else:
                        findings.append({
                            **common, "original_severity": raw, "severity_scale": severity_scale,
                            "rule_id": rule_id, "cwe": cwe,
                        })
            for notification in run.get("invocations", [{}])[0].get("toolExecutionNotifications", []) if run.get("invocations") else []:
                message_value = notification.get("message", {})
                message = str(message_value.get("text", "")) if isinstance(message_value, dict) else str(message_value)
                diagnostics.append({
                    "tool": "flawfinder", "severity": notification.get("level", "warning"),
                    "category": "tool", "message": message, "file": "", "line": "", "column": "",
                    "fatal": notification.get("level") == "error", "source_artifact": artifact,
                    "evidence_context": context,
                })
    return findings, diagnostics


def _flawfinder_encoding_diagnostics(
    run_dir: Path, unit: dict[str, Any], context: str
) -> list[dict[str, Any]]:
    """Recover precise exclusions from legacy Flawfinder failure stdout."""
    log = run_dir / "tools" / "flawfinder" / str(unit.get("id", "")) / "stdout.raw"
    try:
        text = log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    pattern = re.compile(
        r"Error:\s*encoding error in ([^\r\n]+).*?position\s+(\d+)", re.I | re.DOTALL
    )
    artifact = log.relative_to(run_dir).as_posix() if log.is_file() else ""
    return [
        {
            "tool": "flawfinder", "severity": "warning", "category": "encoding-exclusion",
            "message": "source is not valid UTF-8 and was excluded from Flawfinder evidence",
            "file": match.group(1).strip(), "line": "", "column": "",
            "byte_offset": int(match.group(2)), "fatal": False,
            "source_artifact": artifact, "unit_id": str(unit.get("id", "")),
            "evidence_context": context,
        }
        for match in pattern.finditer(text)
    ]


def _parse_splint_units(source: Path, run_dir: Path, tool: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for unit in tool.get("units", []):
        csv_findings: list[dict[str, Any]] = []
        directory = run_dir / "tools" / "splint" / unit["id"]
        report = directory / "report.csv"
        context = _evidence_context("splint", unit, tool)
        integrity = _report_integrity(unit, report, run_dir, "splint", _validate_splint_report, tool)
        if integrity is not None:
            diagnostics.append(integrity)
            continue
        if report.is_file():
            artifact = report.relative_to(run_dir).as_posix()
            try:
                rows, _recovered, csv_error = splint_rows(report.read_text(encoding="utf-8"))
            except (OSError, UnicodeError) as exc:
                diagnostics.append(_integrity_diagnostic("splint", unit, report, run_dir, f"Splint CSV parse failed: {exc}", context))
                continue
            if csv_error is not None:
                diagnostics.append(_integrity_diagnostic("splint", unit, report, run_dir, f"Splint CSV parse failed: {csv_error}", context))
                continue
            if rows:
                header = [cell.strip().lower() for cell in rows[0]]
                for row in rows[1:]:
                    values = {header[index]: cell for index, cell in enumerate(row) if index < len(header)}
                    file_value = _first(values, "file", "filename", "path", "source")
                    line = _first(values, "line", "linenumber", "line number")
                    column = _first(values, "column", "col")
                    message = _splint_csv_message(values)
                    if not message and len(row) >= 3:
                        file_value, line, message = row[0], row[1], ",".join(row[2:])
                    if not message:
                        continue
                    common = {
                        "tool": "splint", "message": message, "file": file_value, "line": line,
                        "column": column, "source_artifact": artifact,
                        "evidence_context": context,
                    }
                    if _is_diagnostic(message):
                        diagnostics.append({
                            **common, "severity": "error" if _is_fatal(message) else "warning",
                            "category": _diagnostic_category(message), "fatal": _is_fatal(message),
                        })
                    else:
                        # "Flag Name" is Splint's own rule identity (usereleased,
                        # boundswrite); without it every row collapses onto one
                        # opaque rule_id and the fingerprints stop distinguishing.
                        csv_findings.append({
                            **common, "original_severity": "unknown",
                            "rule_id": _first(values, "flag name", "rule", "rule_id") or "splint-warning",
                            "cwe": _extract_cwe(message),
                        })
        findings.extend(csv_findings)
        # Splint reports the same warnings twice -- once as CSV rows, once as
        # text on stdout -- so taking findings from both files reports every
        # warning twice.  The CSV is the structured one and wins; the logs are
        # still read, because a parse error or a missing include is only ever
        # reported there, and because a run whose CSV never got written must
        # not lose its evidence.  Each stream keeps its own artifact: they are
        # two files, and a finding must point at the one it came from.
        for name in ("stdout.raw", "stderr.raw"):
            path = directory / name
            if not path.is_file():
                continue
            log_findings, log_diagnostics = _parse_splint_text(
                path.read_text(encoding="utf-8", errors="replace"),
                path.relative_to(run_dir).as_posix(), context,
            )
            if not csv_findings:
                findings.extend(log_findings)
            diagnostics.extend(log_diagnostics)
    return findings, diagnostics


def _splint_csv_message(values: dict[str, str]) -> str:
    """Splint's warning text, not its row number.

    The real header is ``Warning, Flag Code, Flag Name, Priority, File, Line,
    Column, Warning Text, Additional Text``: "Warning" is the ordinal, and
    reading it as the message files findings whose entire text is "1", "2",
    "3".  The columns are matched most-specific first so a hand-written
    ``file,line,message`` CSV keeps working.
    """
    message = _first(values, "warning text", "message", "description", "text")
    extra = _first(values, "additional text")
    if message and extra and extra not in message:
        message = f"{message} {extra}"
    # A constraint warning spans several CSV lines; the text parser renders the
    # same warning on one, and the two must not read as different findings.
    return " ".join(message.split())


_SPLINT_LOCATION = re.compile(r"^(\S.*?):(\d+)(?::(\d+))?:\s+(.+)$")


_SPLINT_UNKNOWN = re.compile(r"^<\s*Location unknown\s*>:\s+(.+)$", re.I)


_SPLINT_WRAPPED_LOCATION = re.compile(r"^(.+?):(\d+):\s*$")


_SPLINT_WRAPPED_COLUMN = re.compile(r"^\s+(\d+):\s+(.+)$")


_SPLINT_WRAPPED_PATH = re.compile(r"^\s+(.+?):(\d+)(?::(\d+))?:\s*(.*)$")


def _parse_splint_text(text: str, artifact: str, evidence_context: str = "source-only") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    current: dict[str, str] | None = None
    continuation: list[str] = []
    wrapped_location: tuple[str, str] | None = None
    pending_prefix: str | None = None

    def add(message: str, file_value: str = "", line: str = "", column: str = "") -> None:
        common = {
            "tool": "splint", "message": message, "file": file_value, "line": line, "column": column,
            "source_artifact": artifact,
            "evidence_context": evidence_context,
        }
        if _is_diagnostic(message):
            diagnostics.append({
                **common, "severity": "error" if _is_fatal(message) else "warning",
                "category": _diagnostic_category(message), "fatal": _is_fatal(message),
            })
        else:
            findings.append({
                **common, "original_severity": "unknown", "rule_id": "splint-warning", "cwe": _extract_cwe(message),
            })

    def flush() -> None:
        nonlocal current, continuation
        if current is None:
            return
        details = " ".join(value.strip() for value in continuation if value.strip())
        add(current["message"] + ((" " + details) if details else ""), current["file"], current["line"], current["column"])
        current, continuation = None, []

    for raw in text.splitlines():
        raw = raw.rstrip("\r\n")
        if not raw.strip() or raw.lower().startswith("finished checking"):
            continue
        match = _SPLINT_LOCATION.match(raw)
        if match:
            flush()
            wrapped_location, pending_prefix = None, None
            current = {"file": match.group(1), "line": match.group(2), "column": match.group(3) or "", "message": match.group(4).strip()}
            continue
        unknown = _SPLINT_UNKNOWN.match(raw)
        if unknown:
            flush()
            add(unknown.group(1).strip(), "< Location unknown >")
            wrapped_location, pending_prefix = None, None
            continue
        if current is not None and raw[:1].isspace():
            continuation.append(raw)
            continue
        wrapped_path = _SPLINT_WRAPPED_PATH.match(raw)
        if pending_prefix is not None and wrapped_path:
            flush()
            current = {"file": pending_prefix + wrapped_path.group(1).strip(), "line": wrapped_path.group(2), "column": wrapped_path.group(3) or "", "message": wrapped_path.group(4).strip()}
            pending_prefix, wrapped_location = None, None
            continue
        wrapped_column = _SPLINT_WRAPPED_COLUMN.match(raw)
        if wrapped_location is not None and wrapped_column:
            flush()
            current = {"file": wrapped_location[0], "line": wrapped_location[1], "column": wrapped_column.group(1), "message": wrapped_column.group(2).strip()}
            wrapped_location, pending_prefix = None, None
            continue
        wrapped = _SPLINT_WRAPPED_LOCATION.match(raw)
        if wrapped:
            flush()
            wrapped_location, pending_prefix = (wrapped.group(1), wrapped.group(2)), None
            continue
        if current is not None and not raw[:1].isspace():
            flush()
        if current is None and _is_diagnostic(raw):
            add(raw.strip())
            wrapped_location, pending_prefix = None, None
            continue
        if current is None and ":" not in raw and "/" in raw and not raw[:1].isspace():
            pending_prefix, wrapped_location = raw.strip(), None
    flush()
    return findings, diagnostics


# Host paths a model can invent out of thin air.  Scrubbed here rather than in
# the export stage so review/summary.json is clean at source (design 11.1).
_HOST_PATH_PATTERNS = (
    re.compile(r"/home/[^/\s\"'<>]+"),
    re.compile(r"/mnt/[A-Za-z]/(?:[^/\s\"'<>]+/)*Users/[^/\s\"'<>]+", re.I),
    re.compile(r"[A-Za-z]:\\+(?:[^\\\r\n\"'<>]+\\+)*Users\\+[^\\\r\n\"'<>]+", re.I),
)


def _scrub_host_paths(value: str) -> str:
    """Replace invented host paths with the same token the export stage uses."""
    for pattern in _HOST_PATH_PATTERNS:
        value = pattern.sub("<HOME>", value)
    return value


def _parse_llm_units(source: Path, run_dir: Path, scanner: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Read one scanner's per-unit findings.json, and nothing else.

    Reading only the parsed report -- exactly as the cppcheck parser reads only
    report.xml -- is what makes rebuild-dashboard and recover-report work
    offline with no endpoint, no credential and no network.
    """
    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    declared = str(scanner.get("producer", ""))
    model = str(scanner.get("version") or "")
    for unit in scanner.get("units", []):
        if not isinstance(unit, dict):
            continue
        producer = str(unit.get("producer") or declared)
        unit_id = str(unit.get("id", ""))
        directory = run_dir / "llm" / "sessions" / producer / unit_id
        report = directory / "findings.json"
        context = _evidence_context(producer, unit, scanner)
        integrity = _report_integrity(unit, report, run_dir, producer, _validate_llm_report, scanner)
        if integrity is not None:
            diagnostics.append(_as_llm_diagnostic(integrity))
            continue
        artifact = report.relative_to(run_dir).as_posix()
        rationale = (directory / "response.json").relative_to(run_dir).as_posix()
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            diagnostics.append(_as_llm_diagnostic(_integrity_diagnostic(
                producer, unit, report, run_dir, f"LLM findings parse failed: {exc}", context
            )))
            continue
        fallback = next((item for item in unit.get("input_files", []) if isinstance(item, str)), "")
        for item in data.get("findings", []):
            if not isinstance(item, dict):
                continue
            message = _scrub_host_paths(str(item.get("message", "")).strip())
            if not message:
                continue
            span = _line_span(item)
            category = str(item.get("category", "")).strip().lower()
            findings.append({
                "tool": producer, "producer": producer, "engine": "llm",
                "evidence_class": "generated", "gate_eligible": False,
                "message": message,
                "file": _scrub_host_paths(str(item.get("file", "")).strip()) or fallback,
                "line": str(span[0]) if span else "", "column": "",
                "rule_id": _scrub_host_paths(str(item.get("rule_id", "")).strip()) or category or "llm-finding",
                "cwe": _extract_cwe(str(item.get("cwe", ""))),
                "original_severity": str(item.get("severity", "")).strip().lower() or "unknown",
                "source_artifact": artifact,
                "evidence_context": context,
                "category": category or "unknown",
                "confidence": item["confidence"] if isinstance(item.get("confidence"), (int, float)) and not isinstance(item.get("confidence"), bool) else None,
                "symbol": _scrub_host_paths(str(item.get("symbol", "")).strip()),
                "line_range": list(span),
                "unit_id": str(data.get("unit_id") or unit_id),
                "model": model,
                "skill_version": str(unit.get("skill_version", "")),
                "rationale_artifact": rationale,
            })
        dropped = [str(reason) for reason in data.get("malformed", []) if str(reason).strip()]
        if dropped:
            diagnostics.append({
                "tool": producer, "severity": "warning", "category": "llm-malformed",
                "message": _scrub_host_paths(
                    f"{len(dropped)} model finding(s) failed validation and were dropped: {dropped[0]}"
                ),
                "file": fallback, "line": "", "column": "", "fatal": False,
                "source_artifact": artifact, "unit_id": unit_id, "evidence_context": context,
            })
    return findings, diagnostics


def _as_llm_diagnostic(diagnostic: dict[str, Any]) -> dict[str, Any]:
    """Re-tag a scanner integrity problem so it cannot gate the run.

    `report-integrity` marks the derived review partial, which the runner turns
    into exit code 10.  A model timeout must never do that, so the shared
    mechanism is reused and only its category and severity change.
    """
    return {
        **diagnostic, "category": "llm-report-integrity", "severity": "warning", "fatal": False,
    }


def _line_span(item: dict[str, Any]) -> tuple[int, int] | tuple[()]:
    value = item.get("line_range")
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        value = [item.get("line"), item.get("line")]
    numbers: list[int] = []
    for entry in value:
        if isinstance(entry, bool) or not isinstance(entry, int):
            return ()
        numbers.append(entry)
    start, end = numbers
    return (start, max(start, end)) if start > 0 else ()


def _evidence_context(tool_name: str, unit: dict[str, Any], tool: dict[str, Any]) -> str:
    # A unit a later attempt superseded keeps its rows -- nothing is ever
    # dropped from the review -- but they are tagged so a reader (and the
    # dashboard) can tell the attempt that stands from the one it replaced.
    suffix = "/superseded" if unit.get("superseded_by") else ""
    declared = unit.get("evidence_context")
    if declared in {"build-aware", "source-only"}:
        return str(declared) + suffix
    if tool_name == "cppcheck":
        return ("build-aware" if unit.get("id") == "compile-db" else "source-only") + suffix
    if tool_name == "splint" and tool.get("scope") == "build":
        return "build-aware" + suffix
    return "source-only" + suffix


def _report_integrity(
    unit: dict[str, Any],
    report: Path,
    run_dir: Path,
    tool_name: str,
    validator: Callable[[Path], tuple[bool, str | None]],
    tool: dict[str, Any],
) -> dict[str, Any] | None:
    context = _evidence_context(tool_name, unit, tool)
    declared = unit.get("valid_report")
    if declared is not True and not (declared is None and tool.get("_allow_undeclared_valid")):
        reason = unit.get("reason") or "unit did not declare a valid native report"
        return _integrity_diagnostic(tool_name, unit, report, run_dir, str(reason), context)
    if not report.is_file():
        return _integrity_diagnostic(tool_name, unit, report, run_dir, "declared valid report is missing", context)
    valid, reason = validator(report)
    if not valid:
        return _integrity_diagnostic(tool_name, unit, report, run_dir, reason or "native report validation failed", context)
    return None


def _integrity_diagnostic(
    tool_name: str,
    unit: dict[str, Any],
    report: Path,
    run_dir: Path,
    reason: str,
    context: str,
) -> dict[str, Any]:
    try:
        artifact = report.relative_to(run_dir).as_posix()
    except ValueError:
        artifact = ""
    inputs = [str(item) for item in unit.get("input_files", []) if isinstance(item, str)]
    return {
        "tool": tool_name, "severity": "error", "category": "report-integrity",
        "message": reason, "file": inputs[0] if len(inputs) == 1 else "", "line": "", "column": "",
        "fatal": False, "source_artifact": artifact if report.exists() else "",
        "unit_id": str(unit.get("id", "")), "excluded_files": inputs,
        "evidence_context": context,
    }


def _validate_cppcheck_report(path: Path) -> tuple[bool, str | None]:
    try:
        parser = ET.iterparse(path, events=("start", "end"))
        root_tag = None
        for event, element in parser:
            if root_tag is None and event == "start":
                root_tag = element.tag
            if event == "end":
                element.clear()
    except (OSError, ET.ParseError) as exc:
        return False, f"invalid Cppcheck XML: {exc}"
    return (True, None) if root_tag == "results" else (False, "Cppcheck XML root is not results")


def _validate_flawfinder_report(path: Path) -> tuple[bool, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return False, f"invalid Flawfinder SARIF: {exc}"
    if not isinstance(value, dict) or value.get("version") != "2.1.0":
        return False, "Flawfinder report is not SARIF 2.1.0"
    runs = value.get("runs")
    if not isinstance(runs, list) or not all(isinstance(run, dict) for run in runs):
        return False, "invalid Flawfinder SARIF: runs must be an array of objects"
    for run in runs:
        if "results" in run and not isinstance(run["results"], list):
            return False, "invalid Flawfinder SARIF: results must be an array"
        if not all(isinstance(result, dict) for result in run.get("results", [])):
            return False, "invalid Flawfinder SARIF: results must contain objects"
        tool_value = run.get("tool", {})
        if not isinstance(tool_value, dict):
            return False, "invalid Flawfinder SARIF: tool must be an object"
        driver = tool_value.get("driver", {})
        rules = driver.get("rules", []) if isinstance(driver, dict) else []
        if not isinstance(driver, dict) or not isinstance(rules, list) or not all(isinstance(rule, dict) for rule in rules):
            return False, "invalid Flawfinder SARIF: driver rules must be an array of objects"
        for result in run.get("results", []):
            locations = result.get("locations", [])
            if not isinstance(locations, list) or not all(isinstance(location, dict) for location in locations):
                return False, "invalid Flawfinder SARIF: locations must be an array of objects"
            for location in locations:
                physical = location.get("physicalLocation", {})
                if not isinstance(physical, dict) or not isinstance(physical.get("region", {}), dict) or not isinstance(physical.get("artifactLocation", {}), dict):
                    return False, "invalid Flawfinder SARIF: physical locations must be objects"
        invocations = run.get("invocations", [])
        if not isinstance(invocations, list) or not all(isinstance(item, dict) for item in invocations):
            return False, "invalid Flawfinder SARIF: invocations must be an array of objects"
        for invocation in invocations:
            notifications = invocation.get("toolExecutionNotifications", [])
            if not isinstance(notifications, list) or not all(isinstance(item, dict) for item in notifications):
                return False, "invalid Flawfinder SARIF: notifications must be an array of objects"
    return True, None


def _validate_splint_report(path: Path) -> tuple[bool, str | None]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return False, f"invalid Splint CSV: {exc}"
    _rows, _recovered, error = splint_rows(text)
    return (True, None) if error is None else (False, error)


def _validate_llm_report(path: Path) -> tuple[bool, str | None]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return False, f"invalid LLM findings report: {exc}"
    if not isinstance(value, dict):
        return False, "invalid LLM findings report: expected a JSON object"
    if not isinstance(value.get("schema_version"), int) or isinstance(value.get("schema_version"), bool):
        return False, "invalid LLM findings report: schema_version must be an integer"
    if not isinstance(value.get("valid_report"), bool):
        return False, "invalid LLM findings report: valid_report must be a boolean"
    if not isinstance(value.get("producer"), str) or not value["producer"]:
        return False, "invalid LLM findings report: producer must be a non-empty string"
    items = value.get("findings")
    if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
        return False, "invalid LLM findings report: findings must be an array of objects"
    malformed = value.get("malformed", [])
    if not isinstance(malformed, list) or not all(isinstance(item, str) for item in malformed):
        return False, "invalid LLM findings report: malformed must be an array of strings"
    for item in items:
        if not str(item.get("message", "")).strip():
            return False, "invalid LLM findings report: every finding needs a message"
    return True, None


def _normalize_severity(tool: str, value: str, scale: str | None = None, *, engine: str = "static") -> str:
    raw = str(value or "").strip().lower()
    if engine == "llm":
        # Without a real normalized severity every LLM finding ranks 0, sorts
        # last, and is the first thing the dashboard embed limit discards.
        return raw if raw in SEVERITY_RANK else "unknown"
    # A total function: a manifest from a future version, or one hand-edited to
    # name a tool this build does not have, must normalise to "unknown" rather
    # than abort a review of the findings that *are* readable.
    declared = adapters().get(tool)
    return declared.severity(raw, scale) if declared is not None else "unknown"


def _sarif_raw_severity(result: dict[str, Any], rule: dict[str, Any]) -> tuple[str, str | None]:
    properties = result.get("properties", {})
    rule_properties = rule.get("properties", {})
    if not isinstance(properties, dict):
        properties = {}
    if not isinstance(rule_properties, dict):
        rule_properties = {}
    for value, scale in (
        (properties.get("security-severity"), "security-severity"),
        (properties.get("level"), "level"),
        (rule_properties.get("security-severity"), "security-severity"),
        (rule_properties.get("level"), "level"),
        (result.get("level"), "level"),
    ):
        if value is not None and str(value) != "":
            return str(value), scale
    return "unknown", None


def _is_diagnostic(value: str) -> bool:
    return is_diagnostic(value)


def _is_fatal(value: str) -> bool:
    return is_fatal(value)


def _diagnostic_category(value: str) -> str:
    return diagnostic_category(value)


def _extract_cwe(value: str) -> str:
    match = re.search(r"CWE-?(\d+)", value, re.I)
    return f"CWE-{match.group(1)}" if match else ""


def _first(values: dict[str, str], *names: str) -> str:
    return next((values[name] for name in names if values.get(name)), "")


def _deduplicate(items: list[dict[str, Any]], diagnostic: bool) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    result = []
    fields = (
        "tool", *(("unit_id",) if diagnostic else ()), "evidence_context", "file", "line", "column",
        "category" if diagnostic else "rule_id", "message",
    )
    for item in items:
        key = tuple(item.get(field, "") for field in fields)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _fingerprint(item: dict[str, Any]) -> str:
    stable = "\0".join(str(item.get(key, "")).strip().lower() for key in (
        "tool", "canonical_path", "line", "column", "rule_id", "message",
    ))
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()

from __future__ import annotations

import csv
import hashlib
import json
import re
import urllib.parse
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable, Iterable

from .grading import (
    GRADING_MAPPING_VERSION,
    REVIEW_LEVEL_RANK,
    grading_reference,
    reference_review_level,
)
from .tools import PRODUCER_ORDER, TOOL_NAMES

REVIEW_SCHEMA_VERSION = 3
SEVERITY_MAPPING_VERSION = 2
TOOL_ORDER = TOOL_NAMES
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}
OVERLAP_LINE_DISTANCE = 3


def _producer_rank(name: str) -> int:
    """Total ordering key; unknown producers sort last instead of raising."""
    try:
        return PRODUCER_ORDER.index(name)
    except ValueError:
        return len(PRODUCER_ORDER)


def build_review(
    source: Path,
    run_dir: Path,
    manifest: dict[str, Any],
    inventory: list[dict[str, Any]],
    *,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    parsers = {
        "cppcheck": _parse_cppcheck_units,
        "flawfinder": _parse_flawfinder_units,
        "splint": _parse_splint_units,
    }
    for tool in TOOL_ORDER:
        _check_cancelled(cancelled)
        execution = dict(manifest.get("tools", {}).get(tool, {}))
        execution["_allow_undeclared_valid"] = manifest.get("manifest_schema_version") is None
        tool_findings, tool_diagnostics = parsers[tool](source, run_dir, execution)
        findings.extend(tool_findings)
        diagnostics.extend(tool_diagnostics)

    findings = _deduplicate(findings, diagnostic=False)
    diagnostics = _deduplicate(diagnostics, diagnostic=True)
    canonical_cache: dict[str, str] = {}

    def cached_canonical(file_value: Any) -> str:
        key = str(file_value or "")
        if key not in canonical_cache:
            canonical_cache[key] = canonical_path(key, source)
        return canonical_cache[key]

    for item in findings:
        _check_cancelled(cancelled)
        item["canonical_path"] = cached_canonical(item.get("file", ""))
        item["severity"] = _normalize_severity(
            item["tool"], item.get("original_severity", ""), item.get("severity_scale")
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
        item["engine"] = "static"
        item["producer"] = item["tool"]
        item["evidence_class"] = "native"
        item["gate_eligible"] = True
        item["fingerprint"] = _fingerprint(item)
    for item in diagnostics:
        _check_cancelled(cancelled)
        item["canonical_path"] = cached_canonical(item.get("file", ""))

    findings.sort(key=lambda item: (
        -item["rank"], _producer_rank(item["tool"]), item["canonical_path"],
        _line_number(item.get("line")), str(item.get("line", "")), item["fingerprint"],
    ))
    diagnostics.sort(key=lambda item: (
        _producer_rank(item["tool"]), not item.get("fatal", False), item["canonical_path"],
        _line_number(item.get("line")), item.get("message", ""),
    ))
    severity_counts = Counter(item["severity"] for item in findings)
    review_level_counts = Counter(item["review_level"] for item in findings)
    context_counts = Counter(item.get("evidence_context", "source-only") for item in findings)
    engine_counts = Counter(item.get("engine", "static") for item in findings)
    severity_by_context = {
        context: {
            name: count for name in SEVERITY_RANK
            if (count := sum(
                item["severity"] == name and item.get("evidence_context") == context
                for item in findings
            ))
        }
        for context in ("build-aware", "source-only")
    }
    review_level_by_context = {
        context: {
            name: count for name in REVIEW_LEVEL_RANK
            if (count := sum(
                item["review_level"] == name and item.get("evidence_context") == context
                for item in findings
            ))
        }
        for context in ("build-aware", "source-only")
    }
    severity_by_engine = {
        engine: {
            name: count for name in SEVERITY_RANK
            if (count := sum(
                item["severity"] == name and item.get("engine") == engine
                for item in findings
            ))
        }
        for engine in ("static", "llm")
    }
    review_level_by_engine = {
        engine: {
            name: count for name in REVIEW_LEVEL_RANK
            if (count := sum(
                item["review_level"] == name and item.get("engine") == engine
                for item in findings
            ))
        }
        for engine in ("static", "llm")
    }
    tools: dict[str, Any] = {}
    for tool in TOOL_ORDER:
        execution = manifest["tools"].get(tool, {})
        inferred_exclusions = [
            {
                "path": item.get("canonical_path") or item.get("file", ""),
                "byte_offset": item.get("byte_offset"),
                "reason": item.get("message", ""),
                "category": "encoding",
            }
            for item in diagnostics
            if item.get("tool") == tool and item.get("category") == "encoding-exclusion"
        ]
        excluded_files = list(execution.get("excluded_files", [])) or inferred_exclusions
        coverage = _normalized_review_coverage(execution, excluded_files)
        tools[tool] = {
            "status": execution.get("status", "unknown"),
            "reason": execution.get("reason"),
            "requested": execution.get("requested", False),
            "version": execution.get("version"),
            "executable": execution.get("executable"),
            "coverage": coverage,
            "excluded_files": excluded_files,
            "unit_counts": execution.get("unit_counts", {}),
            "units": execution.get("units", []),
            "valid_reports": execution.get("valid_reports", 0),
            "total_findings": sum(item["tool"] == tool for item in findings),
            "finding_counts": {
                "total": sum(item["tool"] == tool for item in findings),
                "build-aware": sum(item["tool"] == tool and item.get("evidence_context") == "build-aware" for item in findings),
                "source-only": sum(item["tool"] == tool and item.get("evidence_context") == "source-only" for item in findings),
            },
            "total_diagnostics": sum(item["tool"] == tool for item in diagnostics),
        }
    source_manifest = {
        "total_files": len(inventory),
        "files": [item["path"] for item in inventory],
        "suffix_counts": dict(sorted(Counter(Path(item["path"]).suffix.lower() for item in inventory).items())),
        "include_patterns": manifest.get("source_options", {}).get("include", ["**/*"]),
        "exclude_patterns": manifest.get("source_options", {}).get("exclude", []),
    }
    omitted_units = [
        {
            "tool": item.get("tool"), "unit_id": item.get("unit_id"),
            "artifact": item.get("source_artifact", ""),
            "input_files": item.get("excluded_files", []), "reason": item.get("message", ""),
        }
        for item in diagnostics if item.get("category") == "report-integrity"
    ]
    return {
        "review_schema_version": REVIEW_SCHEMA_VERSION,
        "severity_mapping_version": SEVERITY_MAPPING_VERSION,
        "grading_reference": grading_reference(),
        "project": str(source.resolve()),
        "run": {
            "id": manifest.get("run_id"), "started_at": manifest.get("started_at"),
            "completed_at": manifest.get("finished_at"), "tool_order": list(TOOL_ORDER),
            "producer_order": list(PRODUCER_ORDER),
            "status": manifest.get("status"),
        },
        "tools": tools,
        "source_manifest": source_manifest,
        "coverage_gaps": [
            {
                "tool": tool_name,
                "excluded": data.get("coverage", {}).get("excluded", 0),
                "unanalyzed": max(
                    0,
                    int(data.get("coverage", {}).get("effective_total", data.get("coverage", {}).get("total", 0)) or 0)
                    - int(data.get("coverage", {}).get("analyzed", data.get("coverage", {}).get("covered", 0)) or 0),
                ),
                "excluded_files": data.get("excluded_files", []),
            }
            for tool_name, data in tools.items()
            if data.get("requested") and (
                data.get("coverage", {}).get("excluded", 0)
                or int(data.get("coverage", {}).get("analyzed", data.get("coverage", {}).get("covered", 0)) or 0)
                < int(data.get("coverage", {}).get("effective_total", data.get("coverage", {}).get("total", 0)) or 0)
            )
        ],
        "total_findings": len(findings),
        "finding_counts": {
            "total": len(findings), "build-aware": context_counts["build-aware"],
            "source-only": context_counts["source-only"],
        },
        "finding_counts_by_engine": {
            "total": len(findings), "static": engine_counts["static"], "llm": engine_counts["llm"],
        },
        "total_diagnostics": len(diagnostics),
        "severity_counts": {name: severity_counts[name] for name in SEVERITY_RANK if severity_counts[name]},
        "severity_counts_by_context": severity_by_context,
        "severity_counts_by_engine": severity_by_engine,
        "review_level_counts": {
            name: review_level_counts[name] for name in REVIEW_LEVEL_RANK if review_level_counts[name]
        },
        "review_level_counts_by_context": review_level_by_context,
        "review_level_counts_by_engine": review_level_by_engine,
        "top_files": _top_counts((item["canonical_path"] for item in findings), "file"),
        "top_rules": _top_counts((item["rule_id"] for item in findings), "rule_id"),
        "top_cwes": _top_counts((item["cwe"] for item in findings if item.get("cwe")), "cwe"),
        "findings": findings,
        "diagnostics": diagnostics,
        "report_integrity": {
            "status": "partial" if omitted_units else "complete",
            "included_reports": max(0, sum(
                len(tool.get("units", [])) for tool in tools.values()
            ) - len(omitted_units)),
            "omitted_units": omitted_units,
        },
        "overlap_groups": _build_overlap_groups(findings),
        "notice": "Derived review data is non-authoritative; consult the linked native evidence.",
    }


def write_review(
    run_dir: Path,
    summary: dict[str, Any],
    max_findings: int = 200,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> None:
    _check_cancelled(cancelled)
    directory = run_dir / "review"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    _check_cancelled(cancelled)
    (directory / "summary.md").write_text(markdown_report(summary, max_findings), encoding="utf-8")


def _check_cancelled(cancelled: Callable[[], bool] | None) -> None:
    if cancelled is not None and cancelled():
        raise InterruptedError("run interrupted")


def markdown_report(summary: dict[str, Any], max_findings: int = 200) -> str:
    contexts = summary.get("finding_counts", {})
    lines = [
        "# Code Analyzer Review", "", f"Project: `{summary.get('project', '')}`",
        f"Run: `{summary.get('run', {}).get('id', '')}`", f"Total findings: `{summary.get('total_findings', 0)}`",
        f"Build-aware findings: `{contexts.get('build-aware', 0)}`",
        f"Source-only findings: `{contexts.get('source-only', 0)}`",
        f"Tool diagnostics: `{summary.get('total_diagnostics', 0)}`",
    ]
    reference = summary.get("grading_reference", {})
    document = reference.get("document", {})
    section = reference.get("section", {})
    lines.extend([
        "", "## Code Review Grading Reference", "",
        f"- Document: `{document.get('file_name', 'not declared')}`",
        f"- Document SHA-256: `{document.get('sha256', 'not declared')}`",
        f"- Section: `{section.get('number', '')} {section.get('title', '')}`",
    ])
    for level in reference.get("levels", []):
        lines.append(f"- `{level.get('label', level.get('id', ''))}`: {level.get('description', '')}")
    application = reference.get("application", {})
    if application:
        lines.append(f"- Mapping: {application.get('note', '')}")
        lines.append("- Manual verification is required; a tool level is not an automatic vulnerability verdict.")
    lines.extend(["", "## Tool Status", ""])
    for tool, data in summary.get("tools", {}).items():
        reason = f" — {data['reason']}" if data.get("reason") else ""
        lines.append(f"- `{tool}`: `{data.get('status', 'unknown')}`; findings: `{data.get('total_findings', 0)}`{reason}")
    lines.extend(["", "## Severity Counts", ""])
    counts = summary.get("severity_counts", {})
    lines.extend([f"- `{key}`: {value}" for key, value in counts.items()] or ["- No findings."])
    lines.extend(["", "## Code Review Level Counts", ""])
    level_counts = summary.get("review_level_counts", {})
    lines.extend([f"- `{key}`: {value}" for key, value in level_counts.items()] or ["- No findings."])
    lines.extend(["", "## Tool Diagnostics", ""])
    for item in summary.get("diagnostics", []):
        lines.append(
            f"- `{item.get('severity', 'warning')}` `{item.get('tool', '')}` `{item.get('category', '')}` "
            f"{item.get('canonical_path') or '<unknown>'}:{item.get('line', '')} — {item.get('message', '')}"
        )
    if not summary.get("diagnostics"):
        lines.append("- No tool diagnostics.")
    lines.extend(["", "## Cross-tool Nearby Overlap", ""])
    for group in summary.get("overlap_groups", []):
        lines.append(f"- `{group['canonical_path']}:{group['line']}`: {', '.join(group['tools'])}")
    if not summary.get("overlap_groups"):
        lines.append("- No cross-tool overlap groups.")
    lines.extend(["", f"## Findings (first {max_findings})", ""])
    for finding in summary.get("findings", [])[:max_findings]:
        lines.append(
            f"- review level `{finding.get('review_level', 'unmapped')}`; normalized severity `{finding['severity']}`; "
            f"`{finding['tool']}` `{finding.get('evidence_context', 'source-only')}` `{finding['rule_id']}` "
            f"{finding.get('canonical_path') or '<unknown>'}:{finding.get('line', '')} — {finding.get('message', '')}"
        )
    if not summary.get("findings"):
        lines.append("- No findings to list.")
    lines.extend([
        "", "## Notes", "", "- This review is derived and non-authoritative; confirm findings against native artifacts.",
        "- Nearby overlap preserves every finding and does not merge or deduplicate tool evidence.", "",
    ])
    return "\n".join(lines)


def should_fail(summary: dict[str, Any], policy: str) -> bool:
    if policy == "none":
        return False
    minimum = SEVERITY_RANK[policy]
    return any(
        int(item.get("rank", 0)) >= minimum and item.get("gate_eligible", True)
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


def _normalized_review_coverage(
    execution: dict[str, Any], excluded_files: list[dict[str, Any]]
) -> dict[str, Any]:
    coverage = dict(execution.get("coverage", {}))
    if "analyzed" in coverage and "attempted" in coverage and "excluded" in coverage:
        return coverage
    units = execution.get("units", [])
    attempted = {
        path for unit in units if isinstance(unit, dict) and (
            "process" in unit or unit.get("status") in {"completed", "partial", "failed", "timed_out"}
        )
        for path in unit.get("input_files", []) if isinstance(path, str)
    }
    analyzed = {
        path for unit in units if isinstance(unit, dict) and unit.get("valid_report")
        for path in unit.get("input_files", []) if isinstance(path, str)
    }
    total = int(coverage.get("total", len(attempted | analyzed)) or 0)
    excluded = len({str(item.get("path", "")) for item in excluded_files if item.get("path")})
    effective_total = max(0, total - excluded)
    coverage.update({
        "attempted": len(attempted), "analyzed": len(analyzed), "excluded": excluded,
        "covered": len(analyzed), "effective_total": effective_total,
        "ratio": len(analyzed) / effective_total if effective_total else None,
    })
    return coverage


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
                with report.open("r", encoding="utf-8", newline="") as stream:
                    rows = list(csv.reader(stream, strict=True))
            except (OSError, UnicodeError, csv.Error) as exc:
                diagnostics.append(_integrity_diagnostic("splint", unit, report, run_dir, f"Splint CSV parse failed: {exc}", context))
                continue
            if rows:
                header = [cell.strip().lower() for cell in rows[0]]
                for row in rows[1:]:
                    values = {header[index]: cell for index, cell in enumerate(row) if index < len(header)}
                    file_value = _first(values, "file", "filename", "path", "source")
                    line = _first(values, "line", "linenumber", "line number")
                    column = _first(values, "column", "col")
                    message = _first(values, "message", "warning", "description", "text")
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
                        findings.append({
                            **common, "original_severity": "unknown", "rule_id": _first(values, "rule", "rule_id") or "splint-warning",
                            "cwe": _extract_cwe(message),
                        })
        log_artifact = None
        text_parts = []
        for name in ("stdout.raw", "stderr.raw"):
            path = directory / name
            if path.is_file():
                log_artifact = path.relative_to(run_dir).as_posix()
                text_parts.append(path.read_text(encoding="utf-8", errors="replace"))
        log_findings, log_diagnostics = _parse_splint_text("\n".join(text_parts), log_artifact or "", context)
        findings.extend(log_findings)
        diagnostics.extend(log_diagnostics)
    return findings, diagnostics


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


def _evidence_context(tool_name: str, unit: dict[str, Any], tool: dict[str, Any]) -> str:
    declared = unit.get("evidence_context")
    if declared in {"build-aware", "source-only"}:
        return str(declared)
    if tool_name == "cppcheck":
        return "build-aware" if unit.get("id") == "compile-db" else "source-only"
    if tool_name == "splint" and tool.get("scope") == "build":
        return "build-aware"
    return "source-only"


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
        if not text.strip() or "\x00" in text:
            return False, "invalid Splint CSV: report is empty or contains NUL"
        rows = [row for row in csv.reader(text.splitlines(), strict=True) if any(cell.strip() for cell in row)]
    except (OSError, UnicodeError, csv.Error) as exc:
        return False, f"invalid Splint CSV: {exc}"
    if not rows or len(rows[0]) < 2:
        return False, "invalid Splint CSV: expected comma-separated columns"
    width = len(rows[0])
    if any(len(row) != width for row in rows):
        return False, "invalid Splint CSV: inconsistent or truncated rows"
    return True, None


def _normalize_severity(tool: str, value: str, scale: str | None = None) -> str:
    raw = str(value or "").strip().lower()
    if tool == "cppcheck":
        return {
            "error": "high", "warning": "medium", "style": "low", "performance": "low",
            "portability": "low", "information": "info", "debug": "info",
        }.get(raw, "unknown")
    if tool == "flawfinder":
        try:
            numeric = float(raw)
        except ValueError:
            return {"error": "high", "warning": "medium", "note": "info", "none": "unknown"}.get(raw, "unknown")
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
    return "unknown"


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
    return bool(re.search(
        r"parse.?error|syntax.?error|preprocess(?:or|ing)?(?:.?error)?|cannot (?:continue|parse)|internal.?(?:bug|error)|"
        r"cannot (?:find|open|read).*include|include file .*not found|missing.?include|configuration.?error|"
        r"unrecognized (?:option|flag|identifier)|unknown option|no valid configuration",
        value, re.I,
    ))


def _is_fatal(value: str) -> bool:
    return bool(re.search(r"fatal|parse.?error|syntax.?error|cannot (?:continue|parse)|internal.?(?:bug|error)", value, re.I))


def _diagnostic_category(value: str) -> str:
    if re.search(r"parse|syntax|cannot continue|internal|unrecognized identifier", value, re.I):
        return "parsing"
    if re.search(r"include", value, re.I):
        return "include"
    if re.search(r"preprocess|configuration|macro|option|flag", value, re.I):
        return "configuration"
    return "tool"


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


def _top_counts(values: Iterable[str], key: str) -> list[dict[str, Any]]:
    return [{key: value, "count": count} for value, count in Counter(value or "<unknown>" for value in values).most_common(20)]


def _line_number(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 2**31 - 1


def _finding_category(item: dict[str, Any]) -> str:
    value = f"{item.get('cwe', '')} {item.get('rule_id', '')} {item.get('message', '')}"
    match = re.search(r"CWE-?(\d+)", value, re.I)
    cwe = int(match.group(1)) if match else None
    if cwe == 476:
        return "null-dereference"
    if cwe in {119, 120, 121, 122, 124, 125, 126, 127, 131, 680, 787, 788, 805}:
        return "buffer"
    if cwe == 457:
        return "uninitialized"
    if cwe in {401, 404, 772, 775}:
        return "resource-leak"
    if cwe == 134:
        return "format"
    if cwe in {327, 330, 338}:
        return "randomness"
    for category, pattern in (
        ("null-dereference", r"null pointer|nullpointer|nullderef"),
        ("buffer", r"buffer|overflow|strcpy|strcat|memcpy|memmove"),
        ("uninitialized", r"uninit|used before definition|use.?def"),
        ("resource-leak", r"memory leak|resource leak|not released"),
        ("format", r"format|string format|printf|scanf"),
        ("randomness", r"random|srand|rand\("),
    ):
        if re.search(pattern, value, re.I):
            return category
    return f"CWE-{cwe}" if cwe is not None else "unknown"


def _build_overlap_groups(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in findings:
        if item["canonical_path"] and _line_number(item.get("line")) < 2**31 - 1:
            grouped[(item["canonical_path"], _finding_category(item))].append(item)
    result = []
    for (path, category), items in sorted(grouped.items()):
        items.sort(key=lambda item: (_line_number(item["line"]), _producer_rank(item["tool"])))
        distance = OVERLAP_LINE_DISTANCE if category != "unknown" else 0
        current: list[dict[str, Any]] = []
        first_line: int | None = None
        for item in items:
            line = _line_number(item["line"])
            if current and first_line is not None and line - first_line > distance:
                _emit_overlap(result, path, category, current)
                current, first_line = [], None
            if not current:
                first_line = line
            current.append(item)
        _emit_overlap(result, path, category, current)
    return result


def _emit_overlap(result: list[dict[str, Any]], path: str, category: str, items: list[dict[str, Any]]) -> None:
    tools = {item["tool"] for item in items}
    if len(tools) < 2:
        return
    start = min(_line_number(item["line"]) for item in items)
    end = max(_line_number(item["line"]) for item in items)
    stable = f"{path}\0{category}\0{start}\0{end}"
    result.append({
        "id": hashlib.sha256(stable.encode()).hexdigest()[:16], "canonical_path": path,
        "line": str(start) if start == end else f"{start}-{end}", "line_start": start, "line_end": end,
        "category": category, "tools": sorted(tools, key=_producer_rank),
        "fingerprints": [item["fingerprint"] for item in items],
    })

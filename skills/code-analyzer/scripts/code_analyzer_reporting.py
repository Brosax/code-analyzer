#!/usr/bin/env python3
"""Aggregation, rendering, and atomic report publication."""

from __future__ import annotations

import hashlib
import html
import json
import os
import re
import shutil
import uuid
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from code_analyzer_runtime import (
    OVERLAP_LINE_DISTANCE,
    REMOVED_COMPATIBILITY_LINKS,
    SCHEMA_VERSION,
    SEVERITY_RANK,
    TOOL_ORDER,
    SourceManifest,
    ToolResult,
)


def canonical_path(file_value: str, project: Path) -> str:
    if not file_value:
        return ""
    path = Path(file_value)
    root = project if project.is_dir() else project.parent
    absolute = path if path.is_absolute() else root / path
    try:
        return absolute.resolve(strict=False).relative_to(root.resolve()).as_posix()
    except ValueError:
        return absolute.resolve(strict=False).as_posix()


def _fingerprint(finding: Dict[str, Any]) -> str:
    stable = "\0".join(
        str(finding.get(key, "")).strip().lower()
        for key in ("tool", "canonical_path", "line", "column", "rule_id", "message")
    )
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def _top_counts(values: Iterable[str], key: str) -> List[Dict[str, Any]]:
    return [{key: value, "count": count} for value, count in Counter(value or "<unknown>" for value in values).most_common(20)]


def _line_number(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 2 ** 31 - 1


def _finding_category(finding: Dict[str, Any]) -> str:
    value = "%s %s %s" % (
        finding.get("cwe", ""), finding.get("rule_id", ""), finding.get("message", ""),
    )
    cwe_match = re.search(r"CWE-?(\d+)", value, re.I)
    cwe = int(cwe_match.group(1)) if cwe_match else None
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
    categories = (
        ("null-dereference", r"null pointer|nullpointer|nullderef"),
        ("buffer", r"buffer|overflow|strcpy|strcat|memcpy|memmove"),
        ("uninitialized", r"uninit|used before definition|use.?def"),
        ("resource-leak", r"memory leak|resource leak|not released"),
        ("format", r"format|string format|printf|scanf"),
        ("randomness", r"random|srand|rand\("),
    )
    for category, pattern in categories:
        if re.search(pattern, value, re.I):
            return category
    if cwe is not None:
        return "CWE-%s" % cwe
    return "unknown"


def _build_overlap_groups(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped = defaultdict(list)
    for item in findings:
        if item["canonical_path"] and item["line"] and _line_number(item["line"]) < 2 ** 31 - 1:
            grouped[(item["canonical_path"], _finding_category(item))].append(item)
    overlap_groups = []

    def emit(path: str, category: str, items: List[Dict[str, Any]]) -> None:
        tools = {item["tool"] for item in items}
        if len(tools) < 2:
            return
        start = min(_line_number(item["line"]) for item in items)
        end = max(_line_number(item["line"]) for item in items)
        stable = "%s\0%s\0%s\0%s" % (path, category, start, end)
        overlap_groups.append({
            "id": hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16],
            "canonical_path": path, "line": str(start) if start == end else "%s-%s" % (start, end),
            "line_start": start, "line_end": end, "category": category,
            "tools": sorted(tools, key=TOOL_ORDER.index),
            "fingerprints": [item["fingerprint"] for item in items],
        })

    for (path, category), items in sorted(grouped.items()):
        items.sort(key=lambda item: (_line_number(item["line"]), TOOL_ORDER.index(item["tool"])))
        distance = OVERLAP_LINE_DISTANCE if category != "unknown" else 0
        current = []
        first_line = None
        for item in items:
            line = _line_number(item["line"])
            if current and first_line is not None and line - first_line > distance:
                emit(path, category, current)
                current = []
                first_line = None
            if not current:
                first_line = line
            current.append(item)
        if current:
            emit(path, category, current)
    return overlap_groups


def aggregate_results(project: Path, results: Sequence[ToolResult], run_id: str,
                      started_at: Optional[str] = None, completed_at: Optional[str] = None,
                      manifest: Optional[SourceManifest] = None) -> Dict[str, Any]:
    findings = []
    diagnostics = []
    for result in results:
        for finding in result.findings:
            item = asdict(finding)
            item["severity"] = item["severity"] if item["severity"] in SEVERITY_RANK else "unknown"
            item["rank"] = SEVERITY_RANK[item["severity"]]
            item["canonical_path"] = canonical_path(item["file"], project)
            item["fingerprint"] = _fingerprint(item)
            findings.append(item)
        for diagnostic in result.diagnostics:
            item = asdict(diagnostic)
            item["canonical_path"] = canonical_path(item["file"], project)
            diagnostics.append(item)
    findings.sort(key=lambda item: (
        -item["rank"], TOOL_ORDER.index(item["tool"]), item["canonical_path"],
        _line_number(item["line"]), str(item["line"]),
    ))
    diagnostics.sort(key=lambda item: (
        TOOL_ORDER.index(item["tool"]), not item["fatal"], item["canonical_path"], _line_number(item["line"]),
    ))
    overlap_groups = _build_overlap_groups(findings)
    severity_counts = Counter(item["severity"] for item in findings)
    return {
        "schema_version": SCHEMA_VERSION,
        "project": str(project.resolve()),
        "run": {
            "id": run_id,
            "started_at": started_at,
            "completed_at": completed_at,
            "tool_order": [result.tool for result in results],
        },
        "tools": {result.tool: result.status_dict() for result in results},
        "source_manifest": manifest.payload() if manifest else None,
        "total_findings": len(findings),
        "total_diagnostics": len(diagnostics),
        "severity_counts": {key: severity_counts[key] for key in ("critical", "high", "medium", "low", "info", "unknown") if severity_counts[key]},
        "top_files": _top_counts((item["canonical_path"] for item in findings), "file"),
        "top_rules": _top_counts((item["rule_id"] for item in findings), "rule_id"),
        "top_cwes": _top_counts((item["cwe"] for item in findings if item["cwe"]), "cwe"),
        "findings": findings,
        "diagnostics": diagnostics,
        "overlap_groups": overlap_groups,
    }


def markdown_report(summary: Dict[str, Any], max_findings: int) -> str:
    lines = ["# Code Analyzer", "", "Project: `%s`" % summary["project"],
             "Run: `%s`" % summary["run"]["id"], "Total findings: `%s`" % summary["total_findings"],
             "Tool diagnostics: `%s`" % summary["total_diagnostics"],
             "", "## Tool Status", ""]
    for tool, data in summary["tools"].items():
        reason = " — %s" % data["reason"] if data.get("reason") else ""
        lines.append("- `%s`: `%s`; findings: `%s`%s" % (tool, data["status"], data["total_findings"], reason))
    lines.extend(("", "## Severity Counts", ""))
    if summary["severity_counts"]:
        lines.extend("- `%s`: %s" % item for item in summary["severity_counts"].items())
    else:
        lines.append("- No findings.")
    lines.extend(("", "## Tool Diagnostics", ""))
    if summary["diagnostics"]:
        for diagnostic in summary["diagnostics"]:
            lines.append("- `%s` `%s` `%s` %s:%s — %s" % (
                diagnostic["severity"], diagnostic["tool"], diagnostic["category"],
                diagnostic["canonical_path"] or "<unknown>", diagnostic["line"], diagnostic["message"],
            ))
    else:
        lines.append("- No tool diagnostics.")
    lines.extend(("", "## Cross-tool Overlap", ""))
    if summary["overlap_groups"]:
        for group in summary["overlap_groups"]:
            lines.append("- `%s:%s`: %s" % (group["canonical_path"], group["line"], ", ".join(group["tools"])))
    else:
        lines.append("- No cross-tool overlap groups.")
    lines.extend(("", "## Findings (first %s)" % max_findings, ""))
    for finding in summary["findings"][:max_findings]:
        lines.append("- `%s` `%s` `%s` %s:%s — %s" % (
            finding["severity"], finding["tool"], finding["rule_id"],
            finding["canonical_path"] or "<unknown>", finding["line"], finding["message"],
        ))
    if not summary["findings"]:
        lines.append("- No findings to list.")
    lines.extend(("", "## Notes", "", "- Findings require confirmation against source before code changes.",
                  "- Cross-tool overlap groups preserve every original finding; they do not deduplicate results."))
    return "\n".join(lines) + "\n"


def html_report(summary: Dict[str, Any], max_findings: int) -> str:
    rows = "".join(
        '<tr data-severity="%s" data-tool="%s"><td>%s</td><td>%s</td><td>%s</td><td>%s:%s</td><td>%s</td></tr>' % tuple(
            html.escape(str(value)) for value in (
                item["severity"], item["tool"], item["severity"], item["tool"], item["rule_id"],
                item["canonical_path"], item["line"], item["message"]
            )
        ) for item in summary["findings"][:max_findings]
    )
    statuses = "".join("<li><b>%s</b>: %s (%s findings, %s diagnostics)%s</li>" % (
        html.escape(tool), html.escape(data["status"]), data["total_findings"], data["total_diagnostics"],
        " — %s" % html.escape(str(data["reason"])) if data.get("reason") else "",
    ) for tool, data in summary["tools"].items())
    diagnostic_rows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s:%s</td><td>%s</td></tr>" % tuple(
        html.escape(str(value)) for value in (
            item["severity"], item["tool"], item["category"], item["canonical_path"], item["line"], item["message"]
        )
    ) for item in summary["diagnostics"])
    severity_options = "".join('<option value="%s">%s</option>' % (html.escape(value), html.escape(value))
                               for value in summary["severity_counts"])
    tool_options = "".join('<option value="%s">%s</option>' % (html.escape(value), html.escape(value))
                           for value in summary["tools"])
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Code Analyzer</title><style>body{font:14px system-ui;margin:2rem;color:#172033}header{background:#172033;color:white;padding:1rem}.filters{display:flex;gap:.75rem;flex-wrap:wrap;margin:1rem 0}.filters input,.filters select{padding:.45rem}table{border-collapse:collapse;width:100%%}th,td{border:1px solid #ccd3df;padding:.5rem;text-align:left}tr[hidden]{display:none}.meta{color:#526071}</style></head><body><header><h1>Code Analyzer</h1><p>%s</p></header><p class="meta">%s source files · %s findings · %s diagnostics · <a href="summary.json">summary.json</a></p><h2>Tool status</h2><ul>%s</ul><h2>Tool diagnostics</h2><table><thead><tr><th>Severity</th><th>Tool</th><th>Category</th><th>Location</th><th>Message</th></tr></thead><tbody>%s</tbody></table><h2>Findings (showing %s of %s)</h2><div class="filters"><label>Severity <select id="severity"><option value="">All</option>%s</select></label><label>Tool <select id="tool"><option value="">All</option>%s</select></label><label>Search <input id="search" type="search" placeholder="Rule, file, or message"></label></div><table id="findings"><thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Location</th><th>Message</th></tr></thead><tbody>%s</tbody></table><script>const severity=document.getElementById('severity'),tool=document.getElementById('tool'),search=document.getElementById('search'),rows=[...document.querySelectorAll('#findings tbody tr')];function filter(){const q=search.value.toLowerCase();for(const row of rows){row.hidden=!!((severity.value&&row.dataset.severity!==severity.value)||(tool.value&&row.dataset.tool!==tool.value)||(q&&!row.textContent.toLowerCase().includes(q)));}}for(const input of [severity,tool,search])input.addEventListener('input',filter);</script></body></html>""" % (
        html.escape(summary["project"]), (summary.get("source_manifest") or {}).get("total_files", 0),
        summary["total_findings"], summary["total_diagnostics"], statuses,
        diagnostic_rows or '<tr><td colspan="5">No tool diagnostics</td></tr>',
        min(max_findings, summary["total_findings"]), summary["total_findings"],
        severity_options, tool_options, rows or '<tr><td colspan="5">No findings</td></tr>',
    )


def write_outputs(summary: Dict[str, Any], results: Sequence[ToolResult], run_dir: Path, max_findings: int) -> None:
    for result in results:
        tool_dir = run_dir / result.tool
        tool_dir.mkdir(parents=True, exist_ok=True)
        tool_summary = result.status_dict()
        tool_summary.update({
            "schema_version": SCHEMA_VERSION, "project": summary["project"],
            "findings": [item for item in summary["findings"] if item["tool"] == result.tool],
            "diagnostics": [item for item in summary["diagnostics"] if item["tool"] == result.tool],
        })
        (tool_dir / "summary.json").write_text(json.dumps(tool_summary, indent=2), encoding="utf-8")
        tool_lines = ["# Code Analyzer — %s" % result.tool, "", "Status: `%s`" % result.status,
                      "Findings: `%s`" % len(result.findings),
                      "Diagnostics: `%s`" % len(result.diagnostics), ""]
        if result.reason:
            tool_lines.extend(("Reason: %s" % result.reason, ""))
        (tool_dir / "summary.md").write_text("\n".join(tool_lines), encoding="utf-8")
    combined = run_dir / "combined"
    combined.mkdir(parents=True, exist_ok=True)
    (combined / "source-manifest.json").write_text(
        json.dumps(summary.get("source_manifest") or {}, indent=2), encoding="utf-8"
    )
    (combined / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (combined / "summary.md").write_text(markdown_report(summary, max_findings), encoding="utf-8")
    (combined / "index.html").write_text(html_report(summary, max_findings), encoding="utf-8")


def should_fail(summary: Dict[str, Any], policy: str) -> bool:
    if policy == "none":
        return False
    if policy == "tool-error":
        return any(data.get("status") in ("failed", "timed_out") for data in summary["tools"].values())
    minimum = SEVERITY_RANK[policy]
    return any(int(item["rank"]) >= minimum for item in summary["findings"])


def _safe_run_id(value: Optional[str]) -> str:
    if value:
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", value):
            raise ValueError("invalid run id")
        return value
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return "%s-%s" % (stamp, uuid.uuid4().hex[:8])


def _atomic_symlink(target: str, link: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    temporary = link.parent / (".%s.%s.tmp" % (link.name, uuid.uuid4().hex[:8]))
    try:
        temporary.symlink_to(target, target_is_directory=True)
        os.replace(str(temporary), str(link))
    finally:
        if temporary.is_symlink():
            temporary.unlink()


def _migrate_flat_report(out_root: Path, runs: Path) -> Optional[Tuple[Path, List[str]]]:
    names = list(TOOL_ORDER) + ["combined"] + list(REMOVED_COMPATIBILITY_LINKS)
    directories = []
    for name in names:
        path = out_root / name
        if path.is_symlink() or not path.exists():
            continue
        if not path.is_dir():
            raise FileExistsError("report compatibility path is not a directory or symlink: %s" % path)
        directories.append(name)
    if not directories:
        return None
    run_id = "legacy-%s-%s" % (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), uuid.uuid4().hex[:8])
    staging = runs / (".%s.migrating" % run_id)
    final = runs / run_id
    staging.mkdir()
    moved = []
    try:
        for name in directories:
            os.replace(str(out_root / name), str(staging / name))
            moved.append(name)
        os.replace(str(staging), str(final))
    except Exception:
        source = final if final.exists() else staging
        for name in reversed(moved):
            if (source / name).exists():
                os.replace(str(source / name), str(out_root / name))
        if staging.exists():
            staging.rmdir()
        if final.exists():
            final.rmdir()
        raise
    return final, directories


def _rollback_flat_report(migration: Optional[Tuple[Path, List[str]]], out_root: Path) -> None:
    if not migration:
        return
    legacy_run, names = migration
    for name in names:
        source = legacy_run / name
        if source.exists():
            os.replace(str(source), str(out_root / name))
    if legacy_run.exists():
        legacy_run.rmdir()


def _link_snapshot(out_root: Path, names: Sequence[str]) -> Dict[str, Optional[str]]:
    snapshot = {}
    for name in names:
        path = out_root / name
        if path.is_symlink():
            snapshot[name] = os.readlink(str(path))
        elif path.exists():
            raise FileExistsError("report link path is not a symlink: %s" % path)
        else:
            snapshot[name] = None
    return snapshot


def _restore_links(out_root: Path, snapshot: Dict[str, Optional[str]]) -> None:
    errors = []
    for name, target in snapshot.items():
        path = out_root / name
        try:
            if path.is_symlink():
                path.unlink()
            if target is not None:
                path.symlink_to(target, target_is_directory=True)
        except OSError as exc:
            errors.append("%s: %s" % (path, exc))
    if errors:
        raise OSError("unable to restore report links: %s" % "; ".join(errors))


def publish_run(staging: Path, out_root: Path, run_id: str, overwrite: bool) -> Path:
    runs = out_root / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    final = runs / run_id
    backup = None
    link_names = ["latest"] + list(TOOL_ORDER) + ["combined"] + list(REMOVED_COMPATIBILITY_LINKS)
    latest = out_root / "latest"
    if latest.exists() and not latest.is_symlink():
        raise FileExistsError("report latest path is not a symlink: %s" % latest)
    migration = _migrate_flat_report(out_root, runs)
    try:
        snapshot = _link_snapshot(out_root, link_names)
    except Exception:
        _rollback_flat_report(migration, out_root)
        raise
    if final.exists() or final.is_symlink():
        if not overwrite:
            _rollback_flat_report(migration, out_root)
            raise FileExistsError("run id already exists: %s" % run_id)
        backup = runs / (".%s.replaced.%s" % (run_id, uuid.uuid4().hex[:8]))
        try:
            os.replace(str(final), str(backup))
        except Exception:
            _rollback_flat_report(migration, out_root)
            raise
    try:
        os.replace(str(staging), str(final))
        _atomic_symlink("runs/%s" % run_id, latest)
        for name in list(TOOL_ORDER) + ["combined"]:
            link = out_root / name
            if (final / name).exists():
                _atomic_symlink("latest/%s" % name, link)
            elif link.is_symlink():
                link.unlink()
        for name in REMOVED_COMPATIBILITY_LINKS:
            link = out_root / name
            if link.is_symlink():
                link.unlink()
    except Exception as publish_error:
        rollback_errors = []
        for operation in (
            lambda: _restore_links(out_root, snapshot),
            lambda: os.replace(str(final), str(staging)) if final.exists() or final.is_symlink() else None,
            lambda: os.replace(str(backup), str(final)) if backup and (backup.exists() or backup.is_symlink()) else None,
            lambda: _rollback_flat_report(migration, out_root),
        ):
            try:
                operation()
            except Exception as exc:
                rollback_errors.append(str(exc))
        if rollback_errors:
            raise RuntimeError(
                "report publication failed and rollback was incomplete: %s" % "; ".join(rollback_errors)
            ) from publish_error
        raise
    if backup and (backup.exists() or backup.is_symlink()):
        if backup.is_symlink():
            backup.unlink()
        else:
            shutil.rmtree(str(backup), ignore_errors=True)
    return final

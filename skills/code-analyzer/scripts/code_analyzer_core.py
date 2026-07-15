#!/usr/bin/env python3
"""Core runtime for the Code Analyzer skill (standard-library only)."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


SCHEMA_VERSION = "2.0"
TOOL_ORDER = ("cppcheck", "flawfinder", "splint")
REQUIRED_TOOLS = frozenset(("cppcheck", "flawfinder"))
REMOVED_COMPATIBILITY_LINKS = ("clang-tidy",)
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}


@dataclass
class Finding:
    tool: str
    severity: str
    rule_id: str
    message: str
    file: str = ""
    line: str = ""
    cwe: str = ""
    column: str = ""
    source_report: str = ""


@dataclass
class ToolRequest:
    tool: str
    command: List[str]
    cwd: Path
    out_dir: Path
    required: bool
    timeout_seconds: int = 1800
    accepted_returncodes: Tuple[int, ...] = (0,)
    stdout_name: str = "stdout.txt"
    stderr_name: str = "stderr.txt"
    version_command: Optional[List[str]] = None


@dataclass
class ToolResult:
    tool: str
    status: str
    reason: str = ""
    findings: List[Finding] = field(default_factory=list)
    command: List[str] = field(default_factory=list)
    returncode: Optional[int] = None
    version: str = ""
    executable: str = ""
    duration_seconds: float = 0.0
    required: bool = False
    stdout: str = ""
    stderr: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def status_dict(self) -> Dict[str, Any]:
        payload = {
            "status": self.status,
            "reason": self.reason,
            "required": self.required,
            "command": self.command,
            "returncode": self.returncode,
            "executable": self.executable,
            "version": self.version,
            "duration_seconds": round(self.duration_seconds, 6),
            "total_findings": len(self.findings),
            "summary": "%s/summary.json" % self.tool,
        }
        payload.update(self.metadata)
        return payload


def _resolve_executable(value: str) -> Optional[str]:
    if os.path.sep in value or (os.path.altsep and os.path.altsep in value):
        path = Path(value).expanduser()
        return str(path.resolve()) if path.is_file() and os.access(str(path), os.X_OK) else None
    return shutil.which(value)


def probe_tool(binary: str, required: bool, capabilities: Sequence[str],
               version_args: Sequence[str] = ("--version",)) -> Dict[str, Any]:
    executable = _resolve_executable(binary)
    if not executable:
        return {
            "path": None,
            "version": None,
            "available": False,
            "required": required,
            "capabilities": list(capabilities),
            "reason": "executable not found: %s" % binary,
        }
    version = ""
    reason = ""
    try:
        completed = subprocess.run(
            [executable] + list(version_args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=False, timeout=5,
        )
        version = (completed.stdout.strip() or completed.stderr.strip()).splitlines()[0][:500]
    except (OSError, subprocess.SubprocessError) as exc:
        reason = "version probe failed: %s" % exc
    return {
        "path": executable,
        "version": version or None,
        "available": True,
        "required": required,
        "capabilities": list(capabilities),
        "reason": reason or None,
    }


def _terminate_process_group(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except OSError:
            pass


def execute_request(request: ToolRequest) -> ToolResult:
    """Run one analyzer with preflight, version capture, streamed logs and timeout."""
    started = time.monotonic()
    executable = _resolve_executable(request.command[0])
    if not executable:
        status = "failed" if request.required else "skipped"
        return ToolResult(
            request.tool, status, "executable not found: %s" % request.command[0],
            command=request.command, required=request.required,
            duration_seconds=time.monotonic() - started,
        )
    command = [executable] + request.command[1:]
    version_cmd = request.version_command or [executable, "--version"]
    version = ""
    try:
        version_result = subprocess.run(
            version_cmd, cwd=str(request.cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=False, timeout=min(10, max(1, request.timeout_seconds)),
        )
        version = (version_result.stdout.strip() or version_result.stderr.strip()).splitlines()[0][:500]
    except (OSError, subprocess.SubprocessError):
        version = "unknown"

    request.out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = request.out_dir / request.stdout_name
    stderr_path = request.out_dir / request.stderr_name
    stdout_parts: List[str] = []
    stderr_parts: List[str] = []
    try:
        process = subprocess.Popen(
            command,
            cwd=str(request.cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            start_new_session=(os.name == "posix"),
        )
    except OSError as exc:
        return ToolResult(
            request.tool, "failed" if request.required else "skipped", str(exc),
            command=command, version=version, executable=executable, required=request.required,
            duration_seconds=time.monotonic() - started,
        )

    def drain(stream: Any, path: Path, parts: List[str]) -> None:
        with path.open("w", encoding="utf-8") as output:
            for chunk in iter(stream.readline, ""):
                parts.append(chunk)
                output.write(chunk)
                output.flush()
        stream.close()

    threads = [
        threading.Thread(target=drain, args=(process.stdout, stdout_path, stdout_parts), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr_path, stderr_parts), daemon=True),
    ]
    for thread in threads:
        thread.start()

    status = "ok"
    reason = ""
    try:
        process.wait(timeout=request.timeout_seconds)
        if process.returncode not in request.accepted_returncodes:
            status = "failed"
            reason = "unexpected exit code: %s" % process.returncode
    except subprocess.TimeoutExpired:
        status = "timed_out"
        reason = "timed out after %s seconds" % request.timeout_seconds
        _terminate_process_group(process)
    except KeyboardInterrupt:
        _terminate_process_group(process)
        raise
    finally:
        for thread in threads:
            thread.join(timeout=3)

    return ToolResult(
        request.tool, status, reason, command=command, returncode=process.returncode,
        version=version, executable=executable, duration_seconds=time.monotonic() - started,
        required=request.required, stdout="".join(stdout_parts), stderr="".join(stderr_parts),
    )


def _severity_cppcheck(value: str) -> str:
    return {
        "error": "high", "warning": "medium", "style": "low", "performance": "low",
        "portability": "low", "information": "info",
    }.get(value.lower(), "unknown")


def _severity_flawfinder(value: str) -> str:
    try:
        level = int(value)
    except (TypeError, ValueError):
        return "unknown"
    return "critical" if level >= 5 else "high" if level == 4 else "medium" if level == 3 else "low" if level >= 1 else "unknown"


def _parse_cppcheck(text: str) -> List[Finding]:
    start = text.find("<?xml")
    if start < 0:
        start = text.find("<results")
    if start < 0:
        if text.strip():
            raise ValueError("Cppcheck output did not contain XML")
        return []
    root = ET.fromstring(text[start:])
    findings = []
    for error in root.findall(".//error"):
        locations = error.findall("location") or [None]
        for location in locations:
            findings.append(Finding(
                "cppcheck", _severity_cppcheck(error.get("severity", "")), error.get("id", ""),
                error.get("msg", "") or error.get("verbose", ""),
                location.get("file", "") if location is not None else "",
                location.get("line", "") if location is not None else "",
                "", location.get("column", "") if location is not None else "",
                "cppcheck/summary.json",
            ))
    return findings


def _parse_flawfinder_csv(text: str) -> List[Finding]:
    if not text.strip():
        return []
    header_index = text.find("File,Line,")
    if header_index < 0:
        return _parse_flawfinder_text(text)
    rows = csv.DictReader(text[header_index:].splitlines())
    findings = []
    for row in rows:
        if not row.get("File"):
            continue
        cwes = row.get("CWEs", "")
        cwe_match = re.search(r"CWE-?\d+", cwes, re.I)
        cwe = cwe_match.group(0).upper().replace("CWE", "CWE-").replace("CWE--", "CWE-") if cwe_match else ""
        category = row.get("Category", "")
        name = row.get("Name", "")
        findings.append(Finding(
            "flawfinder", _severity_flawfinder(row.get("Level", "")),
            "%s:%s" % (category, name) if category or name else cwe,
            row.get("Warning", "") or row.get("Suggestion", ""), row.get("File", ""),
            row.get("Line", ""), cwe, row.get("Column", ""), "flawfinder/summary.json",
        ))
    return findings


_FLAWFINDER_TEXT = re.compile(r"^(.*?):(\d+):\s+\[(\d+)\]\s+\(([^)]+)\)\s+([^:]+):\s*(.*)$")


def _parse_flawfinder_text(text: str) -> List[Finding]:
    findings = []
    current = None
    details = []

    def flush() -> None:
        nonlocal current, details
        if current is None:
            return
        message = " ".join([current[5]] + [item.strip() for item in details if item.strip()]).strip()
        cwe_match = re.search(r"CWE-?\d+", message, re.I)
        cwe = cwe_match.group(0).upper().replace("CWE", "CWE-").replace("CWE--", "CWE-") if cwe_match else ""
        findings.append(Finding(
            "flawfinder", _severity_flawfinder(current[2]), "%s:%s" % (current[3], current[4]),
            message, current[0], current[1], cwe, "", "flawfinder/summary.json",
        ))
        current, details = None, []

    for line in text.splitlines():
        match = _FLAWFINDER_TEXT.match(line)
        if match:
            flush()
            current = match.groups()
        elif current is not None and line[:1].isspace():
            details.append(line)
    flush()
    if not findings and text.strip():
        raise ValueError("Flawfinder output contained neither CSV nor recognized text findings")
    return findings


_SPLINT_LOCATION = re.compile(r"^(\S.*?):(\d+)(?::(\d+))?:\s+(.+)$")
_SPLINT_FATAL = re.compile(r"fatal|parse error|cannot continue|internal error|unrecognized", re.I)
_SPLINT_INFO = re.compile(r"include|preprocess|configuration|macro", re.I)
_SPLINT_UNKNOWN = re.compile(r"^<\s*Location unknown\s*>:\s+(.+)$", re.I)
_SPLINT_WRAPPED_LOCATION = re.compile(r"^(.+?):(\d+):\s*$")
_SPLINT_WRAPPED_COLUMN = re.compile(r"^\s+(\d+):\s+(.+)$")
_SPLINT_WRAPPED_PATH = re.compile(r"^\s+(.+?):(\d+)(?::(\d+))?:\s*(.*)$")


def _parse_splint(text: str) -> List[Finding]:
    findings: List[Finding] = []
    current: Optional[Dict[str, str]] = None
    continuation: List[str] = []
    wrapped_location: Optional[Tuple[str, str]] = None
    pending_file_prefix: Optional[str] = None

    def add(message: str, file_value: str = "", line: str = "", column: str = "") -> None:
        severity = "high" if _SPLINT_FATAL.search(message) else "info" if _SPLINT_INFO.search(message) else "medium"
        findings.append(Finding(
            "splint", severity, "splint-warning", message, file_value, line, "", column,
            "splint/summary.json",
        ))

    def flush() -> None:
        nonlocal current, continuation
        if current is None:
            return
        details = " ".join(line.strip() for line in continuation if line.strip())
        message = current["message"] + ((" " + details) if details else "")
        add(message, current["file"], current["line"], current["column"])
        current, continuation = None, []

    for raw_line in text.splitlines():
        if not raw_line.strip():
            continue
        match = _SPLINT_LOCATION.match(raw_line)
        if match:
            flush()
            wrapped_location, pending_file_prefix = None, None
            current = {"file": match.group(1), "line": match.group(2), "column": match.group(3) or "", "message": match.group(4).strip()}
            continue
        unknown = _SPLINT_UNKNOWN.match(raw_line)
        if unknown:
            flush()
            wrapped_location, pending_file_prefix = None, None
            add(unknown.group(1).strip(), "< Location unknown >")
            continue
        if current is not None and raw_line[:1].isspace():
            continuation.append(raw_line)
            continue
        wrapped_path = _SPLINT_WRAPPED_PATH.match(raw_line)
        if pending_file_prefix is not None and wrapped_path:
            flush()
            current = {
                "file": pending_file_prefix + wrapped_path.group(1).strip(), "line": wrapped_path.group(2),
                "column": wrapped_path.group(3) or "", "message": wrapped_path.group(4).strip(),
            }
            pending_file_prefix, wrapped_location = None, None
            continue
        wrapped_column = _SPLINT_WRAPPED_COLUMN.match(raw_line)
        if wrapped_location is not None and wrapped_column:
            flush()
            current = {"file": wrapped_location[0], "line": wrapped_location[1], "column": wrapped_column.group(1), "message": wrapped_column.group(2).strip()}
            wrapped_location, pending_file_prefix = None, None
            continue
        location = _SPLINT_WRAPPED_LOCATION.match(raw_line)
        if location:
            flush()
            wrapped_location, pending_file_prefix = (location.group(1), location.group(2)), None
            continue
        if current is not None and not raw_line[:1].isspace():
            flush()
        if current is None and (_SPLINT_FATAL.search(raw_line) or _SPLINT_INFO.search(raw_line)):
            wrapped_location, pending_file_prefix = None, None
            add(raw_line.strip())
            continue
        if current is None and ":" not in raw_line and "/" in raw_line and not raw_line[:1].isspace():
            pending_file_prefix, wrapped_location = raw_line.strip(), None
    flush()
    unique = []
    seen = set()
    for finding in findings:
        key = (finding.file, finding.line, finding.column, finding.severity, finding.message)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def _discover_sources(project: Path, suffixes: Iterable[str]) -> List[Path]:
    suffix_set = set(suffixes)
    if project.is_file():
        return [project] if project.suffix.lower() in suffix_set else []
    ignored = {".git", ".hg", ".svn", "node_modules", ".cache", ".tools"}
    return sorted(
        path for path in project.rglob("*")
        if path.is_file() and path.suffix.lower() in suffix_set and not any(part in ignored for part in path.parts)
    )


def find_compile_commands(project: Path, explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_absolute():
            path = (project if project.is_dir() else project.parent) / path
        if path.is_dir():
            path = path / "compile_commands.json"
        return path.resolve() if path.is_file() else None
    root = project if project.is_dir() else project.parent
    for candidate in (root / "compile_commands.json", root / "build" / "compile_commands.json"):
        if candidate.is_file():
            return candidate.resolve()
    return None


def _run_cppcheck(args: argparse.Namespace, project: Path, out_dir: Path) -> ToolResult:
    command = [args.cppcheck_bin, "--xml", "--xml-version=2", "--enable=%s" % args.cppcheck_enable, "--inline-suppr"]
    if args.jobs:
        command.append("-j%s" % args.jobs)
    if args.inconclusive:
        command.append("--inconclusive")
    if args.force:
        command.append("--force")
    for name in ("std", "platform"):
        value = getattr(args, name)
        if value:
            command.append("--%s=%s" % (name, value))
    if args.suppressions_list:
        command.append("--suppressions-list=%s" % args.suppressions_list)
    compile_commands = find_compile_commands(project, args.compile_commands)
    command.append("--project=%s" % compile_commands if compile_commands else str(project))
    request = ToolRequest("cppcheck", command, project if project.is_dir() else project.parent, out_dir, True,
                          args.timeout_seconds, (0, 1), "cppcheck.stdout.txt", "cppcheck.xml")
    result = execute_request(request)
    if result.status == "ok":
        try:
            result.findings = _parse_cppcheck(result.stderr)
        except (ValueError, ET.ParseError) as exc:
            result.status, result.reason = "failed", "unable to parse Cppcheck output: %s" % exc
    result.metadata["compile_commands"] = str(compile_commands) if compile_commands else None
    return result


def _run_flawfinder(args: argparse.Namespace, project: Path, out_dir: Path) -> ToolResult:
    command = [args.flawfinder_bin, "--csv"]
    if args.flawfinder_minlevel is not None:
        command.append("--minlevel=%s" % args.flawfinder_minlevel)
    if args.context:
        command.append("--context")
    if args.patch:
        command.extend(("--patch", args.patch))
    command.extend(args.flawfinder_extra_arg)
    command.append(str(project))
    request = ToolRequest("flawfinder", command, project if project.is_dir() else project.parent, out_dir, True,
                          args.timeout_seconds, (0, 1), "flawfinder.txt", "flawfinder.stderr.txt")
    result = execute_request(request)
    if result.status == "ok":
        try:
            result.findings = _parse_flawfinder_csv(result.stdout)
        except ValueError as exc:
            result.status, result.reason = "failed", "unable to parse Flawfinder output: %s" % exc
    result.metadata["scan_count"] = 1 if result.returncode is not None else 0
    return result


def _include_dirs(project: Path, explicit: Sequence[str]) -> List[str]:
    root = project if project.is_dir() else project.parent
    ordered = list(explicit)
    seen = {str((root / value).resolve()) if not Path(value).is_absolute() else str(Path(value).resolve()) for value in explicit}
    if project.is_dir():
        for header in project.rglob("*.h"):
            relative_parts = header.relative_to(project).parts
            if any(
                part.startswith(".") or part == "node_modules" or
                part.startswith("review-suite-report") or part.startswith("code-analyzer-report") or
                part.startswith("splint-report")
                for part in relative_parts
            ):
                continue
            value = str(header.parent.resolve())
            if value not in seen:
                seen.add(value)
                ordered.append(value)
    return ordered


def _run_splint(args: argparse.Namespace, project: Path, out_dir: Path) -> ToolResult:
    sources = _discover_sources(project, (".c",))
    if not sources:
        return ToolResult("splint", "skipped", "no C source files found", required=False)
    includes = _include_dirs(project, args.splint_include)
    command = [args.splint_bin]
    command.extend("-I%s" % value for value in includes)
    command.extend("-D%s" % value for value in args.splint_define)
    command.extend(args.splint_flag)
    command.extend(str(path) for path in sources)
    request = ToolRequest(
        "splint", command, project if project.is_dir() else project.parent, out_dir, False,
        args.timeout_seconds, (0, 1), "splint.txt", "splint.stderr.txt",
        [args.splint_bin, "-help", "version"],
    )
    result = execute_request(request)
    if result.status == "ok":
        result.findings = _parse_splint("\n".join((result.stdout, result.stderr)))
    result.metadata.update({"source_count": len(sources), "include_dirs": includes})
    return result


AnalyzerAdapter = Callable[[argparse.Namespace, Path, Path], ToolResult]


ADAPTERS: Dict[str, AnalyzerAdapter] = {
    "cppcheck": _run_cppcheck,
    "flawfinder": _run_flawfinder,
    "splint": _run_splint,
}


def run_tools(args: argparse.Namespace, project: Path, run_dir: Path, tools: Sequence[str]) -> List[ToolResult]:
    def invoke(tool: str) -> ToolResult:
        out_dir = run_dir / tool
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            return ADAPTERS[tool](args, project, out_dir)
        except Exception as exc:  # Keep partial reports usable after one adapter fails.
            return ToolResult(tool, "failed", "adapter error: %s" % exc, required=tool in REQUIRED_TOOLS)

    if args.tool_jobs <= 1 or len(tools) <= 1:
        return [invoke(tool) for tool in tools]
    results = {}
    with ThreadPoolExecutor(max_workers=args.tool_jobs) as pool:
        futures = {pool.submit(invoke, tool): tool for tool in tools}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return [results[tool] for tool in tools]


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


def aggregate_results(project: Path, results: Sequence[ToolResult], run_id: str,
                      started_at: Optional[str] = None, completed_at: Optional[str] = None) -> Dict[str, Any]:
    findings = []
    for result in results:
        for finding in result.findings:
            item = asdict(finding)
            item["severity"] = item["severity"] if item["severity"] in SEVERITY_RANK else "unknown"
            item["rank"] = SEVERITY_RANK[item["severity"]]
            item["canonical_path"] = canonical_path(item["file"], project)
            item["fingerprint"] = _fingerprint(item)
            findings.append(item)
    findings.sort(key=lambda item: (-item["rank"], TOOL_ORDER.index(item["tool"]), item["canonical_path"], str(item["line"])))
    by_location = defaultdict(list)
    for item in findings:
        if item["canonical_path"] and item["line"]:
            by_location[(item["canonical_path"], str(item["line"]))].append(item)
    overlap_groups = []
    for (path, line), items in sorted(by_location.items()):
        if len({item["tool"] for item in items}) < 2:
            continue
        group_id = hashlib.sha256((path + "\0" + line).encode("utf-8")).hexdigest()[:16]
        overlap_groups.append({
            "id": group_id, "canonical_path": path, "line": line,
            "tools": sorted({item["tool"] for item in items}, key=TOOL_ORDER.index),
            "fingerprints": [item["fingerprint"] for item in items],
        })
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
        "total_findings": len(findings),
        "severity_counts": {key: severity_counts[key] for key in ("critical", "high", "medium", "low", "info", "unknown") if severity_counts[key]},
        "top_files": _top_counts((item["canonical_path"] for item in findings), "file"),
        "top_rules": _top_counts((item["rule_id"] for item in findings), "rule_id"),
        "top_cwes": _top_counts((item["cwe"] for item in findings if item["cwe"]), "cwe"),
        "findings": findings,
        "overlap_groups": overlap_groups,
    }


def markdown_report(summary: Dict[str, Any], max_findings: int) -> str:
    lines = ["# Code Analyzer", "", "Project: `%s`" % summary["project"],
             "Run: `%s`" % summary["run"]["id"], "Total findings: `%s`" % summary["total_findings"],
             "", "## Tool Status", ""]
    for tool, data in summary["tools"].items():
        reason = " — %s" % data["reason"] if data.get("reason") else ""
        lines.append("- `%s`: `%s`; findings: `%s`%s" % (tool, data["status"], data["total_findings"], reason))
    lines.extend(("", "## Severity Counts", ""))
    if summary["severity_counts"]:
        lines.extend("- `%s`: %s" % item for item in summary["severity_counts"].items())
    else:
        lines.append("- No findings.")
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
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s:%s</td><td>%s</td></tr>" % tuple(
            html.escape(str(value)) for value in (
                item["severity"], item["tool"], item["rule_id"], item["canonical_path"], item["line"], item["message"]
            )
        ) for item in summary["findings"][:max_findings]
    )
    statuses = "".join("<li><b>%s</b>: %s (%s)</li>" % (
        html.escape(tool), html.escape(data["status"]), data["total_findings"]
    ) for tool, data in summary["tools"].items())
    return """<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Code Analyzer</title><style>body{font:14px system-ui;margin:2rem;color:#172033}header{background:#172033;color:white;padding:1rem}table{border-collapse:collapse;width:100%%}th,td{border:1px solid #ccd3df;padding:.5rem;text-align:left}pre{overflow:auto;background:#f4f6f9;padding:1rem}</style></head><body><header><h1>Code Analyzer</h1><p>%s</p></header><h2>Tool status</h2><ul>%s</ul><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Location</th><th>Message</th></tr></thead><tbody>%s</tbody></table><h2>Summary JSON</h2><pre>%s</pre></body></html>""" % (
        html.escape(summary["project"]), statuses, rows or '<tr><td colspan="5">No findings</td></tr>',
        html.escape(json.dumps(summary, indent=2)),
    )


def write_outputs(summary: Dict[str, Any], results: Sequence[ToolResult], run_dir: Path, max_findings: int) -> None:
    for result in results:
        tool_dir = run_dir / result.tool
        tool_dir.mkdir(parents=True, exist_ok=True)
        tool_summary = result.status_dict()
        tool_summary.update({
            "schema_version": SCHEMA_VERSION, "project": summary["project"],
            "findings": [item for item in summary["findings"] if item["tool"] == result.tool],
        })
        (tool_dir / "summary.json").write_text(json.dumps(tool_summary, indent=2), encoding="utf-8")
        tool_lines = ["# Code Analyzer — %s" % result.tool, "", "Status: `%s`" % result.status,
                      "Findings: `%s`" % len(result.findings), ""]
        if result.reason:
            tool_lines.extend(("Reason: %s" % result.reason, ""))
        (tool_dir / "summary.md").write_text("\n".join(tool_lines), encoding="utf-8")
    combined = run_dir / "combined"
    combined.mkdir(parents=True, exist_ok=True)
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
    temporary.symlink_to(target, target_is_directory=True)
    os.replace(str(temporary), str(link))


def publish_run(staging: Path, out_root: Path, run_id: str, overwrite: bool) -> Path:
    runs = out_root / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    final = runs / run_id
    backup = None
    if final.exists():
        if not overwrite:
            raise FileExistsError("run id already exists: %s" % run_id)
        backup = runs / (".%s.replaced.%s" % (run_id, uuid.uuid4().hex[:8]))
        os.replace(str(final), str(backup))
    try:
        os.replace(str(staging), str(final))
    except Exception:
        if backup and backup.exists():
            os.replace(str(backup), str(final))
        raise
    if backup:
        shutil.rmtree(str(backup), ignore_errors=True)
    _atomic_symlink("runs/%s" % run_id, out_root / "latest")
    for name in list(TOOL_ORDER) + ["combined"]:
        if (final / name).exists():
            _atomic_symlink("latest/%s" % name, out_root / name)
        elif (out_root / name).is_symlink():
            (out_root / name).unlink()
    for name in REMOVED_COMPATIBILITY_LINKS:
        link = out_root / name
        if link.is_symlink():
            link.unlink()
    return final


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Code Analyzer for C and C++ projects.")
    parser.add_argument("--project", default=".")
    parser.add_argument("--out", default="code-analyzer-report")
    parser.add_argument("--tools", default=",".join(TOOL_ORDER))
    parser.add_argument("--max-findings", type=int, default=100)
    parser.add_argument("--fail-on", choices=("none", "tool-error", "medium", "high", "critical"), default="tool-error")
    parser.add_argument("--cppcheck-bin", default="cppcheck")
    parser.add_argument("--flawfinder-bin", default="flawfinder")
    parser.add_argument("--splint-bin", default="splint")
    parser.add_argument("--tool-jobs", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--run-id")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--jobs", type=int)
    parser.add_argument("--compile-commands")
    parser.add_argument("--suppressions-list")
    parser.add_argument("--std")
    parser.add_argument("--platform")
    parser.add_argument("--cppcheck-enable", "--enable", default="warning,style,performance,portability,information")
    parser.add_argument("--inconclusive", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--flawfinder-minlevel", "--minlevel", type=int)
    parser.add_argument("--context", action="store_true")
    parser.add_argument("--patch")
    parser.add_argument("--flawfinder-extra-arg", "--extra-arg", action="append", default=[])
    parser.add_argument("--splint-flag", "--flag", action="append", default=[])
    parser.add_argument("--splint-include", "--include", action="append", default=[])
    parser.add_argument("--splint-define", "--define", action="append", default=[])
    return parser


def doctor(args: argparse.Namespace) -> Dict[str, Any]:
    specs = {
        "cppcheck": (args.cppcheck_bin, True, ("xml", "compile_commands"), ("--version",)),
        "flawfinder": (args.flawfinder_bin, True, ("csv", "cwe"), ("--version",)),
        "splint": (args.splint_bin, False, ("c-analysis",), ("-help", "version")),
    }
    return {"schema_version": SCHEMA_VERSION, "tools": {
        tool: probe_tool(binary, required, capabilities, version_args)
        for tool, (binary, required, capabilities, version_args) in specs.items()
    }}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    tools = [item.strip() for item in args.tools.split(",") if item.strip()]
    invalid = [tool for tool in tools if tool not in TOOL_ORDER]
    if invalid or len(tools) != len(set(tools)):
        print("error: unsupported or duplicate tool(s): %s" % ", ".join(invalid or tools), file=os.sys.stderr)
        return 2
    if args.doctor:
        print(json.dumps(doctor(args), indent=2))
        return 0
    if args.tool_jobs < 1 or args.timeout_seconds < 1:
        print("error: --tool-jobs and --timeout-seconds must be positive", file=os.sys.stderr)
        return 2
    project = Path(args.project).expanduser().resolve()
    if not project.exists():
        print("error: project does not exist: %s" % project, file=os.sys.stderr)
        return 2
    out_root = Path(args.out).expanduser().resolve()
    try:
        run_id = _safe_run_id(args.run_id)
    except ValueError as exc:
        print("error: %s" % exc, file=os.sys.stderr)
        return 2
    final = out_root / "runs" / run_id
    if final.exists() and not args.overwrite:
        print("error: run id already exists: %s" % run_id, file=os.sys.stderr)
        return 2
    out_root.mkdir(parents=True, exist_ok=True)
    staging = out_root / (".staging-%s-%s" % (run_id, uuid.uuid4().hex[:8]))
    staging.mkdir()
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        results = run_tools(args, project, staging, tools)
        completed_at = datetime.now(timezone.utc).isoformat()
        summary = aggregate_results(project, results, run_id, started_at, completed_at)
        write_outputs(summary, results, staging, args.max_findings)
        published = publish_run(staging, out_root, run_id, args.overwrite)
    except KeyboardInterrupt:
        shutil.rmtree(str(staging), ignore_errors=True)
        print("error: analysis cancelled", file=os.sys.stderr)
        return 130
    except Exception as exc:
        shutil.rmtree(str(staging), ignore_errors=True)
        print("error: %s" % exc, file=os.sys.stderr)
        return 2
    print("report: %s" % published)
    print("combined: %s" % (published / "combined" / "summary.md"))
    print("findings: %s" % summary["total_findings"])
    return 1 if should_fail(summary, args.fail_on) else 0

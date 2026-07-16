#!/usr/bin/env python3
"""Analyzer adapters and output parsers for Code Analyzer."""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import os
import re
import shutil
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from code_analyzer_ai import AI_TOOL, run_ai_review
from code_analyzer_runtime import (
    ALL_SOURCE_SUFFIXES,
    ANALYZERS,
    REQUIRED_TOOLS,
    Finding,
    SourceManifest,
    ToolDiagnostic,
    ToolRequest,
    ToolResult,
    analyzer_adapter,
    execute_request,
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
    return (
        "critical" if level >= 5 else "high" if level == 4 else "medium" if level == 3
        else "low" if level >= 1 else "info" if level == 0 else "unknown"
    )


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
        cwe = "CWE-%s" % error.get("cwe") if error.get("cwe") else ""
        for location in locations:
            findings.append(Finding(
                "cppcheck", _severity_cppcheck(error.get("severity", "")), error.get("id", ""),
                error.get("msg", "") or error.get("verbose", ""),
                location.get("file", "") if location is not None else "",
                location.get("line", "") if location is not None else "",
                cwe, location.get("column", "") if location is not None else "",
                "cppcheck/summary.json",
            ))
    return findings


def _parse_cppcheck_file(path: Path) -> List[Finding]:
    findings = []
    for _, error in ET.iterparse(str(path), events=("end",)):
        if error.tag.rsplit("}", 1)[-1] != "error":
            continue
        locations = [item for item in error if item.tag.rsplit("}", 1)[-1] == "location"] or [None]
        cwe = "CWE-%s" % error.get("cwe") if error.get("cwe") else ""
        for location in locations:
            findings.append(Finding(
                "cppcheck", _severity_cppcheck(error.get("severity", "")), error.get("id", ""),
                error.get("msg", "") or error.get("verbose", ""),
                location.get("file", "") if location is not None else "",
                location.get("line", "") if location is not None else "",
                cwe, location.get("column", "") if location is not None else "",
                "cppcheck/summary.json",
            ))
        error.clear()
    return findings


def _parse_flawfinder_rows(rows: Iterable[Dict[str, str]]) -> List[Finding]:
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


def _parse_flawfinder_csv(text: str) -> List[Finding]:
    if not text.strip():
        return []
    header_index = text.find("File,Line,")
    if header_index < 0:
        return _parse_flawfinder_text(text)
    return _parse_flawfinder_rows(csv.DictReader(text[header_index:].splitlines()))


def _parse_flawfinder_file(path: Path) -> List[Finding]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
        for line in stream:
            if line.startswith("File,Line,"):
                return _parse_flawfinder_rows(csv.DictReader(itertools.chain((line,), stream)))
    text = path.read_text(encoding="utf-8", errors="replace")
    return _parse_flawfinder_text(text) if text.strip() else []


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
_SPLINT_FATAL = re.compile(
    r"fatal|parse error|syntax error|cannot (?:continue|parse)|cannot be parsed|internal error",
    re.I,
)
_SPLINT_DIAGNOSTIC = re.compile(
    r"preprocess(?:ing)? error|cannot (?:find|open|read).*include|"
    r"include file .*not found|configuration error|unrecognized (?:option|flag|identifier)",
    re.I,
)
_SPLINT_UNKNOWN = re.compile(r"^<\s*Location unknown\s*>:\s+(.+)$", re.I)
_SPLINT_WRAPPED_LOCATION = re.compile(r"^(.+?):(\d+):\s*$")
_SPLINT_WRAPPED_COLUMN = re.compile(r"^\s+(\d+):\s+(.+)$")
_SPLINT_WRAPPED_PATH = re.compile(r"^\s+(.+?):(\d+)(?::(\d+))?:\s*(.*)$")


def _splint_diagnostic_category(message: str) -> str:
    if re.search(r"parse|cannot continue|internal error|fatal|unrecognized identifier", message, re.I):
        return "parsing"
    if re.search(r"include", message, re.I):
        return "include"
    if re.search(r"preprocess|configuration|macro", message, re.I):
        return "configuration"
    return "tool"


def _parse_splint_lines(lines: Iterable[str]) -> Tuple[List[Finding], List[ToolDiagnostic]]:
    findings: List[Finding] = []
    diagnostics: List[ToolDiagnostic] = []
    current: Optional[Dict[str, str]] = None
    continuation: List[str] = []
    wrapped_location: Optional[Tuple[str, str]] = None
    pending_file_prefix: Optional[str] = None

    def add(message: str, file_value: str = "", line: str = "", column: str = "") -> None:
        fatal = bool(_SPLINT_FATAL.search(message))
        if fatal or _SPLINT_DIAGNOSTIC.search(message):
            diagnostics.append(ToolDiagnostic(
                "splint", "error" if fatal else "warning", _splint_diagnostic_category(message),
                message, file_value, line, column, fatal,
            ))
            return
        findings.append(Finding(
            "splint", "medium", "splint-warning", message, file_value, line, "", column,
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

    for raw_line in lines:
        raw_line = raw_line.rstrip("\r\n")
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
        if current is None and (_SPLINT_FATAL.search(raw_line) or _SPLINT_DIAGNOSTIC.search(raw_line)):
            wrapped_location, pending_file_prefix = None, None
            add(raw_line.strip())
            continue
        if current is None and ":" not in raw_line and "/" in raw_line and not raw_line[:1].isspace():
            pending_file_prefix, wrapped_location = raw_line.strip(), None
    flush()
    unique_findings = []
    seen_findings = set()
    for finding in findings:
        key = (finding.file, finding.line, finding.column, finding.severity, finding.message)
        if key not in seen_findings:
            seen_findings.add(key)
            unique_findings.append(finding)
    unique_diagnostics = []
    seen_diagnostics = set()
    for diagnostic in diagnostics:
        key = (diagnostic.file, diagnostic.line, diagnostic.column, diagnostic.category, diagnostic.message)
        if key not in seen_diagnostics:
            seen_diagnostics.add(key)
            unique_diagnostics.append(diagnostic)
    return unique_findings, unique_diagnostics


def _parse_splint(text: str) -> Tuple[List[Finding], List[ToolDiagnostic]]:
    return _parse_splint_lines(text.splitlines())


def find_compile_commands(project: Path, explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_absolute():
            path = (project if project.is_dir() else project.parent) / path
        if path.is_dir():
            path = path / "compile_commands.json"
        if not path.is_file():
            raise ValueError("compile_commands.json does not exist: %s" % path.resolve(strict=False))
        return path.resolve()
    root = project if project.is_dir() else project.parent
    for candidate in (root / "compile_commands.json", root / "build" / "compile_commands.json"):
        if candidate.is_file():
            return candidate.resolve()
    return None


def _filtered_compile_database(source: Path, destination: Path, manifest: SourceManifest) -> int:
    try:
        entries = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("invalid compile_commands.json: %s" % exc)
    if not isinstance(entries, list):
        raise ValueError("invalid compile_commands.json: root must be an array")
    allowed = set(manifest.files_for(ALL_SOURCE_SUFFIXES))
    filtered = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("file"):
            continue
        path = Path(str(entry["file"]))
        if not path.is_absolute():
            directory = Path(str(entry.get("directory") or source.parent))
            if not directory.is_absolute():
                directory = source.parent / directory
            path = directory / path
        if path.resolve(strict=False) in allowed:
            filtered.append(entry)
    destination.write_text(json.dumps(filtered, indent=2), encoding="utf-8")
    return len(filtered)


@analyzer_adapter("cppcheck")
def _run_cppcheck(args: argparse.Namespace, project: Path, out_dir: Path) -> ToolResult:
    manifest: SourceManifest = args.source_manifest
    sources = manifest.files_for(ALL_SOURCE_SUFFIXES)
    if not sources:
        return ToolResult("cppcheck", "skipped", "no C/C++ source files matched the source manifest", required=True)
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
    compile_commands = args.compile_commands_path
    compile_entry_count = None
    if compile_commands:
        filtered_database = out_dir / "compile_commands.filtered.json"
        try:
            compile_entry_count = _filtered_compile_database(compile_commands, filtered_database, manifest)
        except ValueError as exc:
            return ToolResult("cppcheck", "failed", str(exc), required=True)
        if compile_entry_count == 0:
            return ToolResult("cppcheck", "failed", "compile_commands.json has no entries matching the source manifest", required=True)
        command.append("--project=%s" % filtered_database)
    else:
        file_list = out_dir / "cppcheck-files.txt"
        file_list.write_text("".join("%s\n" % path for path in sources), encoding="utf-8")
        command.append("--file-list=%s" % file_list)
    request = ToolRequest("cppcheck", command, project if project.is_dir() else project.parent, out_dir, True,
                          args.timeout_seconds, (0, 1), "cppcheck.stdout.txt", "cppcheck.xml",
                          process_registry=args.process_registry)
    result = execute_request(request)
    if result.status == "ok":
        try:
            result.findings = _parse_cppcheck_file(out_dir / "cppcheck.xml")
        except (ValueError, ET.ParseError) as exc:
            result.status, result.reason = "failed", "unable to parse Cppcheck output: %s" % exc
    result.metadata.update({
        "compile_commands": str(compile_commands) if compile_commands else None,
        "compile_entries": compile_entry_count,
        "source_count": len(sources),
    })
    return result


def _build_source_view(files: Sequence[Path], root: Path, view: Path) -> None:
    for source in files:
        try:
            relative = source.relative_to(root)
        except ValueError:
            relative = Path("external") / hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:12] / source.name
        destination = view / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(str(source), str(destination), follow_symlinks=True)
        except OSError:
            shutil.copy2(str(source), str(destination))


def _remap_source_view(findings: Sequence[Finding], view: Path, root: Path) -> None:
    for finding in findings:
        if not finding.file:
            continue
        path = Path(finding.file)
        if view.name in path.parts:
            relative = Path(*path.parts[path.parts.index(view.name) + 1:])
            finding.file = str(root / relative)
            continue
        absolute = path if path.is_absolute() else view / path
        try:
            finding.file = str(root / absolute.resolve(strict=False).relative_to(view.resolve()))
        except ValueError:
            pass


@analyzer_adapter("flawfinder")
def _run_flawfinder(args: argparse.Namespace, project: Path, out_dir: Path) -> ToolResult:
    manifest: SourceManifest = args.source_manifest
    sources = manifest.files_for(ALL_SOURCE_SUFFIXES)
    if not sources:
        return ToolResult("flawfinder", "skipped", "no C/C++ files matched the source manifest", required=True)
    command = [args.flawfinder_bin, "--csv"]
    if args.flawfinder_minlevel is not None:
        command.append("--minlevel=%s" % args.flawfinder_minlevel)
    if args.context:
        command.append("--context")
    if args.patch:
        command.extend(("--patch", args.patch))
    command.extend(args.flawfinder_extra_arg)
    # Flawfinder skips hidden directories during recursive scans.
    source_view = out_dir / "source-view"
    if args.patch:
        command.extend(str(path) for path in sources)
    else:
        _build_source_view(sources, manifest.root, source_view)
        command.append(str(source_view))
    request = ToolRequest("flawfinder", command, project if project.is_dir() else project.parent, out_dir, True,
                          args.timeout_seconds, (0, 1), "flawfinder.txt", "flawfinder.stderr.txt",
                          process_registry=args.process_registry)
    try:
        result = execute_request(request)
        if result.status == "ok":
            try:
                result.findings = _parse_flawfinder_file(out_dir / "flawfinder.txt")
                if not args.patch:
                    _remap_source_view(result.findings, source_view, manifest.root)
            except ValueError as exc:
                result.status, result.reason = "failed", "unable to parse Flawfinder output: %s" % exc
    finally:
        shutil.rmtree(str(source_view), ignore_errors=True)
    result.metadata.update({"scan_count": 1 if result.returncode is not None else 0, "source_count": len(sources)})
    return result


def _include_dirs(manifest: SourceManifest, explicit: Sequence[str]) -> List[str]:
    ordered = []
    seen = set()
    for value in explicit:
        path = Path(value)
        resolved = path.resolve() if path.is_absolute() else (manifest.root / path).resolve()
        if str(resolved) not in seen:
            seen.add(str(resolved))
            ordered.append(str(resolved))
    for header in manifest.files_for((".h", ".hh", ".hpp", ".hxx")):
        value = str(header.parent.resolve())
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _chunk_sources(base_command: Sequence[str], sources: Sequence[Path], byte_limit: int) -> List[List[Path]]:
    base_size = sum(len(os.fsencode(value)) + 1 for value in base_command)
    if base_size >= byte_limit:
        raise ValueError("Splint flags and include paths exceed --splint-command-bytes")
    chunks: List[List[Path]] = []
    current: List[Path] = []
    current_size = base_size
    for source in sources:
        source_size = len(os.fsencode(str(source))) + 1
        if base_size + source_size > byte_limit:
            raise ValueError("source path exceeds --splint-command-bytes: %s" % source)
        if current and current_size + source_size > byte_limit:
            chunks.append(current)
            current = []
            current_size = base_size
        current.append(source)
        current_size += source_size
    if current:
        chunks.append(current)
    return chunks


def _concatenate_logs(parts: Sequence[Path], destination: Path) -> None:
    with destination.open("wb") as output:
        for part in parts:
            if not part.exists():
                continue
            with part.open("rb") as source:
                shutil.copyfileobj(source, output)


def _iter_log_lines(paths: Sequence[Path]) -> Iterable[str]:
    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                yield line


@analyzer_adapter("splint")
def _run_splint(args: argparse.Namespace, project: Path, out_dir: Path) -> ToolResult:
    manifest: SourceManifest = args.source_manifest
    sources = manifest.files_for((".c",))
    if not sources:
        return ToolResult("splint", "skipped", "no C source files found", required=False)
    includes = _include_dirs(manifest, args.splint_include)
    base_command = [args.splint_bin]
    base_command.extend("-I%s" % value for value in includes)
    base_command.extend("-D%s" % value for value in args.splint_define)
    base_command.extend(args.splint_flag)
    chunks = _chunk_sources(base_command, sources, args.splint_command_bytes)
    stdout_parts = []
    stderr_parts = []
    part_results = []
    deadline = time.monotonic() + args.timeout_seconds
    for index, chunk in enumerate(chunks, 1):
        remaining = int(deadline - time.monotonic())
        if remaining < 1:
            part_results.append(ToolResult("splint", "timed_out", "timed out after %s seconds" % args.timeout_seconds))
            break
        stdout_name = "splint-part-%04d.txt" % index
        stderr_name = "splint-part-%04d.stderr.txt" % index
        request = ToolRequest(
            "splint", base_command + [str(path) for path in chunk],
            project if project.is_dir() else project.parent, out_dir, False,
            remaining, (0, 1), stdout_name, stderr_name,
            [args.splint_bin, "-help", "version"], args.process_registry,
        )
        part = execute_request(request)
        part_results.append(part)
        stdout_parts.append(out_dir / stdout_name)
        stderr_parts.append(out_dir / stderr_name)
        if part.status in ("failed", "timed_out", "skipped"):
            break
    _concatenate_logs(stdout_parts, out_dir / "splint.txt")
    _concatenate_logs(stderr_parts, out_dir / "splint.stderr.txt")
    findings, diagnostics = _parse_splint_lines(_iter_log_lines(list(itertools.chain(stdout_parts, stderr_parts))))
    for path in itertools.chain(stdout_parts, stderr_parts):
        if path.exists():
            path.unlink()
    status = "ok"
    reason = ""
    for part in part_results:
        if part.status in ("failed", "timed_out", "skipped"):
            status, reason = part.status, part.reason
            break
    fatal_count = sum(1 for diagnostic in diagnostics if diagnostic.fatal)
    if fatal_count and status == "ok":
        status = "failed"
        reason = "Splint reported %s fatal diagnostic(s)" % fatal_count
    first = part_results[0] if part_results else ToolResult("splint", status, reason)
    result = ToolResult(
        "splint", status, reason, findings=findings, diagnostics=diagnostics,
        command=first.command, returncode=first.returncode, version=first.version,
        executable=first.executable, duration_seconds=sum(part.duration_seconds for part in part_results),
        required=False,
    )
    result.metadata.update({
        "source_count": len(sources), "include_dirs": includes, "scan_count": len(part_results),
        "commands": [part.command for part in part_results],
        "stdout_log": "splint.txt", "stderr_log": "splint.stderr.txt",
    })
    return result


ADAPTERS = {name: spec.adapter for name, spec in ANALYZERS.items()}
ADAPTERS[AI_TOOL] = run_ai_review


def run_tools(args: argparse.Namespace, project: Path, run_dir: Path, tools: Sequence[str]) -> List[ToolResult]:
    def invoke(tool: str) -> ToolResult:
        out_dir = run_dir / tool
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            adapter = ADAPTERS.get(tool)
            if adapter is None:
                raise RuntimeError("analyzer adapter is not registered: %s" % tool)
            return adapter(args, project, out_dir)
        except Exception as exc:  # Keep partial reports usable after one adapter fails.
            return ToolResult(tool, "failed", "adapter error: %s" % exc, required=tool in REQUIRED_TOOLS)

    if args.tool_jobs <= 1 or len(tools) <= 1:
        return [invoke(tool) for tool in tools]
    results = {}
    pool = ThreadPoolExecutor(max_workers=args.tool_jobs)
    futures = {}
    try:
        futures = {pool.submit(invoke, tool): tool for tool in tools}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    except KeyboardInterrupt:
        args.process_registry.terminate_all()
        for future in futures:
            future.cancel()
        raise
    finally:
        pool.shutdown(wait=True)
    return [results[tool] for tool in tools]

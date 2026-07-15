#!/usr/bin/env python3
"""Core runtime for the Code Analyzer skill (standard-library only)."""

from __future__ import annotations

import argparse
import functools
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


SCHEMA_VERSION = "2.1"
REMOVED_COMPATIBILITY_LINKS = ("clang-tidy",)
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}
ALL_SOURCE_SUFFIXES = frozenset((
    ".c", ".cc", ".cpp", ".cxx", ".c++", ".tpp", ".txx",
    ".h", ".hh", ".hpp", ".hxx", ".ipp", ".inl",
))
DEFAULT_EXCLUDED_DIRS = frozenset((
    ".git", ".hg", ".svn", ".cache", ".tools", ".tox", ".venv", "venv",
    "node_modules", "vendor", "vendors", "third_party", "third-party", "thirdparty",
    "generated", "build", "dist", "out",
))
DEFAULT_EXCLUDED_PREFIXES = (
    "build-", "cmake-build-", "bazel-", "generated-",
    "code-analyzer-report", "review-suite-report", "splint-report",
)
OVERLAP_LINE_DISTANCE = 3


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
class ToolDiagnostic:
    tool: str
    severity: str
    category: str
    message: str
    file: str = ""
    line: str = ""
    column: str = ""
    fatal: bool = False


@dataclass
class SourceManifest:
    root: Path
    files: List[Path]
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=list)
    default_excludes: bool = True
    excluded_count: int = 0

    def files_for(self, suffixes: Iterable[str]) -> List[Path]:
        allowed = frozenset(value.lower() for value in suffixes)
        return [path for path in self.files if path.suffix.lower() in allowed]

    def relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return path.resolve().as_posix()

    def payload(self) -> Dict[str, Any]:
        suffix_counts = Counter(path.suffix.lower() for path in self.files)
        return {
            "total_files": len(self.files),
            "excluded_paths": self.excluded_count,
            "default_excludes": self.default_excludes,
            "include_patterns": self.include_patterns,
            "exclude_patterns": self.exclude_patterns,
            "suffix_counts": dict(sorted(suffix_counts.items())),
            "files": [self.relative(path) for path in self.files],
        }


class ProcessRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._processes: Dict[int, subprocess.Popen] = {}

    def register(self, process: subprocess.Popen) -> None:
        with self._lock:
            self._processes[process.pid] = process

    def unregister(self, process: subprocess.Popen) -> None:
        with self._lock:
            self._processes.pop(process.pid, None)

    def terminate_all(self) -> None:
        with self._lock:
            processes = list(self._processes.values())
        active = [process for process in processes if process.poll() is None]
        for process in active:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
            except OSError:
                pass
        deadline = time.monotonic() + 2
        for process in active:
            if process.poll() is not None:
                continue
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        for process in active:
            if process.poll() is None:
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except OSError:
                    pass


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
    process_registry: Optional[ProcessRegistry] = None


@dataclass
class ToolResult:
    tool: str
    status: str
    reason: str = ""
    findings: List[Finding] = field(default_factory=list)
    diagnostics: List[ToolDiagnostic] = field(default_factory=list)
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
            "total_diagnostics": len(self.diagnostics),
            "summary": "%s/summary.json" % self.tool,
        }
        payload.update(self.metadata)
        return payload


@dataclass
class AnalyzerSpec:
    name: str
    required: bool
    binary_default: str
    capabilities: Tuple[str, ...]
    version_args: Tuple[str, ...] = ("--version",)
    adapter: Optional[Callable[[argparse.Namespace, Path, Path], ToolResult]] = None


ANALYZERS: Dict[str, AnalyzerSpec] = {
    spec.name: spec for spec in (
        AnalyzerSpec("cppcheck", True, "cppcheck", ("xml", "compile_commands")),
        AnalyzerSpec("flawfinder", True, "flawfinder", ("csv", "cwe")),
        AnalyzerSpec("splint", False, "splint", ("c-analysis",), ("-help", "version")),
    )
}
TOOL_ORDER = tuple(ANALYZERS)
REQUIRED_TOOLS = frozenset(name for name, spec in ANALYZERS.items() if spec.required)


def analyzer_adapter(name: str) -> Callable[[Callable[[argparse.Namespace, Path, Path], ToolResult]],
                                            Callable[[argparse.Namespace, Path, Path], ToolResult]]:
    def register(function: Callable[[argparse.Namespace, Path, Path], ToolResult]
                 ) -> Callable[[argparse.Namespace, Path, Path], ToolResult]:
        ANALYZERS[name].adapter = function
        return function
    return register


@functools.lru_cache(maxsize=256)
def _glob_regex(pattern: str) -> re.Pattern:
    pattern = pattern.replace(os.path.sep, "/")
    if pattern.startswith("./"):
        pattern = pattern[2:]
    if pattern.startswith("/"):
        pattern = pattern[1:]
    expression = "" if "/" in pattern else "(?:.*/)?"
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "*":
            if index + 1 < len(pattern) and pattern[index + 1] == "*":
                index += 2
                if index < len(pattern) and pattern[index] == "/":
                    expression += "(?:.*/)?"
                    index += 1
                else:
                    expression += ".*"
                continue
            expression += "[^/]*"
        elif character == "?":
            expression += "[^/]"
        elif character == "[":
            end = pattern.find("]", index + 1)
            if end < 0:
                expression += r"\["
            else:
                content = pattern[index + 1:end]
                if content.startswith("!"):
                    content = "^" + content[1:]
                elif content.startswith("^"):
                    content = "\\" + content
                expression += "[%s]" % content.replace("\\", r"\\")
                index = end
        else:
            expression += re.escape(character)
        index += 1
    try:
        return re.compile("^%s$" % expression)
    except re.error as exc:
        raise ValueError("invalid source glob %r: %s" % (pattern, exc))


def _matches_patterns(relative_path: str, patterns: Sequence[str]) -> bool:
    normalized = relative_path.replace(os.path.sep, "/")
    return any(_glob_regex(pattern).match(normalized) for pattern in patterns)


def _is_default_excluded(relative_path: Path) -> bool:
    for part in relative_path.parts[:-1]:
        if part in DEFAULT_EXCLUDED_DIRS or any(part.startswith(prefix) for prefix in DEFAULT_EXCLUDED_PREFIXES):
            return True
    return False


def _directory_is_default_excluded(name: str) -> bool:
    return name in DEFAULT_EXCLUDED_DIRS or any(name.startswith(prefix) for prefix in DEFAULT_EXCLUDED_PREFIXES)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent)
        return True
    except ValueError:
        return False


def build_source_manifest(project: Path, include_patterns: Sequence[str], exclude_patterns: Sequence[str],
                          default_excludes: bool, out_root: Path) -> SourceManifest:
    root = project if project.is_dir() else project.parent
    files = []
    excluded_count = 0
    resolved_root = root.resolve()
    resolved_out = out_root.resolve(strict=False)
    exclude_output = resolved_out != resolved_root and _is_within(resolved_out, resolved_root)

    def consider(path: Path) -> None:
        nonlocal excluded_count
        if path.suffix.lower() not in ALL_SOURCE_SUFFIXES:
            return
        resolved = path.resolve(strict=False)
        try:
            relative = resolved.relative_to(resolved_root).as_posix()
        except ValueError:
            relative = resolved.as_posix()
        if exclude_output and _is_within(resolved, resolved_out):
            excluded_count += 1
            return
        if include_patterns and not _matches_patterns(relative, include_patterns):
            excluded_count += 1
            return
        if default_excludes and _is_default_excluded(Path(relative)):
            excluded_count += 1
            return
        if _matches_patterns(relative, exclude_patterns):
            excluded_count += 1
            return
        files.append(resolved)

    def raise_walk_error(error: OSError) -> None:
        raise error

    if project.is_file():
        consider(project)
    else:
        for current, directory_names, file_names in os.walk(
                str(project), followlinks=False, onerror=raise_walk_error):
            current_path = Path(current)
            retained = []
            for name in sorted(directory_names):
                directory = current_path / name
                in_output = exclude_output and _is_within(directory, resolved_out)
                relative_directory = directory.relative_to(project).as_posix()
                explicitly_excluded = (
                    _matches_patterns(relative_directory, exclude_patterns)
                    or _matches_patterns(relative_directory + "/", exclude_patterns)
                )
                if (in_output or explicitly_excluded
                        or (default_excludes and _directory_is_default_excluded(name))):
                    excluded_count += 1
                else:
                    retained.append(name)
            directory_names[:] = retained
            for name in sorted(file_names):
                consider(current_path / name)
    return SourceManifest(
        root=root.resolve(), files=sorted(set(files)), include_patterns=list(include_patterns),
        exclude_patterns=list(exclude_patterns), default_excludes=default_excludes,
        excluded_count=excluded_count,
    )


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
            text=True, encoding="utf-8", errors="replace", check=False, timeout=5,
        )
        output = completed.stdout.strip() or completed.stderr.strip()
        version = output.splitlines()[0][:500] if output else ""
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
    version_cmd = list(request.version_command) if request.version_command else [executable, "--version"]
    if version_cmd and version_cmd[0] == request.command[0]:
        version_cmd[0] = executable
    version = ""
    try:
        version_result = subprocess.run(
            version_cmd, cwd=str(request.cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", check=False,
            timeout=min(10, max(1, request.timeout_seconds)),
        )
        output = version_result.stdout.strip() or version_result.stderr.strip()
        version = output.splitlines()[0][:500] if output else "unknown"
    except (OSError, subprocess.SubprocessError):
        version = "unknown"

    request.out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = request.out_dir / request.stdout_name
    stderr_path = request.out_dir / request.stderr_name
    try:
        process = subprocess.Popen(
            command,
            cwd=str(request.cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=(os.name == "posix"),
        )
    except OSError as exc:
        return ToolResult(
            request.tool, "failed" if request.required else "skipped", str(exc),
            command=command, version=version, executable=executable, required=request.required,
            duration_seconds=time.monotonic() - started,
        )
    if request.process_registry:
        request.process_registry.register(process)

    drain_errors: List[str] = []

    def drain(stream: Any, path: Path) -> None:
        try:
            with path.open("wb") as output:
                for chunk in iter(lambda: stream.read(64 * 1024), b""):
                    output.write(chunk)
        except OSError as exc:
            drain_errors.append("%s: %s" % (path.name, exc))
            for _ in iter(lambda: stream.read(64 * 1024), b""):
                pass
        finally:
            stream.close()

    threads = [
        threading.Thread(target=drain, args=(process.stdout, stdout_path), daemon=True),
        threading.Thread(target=drain, args=(process.stderr, stderr_path), daemon=True),
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
        if request.process_registry:
            request.process_registry.unregister(process)
    if drain_errors and status == "ok":
        status = "failed"
        reason = "unable to write analyzer log: %s" % "; ".join(drain_errors)

    return ToolResult(
        request.tool, status, reason, command=command, returncode=process.returncode,
        version=version, executable=executable, duration_seconds=time.monotonic() - started,
        required=request.required,
        metadata={"stdout_log": request.stdout_name, "stderr_log": request.stderr_name},
    )

#!/usr/bin/env python3
"""Command-line interface for Code Analyzer."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

from code_analyzer_adapters import find_compile_commands, run_tools
from code_analyzer_reporting import (
    _safe_run_id,
    aggregate_results,
    publish_run,
    should_fail,
    write_outputs,
)
from code_analyzer_runtime import (
    ANALYZERS,
    SCHEMA_VERSION,
    TOOL_ORDER,
    ProcessRegistry,
    build_source_manifest,
    probe_tool,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Code Analyzer for C and C++ projects.")
    parser.add_argument("--project", default=".")
    parser.add_argument("--out", default="code-analyzer-report")
    parser.add_argument("--tools", default=",".join(TOOL_ORDER))
    parser.add_argument("--max-findings", type=int, default=100,
                        help="Maximum findings listed in Markdown; HTML always contains all findings.")
    parser.add_argument("--fail-on", choices=("none", "tool-error", "medium", "high", "critical"), default="tool-error")
    for spec in ANALYZERS.values():
        parser.add_argument("--%s-bin" % spec.name, default=spec.binary_default)
    parser.add_argument("--tool-jobs", type=int, default=1)
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--source-include", action="append", default=[], metavar="GLOB")
    parser.add_argument("--source-exclude", action="append", default=[], metavar="GLOB")
    parser.add_argument("--no-default-excludes", action="store_true")
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
    parser.add_argument("--splint-command-bytes", type=int, default=100000)
    return parser


def doctor(args: argparse.Namespace) -> Dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "tools": {
        spec.name: probe_tool(
            getattr(args, "%s_bin" % spec.name.replace("-", "_")), spec.required,
            spec.capabilities, spec.version_args,
        )
        for spec in ANALYZERS.values()
    }}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    tools = [item.strip() for item in args.tools.split(",") if item.strip()]
    invalid = [tool for tool in tools if tool not in TOOL_ORDER]
    if not tools:
        print("error: --tools must select at least one analyzer", file=os.sys.stderr)
        return 2
    if invalid or len(tools) != len(set(tools)):
        print("error: unsupported or duplicate tool(s): %s" % ", ".join(invalid or tools), file=os.sys.stderr)
        return 2
    if args.doctor:
        print(json.dumps(doctor(args), indent=2))
        return 0
    if (args.tool_jobs < 1 or args.timeout_seconds < 1 or args.splint_command_bytes < 4096 or
            args.max_findings < 0 or (args.jobs is not None and args.jobs < 1)):
        print("error: job counts and timeouts must be positive, --max-findings non-negative, and --splint-command-bytes at least 4096", file=os.sys.stderr)
        return 2
    if args.flawfinder_minlevel is not None and not 0 <= args.flawfinder_minlevel <= 5:
        print("error: --flawfinder-minlevel must be between 0 and 5", file=os.sys.stderr)
        return 2
    project = Path(args.project).expanduser().resolve()
    if not project.exists():
        print("error: project does not exist: %s" % project, file=os.sys.stderr)
        return 2
    out_root = Path(args.out).expanduser().resolve()
    try:
        run_id = _safe_run_id(args.run_id)
        args.compile_commands_path = find_compile_commands(project, args.compile_commands)
    except ValueError as exc:
        print("error: %s" % exc, file=os.sys.stderr)
        return 2
    project_root = project if project.is_dir() else project.parent
    for option, attribute in (("--suppressions-list", "suppressions_list"), ("--patch", "patch")):
        value = getattr(args, attribute)
        if not value:
            continue
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = project_root / path
        if not path.is_file():
            print("error: %s file does not exist: %s" % (option, path.resolve(strict=False)), file=os.sys.stderr)
            return 2
        setattr(args, attribute, str(path.resolve()))
    final = out_root / "runs" / run_id
    if (final.exists() or final.is_symlink()) and not args.overwrite:
        print("error: run id already exists: %s" % run_id, file=os.sys.stderr)
        return 2
    try:
        args.source_manifest = build_source_manifest(
            project, args.source_include, args.source_exclude, not args.no_default_excludes, out_root
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print("error: unable to build source manifest: %s" % exc, file=os.sys.stderr)
        return 2
    if not args.source_manifest.files:
        print("error: no C/C++ files matched the source manifest", file=os.sys.stderr)
        return 2
    args.process_registry = ProcessRegistry()
    staging = out_root / (".staging-%s-%s" % (run_id, uuid.uuid4().hex[:8]))
    try:
        out_root.mkdir(parents=True, exist_ok=True)
        staging.mkdir()
    except OSError as exc:
        print("error: unable to create report directory: %s" % exc, file=os.sys.stderr)
        return 2
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        results = run_tools(args, project, staging, tools)
        completed_at = datetime.now(timezone.utc).isoformat()
        summary = aggregate_results(project, results, run_id, started_at, completed_at, args.source_manifest)
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
    print("dashboard: %s" % (published / "combined" / "index.html"))
    print("findings: %s" % summary["total_findings"])
    print("diagnostics: %s" % summary["total_diagnostics"])
    return 1 if should_fail(summary, args.fail_on) else 0

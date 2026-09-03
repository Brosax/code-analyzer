"""The argv vocabulary: what an operator may type, and what it means in config.

Lifted verbatim out of ``cli.py`` so a second front end can share it.  The
conversation's slash commands parse their tail with the very parser the CLI
builds for the same action, which is what makes ``/scan ~/p --llm-jobs 4``
accept exactly what ``code-analyzer analyze`` accepts -- by construction rather
than by two lists kept in step by hand.

Nothing here executes anything: it declares arguments and translates a parsed
namespace into the nested config overrides ``config.load_config`` layers on
top of the file.  The functions keep the shapes and the wording they had as
``cli._*``; ``cli`` re-exports the two names the tests already import.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .llm.profiles import PROFILE_NAMES
from .tools import LLM_PRODUCERS, TOOL_NAMES


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def add_analyze_arguments(run: argparse.ArgumentParser) -> None:
    run.add_argument("--config", type=Path)
    run.add_argument("--output-root", type=Path)
    compile_group = run.add_mutually_exclusive_group()
    compile_group.add_argument("--compile-db", type=Path)
    compile_group.add_argument("--no-compile-db", action="store_true")
    run.add_argument("--tool", choices=TOOL_NAMES, action="append")
    run.add_argument("--include", action="append", type=Path, help="project include directory")
    run.add_argument("--system-include", action="append", type=Path)
    run.add_argument("--define", action="append")
    run.add_argument("--undefine", action="append")
    run.add_argument("--exclude", action="append", help="source-relative exclusion glob")
    run.add_argument("--c-standard")
    run.add_argument("--cpp-standard")
    run.add_argument("--cppcheck-platform")
    run.add_argument("--cppcheck-timeout", type=positive_float)
    run.add_argument("--flawfinder-timeout", type=positive_float)
    run.add_argument("--splint-tu-timeout", type=positive_float)
    run.add_argument("--splint-total-timeout", type=positive_float)
    run.add_argument("--splint-scope", choices=("auto", "build", "inventory"))
    run.add_argument("--splint-jobs", type=positive_int)
    run.add_argument("--splint-heartbeat", type=positive_float)
    run.add_argument("--splint-mode", choices=("strict", "checks", "standard", "weak"), help="Splint's predefined check mode")
    run.add_argument("--build-assist", choices=("off", "propose", "auto"), help="diagnose Splint/Cppcheck preprocessing failures and re-run failed units with an inferred build context")
    run.add_argument("--build-assist-yes", action="store_true", help="apply a proposed build-context patch without asking (headless runs otherwise only record it)")
    run.add_argument("--log-level", choices=("debug", "info", "warning"), help="how much logs/runner.log records")
    run.add_argument("--llm", action=argparse.BooleanOptionalAction, default=None, help="run the LLM scanners as a second, independent detection path")
    add_llm_arguments(run)
    run.add_argument("--llm-scanner", choices=LLM_PRODUCERS, action="append")
    run.add_argument("--llm-token-budget", type=positive_int, metavar="N", help="prompt token budget for the whole LLM phase")
    run.add_argument("--llm-risk", action="append", metavar="PATTERN=TIER")
    run.add_argument("--termination-grace", type=positive_float)
    run.add_argument("--events-file", type=Path, metavar="PATH", help="write the run-level event log here instead of <run_dir>/events.jsonl")
    run.add_argument("--follow-symlinks", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--respect-gitignore", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--shareable-export", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--review", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--fail-on", choices=("none", "medium", "high", "critical"))


def add_llm_arguments(run: argparse.ArgumentParser) -> None:
    """The provider flags both the scanners and the validator take."""
    run.add_argument("--llm-profile", choices=PROFILE_NAMES, help="built-in provider profile supplying endpoint, model and api_key_env defaults")
    run.add_argument("--llm-endpoint", metavar="URL")
    run.add_argument("--llm-model", metavar="NAME")
    run.add_argument("--llm-jobs", type=positive_int)
    run.add_argument("--llm-total-timeout", type=positive_float, metavar="SECONDS")
    run.add_argument("--llm-no-cache", action="store_true")


def assess_overrides(args: argparse.Namespace) -> dict[str, Any]:
    value: dict[str, Any] = {}
    llm = llm_overrides(args)
    if llm:
        value["llm"] = llm
    if getattr(args, "max_candidates", None) is not None:
        value["audit"] = {"validation_max_candidates": args.max_candidates}
    return value


def llm_overrides(args: argparse.Namespace) -> dict[str, Any]:
    llm: dict[str, Any] = {}
    if args.llm_profile is not None:
        llm["profile"] = args.llm_profile
    if args.llm_endpoint is not None:
        llm["endpoint"] = args.llm_endpoint
    if args.llm_model is not None:
        llm["model"] = args.llm_model
    if args.llm_jobs is not None:
        llm["jobs"] = args.llm_jobs
    if args.llm_total_timeout is not None:
        llm["total_timeout_seconds"] = args.llm_total_timeout
    if args.llm_no_cache:
        llm["cache"] = False
    return llm


def analyze_overrides(args: argparse.Namespace) -> dict[str, Any]:
    value: dict[str, Any] = {}
    run: dict[str, Any] = {}
    source: dict[str, Any] = {}
    build: dict[str, Any] = {}
    tools: dict[str, Any] = {}
    review: dict[str, Any] = {}
    llm = llm_overrides(args)
    if args.output_root is not None:
        run["output_root"] = str(args.output_root.resolve())
    if args.shareable_export is not None:
        run["shareable_export"] = args.shareable_export
    if args.termination_grace is not None:
        run["termination_grace_seconds"] = args.termination_grace
    if args.events_file is not None:
        run["events_file"] = str(args.events_file.resolve())
    if getattr(args, "log_level", None) is not None:
        run["log_level"] = args.log_level
    if args.exclude is not None:
        source["exclude"] = args.exclude
    if args.follow_symlinks is not None:
        source["follow_symlinks"] = args.follow_symlinks
    if args.respect_gitignore is not None:
        source["respect_gitignore"] = args.respect_gitignore
    if args.compile_db is not None:
        build.update({"compile_database_mode": "explicit", "compile_database": str(args.compile_db.resolve())})
    elif args.no_compile_db:
        build.update({"compile_database_mode": "disabled", "compile_database": None})
    for argument, key in ((args.include, "include"), (args.system_include, "system_include")):
        if argument is not None:
            build[key] = [str(path.resolve()) for path in argument]
    for argument, key in ((args.define, "define"), (args.undefine, "undefine")):
        if argument is not None:
            build[key] = argument
    for key in ("c_standard", "cpp_standard", "cppcheck_platform"):
        if getattr(args, key) is not None:
            build[key] = getattr(args, key)
    timeout_values = {
        "cppcheck": ("timeout_seconds", args.cppcheck_timeout),
        "flawfinder": ("timeout_seconds", args.flawfinder_timeout),
        "splint_tu": ("tu_timeout_seconds", args.splint_tu_timeout),
        "splint_total": ("total_timeout_seconds", args.splint_total_timeout),
    }
    for name, (key, timeout) in timeout_values.items():
        if timeout is not None:
            tool = name.split("_", 1)[0]
            tools.setdefault(tool, {})[key] = timeout
    if args.splint_scope is not None:
        tools.setdefault("splint", {})["scope"] = args.splint_scope
    if args.splint_jobs is not None:
        tools.setdefault("splint", {})["jobs"] = args.splint_jobs
    if args.splint_heartbeat is not None:
        tools.setdefault("splint", {})["heartbeat_seconds"] = args.splint_heartbeat
    if getattr(args, "splint_mode", None) is not None:
        tools.setdefault("splint", {})["mode"] = args.splint_mode
    if getattr(args, "build_assist", None) is not None:
        build["assist"] = args.build_assist
    if args.llm is not None:
        llm["enabled"] = args.llm
    if args.llm_scanner:
        llm["scanners"] = [name for name in LLM_PRODUCERS if name in set(args.llm_scanner)]
    if args.llm_token_budget is not None:
        llm["total_prompt_tokens"] = args.llm_token_budget
    if args.llm_risk:
        llm["risk_overrides"] = args.llm_risk
    if args.review is not None:
        review["enabled"] = args.review
    if args.fail_on is not None:
        review["fail_on"] = args.fail_on
    if args.tool:
        selected = set(args.tool)
        for name in TOOL_NAMES:
            tools.setdefault(name, {})["enabled"] = name in selected
    if run:
        value["run"] = run
    if source:
        value["source"] = source
    if build:
        value["build"] = build
    if tools:
        value["tools"] = tools
    if review:
        value["review"] = review
    if llm:
        value["llm"] = llm
    return value


def normalize_compile_db_args(argv: list[str]) -> list[str]:
    """Let ``--cmake-arg -D...`` work despite argparse option parsing.

    Values are only regrouped before the custom-command ``--`` separator and
    remain individual argv elements when CMake is eventually executed.
    """
    if not argv or argv[0] != "compile-db":
        return argv
    result: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--":
            result.extend(argv[index:])
            break
        if item == "--cmake-arg" and index + 1 < len(argv):
            result.append("--cmake-arg=" + argv[index + 1])
            index += 2
            continue
        result.append(item)
        index += 1
    return result

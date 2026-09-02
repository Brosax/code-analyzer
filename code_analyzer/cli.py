from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .compile_db_wizard import run_compile_db
from .config import load_config
from .control import auto_no, auto_yes, stdin_decider
from .dashboard import rebuild_dashboard
from .doctor import probe_all
from .errors import UserError
from .events import EVENTS_FILE, JsonlEventSink, events_file
from .llm.doctor import probe_llm
from .llm.profiles import PROFILE_NAMES, third_party_warning
from .llm.resume import run_resume
from .reconfigure import run_tools_resume
from .recovery import recover_report
from .runner import analyze
from .serve import DEFAULT_PORT, serve
from .status import EXIT_COMPLETE, EXIT_PARTIAL
from .tools import LLM_PRODUCERS, TOOL_NAMES
from .validate import run_assess


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="code-analyzer", description="Evidence-first C/C++ static analysis runner")
    root.add_argument("--version", action="version", version=f"code-analyzer {__version__}")
    commands = root.add_subparsers(dest="command")
    tui = commands.add_parser("tui", help="open the basic full-screen scan interface")
    tui.add_argument("source", type=Path, nargs="?", default=Path.cwd())
    tui.add_argument("--config", type=Path)
    doctor = commands.add_parser("doctor", help="probe analyzer and WSL capabilities")
    doctor.add_argument("--config", type=Path)
    doctor.add_argument("--json", action="store_true", dest="as_json")
    llm_doctor = commands.add_parser("llm-doctor", help="probe the LLM provider and estimate a full scan")
    llm_doctor.add_argument("source", type=Path, nargs="?", help="source tree to estimate a full scan of")
    llm_doctor.add_argument("--config", type=Path)
    llm_doctor.add_argument("--json", action="store_true", dest="as_json")
    _add_llm_arguments(llm_doctor)
    llm_resume = commands.add_parser("llm-resume", help="scan the units a run left unscheduled or interrupted")
    llm_resume.add_argument("report_directory", type=Path, metavar="REPORT_DIR")
    llm_resume.add_argument("--config", type=Path)
    _add_llm_arguments(llm_resume)
    compile_db = commands.add_parser("compile-db", help="discover or prepare a JSON compilation database")
    compile_db.add_argument("source", type=Path)
    compile_db.add_argument("--json", action="store_true", dest="as_json", help="report discovery without executing anything")
    compile_db.add_argument("--method", choices=("cmake", "command"))
    compile_db.add_argument("--build-dir", type=Path)
    compile_db.add_argument("--generator", choices=("Ninja", "Unix Makefiles"))
    compile_db.add_argument("--preset")
    compile_db.add_argument("--cmake-arg", action="append", default=[])
    compile_db.add_argument("--expected-db", type=Path)
    compile_db.add_argument("--timeout", type=_positive_float, default=900.0)
    compile_db.add_argument("--yes", action="store_true")
    # ``*`` (instead of REMAINDER) keeps options after SOURCE parseable.  The
    # conventional ``--`` separator still protects every custom command arg.
    compile_db.add_argument("command_argv", nargs="*", metavar="COMMAND")
    rebuild = commands.add_parser("rebuild-dashboard", help="rebuild index.html from an existing report")
    rebuild.add_argument("report_directory", type=Path, metavar="REPORT_DIR")
    recover = commands.add_parser("recover-report", help="rebuild all derived artifacts from existing native evidence")
    recover.add_argument("report_directory", type=Path, metavar="REPORT_DIR")
    run = commands.add_parser("analyze", help="analyze a C/C++ source tree")
    run.add_argument("source", type=Path)
    _add_analyze_arguments(run)
    live = commands.add_parser("serve", help="serve a live view of a run over HTTP (127.0.0.1 only)")
    live.add_argument("report_directory", type=Path, nargs="?", metavar="REPORT_DIR", help="a run directory to watch, read-only")
    live.add_argument("--analyze", type=Path, metavar="SOURCE", help="run the analysis in this process, with cancel support")
    live.add_argument("--port", type=int, default=DEFAULT_PORT)
    _add_analyze_arguments(live)
    resume_tools = commands.add_parser("tools-resume", help="continue a finished run's build-context loop: diagnose, patch, re-run the failed Splint/Cppcheck units, re-derive the review")
    resume_tools.add_argument("report_directory", type=Path, metavar="REPORT_DIR")
    resume_tools.add_argument("--tool", choices=("splint", "cppcheck"), help="only this tool (default: every reconfigurable tool in the run)")
    resume_tools.add_argument("--build-assist", choices=("propose", "auto"), help="override the run's build.assist for this resume")
    resume_tools.add_argument("--build-assist-yes", action="store_true", help="apply the proposed patch without asking")
    assess = commands.add_parser("assess", help="validate the correlated candidates of a finished run with the LLM validator")
    assess.add_argument("report_directory", type=Path, metavar="REPORT_DIR")
    assess.add_argument("--config", type=Path)
    assess.add_argument("--max-candidates", type=_positive_int, metavar="N", help="validate at most N pending candidates, highest risk first")
    _add_llm_arguments(assess)
    return root


def _add_analyze_arguments(run: argparse.ArgumentParser) -> None:
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
    run.add_argument("--cppcheck-timeout", type=_positive_float)
    run.add_argument("--flawfinder-timeout", type=_positive_float)
    run.add_argument("--splint-tu-timeout", type=_positive_float)
    run.add_argument("--splint-total-timeout", type=_positive_float)
    run.add_argument("--splint-scope", choices=("auto", "build", "inventory"))
    run.add_argument("--splint-jobs", type=_positive_int)
    run.add_argument("--splint-heartbeat", type=_positive_float)
    run.add_argument("--splint-mode", choices=("strict", "checks", "standard", "weak"), help="Splint's predefined check mode")
    run.add_argument("--build-assist", choices=("off", "propose", "auto"), help="diagnose Splint/Cppcheck preprocessing failures and re-run failed units with an inferred build context")
    run.add_argument("--build-assist-yes", action="store_true", help="apply a proposed build-context patch without asking (headless runs otherwise only record it)")
    run.add_argument("--log-level", choices=("debug", "info", "warning"), help="how much logs/runner.log records")
    run.add_argument("--llm", action=argparse.BooleanOptionalAction, default=None, help="run the LLM scanners as a second, independent detection path")
    _add_llm_arguments(run)
    run.add_argument("--llm-scanner", choices=LLM_PRODUCERS, action="append")
    run.add_argument("--llm-token-budget", type=_positive_int, metavar="N", help="prompt token budget for the whole LLM phase")
    run.add_argument("--llm-risk", action="append", metavar="PATTERN=TIER")
    run.add_argument("--termination-grace", type=_positive_float)
    run.add_argument("--events-file", type=Path, metavar="PATH", help="write the run-level event log here instead of <run_dir>/events.jsonl")
    run.add_argument("--follow-symlinks", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--respect-gitignore", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--shareable-export", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--review", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--fail-on", choices=("none", "medium", "high", "critical"))


def _add_llm_arguments(run: argparse.ArgumentParser) -> None:
    """The provider flags both the scanners and the validator take."""
    run.add_argument("--llm-profile", choices=PROFILE_NAMES, help="built-in provider profile supplying endpoint, model and api_key_env defaults")
    run.add_argument("--llm-endpoint", metavar="URL")
    run.add_argument("--llm-model", metavar="NAME")
    run.add_argument("--llm-jobs", type=_positive_int)
    run.add_argument("--llm-total-timeout", type=_positive_float, metavar="SECONDS")
    run.add_argument("--llm-no-cache", action="store_true")


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    root_parser = parser()
    if not raw_argv:
        if _has_tty():
            raw_argv = ["tui", str(Path.cwd())]
        else:
            root_parser.print_help(file=sys.stderr)
            print("\ncode-analyzer: hint: run 'code-analyzer tui [SOURCE]' in an interactive terminal", file=sys.stderr)
            return 2
    raw_argv = _normalize_compile_db_args(raw_argv)
    # Split the custom command off before argparse sees it: ``--`` handling for
    # subparser positionals is version-dependent (fixed in Python 3.12.5).
    command_tail: list[str] | None = None
    if raw_argv and raw_argv[0] == "compile-db" and "--" in raw_argv:
        separator = raw_argv.index("--")
        raw_argv, command_tail = raw_argv[:separator], raw_argv[separator + 1:]
    args = root_parser.parse_args(raw_argv)
    if command_tail is not None:
        args.command_argv = list(args.command_argv) + command_tail
    try:
        if args.command == "tui":
            if not _has_tty():
                root_parser.print_help(file=sys.stderr)
                print("\ncode-analyzer: error: TUI requires an interactive terminal (TTY)", file=sys.stderr)
                return 2
            from .tui import run_tui

            outcome = run_tui(args.source, args.config)
            if outcome.report_directory is not None:
                print(outcome.report_directory)
            return outcome.exit_code
        if args.command == "doctor":
            config = load_config(Path.cwd(), args.config, None)
            _warn_third_party(config)
            result = probe_all(config)
            if args.as_json:
                print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
            else:
                _print_doctor(result)
            return 0 if result["ok"] else 20
        if args.command == "llm-doctor":
            source = (args.source or Path.cwd()).expanduser().resolve()
            config = load_config(source, args.config, {"llm": _llm_overrides(args)} if _llm_overrides(args) else None)
            result = probe_llm(config, source if args.source is not None else None)
            if args.as_json:
                print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
            else:
                _print_llm_doctor(result)
            return 0 if result["ok"] else 20
        if args.command == "compile-db":
            return run_compile_db(args)
        if args.command == "rebuild-dashboard":
            print(rebuild_dashboard(args.report_directory))
            return 0
        if args.command == "recover-report":
            print(recover_report(args.report_directory))
            return 0
        if args.command == "llm-resume":
            report_directory = args.report_directory.expanduser().resolve()
            config = load_config(_scanned_source(report_directory), args.config, _assess_overrides(args))
            _warn_third_party(config)
            block = run_resume(report_directory, config,
                               progress=lambda text: print(f"code-analyzer: {text}", file=sys.stderr))
            print(report_directory)
            return int(block["exit_code"])
        if args.command == "tools-resume":
            if args.build_assist_yes:
                decider = auto_yes
            elif _has_tty():
                decider = stdin_decider(sys.stdin, sys.stderr)
            else:
                decider = auto_no
            report_dir = args.report_directory.expanduser().resolve()
            with JsonlEventSink(report_dir / EVENTS_FILE, append=True) as sink:
                block = run_tools_resume(
                    report_dir, tool=args.tool, assist=args.build_assist, decider=decider,
                    progress=lambda message: print(f"[code-analyzer] {message}", file=sys.stderr, flush=True),
                    event_sink=sink,
                )
            print(report_dir)
            print(f"[code-analyzer] build-context {block.get('outcome')}: {block.get('reason') or 'see manifest.json build_context'}", file=sys.stderr)
            return EXIT_COMPLETE if block.get("outcome") in {"applied", "skipped"} else EXIT_PARTIAL
        if args.command == "assess":
            report_directory = args.report_directory.expanduser().resolve()
            config = load_config(_scanned_source(report_directory), args.config, _assess_overrides(args))
            _warn_third_party(config)
            block = run_assess(report_directory, config,
                               progress=lambda text: print(f"code-analyzer: {text}", file=sys.stderr))
            print(report_directory)
            return int(block["exit_code"])
        if args.command == "serve":
            if args.analyze is None and args.report_directory is None:
                raise UserError("serve needs REPORT_DIR or --analyze SOURCE")
            if args.analyze is not None:
                source = args.analyze.expanduser().resolve()
                config = load_config(source, args.config, _overrides(args))
                if config["llm"]["enabled"]:
                    _warn_third_party(config)
                return serve(None, analyze=(source, config), port=args.port,
                             announce=lambda text: print(f"code-analyzer: {text}", file=sys.stderr))
            return serve(args.report_directory.expanduser().resolve(), port=args.port,
                         announce=lambda text: print(f"code-analyzer: {text}", file=sys.stderr))
        source = args.source.expanduser().resolve()
        overrides = _overrides(args)
        config = load_config(source, args.config, overrides)
        if config["llm"]["enabled"]:
            _warn_third_party(config)
        if getattr(args, "build_assist_yes", False):
            decider = auto_yes
        elif _has_tty():
            decider = stdin_decider(sys.stdin, sys.stderr)
        else:
            decider = auto_no
        with JsonlEventSink(events_file(config)) as sink:
            exit_code, run_dir = analyze(source, config, event_sink=sink, decider=decider)
        print(run_dir)
        return exit_code
    except UserError as exc:
        print(f"code-analyzer: error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("code-analyzer: interrupted", file=sys.stderr)
        return 130


def _warn_third_party(config: dict[str, Any]) -> None:
    warning = third_party_warning(config["llm"])
    if warning:
        print(f"code-analyzer: warning: {warning}", file=sys.stderr)


def _has_tty() -> bool:
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def _scanned_source(report_directory: Path) -> Path:
    """The tree a run scanned, so its project config applies to assess too."""
    try:
        manifest = json.loads((report_directory / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise UserError(f"not a run directory: {report_directory} ({exc})") from exc
    source = Path(str((manifest or {}).get("source") or "")) if isinstance(manifest, dict) else Path("")
    if not source.is_dir():
        raise UserError(f"the scanned source tree is not a directory: {source}; assess needs the source")
    return source


def _assess_overrides(args: argparse.Namespace) -> dict[str, Any]:
    value: dict[str, Any] = {}
    llm = _llm_overrides(args)
    if llm:
        value["llm"] = llm
    if getattr(args, "max_candidates", None) is not None:
        value["audit"] = {"validation_max_candidates": args.max_candidates}
    return value


def _llm_overrides(args: argparse.Namespace) -> dict[str, Any]:
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


def _overrides(args: argparse.Namespace) -> dict[str, Any]:
    value: dict[str, Any] = {}
    run: dict[str, Any] = {}
    source: dict[str, Any] = {}
    build: dict[str, Any] = {}
    tools: dict[str, Any] = {}
    review: dict[str, Any] = {}
    llm = _llm_overrides(args)
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


def _normalize_compile_db_args(argv: list[str]) -> list[str]:
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


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _print_doctor(result: dict[str, Any]) -> None:
    print(f"code-analyzer {result['analyzer_version']}")
    platform = result["platform"]
    print(f"Python: {result['python']['version']} ({'ok' if result['python']['ok'] else 'unsupported'})")
    print(f"WSL: {platform['wsl']}  Ubuntu: {platform['ubuntu']}  C.UTF-8: {platform['c_utf8']}")
    for name, item in result["tools"].items():
        version = f" — {item['version']}" if item.get("version") else ""
        print(f"{name}: {item['status']}{version}")
        if item.get("missing_capabilities"):
            print("  missing capabilities: " + ", ".join(item["missing_capabilities"]))
        # A build that implements an option without listing it is compatible,
        # but silently so: the JSON has always recorded which flags the help
        # omitted and that the canary is what decided, and the terminal should
        # say the same rather than leaving the operator to trust a bare word.
        undocumented = [flag for flag in item.get("help_missing_capabilities") or [] if flag not in (item.get("missing_capabilities") or [])]
        if undocumented and item.get("status") == "compatible":
            print(f"  not listed in --help, verified by canary: {', '.join(undocumented)}")
        if item.get("guidance"):
            print("  " + item["guidance"])


def _print_llm_doctor(result: dict[str, Any]) -> None:
    print(f"endpoint: {result['endpoint']}  (profile: {result['profile']})")
    print(f"model: {result['model']}")
    if result["third_party_warning"]:
        print(f"WARNING: {result['third_party_warning']}")
    runtime = result["runtime"]
    print(f"runtime: {'available' if runtime['available'] else 'MISSING'}  sdk {runtime['sdk_version'] or 'unknown'}")
    credential = result["credential"]
    print(f"credential: {'ok' if credential['ok'] else 'unusable'}"
          + (f" — {credential.get('source')}" if credential["ok"] else f" — {credential['reason']}"))
    models = result["models"]
    if not models["reachable"]:
        print(f"models: unreachable — {models['reason']}")
    else:
        print(f"models: {len(models['available'])} served; configured model {'present' if models['model_present'] else 'ABSENT'}")
        if not models["model_present"]:
            print(f"  {models['reason']}")
    window = result["context_window"]
    print(f"context window: configured {window['configured']}, served {window['served'] if window['served'] is not None else 'unreported'}")
    if window["reason"]:
        print(f"  {window['reason']}")
    benchmark = result["benchmark"]
    if not benchmark["ok"]:
        print(f"benchmark: failed — {benchmark['reason']}")
    else:
        rate = f"{benchmark['tokens_per_second']} tok/s" if benchmark["tokens_per_second"] else "rate unreported"
        print(f"benchmark: {benchmark['latency_seconds']}s for one request, {rate}")
        if benchmark.get("served_other_model"):
            print(f"  WARNING: the endpoint answered as {benchmark['served_model']!r}, not {result['model']!r}")
    estimate = result["estimate"]
    if estimate["known"]:
        print(f"estimated full scan: {_duration(estimate['wall_clock_seconds'])}")
        print(f"  {estimate['basis']}")
    else:
        print(f"estimated full scan: unknown — {estimate['reason']}")


def _duration(seconds: float) -> str:
    minutes, remainder = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m {remainder}s" if minutes else f"{remainder}s"


if __name__ == "__main__":
    raise SystemExit(main())

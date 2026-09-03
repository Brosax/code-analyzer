from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .argv import (
    add_analyze_arguments,
    add_llm_arguments,
    analyze_overrides,
    assess_overrides,
    llm_overrides,
    normalize_compile_db_args,
    positive_float,
    positive_int,
)
from .compile_db_wizard import run_compile_db
from .config import load_config
from .control import auto_no, auto_yes, stdin_decider
from .dashboard import rebuild_dashboard
from .doctor import probe_all
from .errors import UserError
from .events import EVENTS_FILE, JsonlEventSink, events_file
from .llm.doctor import probe_llm
from .llm.profiles import third_party_warning
from .llm.resume import run_resume
from .reconfigure import run_tools_resume
from .recovery import recover_report
from .runner import analyze
from .serve import DEFAULT_PORT, serve
from .status import EXIT_COMPLETE, EXIT_PARTIAL
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
    add_llm_arguments(llm_doctor)
    llm_resume = commands.add_parser("llm-resume", help="scan the units a run left unscheduled or interrupted")
    llm_resume.add_argument("report_directory", type=Path, metavar="REPORT_DIR")
    llm_resume.add_argument("--config", type=Path)
    add_llm_arguments(llm_resume)
    compile_db = commands.add_parser("compile-db", help="discover or prepare a JSON compilation database")
    compile_db.add_argument("source", type=Path)
    compile_db.add_argument("--json", action="store_true", dest="as_json", help="report discovery without executing anything")
    compile_db.add_argument("--method", choices=("cmake", "command"))
    compile_db.add_argument("--build-dir", type=Path)
    compile_db.add_argument("--generator", choices=("Ninja", "Unix Makefiles"))
    compile_db.add_argument("--preset")
    compile_db.add_argument("--cmake-arg", action="append", default=[])
    compile_db.add_argument("--expected-db", type=Path)
    compile_db.add_argument("--timeout", type=positive_float, default=900.0)
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
    add_analyze_arguments(run)
    live = commands.add_parser("serve", help="serve a live view of a run over HTTP (127.0.0.1 only)")
    live.add_argument("report_directory", type=Path, nargs="?", metavar="REPORT_DIR", help="a run directory to watch, read-only")
    live.add_argument("--analyze", type=Path, metavar="SOURCE", help="run the analysis in this process, with cancel support")
    live.add_argument("--port", type=int, default=DEFAULT_PORT)
    add_analyze_arguments(live)
    resume_tools = commands.add_parser("tools-resume", help="continue a finished run's build-context loop: diagnose, patch, re-run the failed Splint/Cppcheck units, re-derive the review")
    resume_tools.add_argument("report_directory", type=Path, metavar="REPORT_DIR")
    resume_tools.add_argument("--tool", choices=("splint", "cppcheck"), help="only this tool (default: every reconfigurable tool in the run)")
    resume_tools.add_argument("--build-assist", choices=("propose", "auto"), help="override the run's build.assist for this resume")
    resume_tools.add_argument("--build-assist-yes", action="store_true", help="apply the proposed patch without asking")
    assess = commands.add_parser("assess", help="validate the correlated candidates of a finished run with the LLM validator")
    assess.add_argument("report_directory", type=Path, metavar="REPORT_DIR")
    assess.add_argument("--config", type=Path)
    assess.add_argument("--max-candidates", type=positive_int, metavar="N", help="validate at most N pending candidates, highest risk first")
    add_llm_arguments(assess)
    return root


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
    raw_argv = normalize_compile_db_args(raw_argv)
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
            config = load_config(source, args.config, {"llm": llm_overrides(args)} if llm_overrides(args) else None)
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
            config = load_config(_scanned_source(report_directory), args.config, assess_overrides(args))
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
            config = load_config(_scanned_source(report_directory), args.config, assess_overrides(args))
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
                config = load_config(source, args.config, analyze_overrides(args))
                if config["llm"]["enabled"]:
                    _warn_third_party(config)
                return serve(None, analyze=(source, config), port=args.port,
                             announce=lambda text: print(f"code-analyzer: {text}", file=sys.stderr))
            return serve(args.report_directory.expanduser().resolve(), port=args.port,
                         announce=lambda text: print(f"code-analyzer: {text}", file=sys.stderr))
        source = args.source.expanduser().resolve()
        overrides = analyze_overrides(args)
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


# The argv vocabulary moved to argv.py so the conversation front end can parse
# a slash command with the very parser this file builds.  Kept as a name here
# because it is what the CLI's own tests reach for.
_overrides = analyze_overrides


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

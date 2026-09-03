from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .actions import ActionContext, ActionRequest, by_name, invoke
from .analysis import AnalysisEvent
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
from .ask import stdin_asker
from .config import load_config
from .control import auto_no, auto_yes, stdin_decider
from .errors import UserError
from .events import EVENTS_FILE, JsonlEventSink, events_file
from .llm.profiles import third_party_warning
from .serve import DEFAULT_PORT, serve


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
    pre = commands.add_parser("preflight", help="read-only checks before a scan")
    pre.add_argument("source", type=Path)
    pre.add_argument("--config", type=Path)
    cfg = commands.add_parser("config", help="show the effective configuration")
    cfg.add_argument("source", nargs="?", type=Path)
    cfg.add_argument("--config", type=Path)
    cfg.add_argument("--filter", help="only paths or labels containing this")
    cfg.add_argument("--all", action="store_true", help="include the advanced fields")
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
    # A third dispatch: neither a subcommand nor a flag, so it is something the
    # operator said.  The deterministic parser resolves it or reports why it
    # could not -- it never reaches a model here, because a non-interactive run
    # that quietly called a provider would be a surprise, and an outage would
    # change exit codes.  `/ask` off a terminal needs its own command.
    known = set(_subcommands(root_parser))
    if raw_argv and raw_argv[0] not in known and not raw_argv[0].startswith("-"):
        return _spoken(raw_argv, root_parser)
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
            outcome = _invoke("doctor", ActionRequest("doctor", config=config, args=args))
            result = outcome.data or {}
            if args.as_json:
                print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
            else:
                _print_doctor(result)
            return outcome.exit_code
        if args.command == "llm-doctor":
            source = (args.source or Path.cwd()).expanduser().resolve()
            config = load_config(source, args.config, {"llm": llm_overrides(args)} if llm_overrides(args) else None)
            outcome = _invoke("llm-doctor", ActionRequest(
                "llm-doctor", source=source if args.source is not None else None, config=config, args=args))
            result = outcome.data or {}
            if args.as_json:
                print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
            else:
                _print_llm_doctor(result)
            return outcome.exit_code
        if args.command == "compile-db":
            return _invoke("compile-db", ActionRequest(
                "compile-db", source=args.source, args=args),
                ask=stdin_asker(sys.stdin, sys.stderr)).exit_code
        if args.command == "preflight":
            source = args.source.expanduser().resolve()
            config = load_config(source, args.config, None)
            outcome = _invoke("preflight", ActionRequest("preflight", source=source, config=config, args=args))
            for line in outcome.lines:
                print(f"code-analyzer: {line}", file=sys.stderr)
            print(outcome.summary)
            return outcome.exit_code
        if args.command == "config":
            source = (args.source or Path.cwd()).expanduser().resolve()
            config = load_config(source, args.config, None)
            outcome = _invoke("config", ActionRequest(
                "config", source=source, config=config, args=args,
                values={"filter": args.filter, "all": args.all}))
            for line in outcome.lines:
                print(line)
            return outcome.exit_code
        if args.command == "rebuild-dashboard":
            outcome = _invoke("rebuild-dashboard", ActionRequest(
                "rebuild-dashboard", report_directory=args.report_directory, args=args))
            print((outcome.data or {}).get("index"))
            return outcome.exit_code
        if args.command == "recover-report":
            outcome = _invoke("recover-report", ActionRequest(
                "recover-report", report_directory=args.report_directory, args=args))
            print((outcome.data or {}).get("index"))
            return outcome.exit_code
        if args.command == "llm-resume":
            report_directory = args.report_directory.expanduser().resolve()
            config = load_config(_scanned_source(report_directory), args.config, assess_overrides(args))
            _warn_third_party(config)
            outcome = _invoke("llm-resume", ActionRequest(
                "llm-resume", report_directory=report_directory, config=config, args=args),
                emit=_stderr_emitter("code-analyzer: "))
            print(report_directory)
            return outcome.exit_code
        if args.command == "tools-resume":
            if args.build_assist_yes:
                decider = auto_yes
            elif _has_tty():
                decider = stdin_decider(sys.stdin, sys.stderr)
            else:
                decider = auto_no
            report_dir = args.report_directory.expanduser().resolve()
            with JsonlEventSink(report_dir / EVENTS_FILE, append=True) as sink:
                outcome = _invoke("tools-resume", ActionRequest(
                    "tools-resume", report_directory=report_dir, args=args),
                    emit=_stderr_emitter("[code-analyzer] "), decide=decider, event_sink=sink)
            block = outcome.data or {}
            print(report_dir)
            print(f"[code-analyzer] build-context {block.get('outcome')}: {block.get('reason') or 'see manifest.json build_context'}", file=sys.stderr)
            return outcome.exit_code
        if args.command == "assess":
            report_directory = args.report_directory.expanduser().resolve()
            config = load_config(_scanned_source(report_directory), args.config, assess_overrides(args))
            _warn_third_party(config)
            outcome = _invoke("assess", ActionRequest(
                "assess", report_directory=report_directory, config=config, args=args),
                emit=_stderr_emitter("code-analyzer: "))
            print(report_directory)
            return outcome.exit_code
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
            outcome = _invoke("analyze", ActionRequest("scan", source=source, config=config, args=args),
                              decide=decider, event_sink=sink, terminal=True)
        print(outcome.report_directory)
        return outcome.exit_code
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


def _subcommands(root_parser: argparse.ArgumentParser) -> list[str]:
    for action in root_parser._subparsers._group_actions:  # noqa: SLF001
        if isinstance(action, argparse._SubParsersAction):  # noqa: SLF001
            return list(action.choices)
    return []


def _spoken(raw_argv: list[str], root_parser: argparse.ArgumentParser) -> int:
    """Run what the operator said, or say why it could not be run.

    A resolved action with a subject runs exactly as the equivalent subcommand
    would.  A bare path does not: a scan is not a side effect, so off a
    terminal it prints the argv it would have run and exits 2.  A sentence is
    refused outright -- see the ASK branch.
    """
    from .intent import ACTION, AMBIGUOUS, ASK, Intent, parse

    line = " ".join(raw_argv)
    intent: Intent = parse(line)
    if intent.kind == ASK:
        # Every unrecognised line now lands here, not just a literal `/ask`.
        # A headless run must never call a provider and a provider outage must
        # never move an exit code, so this is refused on a terminal too: a
        # one-shot argv is not a conversation.
        print("code-analyzer: error: 这句话需要一个模型来读；在交互式会话里说它：code-analyzer tui",
              file=sys.stderr)
        return 2
    if intent.kind == AMBIGUOUS:
        print(f"code-analyzer: error: {intent.problem}", file=sys.stderr)
        for candidate in intent.candidates:
            print(f"  code-analyzer {candidate} {' '.join(raw_argv)}", file=sys.stderr)
        return 2
    if intent.kind != ACTION:
        print(f"code-analyzer: error: {intent.problem}", file=sys.stderr)
        return 2
    action = by_name(intent.action)
    equivalent = [action.cli_command or action.name, *intent.argv]
    if intent.confidence == "path" and not _has_tty():
        print("code-analyzer: error: that reads as:", file=sys.stderr)
        print(f"  code-analyzer {' '.join(equivalent)}", file=sys.stderr)
        print("code-analyzer: run it explicitly, or say it in an interactive session", file=sys.stderr)
        return 2
    return main(equivalent)


def _invoke(command: str, request: ActionRequest, **context: Any) -> Any:
    """Run the registry action behind one subcommand.

    The CLI keeps its own printing: the registry says what happened, this file
    says what reaches a terminal.  Unifying the two is exactly where a stdout
    contract or an exit code gets changed by accident.
    """
    return invoke(by_name(request.action), ActionContext(request=request, **context))


def _stderr_emitter(prefix: str) -> Any:
    """The progress line these commands printed, now derived from an event."""

    def emit(event: AnalysisEvent) -> None:
        if event.status == "info":
            print(f"{prefix}{event.message}", file=sys.stderr, flush=True)

    return emit


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

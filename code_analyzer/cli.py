"""The command line: four commands, one of which is the page.

    code-analyzer                  open the evaluation page (needs a terminal to print its one-time URL)
    code-analyzer web [--port N]   the same, explicitly
    code-analyzer analyze SOURCE   headless, deterministic, never calls a model; exit code 0/1/10/20/130
    code-analyzer probe            measure what the configured model can do (maintainers; needs an idle GPU)
    code-analyzer rebuild EVAL     rebuild an evaluation's index and list from its ledger and evidence, offline

Everything else -- profiles, build context, review, export -- is done on the page, by the conversation or its
buttons.  Exit codes: 0 complete, 1 the --fail-on gate fired, 2 usage error, 10 partial, 20 failed, 130
interrupted (Ctrl+C or SIGTERM).
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from pathlib import Path
from typing import Any

from . import __version__
from .errors import UserError


def positive(kind: type) -> Any:
    def parse(value: str) -> Any:
        parsed = kind(value)
        if parsed <= 0:
            raise argparse.ArgumentTypeError("must be greater than zero")
        return parsed
    return parse


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="code-analyzer", description="SESIP code evaluation: static analyzers, "
                                   "a numbered vulnerability list, targeted AI review on the local GPU")
    root.add_argument("--version", action="version", version=f"code-analyzer {__version__}")
    commands = root.add_subparsers(dest="command")
    web = commands.add_parser("web", help="open the local evaluation page (127.0.0.1); the default")
    web.add_argument("--port", type=int, help="port (default: settings.toml port, 8765)")
    analyze = commands.add_parser(
        "analyze", help="headless: run the analyzers, index the evidence, number the vulnerability list (no model)")
    analyze.add_argument("source", type=Path)
    analyze.add_argument("--profile", help="a built-in profile (rt700-tp-v1.1, generic-sesip) or a profile TOML; "
                                           "default: the evaluation's own, else rt700-tp-v1.1")
    analyze.add_argument("--eval-dir", type=Path, help="evaluation directory (created if new, reused if it exists)")
    analyze.add_argument("--buildctx", type=Path, help="a build context TOML ([build] and [tools] only)")
    analyze.add_argument("--tool", action="append", choices=("cppcheck", "flawfinder", "splint"),
                         help="run only this analyzer (repeatable)")
    database = analyze.add_mutually_exclusive_group()
    database.add_argument("--compile-db", type=Path, help="an explicit compile_commands.json")
    database.add_argument("--no-compile-db", action="store_true", help="do not look for a compilation database")
    analyze.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude a path glob")
    analyze.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default="none",
                         help="exit 1 when a native (never AI) finding reaches this severity")
    probe = commands.add_parser("probe", help="measure what the configured model can do (maintainers; idle GPU)")
    probe.add_argument("--endpoint", help="model endpoint (default: settings.toml [local_model] endpoint)")
    probe.add_argument("--model", help="model name (default: settings.toml [local_model] name)")
    probe.add_argument("--transport", choices=("v1", "api_chat"), default="v1")
    probe.add_argument("--only", help="comma-separated items, e.g. P1,P3,P9 (default: all but the heavy P12)")
    probe.add_argument("--repeat", type=positive(int), default=10, help="repetitions per repeated item")
    probe.add_argument("--heavy", action="store_true", help="also run P12: minutes of background load")
    probe.add_argument("--minutes", type=positive(float), default=10.0, help="P12 load duration per concurrency")
    probe.add_argument("--json", action="store_true", dest="as_json")
    rebuild = commands.add_parser("rebuild", help="rebuild an evaluation's index and list offline (no tool runs)")
    rebuild.add_argument("eval_dir", type=Path, metavar="EVAL_DIR")
    return root


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    root_parser = parser()
    if not raw_argv:
        if not _has_tty():
            root_parser.print_help(file=sys.stderr)
            print("\ncode-analyzer: hint: 'code-analyzer web' opens the evaluation page; "
                  "'code-analyzer analyze SOURCE' runs headless", file=sys.stderr)
            return 2
        raw_argv = ["web"]
    args = root_parser.parse_args(raw_argv)
    if args.command is None:
        root_parser.print_help(file=sys.stderr)
        return 2
    try:
        _interrupt_on_terminate()
        if args.command == "web":
            from .web.server import serve

            serve(port=args.port, announce=lambda line: print(line, file=sys.stderr, flush=True))
            return 0
        if args.command == "analyze":
            return _analyze(args)
        if args.command == "probe":
            return _probe(args)
        if args.command == "rebuild":
            return _rebuild(args)
    except UserError as error:
        print(f"code-analyzer: error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ncode-analyzer: interrupted", file=sys.stderr)
        return 130
    return 2


def _terminate(signum: int, _frame: Any) -> None:
    """SIGTERM ends a headless run the way Ctrl+C ends an attended one: exit 130, status interrupted.

    A run under a supervisor is stopped with TERM, not INT; without this the process died mid-run and the
    manifest said ``running`` for ever (the TF-M run of 2026-09-04 and the Juliet run of 2026-09-05).
    """
    raise KeyboardInterrupt


def _interrupt_on_terminate() -> None:
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _terminate)


def _analyze(args: argparse.Namespace) -> int:
    from .evidence.analyze import evaluate
    from .evidence.buildctx_schema import load_buildctx

    outcome = evaluate(
        args.source, eval_dir=args.eval_dir, profile=args.profile,
        buildctx=load_buildctx(args.buildctx) if args.buildctx else None, tools=args.tool,
        compile_db=False if args.no_compile_db else args.compile_db, exclude=args.exclude,
        fail_on=args.fail_on, progress=lambda line: print(f"[code-analyzer] {line}", file=sys.stderr))
    print(outcome.workspace.root)
    print(f"[code-analyzer] evaluation finished: exit code {outcome.exit_code}", file=sys.stderr)
    return outcome.exit_code


def _rebuild(args: argparse.Namespace) -> int:
    from .evidence.analyze import reindex
    from .evidence.workspace import Workspace

    workspace = Workspace.open(args.eval_dir)
    counts = reindex(workspace, progress=lambda line: print(f"[code-analyzer] {line}", file=sys.stderr))
    print(json.dumps(counts, sort_keys=True))
    return 0


def _probe(args: argparse.Namespace) -> int:
    from .model.client import Endpoint
    from .model.probe import ITEMS, run_probe
    from .settings import load_settings

    settings = load_settings()
    endpoint = Endpoint(args.endpoint or settings.local_endpoint, args.model or settings.local_model,
                        transport=args.transport)
    items = tuple(item.strip().upper() for item in args.only.split(",")) if args.only else ITEMS
    print(f"code-analyzer: probing {endpoint.model} at {endpoint.base_url}; the GPU should be idle", file=sys.stderr)
    path, document = run_probe(endpoint, items=items, repeat=args.repeat, heavy=args.heavy,
                               minutes=args.minutes, log=lambda line: print(line, file=sys.stderr))
    verdict = document["verdict"]
    if args.as_json:
        print(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(f"codec: {verdict['codec']}  batch concurrency: {verdict['batch_concurrency']}  "
              f"window: {document.get('window')}  HTTP 500s: {verdict['http_500']}")
        for failed in verdict["failed_checks"]:
            print(f"  failed: {failed}")
        print(path)
    return 0


def _has_tty() -> bool:
    return bool(sys.stdin.isatty() and sys.stdout.isatty())

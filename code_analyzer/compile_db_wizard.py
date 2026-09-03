from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any, TextIO

from .ask import CONFIRM, TEXT, Asker, Question, stdin_asker
from .compile_db import candidate_score, discover_candidate_paths, inspect_compile_db
from .errors import UserError
from .persist import write_json
from .process import run_process
from .progress import ProgressDisplay


class _MissingComponent(Exception):
    pass


def run_compile_db(
    args: Any, *, stdin: TextIO | None = None, stdout: TextIO | None = None,
    stderr: TextIO | None = None, ask: Asker | None = None,
) -> int:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    # The two prompts below are the only places this program stops and waits.
    # They go through the asker so the conversation can render them as turns;
    # the default reproduces exactly what the terminal did before.
    ask = ask if ask is not None else stdin_asker(stdin, stderr)
    source = args.source.expanduser().resolve()
    if not source.is_dir():
        raise UserError(f"source is not a directory: {source}")

    report = inspect_environment(source)
    selected = _best_valid(report["candidates"])
    report["selected"] = selected["path"] if selected else None
    if args.as_json:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False), file=stdout)
        return 0 if selected else 10
    if selected:
        print(selected["path"], file=stdout)
        return 0

    _validate_method_options(args)
    method = args.method
    if method is None:
        method = "cmake" if report["project"]["cmake_lists"] else None
    if method is None:
        _print_no_database(report, source, stderr)
        return 10
    try:
        if method == "cmake":
            prepared = _prepare_cmake(args, source, report, ask)
        else:
            prepared = _prepare_command(args, source)
    except _MissingComponent as exc:
        _missing_executable(str(exc), stderr)
        return 10

    argv, cwd, expected, impact = prepared
    if not shutil.which(argv[0]):
        _missing_executable(argv[0], stderr)
        return 10
    _print_preview(argv, cwd, expected, impact, stderr)
    if not args.yes:
        if not ask.interactive:
            print("code-analyzer: generation was not run in a non-interactive session; pass --yes to execute it", file=stderr)
            return 10
        try:
            answer = ask(Question("compile-db.continue", CONFIRM, "Continue? [y/N] "))
        except KeyboardInterrupt:
            print("\ncode-analyzer: interrupted", file=stderr)
            return 130
        if answer.interrupted:
            print("\ncode-analyzer: interrupted", file=stderr)
            return 130
        if not answer.yes:
            print("code-analyzer: generation cancelled", file=stderr)
            return 10

    preparation = _preparation_directory(source)
    stdout_path = preparation / "stdout.log"
    stderr_path = preparation / "stderr.log"
    metadata = {
        "source": str(source), "method": method, "argv": argv, "cwd": str(cwd),
        "expected_database": str(expected), "stdout_log": str(stdout_path),
        "stderr_log": str(stderr_path), "status": "running",
    }
    _write_json(preparation / "preparation.json", metadata)
    print(f"code-analyzer: preparation log: {preparation}", file=stderr)
    try:
        with ProgressDisplay(stderr) as display:
            display.emit("configuring compile database")
            process = run_process(
                argv, cwd, stdout_path, stderr_path, args.timeout, 5.0,
                heartbeat=lambda elapsed: display.emit(f"compile database command active ({int(elapsed)}s)"),
            )
    except OSError as exc:
        metadata.update({"status": "failed", "error": str(exc)})
        _write_json(preparation / "preparation.json", metadata)
        print(f"code-analyzer: generation failed: {exc}", file=stderr)
        return 20
    metadata["process"] = process.as_dict()
    if process.interrupted:
        metadata["status"] = "interrupted"
        _write_json(preparation / "preparation.json", metadata)
        return 130
    if process.timed_out or process.exit_code != 0:
        metadata["status"] = "timed_out" if process.timed_out else "failed"
        _write_json(preparation / "preparation.json", metadata)
        detail = "timed out" if process.timed_out else f"exited with status {process.exit_code}"
        print(f"code-analyzer: compile database command {detail}; see {preparation}", file=stderr)
        return 20

    # Validate the expected product directly (custom build directories may be
    # outside automatic search), then perform discovery again for the log.
    validation = inspect_compile_db(expected, source)
    rediscovered = [inspect_compile_db(path, source) for path in discover_candidate_paths(source)]
    metadata.update({"status": "completed" if validation["usable"] else "invalid_product", "validation": validation, "rediscovered_candidates": rediscovered})
    _write_json(preparation / "preparation.json", metadata)
    if not validation["usable"]:
        issues = "; ".join(validation["issues"]) or "unknown validation error"
        print(f"code-analyzer: generated database is not usable: {issues}; see {preparation}", file=stderr)
        return 20
    _print_success(source, expected, stdout)
    return 0


def inspect_environment(source: Path) -> dict[str, Any]:
    candidates = [inspect_compile_db(path, source) for path in discover_candidate_paths(source)]
    components = {name: shutil.which(name) for name in ("cmake", "ninja", "make", "bear")}
    presets = _read_presets(source)
    suggested: list[str] = []
    quoted_source = shlex.quote(str(source))
    if (source / "CMakeLists.txt").is_file():
        suggested.append(f"code-analyzer compile-db {quoted_source} --method cmake")
    suggested.append(f"code-analyzer compile-db {quoted_source} --json")
    return {
        "source": str(source),
        "selected": None,
        "candidates": candidates,
        "components": components,
        "project": {
            "cmake_lists": str(source / "CMakeLists.txt") if (source / "CMakeLists.txt").is_file() else None,
            "preset_files": presets["files"],
            "configure_presets": presets["presets"],
        },
        "suggested_commands": suggested,
    }


def _prepare_cmake(args: Any, source: Path, report: dict[str, Any], ask: Asker) -> tuple[list[str], Path, Path, str]:
    if not report["project"]["cmake_lists"]:
        raise UserError(f"CMakeLists.txt does not exist in source: {source}")
    if args.preset and (args.build_dir is not None or args.generator is not None):
        raise UserError("--preset cannot be combined with --build-dir or --generator")
    extra = list(args.cmake_arg or [])
    if not args.yes and not extra and not args.preset and ask.interactive:
        # The only free-text question in the program.  It still splits like a
        # shell, and an unbalanced quote is still a UserError rather than a
        # silently different argv.
        entered = ask(Question("compile-db.cmake-args", TEXT, "Additional CMake arguments (optional): ")).text
        try:
            extra = shlex.split(entered)
        except ValueError as exc:
            raise UserError(f"invalid additional CMake arguments: {exc}") from exc
    if args.preset:
        known = {item["name"]: item for item in report["project"]["configure_presets"]}
        if known and args.preset not in known:
            raise UserError(f"unknown configure preset: {args.preset}")
        argv = ["cmake", "--preset", args.preset, "-S", str(source), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", *extra]
        build_dir = _preset_build_dir(source, known.get(args.preset), args.preset)
        if build_dir is None:
            raise UserError("cannot determine preset binaryDir safely")
        _validate_build_dir(source, build_dir)
    else:
        build_dir = (args.build_dir.expanduser() if args.build_dir is not None else source / "build" / "code-analyzer")
        if not build_dir.is_absolute():
            build_dir = (Path.cwd() / build_dir).resolve()
        else:
            build_dir = build_dir.resolve()
        _validate_build_dir(source, build_dir)
        generator = args.generator or _default_generator(report["components"])
        if generator is None:
            raise _MissingComponent("ninja or make")
        generator_tool = "ninja" if generator == "Ninja" else "make"
        if not report["components"].get(generator_tool):
            raise _MissingComponent(generator_tool)
        argv = ["cmake", "-S", str(source), "-B", str(build_dir), "-G", generator, "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON", *extra]
    return argv, source, build_dir / "compile_commands.json", "runs CMake configure code only; it does not build targets or clean the build directory"


def _prepare_command(args: Any, source: Path) -> tuple[list[str], Path, Path, str]:
    if args.expected_db is None:
        raise UserError("--method command requires --expected-db")
    argv = list(args.command_argv or [])
    if argv and argv[0] == "--":
        argv.pop(0)
    if not argv:
        raise UserError("--method command requires a command after --")
    expected = args.expected_db.expanduser()
    if not expected.is_absolute():
        expected = (Path.cwd() / expected).resolve()
    else:
        expected = expected.resolve()
    return argv, source, expected, "runs the exact supplied argv without a shell; the command may configure or build the project"


def _validate_build_dir(source: Path, build_dir: Path) -> None:
    forbidden = {source.resolve(), Path.home().resolve(), Path(build_dir.anchor).resolve()}
    if build_dir in forbidden:
        raise UserError(f"unsafe build directory: {build_dir}")
    if build_dir.exists() and not build_dir.is_dir():
        raise UserError(f"build directory is not a directory: {build_dir}")


def _validate_method_options(args: Any) -> None:
    if args.method == "cmake":
        if args.expected_db is not None or args.command_argv:
            raise UserError("CMake mode does not accept --expected-db or a custom command")
    elif args.method == "command":
        if args.build_dir is not None or args.generator is not None or args.preset is not None or args.cmake_arg:
            raise UserError("command mode does not accept CMake build, generator, preset, or argument options")
    elif args.expected_db is not None or args.command_argv:
        raise UserError("custom generation requires --method command")


def _default_generator(components: dict[str, str | None]) -> str | None:
    if components.get("ninja"):
        return "Ninja"
    if components.get("make"):
        return "Unix Makefiles"
    return None


def _read_presets(source: Path) -> dict[str, Any]:
    files: list[str] = []
    raw_presets: dict[str, dict[str, Any]] = {}
    for name in ("CMakePresets.json", "CMakeUserPresets.json"):
        path = source / name
        if not path.is_file():
            continue
        files.append(str(path))
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        for item in data.get("configurePresets", []) if isinstance(data, dict) else []:
            if isinstance(item, dict) and isinstance(item.get("name"), str):
                raw_presets[item["name"]] = item
    presets: list[dict[str, Any]] = []
    for name, item in raw_presets.items():
        if item.get("hidden", False):
            continue
        binary_dir = _inherited_preset_value(name, "binaryDir", raw_presets, set())
        presets.append({"name": name, "binaryDir": binary_dir if isinstance(binary_dir, str) else None})
    return {"files": files, "presets": presets}


def _inherited_preset_value(name: str, key: str, presets: dict[str, dict[str, Any]], seen: set[str]) -> Any:
    if name in seen or name not in presets:
        return None
    item = presets[name]
    if key in item:
        return item[key]
    parents = item.get("inherits", [])
    if isinstance(parents, str):
        parents = [parents]
    if not isinstance(parents, list):
        return None
    for parent in parents:
        if isinstance(parent, str):
            value = _inherited_preset_value(parent, key, presets, seen | {name})
            if value is not None:
                return value
    return None


def _preset_build_dir(source: Path, preset: dict[str, Any] | None, name: str) -> Path | None:
    if not preset or not preset.get("binaryDir"):
        return None
    value = preset["binaryDir"]
    replacements = {
        "${sourceDir}": str(source), "${sourceParentDir}": str(source.parent),
        "${sourceDirName}": source.name, "${presetName}": name,
    }
    for token, replacement in replacements.items():
        value = value.replace(token, replacement)
    if "${" in value or "$env{" in value or "$penv{" in value:
        return None
    path = Path(value).expanduser()
    return (path if path.is_absolute() else source / path).resolve()


def _best_valid(candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    valid = [item for item in candidates if item["usable"]]
    return max(valid, key=candidate_score, default=None)


def _print_preview(argv: list[str], cwd: Path, expected: Path, impact: str, stderr: TextIO) -> None:
    print("Compile database preparation:", file=stderr)
    print(f"  cwd: {cwd}", file=stderr)
    print(f"  argv: {shlex.join(argv)}", file=stderr)
    print(f"  output: {expected}", file=stderr)
    print(f"  impact: {impact}", file=stderr)


def _print_no_database(report: dict[str, Any], source: Path, stderr: TextIO) -> None:
    print(f"code-analyzer: no valid compile_commands.json was found for {source}", file=stderr)
    if not report["project"]["cmake_lists"]:
        print("No CMakeLists.txt was detected. For a custom build, provide the expected output and exact command:", file=stderr)
        print(f"  code-analyzer compile-db {shlex.quote(str(source))} --method command --expected-db PATH -- COMMAND [ARG ...]", file=stderr)


def _missing_executable(name: str, stderr: TextIO) -> None:
    print(f"code-analyzer: required executable not found: {name}", file=stderr)
    hints = {
        "cmake": "Install CMake with your platform package manager (Ubuntu: sudo apt install cmake).",
        "ninja": "Install Ninja with your platform package manager (Ubuntu: sudo apt install ninja-build).",
        "make": "Install Make with your platform package manager (Ubuntu: sudo apt install make).",
        "bear": "Install Bear with your platform package manager (Ubuntu: sudo apt install bear).",
        "ninja or make": "Install Ninja or Make with your platform package manager (Ubuntu: sudo apt install ninja-build or sudo apt install make).",
    }
    if name in hints:
        print(hints[name], file=stderr)


def _print_success(source: Path, database: Path, stdout: TextIO) -> None:
    source_arg = shlex.quote(str(source))
    db_arg = shlex.quote(str(database))
    print(f"code-analyzer analyze {source_arg} --compile-db {db_arg}", file=stdout)
    try:
        configured = os.path.relpath(database, source)
    except ValueError:
        configured = str(database)
    configured = configured.replace("\\", "/")
    print("", file=stdout)
    print("[build]", file=stdout)
    print('compile_database_mode = "explicit"', file=stdout)
    print(f"compile_database = {json.dumps(configured, ensure_ascii=False)}", file=stdout)


def _preparation_directory(source: Path) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    slug = "".join(char if char.isalnum() or char in "-_" else "-" for char in source.name) or "source"
    path = Path.cwd().resolve() / "code-analyzer-reports" / "compile-db" / slug / f"{stamp}-{uuid.uuid4().hex[:12]}"
    try:
        path.mkdir(parents=True)
    except OSError as exc:
        raise UserError(f"cannot create compile database preparation directory {path}: {exc}") from exc
    return path


def _write_json(path: Path, value: Any) -> None:
    write_json(path, value)


def _interactive(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


def input_from(stdin: TextIO, stderr: TextIO, prompt: str) -> str:
    print(prompt, end="", file=stderr, flush=True)
    value = stdin.readline()
    if value == "":
        return ""
    return value.rstrip("\n")

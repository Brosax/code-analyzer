"""A compilation database from the project's own CMake, configured in a jail on a human's click.

``propose`` builds the exact argv from closed, typed parameters -- a configure
preset the project declares, a generator, ``-D`` defines with plain names and
values, a toolchain file inside the source tree -- and returns what the card
shows.  Nothing runs.  ``run`` (only from an approved card) configures into
``<workspace>/compile_db/B<n>`` inside core/sandbox.py's jail, validates the
``compile_commands.json`` it produced, and records it as the next build
context version, so the next tool run is build-aware.  Configure only: no
target is built.
"""
from __future__ import annotations

import re
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..compile_db import inspect_compile_db
from ..compile_db_wizard import _read_presets
from ..core import sandbox
from ..errors import UserError
from ..evidence.analyze import current_buildctx
from ..evidence.buildctx_schema import buildctx_sha, buildctx_text
from ..evidence.workspace import Workspace
from ..process import run_process

GENERATORS = ("Ninja", "Unix Makefiles")
DEFINE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,80}")
DEFINE_VALUE = re.compile(r"[A-Za-z0-9_./+:=,-]{0,200}")
MAX_DEFINES = 24
TIMEOUT_SECONDS = 900


def propose(workspace: Workspace, *, preset: str = "", generator: str = "", defines: dict[str, Any] | None = None,
            toolchain_file: str = "") -> dict[str, Any]:
    source = workspace.source.resolve()
    if not (source / "CMakeLists.txt").is_file():
        raise UserError("the source tree has no top-level CMakeLists.txt; ask the evaluator for a "
                        "compile_commands.json from the vendor's build instead")
    if shutil.which("cmake") is None:
        raise UserError("cmake is not installed on this machine")
    if sandbox.available() is None:
        raise UserError("bubblewrap (bwrap) is not installed; the configure step only runs inside it")
    defines = dict(defines or {})
    if len(defines) > MAX_DEFINES:
        raise UserError(f"at most {MAX_DEFINES} defines")
    for name, value in defines.items():
        if not DEFINE_NAME.fullmatch(str(name)) or not DEFINE_VALUE.fullmatch(str(value)):
            raise UserError(f"define {name!r}={value!r}: names are C identifiers, values plain words or paths")
    number = len(workspace.ledger.of("compile_db_proposed")) + 1
    build = workspace.root / "compile_db" / f"B{number}"
    argv = ["cmake", "-S", str(source), "-B", str(build), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
    if preset:
        presets = {item["name"] for item in _read_presets(source)["presets"]}
        if preset not in presets:
            raise UserError(f"unknown configure preset {preset!r}; the project declares {sorted(presets) or 'none'}")
        argv = ["cmake", "--preset", preset, "-S", str(source), "-B", str(build), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
    elif generator:
        if generator not in GENERATORS:
            raise UserError(f"generator must be one of {GENERATORS}")
        argv += ["-G", generator]
    if toolchain_file:
        target = (source / toolchain_file).resolve()
        if not target.is_relative_to(source) or not target.is_file():
            raise UserError(f"toolchain file {toolchain_file!r} is not a file in the source tree")
        argv.append(f"-DCMAKE_TOOLCHAIN_FILE={target}")
    argv += [f"-D{name}={value}" for name, value in sorted(defines.items())]
    record = workspace.ledger.append("compile_db_proposed", number=number, argv=argv, build_dir=str(build))
    return {"number": number, "argv": argv, "build_dir": str(build), "seq": record["seq"]}


def run(workspace: Workspace, number: int, *, progress: Callable[[str], None] = lambda _l: None,
        cancelled: Callable[[], bool] = lambda: False) -> dict[str, Any]:
    proposals = {r["number"]: r for r in workspace.ledger.of("compile_db_proposed")}
    if number not in proposals:
        raise UserError(f"no compile database proposal B{number}")
    proposal = proposals[number]
    build = Path(proposal["build_dir"])
    if not build.resolve().is_relative_to(workspace.root.resolve()):
        raise UserError("the build directory must be inside the evaluation")
    build.mkdir(parents=True, exist_ok=True)
    logs = build.parent / f"B{number}.logs"
    tool = shutil.which(proposal["argv"][0])
    argv = sandbox.jail(list(proposal["argv"]), writable=build, cwd=workspace.source,
                        readable=[workspace.source, *([Path(tool).parent] if tool else [])])
    progress(f"configuring in the sandbox: {' '.join(proposal['argv'])}")
    result = run_process(argv, workspace.source, logs / "stdout.log", logs / "stderr.log", TIMEOUT_SECONDS, 5.0,
                         cancelled=cancelled,
                         heartbeat=lambda elapsed: progress(f"cmake configure running ({int(elapsed)}s)"))
    database = build / "compile_commands.json"
    validation = inspect_compile_db(database, workspace.source) if database.is_file() else \
        {"usable": False, "issues": ["cmake produced no compile_commands.json"]}
    tail = _tail(logs / "stderr.log") or _tail(logs / "stdout.log")
    outcome = {"number": number, "exit_code": result.exit_code, "timed_out": result.timed_out,
               "usable": bool(validation.get("usable")), "issues": list(validation.get("issues") or [])[:5],
               "entries": validation.get("entries"), "log_tail": tail}
    if outcome["usable"]:
        context = current_buildctx(workspace)
        context["build"]["compile_database"] = str(database)
        context["build"]["compile_database_mode"] = "explicit"
        version, _ = workspace.save_version("buildctx", buildctx_text(context))
        workspace.ledger.append("buildctx_version", version=version, sha256=buildctx_sha(context),
                                by=f"compile database B{number}")
        outcome["buildctx_version"] = version
        progress(f"compile database with {validation.get('entries')} entries; build context v{version} uses it; "
                 "run the tools again to use it")
    else:
        progress(f"no usable compile database (exit {result.exit_code}): {'; '.join(outcome['issues'])}")
    workspace.ledger.append("compile_db_generated", **outcome)
    return outcome


def _tail(path: Path, lines: int = 12) -> str:
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-lines:])
    except OSError:
        return ""


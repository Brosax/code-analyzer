"""The headless evaluation: run the analyzers, index the evidence, number the list.

Deterministic and model-free: ``code-analyzer evaluate`` never opens a socket to
a model, and an unreachable provider cannot change its exit code.

The static tools run through the proven runner (runner.py ``_analyze``) --
its inventory hashing, before/after source-stability check, cancellation and
SIGTERM handling, per-unit evidence and exit-code algebra are exactly what the
old ``analyze`` produced -- with the review, the export, the model and the old
build-assist loop switched off.  Its run directory lands under the evaluation's
``calls/Cnnnn-static/``; everything derived (index, clusters, the numbered
list) is built from that evidence here.

Exit codes are the runner's (0 complete, 10 partial, 20 failed, 130
interrupted); ``--fail-on`` can turn a complete run into 1 when a native,
gate-eligible finding reaches the threshold.  AI output never gates.
"""
from __future__ import annotations

import copy
import hashlib
import json
import tomllib
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import DEFAULTS, validate_config
from ..core.cancel import CancellationToken
from ..errors import UserError
from ..persist import json_bytes, jsonl_bytes
from ..sesip.active import active_profile, save_draft, select_builtin
from ..sesip.profile import BUILTINS, DEFAULT_HEADLESS, Profile, load_profile
from ..sesip.pv import build_entries, number, numbering_record
from ..settings import load_settings
from ..tools import TOOL_NAMES
from . import promoted, static_run
from .buildctx_schema import (
    buildctx_sha,
    buildctx_text,
    default_buildctx,
    parse_buildctx,
)
from .findings import parse_run
from .overlays import replay
from .parsing import should_fail
from .store import Store, index_current
from .triage import SourceLines, cluster
from .workspace import Workspace, _atomic

EXIT_GATE = 1


@dataclass
class Outcome:
    exit_code: int
    workspace: Workspace
    call_id: str
    run_dir: Path | None
    counts: dict[str, Any]


def evaluate(source: Path, *, eval_dir: Path | None = None, data_root: Path | None = None,
             profile: str | Path | None = None, buildctx: dict[str, Any] | None = None,
             tools: list[str] | None = None, compile_db: Path | None | bool = None,
             exclude: list[str] | None = None, fail_on: str = "none",
             progress: Callable[[str], None] = lambda _line: None,
             cancellation: CancellationToken | None = None) -> Outcome:
    source = source.expanduser().resolve()
    workspace = _workspace(source, eval_dir, data_root)
    chosen = _choose_profile(workspace, profile)
    context = buildctx or current_buildctx(workspace)
    number_, sha = _record_buildctx(workspace, context)
    progress(f"evaluation {workspace.root.name}: profile {chosen.name}, build context v{number_}")

    call_id = workspace.next_call_id()
    call_dir = workspace.call_directory(call_id, "static")
    config = static_config(context, output_root=call_dir, tools=tools, compile_db=compile_db, exclude=exclude)
    workspace.ledger.append("call_started", call_id=call_id, call_kind="static", tools=_enabled(config),
                            buildctx_sha=sha, scope="all")
    try:
        exit_code, run_dir = static_run.run(source, config, progress, cancellation=cancellation)
    except BaseException:
        workspace.ledger.append("call_finished", call_id=call_id, status="failed", exit_code=20)
        raise
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    call = {"call_id": call_id, "kind": "static", "run_dir": str(run_dir.relative_to(workspace.root)),
            "status": manifest.get("status"), "exit_code": exit_code, "buildctx_sha": sha,
            "tools": {name: item.get("status") for name, item in manifest.get("tools", {}).items()},
            "inventory_sha256": _inventory_digest(manifest)}
    _atomic(call_dir / "call.json", json_bytes(call))
    workspace.ledger.append("call_finished", call_id=call_id, status=call["status"], exit_code=exit_code,
                            run_dir=call["run_dir"])
    if exit_code == 130:
        return Outcome(exit_code, workspace, call_id, run_dir, {})

    counts, rows = index(workspace, chosen, run_dir, progress=progress)
    if exit_code == 0 and fail_on != "none" and should_fail({"findings": rows}, fail_on):
        exit_code = EXIT_GATE
        workspace.ledger.append("gate_triggered", policy=fail_on, call_id=call_id)
    return Outcome(exit_code, workspace, call_id, run_dir, counts)


def index(workspace: Workspace, profile: Profile, run_dir: Path, *,
          progress: Callable[[str], None] = lambda _line: None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Parse a call's evidence, cluster it, number the list, and write index.sqlite."""
    parsed = parse_run(run_dir, source=workspace.source)
    lines = SourceLines(parsed.source)
    ai_rows, ai_stale = promoted.rows(workspace, lines, str)
    parsed.findings.extend(ai_rows)
    clusters = cluster(parsed.findings, parsed.source, lines=lines)
    members: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in parsed.findings:
        if row.get("cluster_id"):
            members[row["cluster_id"]].append(row)
    triage = build_entries([c.as_row() for c in clusters], members, profile)
    previous = latest_numbering(workspace)
    entries, retired = number(triage.entries, previous)
    listed = [e for e in entries if e.pv_id]
    version = _save_numbering(workspace, listed, retired, previous)
    counts = {
        "findings": len(parsed.findings), "clusters": len(clusters), "in_toe": len(triage.entries),
        "outside_toe": triage.outside_toe, **{f"partition_{k}": v for k, v in triage.counts.items()},
        "listed": len(listed), "retired": len(retired),
        "kept": sum(1 for e in listed if e.match != "new"), "new": sum(1 for e in listed if e.match == "new"),
        "ai_promoted": len(ai_rows), "ai_stale": ai_stale,
    }
    assert counts["in_toe"] == sum(triage.counts.values()), "conservation: every in-TOE cluster has a partition"
    store = Store.build(workspace.index_path, parsed, clusters, pvs=listed,
                        triage={k: v for k, v in counts.items() if isinstance(v, int)})
    replay(workspace, store)
    store.close()
    workspace.ledger.append("index_built", numbering_version=version, profile_sha256=profile.sha256,
                            run_dir=_relative(run_dir, workspace.root),
                            **{k: v for k, v in counts.items() if isinstance(v, int)})
    progress(f"list: {counts['partition_main']} main, {counts['partition_unmapped']} to verify, "
             f"{counts['partition_below']} below threshold; {counts['kept']} kept their numbers, "
             f"{counts['new']} new, {counts['retired']} retired")
    return counts, parsed.findings


def reindex(workspace: Workspace, *, progress: Callable[[str], None] = lambda _line: None) -> dict[str, Any]:
    """Rebuild the list from the last completed call's evidence, under the current profile. No tool runs."""
    calls = [r for r in workspace.ledger.of("call_finished") if r.get("run_dir") and r.get("exit_code") != 130]
    if not calls:
        raise UserError("no completed tool run to rebuild the list from; run the tools first")
    counts, _ = index(workspace, active_profile(workspace), workspace.root / calls[-1]["run_dir"], progress=progress)
    return counts


def ensure_index(workspace: Workspace) -> bool:
    """Make sure index.sqlite is current, rebuilding it from the evidence when its schema is old.
    Returns False when there is nothing to build from yet."""
    if index_current(workspace.index_path):
        return True
    if not any(r.get("run_dir") and r.get("exit_code") != 130 for r in workspace.ledger.of("call_finished")):
        return False
    reindex(workspace)
    return True


def current_buildctx(workspace: Workspace) -> dict[str, Any]:
    known = workspace.ledger.of("buildctx_version")
    if not known:
        return default_buildctx()
    return parse_buildctx(workspace.version_text("buildctx", int(known[-1]["version"])))


def _choose_profile(workspace: Workspace, profile: str | Path | None) -> Profile:
    """The profile to grade with: an explicit one is recorded as selected; otherwise the evaluation's own."""
    if profile is None:
        if not workspace.ledger.of("profile_selected"):
            return select_builtin(workspace, DEFAULT_HEADLESS)
        return active_profile(workspace)
    if isinstance(profile, str) and profile in BUILTINS:
        current = workspace.ledger.of("profile_selected")
        if current and current[-1].get("source") == "builtin" and current[-1]["name"] == profile:
            return load_profile(profile)
        return select_builtin(workspace, profile)
    return save_draft(workspace, Path(profile).expanduser().read_text(encoding="utf-8"))


def latest_numbering(workspace: Workspace) -> list[dict[str, Any]]:
    """Every PV number ever issued in this evaluation, active and retired, from the last snapshot."""
    records = workspace.ledger.of("pv_numbered")
    if not records:
        return []
    path = workspace.root / "pv" / f"numbering.v{records[-1]['version']}.jsonl"
    return [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]


def _save_numbering(workspace: Workspace, listed: list[Any], retired: list[dict[str, Any]],
                    previous: list[dict[str, Any]]) -> int:
    version = len(workspace.ledger.of("pv_numbered")) + 1
    current = [{**numbering_record(e), "retired": False} for e in listed]
    gone = [{**record, "retired": True} for record in retired]
    snapshot = sorted(current + gone, key=lambda r: r["pv_id"])
    directory = workspace.root / "pv"
    directory.mkdir(exist_ok=True)
    data = b"".join(jsonl_bytes(record) for record in snapshot)
    _atomic(directory / f"numbering.v{version}.jsonl", data)
    workspace.ledger.append("pv_numbered", version=version, sha256=hashlib.sha256(data).hexdigest(),
                            listed=len(current), retired=len(gone), previous=len(previous))
    return version


def static_config(buildctx: dict[str, Any], *, output_root: Path, tools: list[str] | None = None,
                  compile_db: Path | None | bool = None, exclude: list[str] | None = None) -> dict[str, Any]:
    """The runner configuration for a static-tools call: evidence only."""
    config = copy.deepcopy(DEFAULTS)
    config["build"] = copy.deepcopy(buildctx["build"])
    config["tools"] = copy.deepcopy(buildctx["tools"])
    config["run"]["output_root"] = str(output_root)
    # settings.toml [analyzers] names where each tool lives on this host; a build context that names its own
    # executable keeps it.
    for name, path in load_settings().analyzers.items():
        if path and name in config["tools"] and config["tools"][name]["executable"] == name:
            config["tools"][name]["executable"] = str(Path(path).expanduser())
    # The build context is driven from the conversation (v3 M6); the old
    # in-run loop that could stop and wait for a decision stays off.
    config["build"]["assist"] = "off"
    if exclude:
        config["source"]["exclude"] = list(exclude)
    if tools:
        unknown = sorted(set(tools) - set(TOOL_NAMES))
        if unknown:
            raise UserError(f"unknown tool(s): {', '.join(unknown)}")
        for name in TOOL_NAMES:
            config["tools"][name]["enabled"] = name in tools
    if compile_db is False:
        config["build"].update({"compile_database_mode": "disabled", "compile_database": None})
    elif isinstance(compile_db, Path):
        config["build"].update({"compile_database_mode": "explicit", "compile_database": str(compile_db.resolve())})
    validate_config(config)
    return config


def _workspace(source: Path, eval_dir: Path | None, data_root: Path | None) -> Workspace:
    if eval_dir is not None and (eval_dir / "evaluation.json").is_file():
        workspace = Workspace.open(eval_dir)
        if Path(workspace.evaluation["source"]) != source:
            raise UserError(f"{eval_dir} evaluates {workspace.evaluation['source']}, not {source}")
        return workspace
    if eval_dir is not None:
        # A headless run has no human to confirm confidentiality: client, the safe default.
        return Workspace.create_at(eval_dir.expanduser(), source, confidentiality="client")
    from ..settings import load_settings  # noqa: PLC0415

    return Workspace.create(data_root or load_settings().data_root, source, confidentiality="client")


def carry_buildctx(source: Workspace, target: Workspace) -> tuple[int, str]:
    """Start ``target`` from ``source``'s build context: include paths, overrides and the compile database
    that point into the old source tree are moved to the new one; everything else is kept as is."""
    text = buildctx_text(current_buildctx(source))
    old, new = str(source.source.resolve()), str(target.source.resolve())
    text = text.replace(f'"{old}/', f'"{new}/').replace(f'"{old}"', f'"{new}"')
    context = tomllib.loads(text)
    number_, sha = _record_buildctx(target, context)
    target.ledger.append("buildctx_carried", version=number_, sha256=sha, source_evaluation=source.root.name)
    return number_, sha


def _record_buildctx(workspace: Workspace, context: dict[str, Any]) -> tuple[int, str]:
    sha = buildctx_sha(context)
    known = workspace.ledger.of("buildctx_version")
    if known and known[-1]["sha256"] == sha:
        return int(known[-1]["version"]), sha
    number_, _ = workspace.save_version("buildctx", buildctx_text(context))
    workspace.ledger.append("buildctx_version", version=number_, sha256=sha, by="default" if not known else "cli")
    return number_, sha


def _relative(path: Path, root: Path) -> str:
    """A call's run directory as the ledger records it: relative when it lives in the workspace."""
    return str(path.relative_to(root)) if path.is_relative_to(root) else str(path)


def _enabled(config: dict[str, Any]) -> list[str]:
    return [name for name in TOOL_NAMES if config["tools"][name]["enabled"]]


def _inventory_digest(manifest: dict[str, Any]) -> str:
    return str(manifest.get("source_inventory", {}).get("sha256") or "")

"""What the seven tools actually do, against one evaluation.

Every handler returns a ``Result``: ``content`` is what the model reads (compact,
at most ~600 tokens, untrusted text fenced), ``card`` is what the page draws.
Query tools ("reason") return content for the next model step; action tools
("render") return a card and end the turn.  A tool that needs a human click
returns an approval card and does nothing else -- ``execute_approved`` runs it
only after ``approvals.py`` has checked who clicked and that nothing changed.

The model never reaches a confirmation: ``profile_edit`` refuses any patch that
touches the fields only a human may set (``NEVER_FROM_MODEL``), and ``export``
always stops at its card.
"""
from __future__ import annotations

import copy
import json
import math
import re
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..core.tomlw import dumps
from ..errors import UserError
from ..evidence.store import Store
from ..evidence.workspace import Workspace
from ..sesip import active
from ..sesip.profile import STRONG_SFR_BASES, parse_profile
from .codecs import data_block, finding_text
from .toolspec import BY_NAME

MAX_CONTENT_CHARS = 2400   # ~600 tokens of mixed Chinese/English
SMALL_REVIEW = 3           # at most this many units run inside an existing grant without a new card
REVIEW_MAX_MINUTES = 240
SOURCE_RADIUS = 15
NEVER_FROM_MODEL = frozenset({"status", "version", "confirmed_by", "confirmed_at", "confidentiality",
                              "allow_public_model", "id"})


@dataclass
class Result:
    content: str = ""
    card: dict[str, Any] | None = None
    approval: dict[str, Any] | None = None   # {"tool", "arguments", "summary", "writes"}
    error: bool = False


@dataclass
class Services:
    """What tools may start in the background; the web server provides these."""
    run_tools: Callable[[Workspace, list[str] | None], Any]
    jobs: Callable[[Workspace], list[dict[str, Any]]]
    export: Callable[[Workspace, str, list[str]], dict[str, Any]]
    rebuild: Callable[[Workspace], Any] = lambda _ws: None
    apply_patch: Callable[[Workspace, str, list[int]], Any] = lambda _ws, _p, _s: None
    review: Callable[[Workspace, dict[str, Any]], Any] = lambda _ws, _a: None
    compile_db: Callable[[Workspace, int], Any] = lambda _ws, _n: None


@dataclass
class ToolContext:
    workspace: Workspace
    services: Services
    results: dict[str, str] = field(default_factory=dict)  # R-handle -> full content (for paging)


def run(ctx: ToolContext, name: str, arguments: dict[str, Any]) -> Result:
    handler = HANDLERS.get(name)
    if handler is None:
        return Result(f"unknown tool {name}", error=True)
    try:
        return handler(ctx, arguments)
    except (UserError, ValueError, KeyError) as error:
        return Result(f"{name} failed: {str(error).strip(chr(39))}", error=True)


# -- query tools --------------------------------------------------------------------------------

def _list(ctx: ToolContext, args: dict[str, Any]) -> Result:
    kind = args["kind"]
    where = dict(args.get("where") or {})
    page = int(args.get("page") or 1)
    if kind == "job":
        jobs = ctx.services.jobs(ctx.workspace)
        lines = [f"{j['id']} {j['kind']} {j['status']} exit={j['exit_code']} {j['elapsed_seconds']}s"
                 + (f" · {finding_text(j['progress'][-1])}" if j.get("progress") else "") for j in jobs]
        return Result("\n".join(lines) or "no jobs yet")
    store = _store(ctx.workspace)
    try:
        if kind == "coverage":
            return Result(_coverage(ctx.workspace, store))
        if kind == "pv":
            filters = {k: where[k] for k in ("partition", "level", "module", "sfr", "status", "path", "family", "ai",
                                             "origin") if where.get(k)}
            if where.get("category"):
                filters["family"] = where["category"]
            sort = {"priority": "priority", "level": "level", "path": "path"}.get(args.get("sort", "priority"),
                                                                                  "priority")
            listing = store.list_pvs(filters, sort=sort, page=page)
            head = (f"{listing['total']} entries match (page {page}); by partition {listing['by_partition']}; "
                    f"by level {listing['by_level']}")
            rows = [_pv_line(row) for row in listing["rows"]]
            return Result("\n".join([head, *rows]))
        if kind in ("finding", "cluster"):
            filters = {k: where[k] for k in ("tool", "level", "path", "rule") if where.get(k)}
            if kind == "cluster":
                listing = store.list_clusters({k: v for k, v in filters.items() if k in ("tool", "level", "path")},
                                              page=page)
                rows = [f"{r['cluster_id']} {r['top_level']} {r['path']}:{r['line_start']} {r['function']}() "
                        f"{r['family']} x{r['members']} [{r['tools']}]" for r in listing["rows"]]
            else:
                listing = store.list_findings(filters, page=page)
                rows = [f"F:{r['fingerprint'][:8]} {r['review_level']} {r['tool']} {r['rule_id']} "
                        f"{r['path']}:{r['line']} {finding_text(r['message'])}" for r in listing["rows"]]
            return Result("\n".join([f"{listing['total']} {kind}s match (page {page})", *rows]))
        if kind == "file":
            rows = store.db.execute("SELECT path, COUNT(*) AS n, MAX(level_rank) AS worst FROM pvs GROUP BY path "
                                    "ORDER BY worst DESC, n DESC LIMIT 20 OFFSET ?", ((page - 1) * 20,)).fetchall()
            return Result("\n".join(f"{r['path']}: {r['n']} entries" for r in rows) or "no listed files")
    finally:
        store.close()
    return Result(f"unknown kind {kind}", error=True)


def _show(ctx: ToolContext, args: dict[str, Any]) -> Result:
    target = str(args["target"]).strip()
    part = args.get("part", "summary")
    radius = min(int(args.get("radius") or SOURCE_RADIUS), 40)
    if re.fullmatch(r"R\d+", target):
        return _page_result(ctx, target, int(args.get("page") or 1))
    if re.fullmatch(r"J\d+", target):
        job = next((j for j in ctx.services.jobs(ctx.workspace) if j["id"] == target), None)
        if job is None:
            return Result(f"no job {target}", error=True)
        tail = [finding_text(line) for line in (job.get("progress") or [])[-8:]]
        return Result(_cap(f"{job['id']} {job['kind']} {job['status']} exit={job['exit_code']} "
                           f"{job['elapsed_seconds']}s\n" + "\n".join(tail)))
    if target == "profile":
        profile = active.active_profile(ctx.workspace)
        view = active.view(profile)
        text = (f"profile {view['name']} ({view['status']}), sha256 {view['sha256'][:12]}\n"
                f"SFR: {', '.join(s['id'] + ' ' + s['title'] for s in view['sfr'])}\n"
                f"levels: {', '.join(level['id'] for level in view['levels'])}\n"
                f"TOE modules: {'; '.join(m['id'] + ' ' + ','.join(m['paths']) for m in view['toe_modules'])}\n"
                f"grading rules: {len(view['grading_rules'])}")
        return Result(_cap(text))
    store = _store(ctx.workspace)
    try:
        if target == "coverage":
            return Result(_coverage(ctx.workspace, store))
        if re.fullmatch(r"PV-\d+", target):
            entry = store.pv(target)
            if entry is None:
                return Result(f"no {target}", error=True)
            members = store.cluster_members(entry["cluster_id"])
            if part == "source":
                return Result(_source(ctx.workspace, entry["path"], int(entry["line_start"]), radius))
            lines = [_pv_line({**entry, "tools": ",".join(entry.get("tools", []))}),
                     f"status {entry['status']}{(' — ' + entry['note']) if entry.get('note') else ''}; "
                     f"priority {entry['priority']} {entry.get('priority_why')}"]
            for member in members[:12]:
                lines.append(f"  F:{member['fingerprint'][:8]} {member['tool']} {member['rule_id']} line "
                             f"{member['line']} [{member.get('review_level')}] {finding_text(member['message'])}")
            if len(members) > 12:
                lines.append(f"  … {len(members) - 12} more members")
            opinion = entry.get("ai")
            if opinion:
                lines.append(f"AI ({opinion.get('lens')} lens, advice only): {opinion['verdict']} "
                             f"{opinion['confidence']}, decisive line {opinion['decisive_line']}"
                             + (f", suggests level {opinion['level_suggestion']}" if opinion.get("level_suggestion")
                                else ""))
                if part in ("ai", "summary"):
                    lines.append("  " + finding_text(opinion.get("rationale", "")))
            elif part == "ai":
                lines.append("no grounded AI verdict on this entry yet (review can verify it)")
            if part in ("evidence", "summary"):
                lines.append(_source(ctx.workspace, entry["path"], int(entry["line_start"]), min(radius, 8)))
            return Result(_cap("\n".join(lines)))
        match = re.fullmatch(r"F:([0-9a-f]{4,64})", target)
        if match:
            rows = store.db.execute("SELECT row FROM findings WHERE fingerprint LIKE ? LIMIT 3",
                                    (match.group(1) + "%",)).fetchall()
            if len(rows) != 1:
                return Result(f"{target} matches {len(rows)} findings; give a longer prefix", error=True)
            row = json.loads(rows[0][0])
            text = (f"{row['tool']} {row['rule_id']} [{row.get('review_level')}] {row['canonical_path']}:{row['line']} "
                    f"({row.get('view_class')}, cluster {row.get('cluster_id') or '-'})\n{finding_text(row['message'])}\n"
                    + _source(ctx.workspace, row["canonical_path"], _int(row["line"]), radius))
            return Result(_cap(text))
    finally:
        store.close()
    match = re.fullmatch(r"(?P<path>[^:\s]+):(?P<line>\d+)", target)
    if match:
        return Result(_source(ctx.workspace, match["path"], int(match["line"]), radius))
    return Result(f"cannot open {target!r}: use a PV/F:/R handle, path:line, 'profile' or 'coverage'", error=True)


# -- action tools -------------------------------------------------------------------------------

def _run_tools(ctx: ToolContext, args: dict[str, Any]) -> Result:
    scope = str(args.get("scope") or "all")
    if scope not in ("all", "toe"):
        return Result("run_tools currently runs on the whole tree ('all'); a narrower scope is not available yet",
                      error=True)
    tools = [t for t in args.get("tools") or [] if t in ("cppcheck", "flawfinder", "splint")] or None
    job = ctx.services.run_tools(ctx.workspace, tools)
    summary = job.summary() if hasattr(job, "summary") else dict(job)
    return Result(f"started {summary['id']} ({', '.join(tools or ['cppcheck', 'flawfinder', 'splint'])})",
                  card={"kind": "job", "job": summary})


def _build_context(ctx: ToolContext, args: dict[str, Any]) -> Result:
    from ..jobs import buildctx_job  # noqa: PLC0415 - pulls in the analyzer stack

    op = args["op"]
    if op == "diagnose":
        report = buildctx_job.diagnose(ctx.workspace)
        if not report:
            return Result("no Splint or Cppcheck units in the last run")
        lines = []
        for tool, info in report.items():
            lines.append(f"{tool}: {info['units_failed']}/{info['units_total']} units failed, "
                         f"{info['units_analysis_reached']} reached analysis; classes {info['classes']}; "
                         f"#error directives {info['error_directives']}")
            for header in info["top_missing"]:
                where = ", ".join(header["candidates"]) or "not in the tree"
                lines.append(f"  missing {header['header']} ({header['units']} units, {header['kind']}): {where}")
        return Result("\n".join(lines))
    if op == "patch":
        proposal = buildctx_job.propose(ctx.workspace, str(args.get("tool") or "splint"))
        document = proposal.get("patch")
        if document is None:
            return Result(proposal.get("reason", "no patch"))
        probe = document.get("probe") or {}
        probe_text = (f"probe: {probe.get('reached_after')}/{probe.get('sampled')} sampled failed units now "
                      f"preprocess (was {probe.get('reached_before')})") if probe else "no probe"
        chosen = document["preselected"]
        labels = [f"{'[x]' if i in chosen else '[ ]'} {label}" for i, label in enumerate(document["labels"])]
        return Result(f"{document['patch_id']}: {len(labels)} item(s) for {document['tool']}; {probe_text}\n"
                      + "\n".join(labels[:20]),
                      approval={"tool": "apply_patch",
                                "arguments": {"patch_id": document["patch_id"], "selected": chosen,
                                              "sha256": proposal["sha256"]},
                                "summary": f"应用构建上下文补丁 {document['patch_id']}（{document['tool']}，"
                                           f"{len(chosen)} 项已勾选；{probe_text}）",
                                "writes": ["buildctx 新版本", f"重跑 {document['failed_units']} 个失败单元"]})
    from ..jobs import compile_db_job  # noqa: PLC0415

    defines = {}
    for item in args.get("defines") or []:
        name, _, value = str(item).partition("=")
        defines[name.strip()] = value.strip()
    proposal = compile_db_job.propose(ctx.workspace, preset=str(args.get("preset") or ""),
                                      generator=str(args.get("generator") or ""), defines=defines,
                                      toolchain_file=str(args.get("toolchain_file") or ""))
    number = proposal["number"]
    return Result(f"B{number} prepared, not run: {' '.join(proposal['argv'])}\nit runs only after the evaluator "
                  "approves the card, inside a sandbox (no network, source read-only, configure only)",
                  approval={"tool": "compile_db", "arguments": {"number": number, "argv": proposal["argv"]},
                            "summary": f"在沙箱里运行 CMake 配置 B{number}（只配置不构建；无网络；源码只读）",
                            "writes": [proposal["build_dir"], "成功时：构建上下文新版本（使用该编译数据库）"]})


def _profile_edit(ctx: ToolContext, args: dict[str, Any]) -> Result:
    patch = args.get("patch")
    if not isinstance(patch, dict) or not patch:
        return Result("patch must be a non-empty JSON object (a merge-patch of the profile)", error=True)
    evaluation = patch.get("evaluation")
    if isinstance(evaluation, dict) and NEVER_FROM_MODEL & set(evaluation):
        return Result(f"only the evaluator can set {sorted(NEVER_FROM_MODEL & set(evaluation))}; "
                      "ask them to confirm on the profile page", error=True)
    current = active.active_profile(ctx.workspace)
    before = tomllib.loads(current.text)
    after = merge_patch(copy.deepcopy(before), patch)
    after.setdefault("evaluation", {})["status"] = "draft"
    text = dumps(after)
    parse_profile(text)  # raises UserError with the reasons
    draft = active.save_draft(ctx.workspace, text)
    ctx.services.rebuild(ctx.workspace)
    diff = _diff(before, after)
    return Result(f"saved draft {draft.name}: {diff}", card={"kind": "profile", "profile": draft.name, "diff": diff})


def review_plan(workspace: Workspace, arguments: dict[str, Any]) -> dict[str, Any]:
    """The deterministic plan for a review, its GPU estimate (labelled) and the budget to ask for."""
    from ..jobs import lens_job  # noqa: PLC0415 - pulls in the analyzer stack
    from ..sesip.coverage import granted_seconds  # noqa: PLC0415

    context = lens_job.setup(workspace)
    plan = lens_job.make_plan(context, focus=arguments.get("focus") or {}, targets=arguments.get("targets") or [],
                              depth=str(arguments.get("depth") or "normal"), lens=str(arguments.get("lens") or ""))
    seconds, basis = lens_job.estimate(workspace, plan)
    minutes = max(1, min(REVIEW_MAX_MINUTES, math.ceil(seconds * 1.2 / 60))) if plan.targets else 0
    return {"counts": plan.counts(), "skipped": plan.skipped, "estimate_seconds": round(seconds),
            "basis": basis, "budget_minutes": minutes, "targets": len(plan.targets),
            "sample": [t.as_dict() for t in plan.targets[:15]], "grant": granted_seconds(workspace)}


def _review(ctx: ToolContext, args: dict[str, Any]) -> Result:
    arguments = {"focus": {k: str(v) for k, v in (args.get("focus") or {}).items() if v},
                 "targets": [str(t) for t in args.get("targets") or []],
                 "depth": "quick" if args.get("depth") == "quick" else "normal", "lens": str(args.get("lens") or "")}
    plan = review_plan(ctx.workspace, arguments)
    counts, skipped = plan["counts"], plan["skipped"]
    if not plan["targets"]:
        return Result(f"nothing to review for that focus; skipped: {skipped or 'none'}")
    minutes = plan["budget_minutes"]
    text = (f"plan: verify {counts['T1']} list entr(ies), look at {counts['T2']} unit(s) with no tool alarm; "
            f"{plan['basis']}, about {plan['estimate_seconds'] // 60} min GPU; skipped {skipped or 'none'}")
    left = plan["grant"]["left"]
    if plan["targets"] <= SMALL_REVIEW and left >= plan["estimate_seconds"]:
        job = ctx.services.review(ctx.workspace, {**arguments, "budget_minutes": min(minutes, left / 60)})
        summary = job.summary() if hasattr(job, "summary") else dict(job or {})
        return Result(f"{text}\nstarted {summary.get('id')} within the GPU time already granted ({left:.0f}s left)",
                      card={"kind": "job", "job": summary})
    return Result(text + "\nthe evaluator approves the GPU time on the card",
                  approval={"tool": "review", "arguments": {**arguments, "budget_minutes": minutes},
                            "summary": f"AI 审查：核实 {counts['T1']} 条清单条目、查看 {counts['T2']} 个无告警单元；"
                                       f"GPU 额度 {minutes} 分钟（{plan['basis']}）",
                            "writes": [f"GPU 额度 {minutes} 分钟", "AI 意见附在条目上（不移除条目）",
                                       "经二次复核的 AI 新发现进入未分级分区"]})


def _export(ctx: ToolContext, args: dict[str, Any]) -> Result:
    variant = args.get("variant", "internal")
    formats = [f for f in args.get("formats") or ["xlsx", "md", "csv"] if f in ("xlsx", "md", "csv")]
    names = [f"pv-list.{f}" for f in formats]
    return Result(f"export needs the evaluator's approval: {variant} {', '.join(names)}",
                  approval={"tool": "export", "arguments": {"variant": variant, "formats": formats},
                            "summary": f"导出清单（{variant}）", "writes": names})


def execute_approved(ctx: ToolContext, tool: str, arguments: dict[str, Any]) -> Result:
    """Run what a human approved.  Only reachable from approvals.py."""
    if tool == "export":
        result = ctx.services.export(ctx.workspace, arguments["variant"], arguments["formats"])
        return Result(f"exported {result['id']}: {', '.join(f['name'] for f in result['files'])}; "
                      f"leak check {result['leak_check']}", card={"kind": "export", "export": result})
    if tool == "review":
        job = ctx.services.review(ctx.workspace, arguments)
        summary = job.summary() if hasattr(job, "summary") else dict(job or {})
        ctx.workspace.ledger.append("review_granted", budget_seconds=float(arguments["budget_minutes"]) * 60,
                                    job=summary.get("id"), arguments={k: v for k, v in arguments.items()
                                                                      if k != "budget_minutes"})
        return Result(f"review started as {summary.get('id')}", card={"kind": "job", "job": summary})
    if tool == "compile_db":
        job = ctx.services.compile_db(ctx.workspace, int(arguments["number"]))
        summary = job.summary() if hasattr(job, "summary") else dict(job or {})
        return Result(f"configuring B{arguments['number']} as {summary.get('id')}", card={"kind": "job", "job": summary})
    if tool == "apply_patch":
        job = ctx.services.apply_patch(ctx.workspace, arguments["patch_id"], list(arguments["selected"]))
        summary = job.summary() if hasattr(job, "summary") else dict(job or {})
        return Result(f"applying {arguments['patch_id']} as {summary.get('id')}", card={"kind": "job", "job": summary})
    raise UserError(f"{tool} has no approved action")


HANDLERS: dict[str, Callable[[ToolContext, dict[str, Any]], Result]] = {
    "list": _list, "show": _show, "run_tools": _run_tools, "build_context": _build_context,
    "profile_edit": _profile_edit, "review": _review, "export": _export,
}
assert set(HANDLERS) == set(BY_NAME)


# -- helpers --------------------------------------------------------------------------------------

def merge_patch(target: Any, patch: Any) -> Any:
    """RFC 7396 JSON merge-patch; arrays are replaced whole."""
    if not isinstance(patch, dict):
        return patch
    if not isinstance(target, dict):
        target = {}
    for key, value in patch.items():
        if value is None:
            target.pop(key, None)
        else:
            target[key] = merge_patch(target.get(key), value)
    return target


def _diff(before: dict[str, Any], after: dict[str, Any]) -> str:
    changes = []
    for key in sorted(set(before) | set(after)):
        if before.get(key) != after.get(key):
            old, new = before.get(key), after.get(key)
            if isinstance(old, list) or isinstance(new, list):
                changes.append(f"{key}: {len(old or [])} -> {len(new or [])} items")
            else:
                changes.append(f"{key} changed")
    return "; ".join(changes) or "no change"


def _store(workspace: Workspace) -> Store:
    from ..evidence.analyze import (
        ensure_index,  # noqa: PLC0415 - analyze pulls in the runner
    )

    if not ensure_index(workspace):
        raise UserError("there is no list yet; run_tools first")
    return Store(workspace.index_path)


def _pv_line(row: dict[str, Any]) -> str:
    sfr = ",".join(s["id"] for s in row.get("sfr", []) if s.get("basis") in STRONG_SFR_BASES) or "-"
    level = row["level"] if row["level"] != "unmapped" else f"unmapped(建议 {row.get('proposed_level') or '-'})"
    verdict = row.get("ai_verdict") or (row.get("ai") or {}).get("verdict") or ""
    return (f"{row['pv_id']} {level} [{row.get('partition')}] {row['path']}:{row['line_start']} "
            f"{row.get('function') or ''}() {row.get('family')} SFR {sfr} {row.get('tools')} {row.get('status')}"
            + (f" AI:{verdict}" if verdict else ""))


def _coverage(workspace: Workspace, store: Store) -> str:
    from ..sesip.coverage import coverage  # noqa: PLC0415

    counts = store.triage_counts()
    by_module = store.db.execute("SELECT module, partition, COUNT(*) FROM pvs GROUP BY module, partition").fetchall()
    modules = "; ".join(f"{m}/{p}: {n}" for m, p, n in by_module)
    view = coverage(workspace, store, active.active_profile(workspace))
    lenses = "; ".join(f"{name} {t['answered']}/{t['asked']} answered, grounding failures "
                       f"{t['grounding_failure_rate'] if t['grounding_failure_rate'] is not None else '-'}"
                       for name, t in view["lenses"].items()) or "no AI review yet"
    return (f"in-TOE clusters {counts.get('in_toe', 0)} = main {counts.get('partition_main', 0)} + unmapped "
            f"{counts.get('partition_unmapped', 0)} + below {counts.get('partition_below', 0)}; outside TOE "
            f"{counts.get('outside_toe', 0)}; listed {counts.get('listed', 0)}\nby module: {modules}\n"
            f"AI: {view['verified']}/{view['listed']} listed entries verified; verdicts {view['verdicts']}; "
            f"promoted AI findings {view['promoted']}; unreviewed {view['unreviewed'] or 'none'}\n"
            f"lenses: {lenses}; GPU grant {view['granted_seconds']}")


def _source(workspace: Workspace, relative: str, line: int, radius: int) -> str:
    root = workspace.source.resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return f"(no file {relative} in the scanned tree)"
    lines = target.read_bytes()[:4 * 1024 * 1024].decode("utf-8", "replace").splitlines()
    start, end = max(1, line - radius), min(len(lines), line + radius)
    body = "\n".join(f"{n:>5}{'>' if n == line else ' '} {lines[n - 1][:200]}" for n in range(start, end + 1))
    return data_block(body, source=f"source {relative}", handle=f"{relative}:{line}")


def _page_result(ctx: ToolContext, handle: str, page: int) -> Result:
    full = ctx.results.get(handle)
    if full is None:
        record = next((r for r in reversed(ctx.workspace.ledger.of("tool_result")) if r.get("handle") == handle), None)
        full = (record.get("full") or record.get("content")) if record else None
    if full is None:
        return Result(f"{handle} is not a result in this conversation", error=True)
    chunk = full[(page - 1) * MAX_CONTENT_CHARS: page * MAX_CONTENT_CHARS]
    return Result(chunk or f"{handle} has no page {page}")


def _cap(text: str) -> str:
    """Handlers return everything; the loop pages long results behind an R handle."""
    return text


def _int(value: Any) -> int:
    try:
        return int(str(value).split("-")[0])
    except ValueError:
        return 1


def source_path(workspace: Workspace) -> Path:
    return workspace.source

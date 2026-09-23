"""The targeted AI review job: plan, look, ground, verify, promote.

One background job per approved review.  The plan is deterministic
(sesip/relevance.py); each (unit, lens) task is one bounded request through the
broker at background priority, so the conversation always goes first.  For
every answer:

* a verdict on a list entry (T1) is grounded and, if grounded, attached to the
  entry as the AI's opinion -- it never moves or removes the entry;
* findings from a look at a function (T2) are grounded one by one; a unit's
  grounded findings of one category are one claim and get one second,
  separate look through ``verify`` (V); only a grounded CONFIRMED / LIKELY there
  promotes it -- one entry, at the member nearest the line the second look
  found decisive (the model tends to report every line that sets a defect up)
  -- into the list (unmapped partition, origin "ai", evidence class "generated");
* everything -- ungrounded answers, failures, the units the budget did not
  reach and why -- is an ``ai_review`` ledger record, which is what the coverage
  page and the grounding failure rate are computed from.

A unit that would not fit the model's window is left unscheduled with that
reason; it is never cut to fit.  Answers are cached by the exact request
(lens version, profile enums, model, prompt), so re-running a review on
unchanged code costs nothing.
"""
from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..aireview import contracts, prompt
from ..aireview import lenses as lens_mod
from ..aireview.code import CodeIndex
from ..analysis import CancellationToken
from ..defaults import endpoint_class
from ..errors import UserError
from ..evidence.analyze import ensure_index, reindex
from ..evidence.grounding import ground
from ..evidence.overlays import ai_opinion
from ..evidence.store import Store
from ..evidence.triage import SourceLines
from ..evidence.workspace import Workspace, _atomic
from ..model.broker import BACKGROUND, Broker
from ..model.client import CancelToken, ModelClient, Reply
from ..persist import json_bytes
from ..sesip import relevance
from ..sesip.active import active_profile
from ..sesip.profile import Profile
from .engine import Attempt, Engine, Summary, Task

WINDOW_MARGIN = 512
LOCAL_MAX_TOKENS = {"verdict": 700, "findings": 1400}   # the local model does not think (reasoning none)
REQUEST_TIMEOUT = 600
PROMOTE = ("CONFIRMED", "LIKELY")
# Measured on the GPU host (probe, 2026-09-22): ~200 prompt tok/s cold, ~20 generated tok/s.
PREFILL_TOK_S = 200.0
ANSWER_SECONDS = 15.0


@dataclass
class Setup:
    workspace: Workspace
    profile: Profile
    code: CodeIndex
    pvs: list[dict[str, Any]]
    run_dir: Path


def setup(workspace: Workspace, *, cancelled: Callable[[], bool] = lambda: False) -> Setup:
    if not ensure_index(workspace):
        raise UserError("there is no list yet; run the tools first")
    calls = [r for r in workspace.ledger.of("call_finished") if r.get("run_dir") and r.get("exit_code") != 130]
    run_dir = workspace.root / calls[-1]["run_dir"]
    store = Store(workspace.index_path)
    try:
        pvs = store.all_pvs()
    finally:
        store.close()
    return Setup(workspace, active_profile(workspace), CodeIndex.for_run(workspace, run_dir, cancelled=cancelled),
                 pvs, run_dir)


def reviewed(workspace: Workspace) -> set[str]:
    return {str(r["review_key"]) for r in workspace.ledger.of("ai_review")
            if r.get("status") in ("done", "cached") and r.get("review_key")}


def make_plan(context: Setup, *, focus: dict[str, Any] | None = None, targets: list[str] | None = None,
              depth: str = "normal", lens: str = "") -> relevance.Plan:
    if lens:
        lens_mod.get(lens)  # raises for an unknown lens
    return relevance.plan(pvs=context.pvs, code=context.code, profile=context.profile,
                          reviewed=reviewed(context.workspace), focus=focus, targets=targets, depth=depth, lens=lens)


def estimate(workspace: Workspace, plan: relevance.Plan) -> tuple[float, str]:
    """GPU seconds for the plan, and how that number was arrived at (always labelled)."""
    measured = [float(r["gpu_seconds"]) for r in workspace.ledger.of("ai_review")
                if r.get("status") == "done" and r.get("gpu_seconds")][-50:]
    if len(measured) >= 5:
        mean = sum(measured) / len(measured)
        return mean * len(plan.targets), f"估算：本评估最近 {len(measured)} 次审查平均 {mean:.0f} 秒/次"
    seconds = sum(((t.line_end - t.line_start + 1) * 12 + 2500) / PREFILL_TOK_S + ANSWER_SECONDS
                  for t in plan.targets)
    return seconds, f"估算：按实测 {PREFILL_TOK_S:.0f} token/s 读入、每次回答约 {ANSWER_SECONDS:.0f} 秒"


# -- the job ------------------------------------------------------------------------------------------

@dataclass
class _Run:
    context: Setup
    client: ModelClient
    broker: Broker
    job_id: str
    stop: CancelToken
    progress: Callable[[str], None]
    model: str
    promoted: int = 0
    next_af: int = 0
    lines: SourceLines | None = None
    enums: tuple[set[str], set[str], set[str]] = field(default_factory=lambda: (set(), set(), set()))
    window: int = 24576
    max_tokens: dict[str, int] = field(default_factory=lambda: dict(LOCAL_MAX_TOKENS))


def limits(client: ModelClient) -> tuple[int, dict[str, int]]:
    """The window and per-contract output caps of the endpoint the job talks to."""
    spec = endpoint_class(client.endpoint.kind)
    if client.endpoint.kind == "local":
        return int(spec["lens_window"]), dict(LOCAL_MAX_TOKENS)
    cap = int(spec["lens_max_tokens"])   # a thinking model spends part of it before answering
    return int(spec["lens_window"]), {"verdict": cap, "findings": cap}


def run(workspace: Workspace, *, client: ModelClient, broker: Broker, token: CancellationToken, job_id: str,
        budget_seconds: float, focus: dict[str, Any] | None = None, targets: list[str] | None = None,
        depth: str = "normal", lens: str = "", progress: Callable[[str], None] = lambda _l: None) -> dict[str, Any]:
    stop = CancelToken()
    watcher = threading.Thread(target=_watch, args=(token, stop), daemon=True, name=f"review-stop-{job_id}")
    watcher.start()
    try:
        progress("indexing functions and the call graph")
        context = setup(workspace, cancelled=token.is_cancelled)
        plan = make_plan(context, focus=focus, targets=targets, depth=depth, lens=lens)
        counts = plan.counts()
        progress(f"plan: {counts['T1']} entries to verify, {counts['T2']} unit look(s); skipped {plan.skipped or 0}")
        workspace.ledger.append("review_started", job=job_id, focus=plan.focus, depth=depth, lens=lens,
                                targets=list(targets or []), planned=len(plan.targets), counts=counts,
                                skipped=plan.skipped, budget_seconds=budget_seconds,
                                channel=client.endpoint.kind, model=client.endpoint.model,
                                host=client.endpoint.host)
        sfr_ids, levels, categories = prompt.profile_enums(context.profile)
        window, caps = limits(client)
        state = _Run(context, client, broker, job_id, stop, progress, client.endpoint.model,
                     next_af=len({r["af"] for r in workspace.ledger.of("ai_finding")}) + 1,
                     lines=SourceLines(workspace.source),
                     enums=(set(sfr_ids), set(levels), set(categories)), window=window, max_tokens=caps)
        # Grouped by lens so consecutive requests share the system prefix (the host's prompt cache).
        ordered = sorted(plan.targets, key=lambda t: (t.tier != "T1", t.lens, -t.score, t.path, t.line_start))
        tasks = [Task(f"t{i + 1:04d}", {"target": t}) for i, t in enumerate(ordered)]
        engine = Engine(lambda task: _work(state, task), budget_seconds=budget_seconds,
                        on_outcome=lambda task, attempt: _record(state, task, attempt),
                        cancelled=token.is_cancelled, progress=progress)
        summary = engine.run(tasks)
    finally:
        stop.cancel("finished")
    return _finish(workspace, job_id, summary, state.promoted, progress)


def _watch(token: CancellationToken, stop: CancelToken) -> None:
    while not stop.cancelled:
        if token.is_cancelled():
            stop.cancel("stopped")
            return
        stop.wait(0.5)


def _finish(workspace: Workspace, job_id: str, summary: Summary, promoted: int,
            progress: Callable[[str], None]) -> dict[str, Any]:
    records = [r for r in workspace.ledger.of("ai_review") if r.get("job") == job_id]
    grounding: dict[str, list[int]] = {}
    for record in records:
        if record.get("status") in ("done", "cached") and record.get("claims"):
            tally = grounding.setdefault(str(record["lens"]), [0, 0])
            tally[0] += int(record.get("claims_grounded", 0))
            tally[1] += int(record["claims"])
    result = {**summary.as_dict(), "promoted": promoted, "grounding": grounding}
    assert result["planned"] == result["started"] + result["unscheduled"], "every planned task is accounted for"
    workspace.ledger.append("review_finished", job=job_id, **result)
    if promoted:
        progress(f"{promoted} verified AI finding(s) join the list; rebuilding it")
        reindex(workspace, progress=progress)
    progress(f"review {job_id}: {summary.started}/{summary.planned} reviewed, {summary.unscheduled} unscheduled "
             f"{summary.unscheduled_reasons or ''}, {summary.gpu_seconds:.0f}s GPU, {promoted} promoted")
    return result


# -- one task -------------------------------------------------------------------------------------------

def _work(state: _Run, task: Task) -> Attempt:
    target: relevance.Target = task.payload["target"]
    lens = lens_mod.get(target.lens)
    candidate = task.payload.get("candidate") or (_candidate(state, target) if target.tier == "T1" else None)
    request = prompt.build(target, lens, state.context.code, state.context.profile, candidate=candidate)
    tokens = prompt.estimate_tokens(request)
    if tokens + state.max_tokens[lens.contract] + WINDOW_MARGIN > state.window:
        return Attempt("unscheduled", "the unit does not fit the model window (never cut to fit)",
                       data={"estimated_tokens": tokens})
    answer, seconds, cached, first = _ask(state, request)
    parsed, problem = _parse(state, lens.contract, answer.text)
    need = (parsed or {}).get("need") or []
    if parsed is not None and need:
        extra = prompt.need_code(state.context.code, need)
        second = prompt.build(target, lens, state.context.code, state.context.profile, candidate=candidate,
                              allow_need=False, extra_code=extra)
        if prompt.estimate_tokens(second) + state.max_tokens[lens.contract] + WINDOW_MARGIN <= state.window:
            answer2, seconds2, cached2, _ = _ask(state, second)
            parsed2, problem2 = _parse(state, lens.contract, answer2.text)
            seconds += seconds2
            if parsed2 is not None:
                answer, parsed, problem, cached, request = answer2, parsed2, problem2, cached and cached2, second
    data: dict[str, Any] = {"prompt_sha256": first, "final_prompt_sha256": answer.prompt_sha256,
                            "usage": answer.usage, "needed": need}
    status = "cached" if cached else "done"
    if parsed is None:
        data["answer_excerpt"] = answer.text[:300]
        return Attempt("failed", f"the answer did not follow the contract: {problem}", seconds, data)
    follow_ups: list[Task] = []
    if lens.contract == "verdict":
        verdict = parsed
        claim = {"file": target.path, "line": verdict["decisive_line"], "evidence_quote": verdict["evidence_quote"],
                 "sfr": verdict["sfr"], "level": verdict["level_suggestion"] or None,
                 "category": verdict["category_suggestion"] or None}
        check = _ground(state, claim, request.shown)
        data.update(verdict=verdict, grounded=check.grounded, problems=check.problems, claims=1,
                    claims_grounded=int(check.grounded))
    else:
        judged, seen = [], set()
        for finding in parsed["findings"]:
            if (finding["line"], finding["category"]) in seen:
                parsed["dropped"].append(f"line {finding['line']} {finding['category']}: repeated")
                continue
            seen.add((finding["line"], finding["category"]))
            claim = {"file": target.path, "line": finding["line"], "decisive_line": finding["end_line"],
                     "evidence_quote": finding["evidence_quote"], "sfr": finding["sfr"],
                     "level": finding["level_suggestion"] or None}
            check = _ground(state, claim, request.shown)
            judged.append({**finding, "grounded": check.grounded, "problems": check.problems})
        # One second look per defect: grounded findings of one category within a few lines are one claim.
        for group in _groups([f for f in judged if f["grounded"]]):
            af = f"AF-{state.next_af}"
            state.next_af += 1
            for item in group:
                item["af"] = af
            follow_ups.append(_second_look(state, target, group))
        data.update(findings=judged, dropped=parsed["dropped"], claims=len(judged),
                    claims_grounded=sum(1 for f in judged if f["grounded"]))
    return Attempt(status, "", seconds, data, follow_ups)


def _ask(state: _Run, request: prompt.Request) -> tuple[Reply, float, bool, str]:
    """(reply, GPU seconds charged, from cache, prompt sha).  Preemption propagates to the engine."""
    fmt = contracts.response_format(request.contract, request.schema)
    body = state.client.body(request.messages, max_tokens=state.max_tokens[request.contract], response_format=fmt)
    key = hashlib.sha256(json_bytes({"lens": request.lens.id, "lens_sha": request.lens.sha256,
                                     "endpoint": state.client.endpoint.describe(), "body": body})).hexdigest()
    path = state.context.workspace.root / "aireview" / "cache" / f"{key}.json"
    if path.is_file():
        stored = json.loads(path.read_text(encoding="utf-8"))
        return Reply(stored["text"], "", [], "stop", stored.get("usage", {}), 200, None, 0.0,
                     stored["prompt_sha256"]), 0.0, True, stored["prompt_sha256"]
    reply = state.broker.chat(state.client, BACKGROUND, stop=state.stop, messages=request.messages,
                              max_tokens=state.max_tokens[request.contract], response_format=fmt, timeout=REQUEST_TIMEOUT,
                              purpose=f"lens:{request.lens.id}")
    if reply.finish_reason != "length":
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic(path, json_bytes({"text": reply.text, "usage": reply.usage, "prompt_sha256": reply.prompt_sha256}))
    return reply, reply.duration_seconds, False, reply.prompt_sha256


def _parse(state: _Run, contract: str, text: str) -> tuple[dict[str, Any] | None, str]:
    sfr_ids, levels, categories = state.enums
    if contract == "verdict":
        return contracts.parse_verdict(text, sfr_ids=sfr_ids, levels=levels, categories=categories)
    return contracts.parse_findings(text, sfr_ids=sfr_ids, levels=levels)


def _ground(state: _Run, claim: dict[str, Any], shown: Any) -> Any:
    sfr_ids, levels, categories = state.enums
    return ground(claim, shown, sfr_ids=sfr_ids, levels=levels, categories=categories or {claim.get("category")})


def _candidate(state: _Run, target: relevance.Target) -> dict[str, Any]:
    store = Store(state.context.workspace.index_path)
    try:
        members = store.cluster_members(str(target.extra.get("cluster_id") or ""))
    finally:
        store.close()
    row = next((r for r in state.context.pvs if r["pv_id"] == target.key), {})
    return {"label": target.key, "family": row.get("family", ""),
            "members": [{"tool": m.get("tool"), "rule_id": m.get("rule_id"), "line": m.get("line"),
                         "review_level": m.get("review_level"), "message": m.get("message", "")} for m in members]}


def _groups(findings: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """A unit's grounded findings of one category are one claim: the model tends to report a defect at every
    line that sets it up, and the second look names the one line where it happens."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in sorted(findings, key=lambda f: (f["category"], f["line"])):
        groups.setdefault(finding["category"], []).append(finding)
    return list(groups.values())


def _second_look(state: _Run, target: relevance.Target, group: list[dict[str, Any]]) -> Task:
    af = group[0]["af"]
    focus = (min(f["line"] for f in group), max(f["end_line"] for f in group))
    second = relevance.Target("V", af, lens_mod.VERIFY, target.path, target.function, target.line_start,
                              target.line_end, focus, target.score,
                              [f"second look at {af} from the {target.lens} lens"], target.sfr_id,
                              target.module, target.text_sha)
    candidate = {"label": af, "family": group[0]["category"], "ai": True,
                 "members": [{"tool": f"ai:{target.lens}", "rule_id": f["category"], "line": f["line"],
                              "review_level": f.get("level_suggestion") or "", "message": f["message"]} for f in group]}
    for index, finding in enumerate(group):
        state.context.workspace.ledger.append(
            "ai_finding", af=af, member=index, job=state.job_id, lens=target.lens, path=target.path,
            function=target.function, line=finding["line"], end_line=finding["end_line"],
            category=finding["category"], cwe=finding["cwe"], message=finding["message"],
            evidence_quote=finding["evidence_quote"], confidence=finding["confidence"], sfr=finding["sfr"],
            level_suggestion=finding["level_suggestion"])
    return Task(af, {"target": second, "candidate": candidate, "group": group, "origin_lens": target.lens})


def _record(state: _Run, task: Task, attempt: Attempt) -> None:
    target: relevance.Target = task.payload["target"]
    lens = lens_mod.get(target.lens)
    workspace = state.context.workspace
    record = workspace.ledger.append(
        "ai_review", job=state.job_id, task=task.id, tier=target.tier, key=target.key, lens=target.lens,
        lens_version=lens.version, review_key=target.review_key, path=target.path, function=target.function,
        line_start=target.line_start, line_end=target.line_end, focus=list(target.focus), reasons=target.reasons,
        sfr_id=target.sfr_id, module=target.module, text_sha=target.text_sha, status=attempt.status,
        reason=attempt.reason, gpu_seconds=round(attempt.gpu_seconds, 2), model=state.model, **attempt.data)
    if target.tier == "T1":
        opinion = ai_opinion(record)
        if opinion is not None:
            store = Store(workspace.index_path)
            try:
                store.set_ai(target.key, opinion)
            finally:
                store.close()
    if target.tier == "V" and attempt.status in ("done", "cached") and attempt.data.get("grounded") \
            and attempt.data.get("verdict", {}).get("verdict") in PROMOTE:
        # One entry per confirmed defect: the member at (or nearest) the line the second look found decisive.
        decisive = int(attempt.data["verdict"]["decisive_line"])
        group = task.payload["group"]
        index, finding = min(enumerate(group), key=lambda item: (abs(item[1]["line"] - decisive),
                                                                 -item[1]["confidence"], item[1]["line"]))
        lines = state.lines or SourceLines(workspace.source)
        workspace.ledger.append(
            "ai_promoted", af=finding["af"], member=index, of=len(group), lens=task.payload["origin_lens"],
            path=target.path, function=target.function, line=finding["line"], end_line=finding["end_line"],
            category=finding["category"], cwe=finding["cwe"], message=finding["message"],
            evidence_quote=finding["evidence_quote"], confidence=finding["confidence"],
            verdict=attempt.data["verdict"]["verdict"], decisive_line=decisive,
            line_text_sha=lines.line_text_sha(target.path, finding["line"]), sfr=finding["sfr"],
            level_suggestion=finding["level_suggestion"], job=state.job_id)
        state.promoted += 1

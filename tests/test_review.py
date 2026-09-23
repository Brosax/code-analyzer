"""M7: targeted AI review -- lenses, contracts, the engine's accounting, relevance, grounding, promotion."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fake_transport import FakeTransport, delta, sse
from test_evaluate import SOURCE, buildctx_file, fake_tools

from code_analyzer.aireview import contracts
from code_analyzer.aireview import lenses as lens_mod
from code_analyzer.analysis import CancellationToken
from code_analyzer.core.tomlw import dumps
from code_analyzer.evidence.analyze import evaluate
from code_analyzer.evidence.buildctx_schema import load_buildctx
from code_analyzer.evidence.store import Store
from code_analyzer.evidence.workspace import Workspace
from code_analyzer.jobs import lens_job
from code_analyzer.jobs.engine import Attempt, Engine, Task
from code_analyzer.kernel import approvals, tools
from code_analyzer.model.broker import Broker, Preempted
from code_analyzer.model.client import Endpoint, ModelClient, ModelError
from code_analyzer.model.egress import open_target
from code_analyzer.sesip import active
from code_analyzer.sesip.catalogue import CATALOGUE
from code_analyzer.sesip.coverage import coverage

USAGE = {"choices": [], "usage": {"prompt_tokens": 900, "completion_tokens": 60}}
BOOT = """\
int check_hash(const unsigned char *h, const unsigned char *e) {
    int i, acc = 0;
    for (i = 0; i <= 32; i++) {
        acc |= h[i] ^ e[i];
    }
    return acc;
}
int boot_verify_image(const unsigned char *img) {
    unsigned char expected[32] = {0};
    return check_hash(img, expected);
}
"""


@pytest.fixture(autouse=True)
def model_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_MODEL", raising=False)


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    source = tmp_path / "project"
    source.mkdir()
    (source / "a.c").write_text(SOURCE, encoding="utf-8")
    (source / "boot.c").write_text(BOOT, encoding="utf-8")
    tools_ = fake_tools(tmp_path, source / "a.c")
    outcome = evaluate(source, eval_dir=tmp_path / "eval", profile="generic-sesip",
                       buildctx=load_buildctx(buildctx_file(tmp_path, tools_)), compile_db=False)
    return outcome.workspace


def reply(value: dict[str, Any]) -> bytes:
    return sse(delta(content=json.dumps(value), finish_reason="stop"), USAGE)


def client(*replies: bytes) -> tuple[ModelClient, FakeTransport]:
    transport = FakeTransport(*replies)
    return ModelClient(Endpoint("http://127.0.0.1:11434/v1", "qwen"), transport=transport,
                       egress=lambda ep: open_target(ep, resolver=lambda h, p: ("127.0.0.1",))), transport


def verdict(value: str, line: int, quote: str, **extra: Any) -> dict[str, Any]:
    return {"verdict": value, "confidence": 0.9, "decisive_line": line, "evidence_quote": quote,
            "rationale": "tmp has 4 elements; index 4 is one past the end.", **extra}


def run(workspace: Workspace, model: ModelClient, **kwargs: Any) -> dict[str, Any]:
    kwargs.setdefault("budget_seconds", 600)
    return lens_job.run(workspace, client=model, broker=Broker(resume_after=0), token=CancellationToken(),
                        job_id=kwargs.pop("job_id", "J1"), **kwargs)


# -- lenses and contracts ------------------------------------------------------------------------

def test_fifteen_lenses_load_and_route_every_catalogue_sfr() -> None:
    lenses = lens_mod.load_all()
    assert len(lenses) == 15 and lenses["verify"].contract == "verdict"
    assert all(lens.contract == "findings" for name, lens in lenses.items() if name != "verify")
    for entry in CATALOGUE:
        assert lens_mod.for_catalogue(entry["name"]).id == entry["lens"]
    text = lenses["sfr-generic"].text(sfr_id="SESIP-FR", sfr_text="The platform can be reset to factory state.")
    assert "SESIP-FR" in text and "factory state" in text and "{sfr" not in text


def test_the_contracts_parse_leniently_and_keep_only_profile_values() -> None:
    fenced = "```json\n" + json.dumps(verdict("likely", 6, "return tmp[4];", sfr=["SESIP-X", "NOPE"],
                                               level_suggestion="error")) + ",\n```"
    parsed, problem = contracts.parse_verdict(fenced.replace("},\n```", "}\n```"), sfr_ids={"SESIP-X"},
                                              levels={"error"}, categories=set())
    assert problem == "" and parsed["verdict"] == "LIKELY" and parsed["sfr"] == ["SESIP-X"]
    assert parsed["level_suggestion"] == "error"
    assert contracts.parse_verdict('{"verdict": "MAYBE"}', sfr_ids=set(), levels=set(), categories=set())[0] is None
    findings, _ = contracts.parse_findings(json.dumps({"findings": [
        {"line": 4, "category": "buffer", "message": "overflow", "evidence_quote": "memcpy(tmp, src, n);",
         "confidence": 0.8}, {"category": "buffer"}, "junk"]}), sfr_ids=set(), levels=set())
    assert len(findings["findings"]) == 1 and len(findings["dropped"]) == 2
    empty, problem = contracts.parse_findings('{"findings": []}', sfr_ids=set(), levels=set())
    assert empty == {"findings": [], "need": [], "dropped": []} and problem == ""


# -- the engine ------------------------------------------------------------------------------------

def test_every_planned_task_is_accounted_for_under_preemption_budget_and_follow_ups() -> None:
    seen: dict[str, int] = {}

    def work(task: Task) -> Attempt:
        seen[task.id] = seen.get(task.id, 0) + 1
        if task.id in ("t2", "t3") and seen[task.id] == 1:
            raise Preempted()
        follow = [Task(f"{task.id}.v", None)] if task.id == "t1" else []
        return Attempt("done", gpu_seconds=10, follow_ups=follow)

    outcomes: list[tuple[str, str]] = []
    summary = Engine(work, budget_seconds=35, on_outcome=lambda t, a: outcomes.append((t.id, a.status))).run(
        [Task(f"t{i}", None) for i in range(1, 7)])
    assert summary.planned == 7 == summary.started + summary.unscheduled
    assert summary.preemptions == 2 and seen["t2"] == 2
    assert summary.unscheduled_reasons == {"GPU budget used up": 3}
    assert outcomes == [("t1", "done"), ("t2", "done"), ("t3", "done"), ("t4", "done"), ("t5", "unscheduled"),
                        ("t6", "unscheduled"), ("t1.v", "unscheduled")]


def test_the_breaker_opens_after_three_transport_failures() -> None:
    def work(task: Task) -> Attempt:
        raise ModelError("TRANSPORT", "connection refused")

    summary = Engine(work, budget_seconds=1000).run([Task(f"t{i}", None) for i in range(6)])
    assert summary.by_status == {"failed": 3, "unscheduled": 3} and "circuit breaker" in summary.breaker


# -- relevance -------------------------------------------------------------------------------------

def test_t1_verifies_entries_and_t2_looks_at_unflagged_sfr_code(workspace: Workspace) -> None:
    context = lens_job.setup(workspace)
    plan = lens_job.make_plan(context)
    tiers = {(t.tier, t.key, t.lens) for t in plan.targets}
    assert ("T1", "PV-0001", "verify") in tiers
    assert ("T2", "boot.c::boot_verify_image", "secure-boot") in tiers
    assert not any(t.key.startswith("a.c::") for t in plan.targets if t.tier == "T2")  # not tied to any SFR
    quick = lens_job.make_plan(context, depth="quick")
    assert {t.tier for t in quick.targets} == {"T1"}


def test_a_tsfi_reaches_callees_as_a_static_approximation(workspace: Workspace) -> None:
    data = active.active_profile(workspace).data
    data = {**data, "tsfi": [{"id": "TSFI-BOOT", "symbols": ["boot_verify_image"], "sfr": ["SESIP-SIP"]}]}
    data["evaluation"] = {**data["evaluation"], "status": "draft"}
    active.save_draft(workspace, dumps(data))
    plan = lens_job.make_plan(lens_job.setup(workspace), focus={"sfr": "SESIP-SIP"})
    reasons = {t.key: t.reasons for t in plan.targets if t.tier == "T2" and t.lens == "secure-boot"}
    assert any("TSFI entry point" in r for r in reasons["boot.c::boot_verify_image"])
    assert any("static approximation" in r for r in reasons["boot.c::check_hash"])


def test_an_alarm_hides_a_function_only_from_the_lens_for_that_kind_of_defect(workspace: Workspace) -> None:
    data = active.active_profile(workspace).data
    data = {**data, "tsfi": [{"id": "TSFI-COPY", "symbols": ["copy"], "sfr": ["SESIP-SARIP"]}],
            "evaluation": {**data["evaluation"], "status": "draft"}}
    active.save_draft(workspace, dumps(data))
    context = lens_job.setup(workspace)
    isolation = lens_job.make_plan(context, focus={"sfr": "SESIP-SARIP"})
    assert ("a.c::copy", "nsc-entry") in {(t.key, t.lens) for t in isolation.targets if t.tier == "T2"}
    memory = lens_job.make_plan(context, focus={"sfr": "SESIP-SARIP"}, lens="memory")
    assert "a.c::copy" not in {t.key for t in memory.targets if t.tier == "T2"}  # PV-0001 is a buffer alarm


def test_the_evaluator_can_name_functions(workspace: Workspace) -> None:
    plan = lens_job.make_plan(lens_job.setup(workspace), targets=["boot.c::check_hash", "boot.c:9", "x.c::nope"])
    looks = sorted((t.key, t.lens) for t in plan.targets)
    assert looks == [("boot.c::boot_verify_image", "error-path"), ("boot.c::boot_verify_image", "memory"),
                     ("boot.c::check_hash", "error-path"), ("boot.c::check_hash", "memory")]
    assert plan.skipped == {"no function x.c::nope in the scanned tree": 1}
    assert all(t.reasons == ["named by the evaluator"] for t in plan.targets)


# -- the job ---------------------------------------------------------------------------------------

def test_a_grounded_verdict_is_attached_and_never_moves_the_entry(workspace: Workspace) -> None:
    before = Store(workspace.index_path).pv("PV-0001")
    model, transport = client(reply(verdict("FALSE_POSITIVE", 6, "return tmp[4];")))
    result = run(workspace, model, targets=["PV-0001"])
    assert (result["planned"], result["started"], result["grounding"]) == (1, 1, {"verify": [1, 1]})
    after = Store(workspace.index_path).pv("PV-0001")
    assert after["ai"]["verdict"] == "FALSE_POSITIVE" and after["partition"] == before["partition"] == "main"
    body = transport.bodies[0]
    assert body["response_format"]["type"] == "json_schema" and "<data" in body["messages"][1]["content"]
    assert "   6| " in body["messages"][1]["content"] or "6| " in body["messages"][1]["content"]


@pytest.mark.parametrize(("line", "quote"), [(6, "return tmp[5];"), (40, "return tmp[4];"), (6, "")])
def test_a_forged_line_or_quote_never_reaches_the_list(workspace: Workspace, line: int, quote: str) -> None:
    model, _ = client(reply(verdict("CONFIRMED", line, quote)))
    run(workspace, model, targets=["PV-0001"])
    record = workspace.ledger.of("ai_review")[-1]
    assert record["grounded"] is False and record["problems"]
    assert Store(workspace.index_path).pv("PV-0001")["ai"] is None


def test_a_verified_ai_finding_joins_the_unmapped_partition(workspace: Workspace) -> None:
    finding = {"line": 3, "end_line": 4, "category": "out-of-bounds", "cwe": "CWE-125",
               "message": "the loop reads h[32] and e[32], one past each 32-byte hash",
               "evidence_quote": "for (i = 0; i <= 32; i++) {", "confidence": 0.9}
    model, transport = client(
        reply({"findings": []}),                                   # boot_verify_image: reviewed, nothing found
        reply({"findings": [finding, dict(finding),                           # a repeat is dropped
                            {**finding, "line": 4, "end_line": 4, "evidence_quote": "acc |= h[i] ^ e[i];"},
                            {**finding, "line": 5, "evidence_quote": "a timing side channel"}]}),
        reply(verdict("CONFIRMED", 3, "for (i = 0; i <= 32; i++) {")))
    data = active.active_profile(workspace).data
    data = {**data, "tsfi": [{"id": "TSFI-BOOT", "symbols": ["boot_verify_image"], "sfr": ["SESIP-SIP"]}],
            "evaluation": {**data["evaluation"], "status": "draft"}}
    active.save_draft(workspace, dumps(data))
    result = run(workspace, model, focus={"sfr": "SESIP-SIP"}, depth="normal", lens="secure-boot")
    assert result["promoted"] == 1 and result["planned"] == result["started"] + result["unscheduled"] == 3
    looks = [r for r in workspace.ledger.of("ai_review") if r["tier"] == "T2"]
    assert {r["key"]: r["claims"] for r in looks} == {"boot.c::boot_verify_image": 0, "boot.c::check_hash": 3}
    # lines 3 and 4 are one claim: one second look; the line it found decisive is what joins the list
    [second] = [r for r in workspace.ledger.of("ai_review") if r["tier"] == "V"]
    assert second["verdict"]["verdict"] == "CONFIRMED" and "AF-1" == second["key"]
    assert [(r["af"], r["line"], r["of"]) for r in workspace.ledger.of("ai_promoted")] == [("AF-1", 3, 2)]
    rows = Store(workspace.index_path).all_pvs()
    [ai] = [r for r in rows if r["path"] == "boot.c"]
    assert (ai["partition"], ai["origin"], ai["level"]) == ("unmapped", "ai", "unmapped")
    listed = Store(workspace.index_path).list_pvs({"origin": "ai"})
    assert [row["path"] for row in listed["rows"]] == ["boot.c"]
    assert len(transport.requests) == 3


def test_answers_are_cached_by_the_exact_request(workspace: Workspace) -> None:
    model, _ = client(reply(verdict("CONFIRMED", 6, "return tmp[4];")))
    run(workspace, model, targets=["PV-0001"], job_id="J1")
    # unchanged code, same lens version: not planned again ...
    assert lens_job.make_plan(lens_job.setup(workspace), depth="quick").targets == []
    # ... and named again by the evaluator, it is answered from the cache at no GPU cost
    again, transport = client()
    result = run(workspace, again, targets=["PV-0001"], job_id="J2")
    assert result["by_status"] == {"cached": 1} and result["gpu_seconds"] == 0 and not transport.requests


def test_a_unit_too_big_for_the_window_is_unscheduled_not_cut(workspace: Workspace) -> None:
    big = "int huge(void) {\n" + "".join(f"    int v{i} = {i} * 7; /* padding padding padding */\n"
                                         for i in range(3000)) + "    return 0;\n}\n"
    (workspace.source / "boot.c").write_text(BOOT + big, encoding="utf-8")
    data = active.active_profile(workspace).data
    data = {**data, "tsfi": [{"id": "T", "symbols": ["huge"], "sfr": ["SESIP-SIP"]}],
            "evaluation": {**data["evaluation"], "status": "draft"}}
    active.save_draft(workspace, dumps(data))
    model, _ = client(*[reply({"findings": []}) for _ in range(4)])
    result = run(workspace, model, focus={"sfr": "SESIP-SIP"}, lens="secure-boot")
    [huge] = [r for r in workspace.ledger.of("ai_review") if r["key"].endswith("::huge")]
    assert huge["status"] == "unscheduled" and "window" in huge["reason"]
    assert result["unscheduled_reasons"] == {huge["reason"]: 1}


# -- the tool, the card, the coverage page ----------------------------------------------------------

def test_the_review_tool_asks_for_gpu_time_and_the_click_grants_it(workspace: Workspace) -> None:
    started: list[dict[str, Any]] = []
    services = tools.Services(run_tools=lambda ws, t: None, jobs=lambda ws: [], export=lambda ws, v, f: {},
                              review=lambda ws, arguments: started.append(arguments) or {"id": "J7"})
    context = tools.ToolContext(workspace, services)
    result = tools.run(context, "review", {"depth": "quick"})
    assert result.approval and result.approval["tool"] == "review" and not started
    card = approvals.show(workspace, result.approval)
    decided = approvals.decide(workspace, context, card["approval_id"], "approve", by="analyst",
                               sha=card["args_sha256"])
    assert started and started[0]["depth"] == "quick" and decided.card["job"]["id"] == "J7"
    assert workspace.ledger.of("review_granted")[-1]["budget_seconds"] == started[0]["budget_minutes"] * 60


def test_coverage_reports_verification_and_grounding(workspace: Workspace) -> None:
    model, _ = client(reply(verdict("CONFIRMED", 6, "return tmp[4];")))
    run(workspace, model, targets=["PV-0001"])
    store = Store(workspace.index_path)
    view = coverage(workspace, store, active.active_profile(workspace))
    assert view["verified"] == 1 and view["verdicts"]["CONFIRMED"] == 1
    assert view["lenses"]["verify"]["grounding_failure_rate"] == 0.0


def test_an_unexpected_error_fails_one_task_not_the_job() -> None:
    def work(task: Task) -> Attempt:
        if task.id == "t1":
            raise FileExistsError("model/0009")
        return Attempt("done", gpu_seconds=1)

    outcomes: list[tuple[str, str, str]] = []
    summary = Engine(work, budget_seconds=100, on_outcome=lambda t, a: outcomes.append((t.id, a.status, a.reason))).run(
        [Task("t1", None), Task("t2", None)])
    assert summary.by_status == {"failed": 1, "done": 1} and summary.planned == summary.started == 2
    assert outcomes[0][2].startswith("internal error: FileExistsError")

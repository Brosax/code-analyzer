"""M5: the agent kernel -- turns, tools, approvals, the prefix, the queue."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from fake_transport import FakeTransport, delta, sse
from test_evaluate import buildctx_file, fake_tools, project

from code_analyzer.errors import UserError
from code_analyzer.evidence.analyze import evaluate
from code_analyzer.evidence.buildctx_schema import load_buildctx
from code_analyzer.evidence.workspace import Workspace
from code_analyzer.export.listing import export
from code_analyzer.kernel import approvals, tools
from code_analyzer.kernel.loop import Kernel
from code_analyzer.kernel.session import Conversation
from code_analyzer.model.broker import Broker
from code_analyzer.model.client import CancelToken, Endpoint, ModelClient
from code_analyzer.model.egress import open_target

USAGE = {"choices": [], "usage": {"prompt_tokens": 100, "completion_tokens": 10}}


@pytest.fixture(autouse=True)
def model_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_MODEL", raising=False)


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    source = project(tmp_path)
    tools_ = fake_tools(tmp_path, source / "a.c")
    outcome = evaluate(source, eval_dir=tmp_path / "eval", profile="generic-sesip",
                       buildctx=load_buildctx(buildctx_file(tmp_path, tools_)), compile_db=False)
    return outcome.workspace


def call(name: str, arguments: dict[str, Any], index: int = 0, cid: str = "") -> dict[str, Any]:
    return {"index": index, "id": cid or f"c{index}-{name}", "function": {"name": name, "arguments": json.dumps(arguments)}}


def calls(*items: dict[str, Any]) -> bytes:
    return sse(delta(tool_calls=list(items), finish_reason="tool_calls"), USAGE)


def answer(text: str) -> bytes:
    return sse(delta(content=text, finish_reason="stop"), USAGE)


class Harness:
    def __init__(self, workspace: Workspace, *replies: bytes) -> None:
        self.workspace = workspace
        self.transport = FakeTransport(*replies)
        self.started: list[Any] = []
        self.exports: list[Any] = []
        client = ModelClient(Endpoint("http://127.0.0.1:11434/v1", "qwen"), transport=self.transport,
                             egress=lambda ep: open_target(ep, resolver=lambda h, p: ("127.0.0.1",)))
        services = tools.Services(
            run_tools=lambda ws, t: self.started.append(t) or {"id": "J9", "kind": "static", "status": "running",
                                                                 "exit_code": None, "elapsed_seconds": 0},
            jobs=lambda ws: [],
            export=lambda ws, variant, formats: self.exports.append((variant, formats)) or export(ws, variant, formats))
        self.kernel = Kernel(workspace, client, Broker(resume_after=0), services)
        self.services = services

    def turn(self, text: str) -> Any:
        self.workspace.ledger.append("user_said", text=text)
        return self.kernel.turn(token=CancelToken())

    def kinds(self) -> list[str]:
        return [r["kind"] for r in self.workspace.ledger.read()
                if r["kind"] in ("user_said", "agent_said", "tool_result", "event_said", "approval_shown")]


def test_a_query_then_an_answer(workspace: Workspace) -> None:
    h = Harness(workspace, calls(call("list", {"kind": "pv", "where": {"level": "error"}})),
                answer("有 1 个 error 条目：PV-0001，在 a.c 第 4-6 行。"))
    outcome = h.turn("列出所有 Error 等级的条目")
    assert (outcome.steps, outcome.ended_by) == (2, "answer")
    assert h.kinds()[-4:] == ["user_said", "agent_said", "tool_result", "agent_said"]
    result = workspace.ledger.of("tool_result")[-1]
    assert result["handle"] == "R1" and "PV-0001" in result["content"]
    second = h.transport.bodies[1]["messages"]
    assert [m["role"] for m in second[-3:]] == ["assistant", "tool", "user"]
    assert second[-1]["content"].startswith("[状态]")   # the tail rides last
    assert "[R1 · list]" in second[-2]["content"]


def test_the_prefix_is_identical_across_steps(workspace: Workspace) -> None:
    h = Harness(workspace, calls(call("show", {"target": "PV-0001"})), answer("好"))
    h.turn("PV-0001 是什么问题？")
    first, second = h.transport.bodies
    assert first["tools"] == second["tools"] and first["messages"][0] == second["messages"][0]
    assert first["messages"][1:-1] == second["messages"][1:len(first["messages"]) - 1]  # history only appended


def test_read_calls_run_together_and_one_action_ends_the_turn(workspace: Workspace) -> None:
    h = Harness(workspace, calls(call("show", {"target": "PV-0001", "part": "summary"}, 0),
                                 call("show", {"target": "profile"}, 1),
                                 call("run_tools", {"scope": "all"}, 2), call("export", {"variant": "internal"}, 3)))
    outcome = h.turn("看看 PV-0001 和档案，然后重新跑一遍工具")
    assert (outcome.steps, outcome.ended_by) == (1, "action")
    assert [r["name"] for r in workspace.ledger.of("tool_result")] == ["show", "show", "run_tools"]
    said = workspace.ledger.of("agent_said")[-1]
    assert [d["name"] for d in said["dropped"]] == ["export"] and h.started == [None]
    assert "<data source=\"source a.c\"" in workspace.ledger.of("tool_result")[0]["content"]


def test_export_waits_for_a_click_bound_to_its_arguments(workspace: Workspace) -> None:
    h = Harness(workspace, calls(call("export", {"variant": "shareable", "formats": ["csv"]})))
    outcome = h.turn("导出清单")
    assert outcome.ended_by == "approval" and h.exports == []
    [card] = approvals.pending(workspace)
    assert card["writes"] == ["pv-list.csv"]
    with pytest.raises(UserError, match="do not match"):
        approvals.decide(workspace, h.kernel.ctx, card["approval_id"], "approve", by="fgt", sha="0" * 64)
    # a voided card stays void
    with pytest.raises(UserError, match="already decided"):
        approvals.decide(workspace, h.kernel.ctx, card["approval_id"], "approve", by="fgt",
                         sha=card["args_sha256"])
    h2 = Harness(workspace, calls(call("export", {"variant": "shareable", "formats": ["csv"]})))
    h2.turn("再导出一次")
    card = approvals.pending(workspace)[0]
    result = approvals.decide(workspace, h2.kernel.ctx, card["approval_id"], "approve", by="fgt",
                              sha=card["args_sha256"])
    assert h2.exports == [("shareable", ["csv"])] and "leak check passed" in result.content
    assert workspace.ledger.of("approval_granted")[-1]["by"] == "fgt"


def test_a_card_expires_and_dies_with_a_state_change(workspace: Workspace) -> None:
    h = Harness(workspace, calls(call("export", {"variant": "internal"})))
    h.turn("导出")
    card = approvals.pending(workspace)[0]
    with pytest.raises(UserError, match="expired"):
        approvals.decide(workspace, h.kernel.ctx, card["approval_id"], "approve", by="fgt",
                         sha=card["args_sha256"], now=time.time() + 3600)
    h.workspace.ledger.append("user_said", text="…")
    h2 = Harness(workspace, calls(call("export", {"variant": "internal"})))
    h2.turn("导出")
    card = approvals.pending(workspace)[0]
    from code_analyzer.sesip import active
    active.select_builtin(workspace, "rt700-tp-v1.1")   # the profile changed under the card
    with pytest.raises(UserError, match="changed"):
        approvals.decide(workspace, h2.kernel.ctx, card["approval_id"], "approve", by="fgt", sha=card["args_sha256"])


def test_the_last_step_asks_for_an_answer_in_words(workspace: Workspace) -> None:
    h = Harness(workspace, calls(call("show", {"target": "profile"})), calls(call("show", {"target": "coverage"})),
                calls(call("list", {"kind": "pv"})))
    outcome = h.turn("随便看看")
    assert (outcome.steps, outcome.ended_by) == (3, "limit")
    third = h.transport.bodies[2]["messages"][-1]["content"]
    assert "不要再调用工具" in third and "不要再调用工具" not in h.transport.bodies[1]["messages"][-1]["content"]
    assert workspace.ledger.of("agent_said")[-1]["dropped"][0]["name"] == "list"


def test_a_malformed_call_gets_one_repair(workspace: Workspace) -> None:
    broken = sse(delta(tool_calls=[{"index": 0, "id": "x", "function": {"name": "list", "arguments": "{kind:"}}],
                       finish_reason="tool_calls"), USAGE)
    h = Harness(workspace, broken, answer("抱歉，重新回答：共 1 条。"))
    outcome = h.turn("有几条？")
    assert outcome.ended_by == "answer"
    assert "无法解析" in workspace.ledger.of("event_said")[-1]["text"]


def test_invalid_arguments_come_back_as_the_tools_result(workspace: Workspace) -> None:
    h = Harness(workspace, calls(call("list", {"kind": "pv", "colour": "red"})), answer("好"))
    h.turn("列出")
    result = workspace.ledger.of("tool_result")[-1]
    assert result["error"] and "unknown key 'colour'" in result["content"]


def test_profile_edit_changes_a_draft_and_never_confirms(workspace: Workspace) -> None:
    h = Harness(workspace, calls(call("profile_edit", {"patch": {"evaluation": {"status": "confirmed"}}})),
                answer("需要您在档案页确认。"))
    h.turn("帮我确认档案")
    assert "only the evaluator" in workspace.ledger.of("tool_result")[-1]["content"]
    patch = {"toe_module": [{"id": "core", "paths": ["**/*.c"]}]}
    h2 = Harness(workspace, calls(call("profile_edit", {"patch": patch})))
    outcome = h2.turn("TOE 只包括 .c 文件")
    assert outcome.ended_by == "action"
    from code_analyzer.sesip.active import active_profile
    profile = active_profile(workspace)
    assert profile.status == "draft" and profile.module_of("x/y.c") == "core" and profile.module_of("x/y.h") is None


def test_queued_messages_and_interruption(workspace: Workspace) -> None:
    blocking = FakeTransport(block=True)
    client = ModelClient(Endpoint("http://127.0.0.1:11434/v1", "qwen"), transport=blocking,
                         egress=lambda ep: open_target(ep, resolver=lambda h, p: ("127.0.0.1",)))
    services = tools.Services(run_tools=lambda ws, t: {}, jobs=lambda ws: [], export=lambda ws, v, f: {})
    events: list[dict[str, Any]] = []
    conversation = Conversation(workspace, lambda: Kernel(workspace, client, Broker(resume_after=0), services),
                                on_delta=events.append)
    conversation.start()
    conversation.say("第一句")
    deadline = time.monotonic() + 5
    while not conversation.busy and time.monotonic() < deadline:
        time.sleep(0.01)
    assert conversation.say("第二句")["queued"] is True
    assert conversation.interrupt()
    deadline = time.monotonic() + 5
    while len(workspace.ledger.of("turn_cancelled")) < 1 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert workspace.ledger.of("turn_cancelled")[0]["reason"] == "interrupted by the evaluator"
    deadline = time.monotonic() + 5
    while len(workspace.ledger.of("user_said")) < 2 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert workspace.ledger.of("user_said")[-1]["text"] == "（写于上一回合进行中）第二句"
    conversation.interrupt()
    assert threading.active_count() >= 1


def test_a_job_can_be_shown_with_its_progress(workspace: Workspace) -> None:
    job = {"id": "J3", "kind": "review", "status": "running", "exit_code": None, "elapsed_seconds": 140,
           "progress": ["plan: 48 entries to verify", "20/48 reviewed, 300s of 1800s GPU budget used"]}
    services = tools.Services(run_tools=lambda ws, t: None, jobs=lambda ws: [job], export=lambda ws, v, f: {})
    context = tools.ToolContext(workspace, services)
    shown = tools.run(context, "show", {"target": "J3"})
    assert not shown.error and "20/48 reviewed" in shown.content and "review running" in shown.content
    listed = tools.run(context, "list", {"kind": "job"})
    assert "20/48 reviewed" in listed.content
    assert tools.run(context, "show", {"target": "J9"}).error

"""One conversational turn: at most three model calls, then an answer or a card.

    step 1..3:  request (system + history + tail) on the interactive lane
                read calls (list/show) in the reply  -> all run, results appended, next step
                one action call (run_tools, profile_edit, export, ...) -> runs or shows a card, turn ends
                no call -> that was the answer, turn ends
    step 3 adds, in words, "answer now without tools": Ollama ignores
    tool_choice "none" in a multi-turn tool conversation (measured 2026-09-22),
    so the tool list -- and with it the prefix cache -- stays unchanged.

A malformed call gets one chance to be repaired: the error goes back as the
tool's result.  Every model reply, every call and every result is appended to
the ledger as it happens, so the page (and a restart) sees exactly what the
model saw.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..evidence.workspace import Workspace
from ..model.broker import INTERACTIVE, Broker
from ..model.client import CancelToken, ModelClient
from . import approvals, context, tools
from .codecs import JsonActionCodec, NativeToolCodec, UserSaid
from .toolspec import BY_NAME, FIXED_TOOLS, validate

MAX_STEPS = 3
CHAT_MAX_TOKENS = 1500
READ_ONLY = frozenset({"read"})

DeltaSink = Callable[[str, str], None]


@dataclass
class TurnOutcome:
    steps: int
    answered: bool
    ended_by: str   # "answer" | "action" | "approval" | "limit" | "invalid"


class Kernel:
    def __init__(self, workspace: Workspace, client: ModelClient, broker: Broker, services: tools.Services, *,
                 codec: str = "native", triage: Callable[[], dict[str, int] | None] = lambda: None,
                 jobs: Callable[[], list[dict[str, Any]]] = list) -> None:
        self.workspace = workspace
        self.client = client
        self.broker = broker
        self.codec = NativeToolCodec() if codec == "native" else JsonActionCodec()
        self.ctx = tools.ToolContext(workspace, services)
        self.triage = triage
        self.jobs = jobs
        self._handles = sum(1 for r in workspace.ledger.of("tool_result") if not r.get("approved"))

    def turn(self, *, token: CancelToken, on_delta: DeltaSink | None = None) -> TurnOutcome:
        repaired = False
        for step in range(1, MAX_STEPS + 1):
            last = step == MAX_STEPS
            entries = context.history(self.workspace)
            if context.needs_fold(entries) and context.fold(self.workspace) is not None:
                entries = context.history(self.workspace)
            state = context.tail(self.workspace, triage=self.triage(), jobs=self.jobs(),
                                 pending=approvals.pending(self.workspace), final=last)
            messages, wire_tools = self.codec.render(context.system_prompt(self.workspace),
                                                     [*entries, UserSaid(state)], FIXED_TOOLS)
            sink = self.codec.stream_filter(on_delta)
            reply = self.broker.chat(self.client, INTERACTIVE, stop=token, messages=messages, tools=wire_tools,
                                     max_tokens=CHAT_MAX_TOKENS, on_delta=sink, timeout=300, purpose="chat")
            if hasattr(sink, "flush"):
                sink.flush()
            decoded = self.codec.decode(reply)
            reads = [c for c in decoded.calls if c.name in BY_NAME and BY_NAME[c.name].effects <= READ_ONLY]
            actions = [c for c in decoded.calls if c not in reads]
            chosen = [] if last else reads + actions[:1]
            dropped = decoded.calls if last else actions[1:]
            self.workspace.ledger.append(
                "agent_said", say=decoded.say, step=step, codec=self.codec.name,
                calls=[{"id": c.id, "name": c.name, "arguments": c.arguments} for c in chosen],
                dropped=[{"name": c.name, "arguments": c.arguments} for c in dropped],
                problems=list(decoded.problems), usage=reply.usage, prompt_sha256=reply.prompt_sha256,
                first_token_seconds=reply.first_token_seconds, duration_seconds=reply.duration_seconds)
            if not chosen:
                if last and decoded.calls:
                    return TurnOutcome(step, bool(decoded.say), "limit")  # it ignored "answer now"
                if decoded.problems and not repaired and not last:
                    repaired = True
                    self.workspace.ledger.append("event_said", text="上一条回复里的工具调用无法解析："
                                                 + "；".join(decoded.problems)[:300] + "。请修正后重试，或直接回答。")
                    continue
                return TurnOutcome(step, bool(decoded.say), "answer" if decoded.say else "invalid")
            ended = ""
            for call in chosen:
                result = self._execute(call.name, call.arguments)
                if call in actions:
                    ended = "approval" if result.approval else "action"
                self._record(call.id, call.name, result)
            if ended:
                return TurnOutcome(step, True, ended)
        return TurnOutcome(MAX_STEPS, False, "limit")

    def _execute(self, name: str, arguments: dict[str, Any]) -> tools.Result:
        spec = BY_NAME.get(name)
        if spec is None:
            return tools.Result(f"there is no tool {name}; the tools are {', '.join(BY_NAME)}", error=True)
        problems = validate(spec.parameters, arguments)
        if problems:
            return tools.Result("invalid arguments: " + "; ".join(problems[:5]), error=True)
        return tools.run(self.ctx, name, arguments)

    def _record(self, call_id: str, name: str, result: tools.Result) -> None:
        self._handles += 1
        handle = f"R{self._handles}"
        content = result.content
        approval_id = None
        if result.approval:
            card = approvals.show(self.workspace, result.approval)
            approval_id = card["approval_id"]
            content = f"{content} — 已出批准卡 {approval_id}，等待评估员点击"
        full = None
        if len(content) > tools.MAX_CONTENT_CHARS:
            full = content
            content = content[:tools.MAX_CONTENT_CHARS] + f"\n…（未完，show({handle}, page=2) 取后续）"
        self.workspace.ledger.append("tool_result", call_id=call_id, name=name, handle=handle, content=content,
                                     full=full, card=result.card, approval_id=approval_id, error=result.error)

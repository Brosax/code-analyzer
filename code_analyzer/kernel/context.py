"""What the model is shown on each request, built so the GPU's prefix cache keeps hitting.

    [system]  method.md + the evaluation's profile summary      stable for hours
    [history] user / agent / tool entries from the ledger       append-only
    [tail]    one last user message: state and a next step      replaced every request

Measured on the GPU host: a repeated 6k-token prefix answers in 4-6 s instead of
25-31 s cold, and changing only the tool list costs a full re-prefill.  So the
system text and the tools never change within a conversation (the profile part
changes only when a profile is confirmed or replaced), history is only ever
appended to, and everything volatile -- counts, jobs, pending cards -- rides
in the tail, which the next request simply drops.

When history outgrows ``FOLD_AT`` tokens it is folded once, deterministically,
down to about ``FOLD_TO``: old tool results become one-line stubs, old agent
prose its first sentence, old user text 400 characters.  Between folds history
stays strictly append-only, so a fold costs one cold prefill, not one per turn.
"""
from __future__ import annotations

import re
from importlib import resources
from typing import Any

from ..evidence.workspace import Workspace
from ..sesip import active
from .codecs import AgentSaid, Call, Entry, ToolResult, UserSaid

FOLD_AT = 12000
FOLD_TO = 6000
CHARS_PER_TOKEN = 1.6
CONVERSATION_KINDS = ("user_said", "event_said", "agent_said", "tool_result", "context_folded")


def method() -> str:
    return resources.files("code_analyzer.kernel").joinpath("method.md").read_text(encoding="utf-8")


def system_prompt(workspace: Workspace) -> str:
    evaluation = workspace.evaluation
    profile = active.active_profile(workspace)
    view = active.view(profile)
    confidentiality = "客户代码（只用本地 GPU）" if evaluation["confidentiality"] == "client" else "公开代码"
    sfrs = "；".join(f"{s['id']} {s['title']}" for s in view["sfr"][:30]) or "（无）"
    modules = "；".join(f"{m['id']}={','.join(m['paths']) or '未映射'}" for m in view["toe_modules"][:20])
    return (f"{method().strip()}\n\n当前评估：{workspace.root.name}（{confidentiality}）。"
            f"档案 {view['name']}（{ {'builtin': '内置', 'draft': '草稿', 'confirmed': '已确认'}.get(view['status'], '') }）。\n"
            f"SFR：{sfrs}\nTOE 模块：{modules}\n等级：{', '.join(level['id'] for level in view['levels'])}")


def history(workspace: Workspace) -> list[Entry]:
    records = [r for r in workspace.ledger.read() if r["kind"] in CONVERSATION_KINDS]
    folds = [r["through_seq"] for r in records if r["kind"] == "context_folded"]
    folded_through = folds[-1] if folds else 0
    entries: list[Entry] = []
    for record in records:
        old = record["seq"] <= folded_through
        kind = record["kind"]
        if kind == "user_said":
            text = record["text"]
            entries.append(UserSaid(text[:400] if old else text))
        elif kind == "event_said":
            entries.append(UserSaid(f"[事件] {record['text']}"))
        elif kind == "agent_said":
            calls = tuple(Call(c["id"], c["name"], c["arguments"]) for c in record.get("calls", []))
            say = _first_sentence(record.get("say", "")) if old else record.get("say", "")
            entries.append(AgentSaid(say, calls))
        elif kind == "tool_result":
            if record.get("approved"):
                # An approved action has no tool call in history: it is an event.
                entries.append(UserSaid(f"[事件] {record['handle']} 已由评估员批准并执行：{record.get('content', '')}"))
                continue
            content = _stub(record) if old else record.get("content", "")
            entries.append(ToolResult(record["call_id"], record["name"], record["handle"], content))
    return entries


def estimate_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN)


def needs_fold(entries: list[Entry]) -> bool:
    return estimate_tokens(_text(entries)) > FOLD_AT


def fold(workspace: Workspace) -> int | None:
    """Fold everything but the most recent turns so history drops to about FOLD_TO tokens."""
    records = [r for r in workspace.ledger.read() if r["kind"] in CONVERSATION_KINDS and r["kind"] != "context_folded"]
    kept_chars = 0
    through = None
    for record in reversed(records):
        kept_chars += len(record.get("text", "") + record.get("say", "") + record.get("content", ""))
        if kept_chars / CHARS_PER_TOKEN > FOLD_TO and record["kind"] == "user_said":
            through = record["seq"] - 1
            break
    if through is None or through <= 0:
        return None
    workspace.ledger.append("context_folded", through_seq=through)
    return through


def tail(workspace: Workspace, *, triage: dict[str, int] | None, jobs: list[dict[str, Any]],
         pending: list[dict[str, Any]], final: bool = False) -> str:
    profile = active.active_profile(workspace)
    parts = [f"[状态] 档案 {profile.name}（{profile.status}）"]
    if triage:
        parts.append(f"清单 主分区 {triage.get('partition_main', 0)}，待核实 {triage.get('partition_unmapped', 0)}，"
                     f"低于阈值 {triage.get('partition_below', 0)}")
    else:
        parts.append("还没有清单")
    running = [j for j in jobs if j.get("status") == "running"]
    if running:
        parts.append("运行中任务 " + "、".join(f"{j['id']}({j['kind']})" for j in running))
    if pending:
        parts.append("待批准卡片 " + "、".join(p["approval_id"] for p in pending))
    parts.append("建议下一步：" + _next_step(profile.status, triage, running))
    text = "；".join(parts)
    if final:
        text += "\n（系统提示）不要再调用工具，直接根据以上结果用中文简短回答。"
    return text


def _next_step(status: str, triage: dict[str, int] | None, running: list[dict[str, Any]]) -> str:
    if running:
        return "等待任务结束，期间可以回答评估员的问题"
    if not triage:
        return "用 run_tools 跑静态工具"
    if status != "confirmed":
        return "请评估员核对并确认档案（SFR、TOE 模块、等级规则）"
    if triage.get("partition_unmapped"):
        return "逐条查看待核实条目，或建议评估员采纳建议等级"
    return "查看主分区条目并讨论处置"


def _stub(record: dict[str, Any]) -> str:
    content = record.get("content", "")
    first = content.splitlines()[0] if content else ""
    return f"[{record['handle']} {record['name']} → {first[:120]}]"


def _first_sentence(text: str) -> str:
    match = re.match(r"(.+?[。．.!?！？])", text.strip(), re.S)
    return (match.group(1) if match else text)[:200]


def _text(entries: list[Entry]) -> str:
    out = []
    for entry in entries:
        if isinstance(entry, UserSaid):
            out.append(entry.text)
        elif isinstance(entry, AgentSaid):
            out.append(entry.say + "".join(str(c.arguments) for c in entry.calls))
        else:
            out.append(entry.content)
    return "\n".join(out)

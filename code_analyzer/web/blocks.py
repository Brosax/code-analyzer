"""The timeline: every ledger record, as one block the page can draw.

Pure and UI-free, so it is tested with pytest rather than in a browser, and the
page needs no logic of its own to explain what happened: it renders
``{id, kind, title, detail, at, refs}`` by kind and nothing else.  The
previous front ends kept two copies of this translation (Python and a JS
rewrite in serve.py); there is one now.
"""
from __future__ import annotations

from typing import Any

STATUS_LABELS = {"open": "未处置", "confirmed": "确认", "false_positive": "误报", "not_exploitable": "不可利用",
                 "needs_test": "需测试"}


def block(record: dict[str, Any]) -> dict[str, Any] | None:
    kind = record["kind"]
    base = {"id": str(record["seq"]), "at": record.get("at", ""), "refs": {}}
    if kind == "evaluation_created":
        confidentiality = "客户·仅本地 GPU" if record.get("confidentiality") == "client" else "公开代码"
        return {**base, "kind": "event", "title": "评估已创建", "detail": f"{record.get('source')} · {confidentiality}"}
    if kind == "profile_selected":
        status = {"builtin": "内置", "draft": "草稿", "confirmed": "已确认"}.get(record.get("status", ""), "")
        by = f"，确认人 {record['by']}" if record.get("by") else ""
        return {**base, "kind": "profile", "title": f"档案：{record.get('name')}（{status}）",
                "detail": f"sha256 {str(record.get('sha256', ''))[:12]}{by}"}
    if kind == "buildctx_version":
        return {**base, "kind": "event", "title": f"构建上下文 v{record.get('version')}",
                "detail": f"sha256 {str(record.get('sha256', ''))[:12]}"}
    if kind == "call_started":
        tools = "、".join(record.get("tools") or [])
        return {**base, "kind": "job", "title": f"开始跑工具 {record.get('call_id')}", "detail": tools,
                "refs": {"call": record.get("call_id")}}
    if kind == "call_finished":
        reconciled = "（进程中断，重开时对账）" if record.get("reconciled") else ""
        return {**base, "kind": "job", "title": f"工具结束 {record.get('call_id')}",
                "detail": f"状态 {record.get('status')} · 退出码 {record.get('exit_code')}{reconciled}",
                "refs": {"call": record.get("call_id")}}
    if kind == "index_built":
        return {**base, "kind": "summary", "title": "清单已更新",
                "detail": (f"主分区 {record.get('partition_main', 0)} · 待核实 {record.get('partition_unmapped', 0)} · "
                           f"低于阈值 {record.get('partition_below', 0)}；保持编号 {record.get('kept', 0)}，"
                           f"新增 {record.get('new', 0)}，退役 {record.get('retired', 0)}")}
    if kind == "pv_status":
        note = f"：{record['note']}" if record.get("note") else ""
        return {**base, "kind": "status", "title": f"{record.get('pv_id')} 标为{STATUS_LABELS.get(record.get('status'), '')}",
                "detail": f"{record.get('by')}{note}", "refs": {"pv": record.get("pv_id")}}
    if kind == "level_accepted":
        return {**base, "kind": "status", "title": f"{record.get('pv_id')} 采纳等级 {record.get('level')}",
                "detail": f"{record.get('by')}（来自 proposed 规则）", "refs": {"pv": record.get("pv_id")}}
    if kind == "export_written":
        files = "、".join(f["name"] for f in record.get("files", []))
        return {**base, "kind": "export", "title": f"导出 {record.get('export_id')}（{record.get('variant')}）",
                "detail": f"{files} · 泄露复验 {record.get('leak_check')}", "refs": {"export": record.get("export_id")}}
    if kind == "gate_triggered":
        return {**base, "kind": "event", "title": "质量门禁触发", "detail": f"策略 {record.get('policy')}"}
    if kind == "profile_extracted":
        pending = len(record.get("unverified", []))
        return {**base, "kind": "profile", "title": f"档案草稿 {record.get('version')} 已从文档抽取",
                "detail": (f"SFR {record.get('sfr', 0)} · 等级 {record.get('levels', 0)} · 分类 {record.get('categories', 0)}"
                           f" · TOE 模块 {record.get('toe_modules', 0)}；{pending} 项引文未核实" +
                           ("；" + "；".join(record.get("problems", [])[:2]) if record.get("problems") else ""))}
    if kind == "user_said":
        return {**base, "kind": "user", "title": "评估员", "detail": record.get("text", "")}
    if kind == "user_queued":
        return {**base, "kind": "queued", "title": "排队中（本回合结束后发送）", "detail": record.get("text", "")}
    if kind == "event_said":
        return {**base, "kind": "event", "title": "事件", "detail": record.get("text", "")}
    if kind == "agent_said":
        calls = "、".join(f"{c['name']}" for c in record.get("calls", []))
        usage = record.get("usage") or {}
        timing = record.get("first_token_seconds")
        meta = f"第 {record.get('step')} 步" + (f" · 首字 {timing:.1f}s" if isinstance(timing, (int, float)) else "") \
            + (f" · 输入 {usage['prompt_tokens']} token" if usage.get("prompt_tokens") else "")
        return {**base, "kind": "agent", "title": "agent", "detail": record.get("say", ""),
                "refs": {"calls": calls, "meta": meta}}
    if kind == "tool_result":
        if record.get("approval_id") and not record.get("approved"):
            return None  # the approval card itself is the block
        title = f"{record.get('name')} → {record.get('handle')}" + ("（出错）" if record.get("error") else "")
        return {**base, "kind": "tool", "title": title, "detail": record.get("content", ""),
                "refs": {"card": record.get("card"), "handle": record.get("handle")}}
    if kind == "approval_shown":
        return {**base, "kind": "approval", "title": f"批准卡 {record['approval_id']}：{record.get('summary', '')}",
                "detail": "将写入：" + "、".join(record.get("writes") or []) + " · 参数 sha256 "
                          + str(record.get("args_sha256", ""))[:12],
                "refs": {"approval": record["approval_id"], "sha": record.get("args_sha256"),
                         "tool": record.get("tool"), "arguments": record.get("arguments"),
                         "expires_at": record.get("expires_at")}}
    if kind in ("approval_granted", "approval_rejected", "approval_expired"):
        verb = {"approval_granted": "已批准", "approval_rejected": "已拒绝", "approval_expired": "已失效"}[kind]
        return {**base, "kind": "status", "title": f"{record['approval_id']} {verb}",
                "detail": record.get("by") or record.get("reason", ""), "refs": {"approval": record["approval_id"]}}
    if kind == "turn_cancelled":
        return {**base, "kind": "status", "title": "本回合已中断", "detail": record.get("reason", "")}
    if kind == "agent_error":
        return {**base, "kind": "error", "title": "agent 出错", "detail": f"{record.get('code')}: {record.get('message')}"}
    if kind == "turn_finished" and record.get("ended_by") == "limit":
        return {**base, "kind": "status", "title": "agent 在 3 步内没能给出结论", "detail": "可以换个问法，或直接用按钮"}
    if kind == "patch_proposed":
        probe = record.get("probe") or {}
        detail = f"{record.get('items')} 项（{record.get('preselected')} 项预选）"
        if probe:
            detail += f"；试跑 {probe.get('reached_after')}/{probe.get('sampled')} 个失败单元恢复预处理"
        return {**base, "kind": "event", "title": f"构建上下文补丁 {record.get('patch_id')}（{record.get('tool')}）",
                "detail": detail}
    if kind == "patch_applied":
        return {**base, "kind": "summary", "title": f"补丁 {record.get('patch_id')} 已应用，构建上下文 v{record.get('buildctx_version')}",
                "detail": (f"{record.get('tool')}：失败单元 {record.get('failed_before')} → {record.get('failed_after')}，"
                           f"进入分析 {record.get('reached_before')} → {record.get('reached_after')}")}
    if kind == "model_pinned":
        return {**base, "kind": "event", "title": f"模型主机已钉住：{record.get('host')}:{record.get('port')}",
                "detail": f"{record.get('model')} · {', '.join(record.get('addresses') or [])} · {record.get('by')}"}
    if kind == "review_started":
        counts = record.get("counts") or {}
        return {**base, "kind": "job", "title": f"AI 审查 {record.get('job')} 开始",
                "detail": (f"核实 {counts.get('T1', 0)} 条清单条目、查看 {counts.get('T2', 0)} 个无告警单元；"
                           f"GPU 额度 {round(float(record.get('budget_seconds') or 0) / 60)} 分钟"),
                "refs": {"job": record.get("job")}}
    if kind == "review_finished":
        reasons = "；".join(f"{k} {v}" for k, v in (record.get("unscheduled_reasons") or {}).items())
        return {**base, "kind": "summary", "title": f"AI 审查 {record.get('job')} 结束",
                "detail": (f"计划 {record.get('planned')} = 已审 {record.get('started')} + 未排上 "
                           f"{record.get('unscheduled')}{('（' + reasons + '）') if reasons else ''}；"
                           f"GPU {record.get('gpu_seconds')} 秒；新进入清单的 AI 发现 {record.get('promoted', 0)} 条"),
                "refs": {"job": record.get("job")}}
    if kind == "ai_promoted":
        return {**base, "kind": "event", "title": f"AI 发现 {record.get('af')} 经复核（{record.get('verdict')}）进入未分级分区",
                "detail": f"{record.get('path')}:{record.get('line')} {record.get('message')}"}
    if kind == "document_added":
        return {**base, "kind": "event", "title": f"文档已上传：{record.get('name')}",
                "detail": f"sha256 {str(record.get('sha256', ''))[:12]}"}
    return None


def blocks(records: list[dict[str, Any]], after: int = 0) -> list[dict[str, Any]]:
    out = []
    for record in records:
        if int(record.get("seq", 0)) > after:
            item = block(record)
            if item is not None:
                out.append(item)
    return out

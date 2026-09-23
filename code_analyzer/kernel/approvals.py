"""Approval cards: the only door from a model's request to a write, a GPU job or a build.

A card is shown with the exact arguments and their sha256.  A human click
approves *that* hash: if the arguments differ, if 30 minutes passed, or if the
evaluation's state moved on (a new profile, build context or list), the card
is void and nothing runs.  Free text in the conversation never approves
anything -- only the approve endpoint, which only the page's button calls.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from ..errors import UserError
from ..evidence.workspace import Workspace
from . import tools

TTL_SECONDS = 1800


def state_of(workspace: Workspace) -> str:
    """What an approval is bound to besides its arguments."""
    parts = []
    for kind in ("profile_selected", "buildctx_version", "pv_numbered"):
        records = workspace.ledger.of(kind)
        parts.append(str(records[-1].get("sha256") or records[-1]["seq"]) if records else "-")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def args_sha(tool: str, arguments: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps([tool, arguments], sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def show(workspace: Workspace, request: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
    number = len(workspace.ledger.of("approval_shown")) + 1
    record = workspace.ledger.append(
        "approval_shown", approval_id=f"A{number}", tool=request["tool"], arguments=request["arguments"],
        args_sha256=args_sha(request["tool"], request["arguments"]), summary=request.get("summary", ""),
        writes=request.get("writes", []), state=state_of(workspace),
        expires_at=(now or time.time()) + TTL_SECONDS)
    return record


def pending(workspace: Workspace, *, now: float | None = None) -> list[dict[str, Any]]:
    decided = {r["approval_id"] for r in workspace.ledger.of("approval_granted", "approval_rejected",
                                                             "approval_expired")}
    moment = now or time.time()
    return [r for r in workspace.ledger.of("approval_shown")
            if r["approval_id"] not in decided and r["expires_at"] > moment]


def decide(workspace: Workspace, ctx: tools.ToolContext, approval_id: str, decision: str, *, by: str,
           sha: str, now: float | None = None) -> tools.Result:
    shown = {r["approval_id"]: r for r in workspace.ledger.of("approval_shown")}
    card = shown.get(approval_id)
    if card is None:
        raise UserError(f"no approval card {approval_id}")
    if any(r["approval_id"] == approval_id for r in
           workspace.ledger.of("approval_granted", "approval_rejected", "approval_expired")):
        raise UserError(f"{approval_id} was already decided")
    if decision == "reject":
        workspace.ledger.append("approval_rejected", approval_id=approval_id, by=by)
        return tools.Result(f"the evaluator rejected {approval_id}")
    reason = ""
    if sha != card["args_sha256"] or args_sha(card["tool"], card["arguments"]) != card["args_sha256"]:
        reason = "the arguments do not match the card"
    elif (now or time.time()) > card["expires_at"]:
        reason = "the card expired (30 minutes)"
    elif state_of(workspace) != card["state"]:
        reason = "the evaluation changed since the card was shown"
    if reason:
        workspace.ledger.append("approval_expired", approval_id=approval_id, reason=reason)
        raise UserError(f"{approval_id} can no longer run: {reason}; ask again")
    workspace.ledger.append("approval_granted", approval_id=approval_id, by=by)
    result = tools.execute_approved(ctx, card["tool"], card["arguments"])
    workspace.ledger.append("tool_result", call_id=approval_id, name=card["tool"], handle=approval_id,
                            content=result.content, card=result.card, approved=True)
    return result

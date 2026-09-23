"""What people decided about list entries, replayed from the ledger onto the index.

The index is derived and can be rebuilt at any time; an analyst's decisions
must survive that.  They live in the ledger -- ``pv_status`` (a disposition
and its note) and ``level_accepted`` (a level an analyst took over from a
proposed rule) -- always with ``by``, and are replayed onto every new index.
They are keyed by PV number, which stays with the defect across re-runs
(sesip/pv.py), so a disposition follows the finding, not a line number.

The AI's verdicts on entries (``ai_review`` records of tier T1) are replayed
the same way, but only grounded ones: an opinion whose quote or line is not in
the code it was shown never reaches the list (it is counted on the coverage
page instead).  An opinion never moves an entry.
"""
from __future__ import annotations

from typing import Any

from .store import Store
from .workspace import Workspace

STATUSES = ("open", "confirmed", "false_positive", "not_exploitable", "needs_test")


def replay(workspace: Workspace, store: Store) -> dict[str, int]:
    """Apply every recorded decision to ``store``; returns how many of each were applied."""
    applied = {"status": 0, "level": 0, "ai": 0}
    for record in workspace.ledger.of("pv_status", "level_accepted", "ai_review"):
        if record["kind"] == "pv_status":
            applied["status"] += store.set_status(record["pv_id"], record["status"], record.get("note", ""))
        elif record["kind"] == "level_accepted":
            applied["level"] += store.set_level(record["pv_id"], record["level"], "analyst", "main")
        else:
            opinion = ai_opinion(record)
            if opinion is not None:
                applied["ai"] += store.set_ai(record["key"], opinion)
    return applied


def ai_opinion(record: dict[str, Any]) -> dict[str, Any] | None:
    """What a grounded verdict on a list entry contributes to it; None for anything else."""
    verdict = record.get("verdict")
    if record.get("tier") != "T1" or record.get("status") not in ("done", "cached") or not isinstance(verdict, dict):
        return None
    if not record.get("grounded"):
        return None
    return {"verdict": verdict["verdict"], "confidence": verdict["confidence"],
            "decisive_line": verdict["decisive_line"], "evidence_quote": verdict["evidence_quote"],
            "rationale": verdict["rationale"], "exploit_note": verdict.get("exploit_note", ""),
            "level_suggestion": verdict.get("level_suggestion", ""),
            "category_suggestion": verdict.get("category_suggestion", ""), "sfr": verdict.get("sfr", []),
            "lens": record.get("lens"), "lens_version": record.get("lens_version"), "model": record.get("model"),
            "prompt_sha256": record.get("prompt_sha256"), "job": record.get("job"), "at": record.get("at")}


def set_status(workspace: Workspace, store: Store, pv_id: str, status: str, note: str, by: str) -> dict[str, Any]:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    if store.pv(pv_id) is None:
        raise KeyError(pv_id)
    record = workspace.ledger.append("pv_status", pv_id=pv_id, status=status, note=note[:2000], by=by)
    store.set_status(pv_id, status, record["note"])
    return store.pv(pv_id) or {}


def accept_proposed(workspace: Workspace, store: Store, pv_ids: list[str], by: str) -> int:
    """An analyst takes over the level a proposed rule suggested; the entry joins the main partition."""
    accepted = []
    for pv_id in pv_ids:
        entry = store.pv(pv_id)
        if entry is None or entry.get("level_basis") != "unmapped" or not entry.get("proposed_level"):
            continue
        accepted.append(("level_accepted", {"pv_id": pv_id, "level": entry["proposed_level"],
                                            "from": "ai" if entry.get("proposed_from") == "ai" else "proposed",
                                            "by": by}))
    if accepted:
        workspace.ledger.append_many(accepted)
        for _, data in accepted:
            store.set_level(data["pv_id"], data["level"], "analyst", "main")
    return len(accepted)

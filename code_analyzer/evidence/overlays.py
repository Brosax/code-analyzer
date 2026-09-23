"""What people decided about list entries, replayed from the ledger onto the index.

The index is derived and can be rebuilt at any time; an analyst's decisions
must survive that.  They live in the ledger -- ``pv_status`` (a disposition
and its note) and ``level_accepted`` (a level an analyst took over from a
proposed rule) -- always with ``by``, and are replayed onto every new index.
They are keyed by PV number, which stays with the defect across re-runs
(sesip/pv.py), so a disposition follows the finding, not a line number.
"""
from __future__ import annotations

from typing import Any

from .store import Store
from .workspace import Workspace

STATUSES = ("open", "confirmed", "false_positive", "not_exploitable", "needs_test")


def replay(workspace: Workspace, store: Store) -> dict[str, int]:
    """Apply every recorded decision to ``store``; returns how many of each were applied."""
    applied = {"status": 0, "level": 0}
    for record in workspace.ledger.of("pv_status", "level_accepted"):
        if record["kind"] == "pv_status":
            applied["status"] += store.set_status(record["pv_id"], record["status"], record.get("note", ""))
        else:
            applied["level"] += store.set_level(record["pv_id"], record["level"], "analyst", "main")
    return applied


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
                                            "from": "proposed", "by": by}))
    if accepted:
        workspace.ledger.append_many(accepted)
        for _, data in accepted:
            store.set_level(data["pv_id"], data["level"], "analyst", "main")
    return len(accepted)

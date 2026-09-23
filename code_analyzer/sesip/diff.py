"""Re-evaluation: what changed in the list between two versions of the TOE's code.

Two evaluations (say TF-M v2.3.0 and a later commit) are compared with the
list's own one-to-one matching (pv.number): shared member fingerprints, then
the anchor, then "moved" (same file, function and defect family, the old
decisive line's text still inside).  The base's list plays the previous
numbering and the head's entries are numbered against it, so the answer is:

* kept   -- head entries matched to a base entry (and how), with the base's
            analyst disposition alongside, so an evaluator re-uses a decision
            instead of re-making it;
* new    -- head entries nothing in the base matches;
* gone   -- base entries nothing in the head matches (fixed, removed, or moved
            beyond recognition -- the diff does not guess which).

Read-only: neither evaluation changes.
"""
from __future__ import annotations

from dataclasses import fields
from typing import Any

from ..errors import UserError
from ..evidence.store import Store, index_current
from ..evidence.workspace import Workspace
from .pv import Entry, number

ENTRY_FIELDS = [f.name for f in fields(Entry)]
SHOWN = ("pv_id", "partition", "level", "path", "line_start", "function", "family", "tools", "status", "note")


def _rows(workspace: Workspace) -> list[dict[str, Any]]:
    if not index_current(workspace.index_path):
        raise UserError(f"{workspace.root.name} has no current list; open it once (or run the tools) first")
    store = Store(workspace.index_path)
    try:
        return store.all_pvs()
    finally:
        store.close()


def compare(base: Workspace, head: Workspace) -> dict[str, Any]:
    base_rows = [r for r in _rows(base) if r.get("partition") in ("main", "unmapped")]
    head_rows = [r for r in _rows(head) if r.get("partition") in ("main", "unmapped")]
    previous = [{"pv_id": r["pv_id"], "anchor": r.get("anchor", ""), "members": r.get("members", []),
                 "path": r["path"], "function": r.get("function", ""), "family": r.get("family", ""),
                 "decisive_line_sha": r.get("decisive_line_sha", "")} for r in base_rows]
    entries = [Entry(**{**{k: row.get(k) for k in ENTRY_FIELDS if k in row}, "pv_id": "", "match": ""})
               for row in head_rows]
    number(entries, previous)
    by_base = {row["pv_id"]: row for row in base_rows}
    kept, new = [], []
    for entry, row in zip(entries, head_rows, strict=True):
        view = {k: row.get(k) for k in SHOWN}
        view["tools"] = ",".join(row.get("tools") or []) if isinstance(row.get("tools"), list) else row.get("tools")
        if entry.match == "new":
            new.append(view)
        else:
            old = by_base[entry.pv_id]
            kept.append({**view, "base_pv_id": entry.pv_id, "how": entry.match, "base_status": old.get("status"),
                         "base_note": old.get("note", ""), "base_level": old.get("level"),
                         "base_line": old.get("line_start")})
    matched = {item["base_pv_id"] for item in kept}
    gone = [{k: row.get(k) for k in SHOWN} for row in base_rows if row["pv_id"] not in matched]
    how: dict[str, int] = {}
    for item in kept:
        how[item["how"]] = how.get(item["how"], 0) + 1
    dispositions = sum(1 for item in kept if item["base_status"] not in (None, "open"))
    return {
        "base": {"id": base.root.name, "source": str(base.source), "listed": len(base_rows)},
        "head": {"id": head.root.name, "source": str(head.source), "listed": len(head_rows)},
        "counts": {"kept": len(kept), "new": len(new), "gone": len(gone), "how": how,
                   "dispositions_to_reuse": dispositions},
        "kept": kept, "new": new, "gone": gone,
    }

"""What was looked at, what was not, and why -- the page an evaluator signs off against.

Everything is computed from the index and the ledger: the triage conservation,
an SFR x TOE-module matrix of listed entries and how many of them the AI has
verified, what each lens was asked and how often its claims failed grounding,
the AI's verdicts across the list, and the reasons units went unreviewed.
Nothing here is an estimate.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from ..evidence.store import Store
from ..evidence.workspace import Workspace
from .profile import Profile

VERDICTS = ("CONFIRMED", "LIKELY", "UNCERTAIN", "FALSE_POSITIVE")


def coverage(workspace: Workspace, store: Store | None, profile: Profile) -> dict[str, Any]:
    pvs = store.all_pvs() if store is not None else []
    triage = store.triage_counts() if store is not None else {}
    records = workspace.ledger.of("ai_review")
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        if record.get("status") in ("done", "cached", "failed") or record["review_key"] not in latest:
            latest[record["review_key"]] = record

    modules = [m["id"] for m in profile.data.get("toe_module", [])]
    sfrs = [{"id": s["id"], "title": s.get("title", "")} for s in profile.data.get("sfr", [])]
    matrix: dict[str, dict[str, dict[str, int]]] = {s["id"]: {m: {"listed": 0, "verified": 0, "looked": 0}
                                                               for m in modules} for s in sfrs}
    for row in pvs:
        for link in row.get("sfr", []):
            cell = matrix.get(link["id"], {}).get(str(row.get("module")))
            if cell is not None:
                cell["listed"] += 1
                cell["verified"] += int(bool(row.get("ai")))
    for record in latest.values():
        if record.get("tier") == "T2" and record.get("status") in ("done", "cached") and record.get("sfr_id"):
            cell = matrix.get(record["sfr_id"], {}).get(str(record.get("module")))
            if cell is not None:
                cell["looked"] += 1

    lenses: dict[str, dict[str, Any]] = defaultdict(lambda: {"asked": 0, "answered": 0, "failed": 0,
                                                             "unscheduled": 0, "claims": 0, "grounded": 0,
                                                             "gpu_seconds": 0.0})
    for record in records:
        tally = lenses[str(record["lens"])]
        tally["asked"] += 1
        status = record.get("status")
        tally["answered" if status in ("done", "cached") else status if status in ("failed", "unscheduled")
              else "failed"] += 1
        tally["claims"] += int(record.get("claims", 0))
        tally["grounded"] += int(record.get("claims_grounded", 0))
        tally["gpu_seconds"] += float(record.get("gpu_seconds") or 0)
    for tally in lenses.values():
        tally["grounding_failure_rate"] = round(1 - tally["grounded"] / tally["claims"], 3) if tally["claims"] else None
        tally["gpu_seconds"] = round(tally["gpu_seconds"], 1)

    verdicts = Counter(str((row.get("ai") or {}).get("verdict") or "none") for row in pvs)
    listed = [row for row in pvs if row.get("partition") in ("main", "unmapped")]
    unreviewed: Counter[str] = Counter()
    for record in latest.values():
        if record.get("status") == "unscheduled":
            unreviewed[str(record.get("reason"))] += 1
    jobs = [{k: r.get(k) for k in ("job", "planned", "started", "unscheduled", "gpu_seconds", "promoted",
                                   "unscheduled_reasons", "at")} for r in workspace.ledger.of("review_finished")]
    return {
        "triage": triage,
        "sfr": sfrs, "modules": modules, "matrix": matrix,
        "lenses": dict(sorted(lenses.items())),
        "verdicts": {v: verdicts.get(v, 0) for v in (*VERDICTS, "none")},
        "listed": len(listed), "verified": sum(1 for row in listed if row.get("ai")),
        "promoted": len(workspace.ledger.of("ai_promoted")),
        "origin": dict(Counter(str(row.get("origin", "tool")) for row in listed)),
        "unreviewed": dict(unreviewed.most_common()),
        "jobs": jobs[-10:],
        "granted_seconds": granted_seconds(workspace),
    }


def granted_seconds(workspace: Workspace) -> dict[str, float]:
    """GPU time humans granted for review, what jobs used, and what is left."""
    granted = sum(float(r.get("budget_seconds") or 0) for r in workspace.ledger.of("review_granted"))
    used = sum(float(r.get("gpu_seconds") or 0) for r in workspace.ledger.of("review_finished"))
    return {"granted": round(granted, 1), "used": round(used, 1), "left": round(max(0.0, granted - used), 1)}

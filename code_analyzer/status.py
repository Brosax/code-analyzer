from __future__ import annotations

from collections import Counter
from typing import Any

# Process exit codes shared by the CLI, the runner, and the status algebra.
EXIT_COMPLETE = 0
EXIT_GATE_FAILED = 1
EXIT_USAGE = 2
EXIT_PARTIAL = 10
EXIT_FAILED = 20
EXIT_INTERRUPTED = 130

# Every word the status ladder can produce, projected onto the five states a
# UI draws.  The projection is a view; nothing persists the five-state form.
# Both front ends read it from here: `serve` projects manifest.json, the TUI
# folds the event stream, and they must not disagree about what a word means.
# "partial" is its own state on purpose: a tool that ran but analysed only
# some of its units is neither a success nor a failure, and drawing it as
# either hides the one thing the operator needs to know.
NODE_STATES: dict[str, str] = {
    "completed": "success", "complete": "success",
    "partial": "partial",
    "timed_out": "failed", "failed": "failed", "interrupted": "failed",
    "incompatible": "failed", "missing": "failed",
    "running": "running", "paused": "running", "pending": "pending",
    "unscheduled": "pending", "skipped": "pending",
    "not_requested": "pending", "not_applicable": "pending", "disabled": "pending",
}
STATES: tuple[str, ...] = ("success", "partial", "failed", "running", "pending")
PHASE_NODES: tuple[str, ...] = ("discovery", "review", "audit", "export", "dashboard")
# serve.py injects this object into its page script, so the two front ends
# cannot draw different glyphs for one state.
STATE_GLYPHS: dict[str, str] = {"success": "✓", "partial": "◐", "failed": "✕", "running": "●", "pending": "○"}


def aggregate_units(units: list[dict[str, Any]], applicable: bool = True) -> str:
    if not applicable or not units:
        return "not_applicable"
    states = [unit["status"] for unit in units]
    if "interrupted" in states:
        return "interrupted"
    valid = any(unit.get("valid_report", False) for unit in units)
    if all(state == "completed" for state in states):
        return "completed"
    if valid:
        return "partial"
    if all(state in {"timed_out", "unscheduled"} for state in states):
        return "timed_out"
    return "failed"


def counts(units: list[dict[str, Any]]) -> dict[str, int]:
    counter = Counter(unit["status"] for unit in units)
    return {
        "planned": len(units),
        "started": sum(counter[s] for s in ("completed", "partial", "timed_out", "failed", "interrupted")),
        "completed": counter["completed"],
        "failed": counter["failed"] + counter["partial"],
        "timed_out": counter["timed_out"],
        "unscheduled": counter["unscheduled"],
    }


def overall(
    tools: dict[str, Any],
    source_stable: bool | None,
    export_status: str,
    review_status: str = "disabled",
) -> tuple[str, int]:
    requested = [item for item in tools.values() if item["requested"]]
    if any(item["status"] == "interrupted" for item in requested):
        return "interrupted", EXIT_INTERRUPTED
    valid = any(item.get("valid_reports", 0) > 0 for item in requested)
    applicable = [item for item in requested if item["status"] != "not_applicable"]
    complete = bool(applicable) and all(item["status"] == "completed" for item in applicable)
    complete &= all(item["status"] in {"completed", "not_applicable"} for item in requested)
    complete &= source_stable is True and export_status in {"completed", "disabled"}
    complete &= review_status in {"completed", "disabled"}
    if complete:
        return "complete", EXIT_COMPLETE
    if valid:
        return "partial", EXIT_PARTIAL
    return "failed", EXIT_FAILED

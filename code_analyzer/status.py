from __future__ import annotations

from collections import Counter
from typing import Any


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


def overall(tools: dict[str, Any], source_stable: bool, export_status: str) -> tuple[str, int]:
    requested = [item for item in tools.values() if item["requested"]]
    if any(item["status"] == "interrupted" for item in requested):
        return "interrupted", 130
    valid = any(item.get("valid_reports", 0) > 0 for item in requested)
    applicable = [item for item in requested if item["status"] != "not_applicable"]
    complete = bool(applicable) and all(item["status"] == "completed" for item in applicable)
    complete &= all(item["status"] in {"completed", "not_applicable"} for item in requested)
    complete &= source_stable and export_status in {"completed", "disabled"}
    if complete:
        return "complete", 0
    if valid:
        return "partial", 10
    return "failed", 20

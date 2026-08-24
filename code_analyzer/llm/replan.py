"""Bounded re-planning: round 0 is deterministic, later rounds are evidence.

The spec this project answers asks for Plan -> Execute -> Observe -> Re-plan.
Three of this repository's contracts collide with the naive form of that loop,
and all three are kept here:

* **The unit plan stays byte-stable.**  Round 0 is exactly what ``build_plan``
  produced -- no model, no observation, no adaptation.  Nothing a model says
  can change which units exist or where their boundaries are.
* **Offline re-derivation stays zero-model.**  ``review.py`` and
  ``recovery.py`` never read ``llm/plan.json``.  It records *why* a run
  scanned what it scanned; it is not an input to any derived artifact.
* **The LLM layer never changes an exit code.**  A re-planning failure is a
  recorded round with no action, not a phase failure and not a tool failure.

What makes the loop bounded is the vocabulary: a decider may only return one
of the actions in :data:`ACTIONS`, aimed at units and producers that already
exist.  An unknown action, an unknown unit or a target outside the plan is
dropped and counted, never guessed at.  ``[llm] max_replan_rounds`` is 0 by
default, so the whole mechanism is dormant until an operator asks for it.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Iterable, Mapping, Sequence

from ..harness.schema import RESPONSE_ERROR_PREFIX, _candidates, _drop_trailing_commas
from .risk import RISK_TIERS, tier_rank

PLAN_PATH = ("llm", "plan.json")
PLAN_SCHEMA_VERSION = 1

# The whole vocabulary.  A decider that wants something else does not get it.
ACTIONS: tuple[str, ...] = (
    "escalate_tier",
    "rescan",
    "extend_deadline",
    "stop_producer",
    "mark_for_validation",
    "stop",
)
DETERMINISTIC = "deterministic"
MODEL = "model"
REPLAN_DECIDERS: tuple[str, ...] = (DETERMINISTIC, MODEL)

# An observation is counts, never text.  A finding's message is model output
# about untrusted source; feeding it back into a planning prompt would be the
# injection path this project closes everywhere else.
OBSERVATION_KEYS = ("categories", "severities", "tiers", "producers", "budget")

MAX_RATIONALE = 300


def observe(
    records: Sequence[Mapping[str, Any]],
    plan: Mapping[str, Any],
    budget: Mapping[str, Any],
) -> dict[str, Any]:
    """Reduce one round's unit records to counts a decider may see.

    Deliberately lossy: categories and severities as tallies, per-tier and
    per-producer scheduling outcomes, and what is left of the budget.  No
    message, no evidence, no path outside the plan.
    """
    categories: dict[str, int] = {}
    severities: dict[str, int] = {}
    producers: dict[str, dict[str, int]] = {}
    for record in records:
        producer = str(record.get("producer") or "")
        entry = producers.setdefault(producer, {"scanned": 0, "unscheduled": 0, "failed": 0, "findings": 0})
        status = str(record.get("status") or "")
        if status == "unscheduled":
            entry["unscheduled"] += 1
        elif status in ("completed", "partial"):
            entry["scanned"] += 1
        else:
            entry["failed"] += 1
        entry["findings"] += int(record.get("finding_count") or 0)
        # The record carries a tally, never the findings themselves: this is
        # the boundary that keeps model text about untrusted source out of any
        # planning decision.
        mix = record.get("finding_mix")
        if not isinstance(mix, Mapping):
            continue
        for table, key in ((categories, "categories"), (severities, "severities")):
            counted = mix.get(key)
            if isinstance(counted, Mapping):
                for name, count in counted.items():
                    if isinstance(count, int) and not isinstance(count, bool):
                        table[str(name)] = table.get(str(name), 0) + count

    units = {str(unit.get("unit_id")): unit for unit in plan.get("units", ())}
    tiers: dict[str, dict[str, int]] = {tier: {"planned": 0, "scanned": 0, "unscheduled": 0} for tier in RISK_TIERS}
    for unit in units.values():
        tier = str(unit.get("risk_tier") or "low")
        if tier in tiers:
            tiers[tier]["planned"] += 1
    for record in records:
        unit = units.get(str(record.get("id") or ""))
        tier = str((unit or {}).get("risk_tier") or "")
        if tier not in tiers:
            continue
        key = "unscheduled" if record.get("status") == "unscheduled" else "scanned"
        tiers[tier][key] += 1
    return {
        "categories": dict(sorted(categories.items())),
        "severities": dict(sorted(severities.items())),
        "tiers": tiers,
        "producers": {name: producers[name] for name in sorted(producers)},
        "budget": dict(sorted(budget.items())) if isinstance(budget, Mapping) else {},
    }


def decide(
    observation: Mapping[str, Any],
    plan: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
    *,
    escalated: Iterable[str] = (),
) -> dict[str, Any]:
    """The deterministic rule table: three rules, each with a stated reason.

    This is the default decider and the only one that runs without an operator
    turning a model on.  Every rule fires on counts the run measured, and each
    one names the evidence that justifies it.
    """
    already = set(escalated)
    units = {str(unit.get("unit_id")): unit for unit in plan.get("units", ())}

    # R1: the risk model guessed low and the code disagreed.  A file that
    # produced a high or critical finding at a low tier was scanned with the
    # smallest context budget; it deserves the large one.
    severe = sorted({
        str(units.get(str(record.get("id")), {}).get("path") or "")
        for record in records
        if _severe(record)
        and tier_rank(str(units.get(str(record.get("id")), {}).get("risk_tier") or "low")) > tier_rank("high")
    } - already - {""})
    if severe:
        return _action(
            "escalate_tier", severe,
            rationale="a high or critical finding came out of a file the risk model put in a low tier",
            to_tier="high",
        )

    # R2: unfinished, not unfinishable.  Units the budget could not afford are
    # scanned now if the budget recovered; the run says so either way.
    unscheduled = sorted({
        f"{record.get('producer')}::{record.get('id')}"
        for record in records if record.get("status") == "unscheduled"
    })
    if unscheduled and _has_budget(observation):
        return _action(
            "rescan", unscheduled,
            rationale="units left unscheduled by the previous round's budget, which has room again",
        )

    # R3: a producer that failed every unit is not producing evidence, it is
    # burning budget the other producers could use.
    dead = sorted(
        name for name, counts in (observation.get("producers") or {}).items()
        if counts.get("scanned", 0) == 0 and counts.get("failed", 0) > 0
    )
    if dead:
        return _action(
            "stop_producer", dead,
            rationale="every dispatched unit failed for this producer; it is spending budget without producing evidence",
        )
    return _action("stop", [], rationale="no rule fired: the round changed nothing worth another round")


def parse_decision(text: str, plan: Mapping[str, Any], producers: Sequence[str]) -> tuple[dict[str, Any], list[str]]:
    """Lenient parse, strict validate -- the same split as the finding schema.

    Returns ``(action, problems)``.  A decision is never trusted: an unknown
    action name, an unknown unit id, a tier outside the vocabulary or a
    producer that is not running are dropped and reported, and a decision that
    loses every target becomes ``stop``.
    """
    problems: list[str] = []
    value = _first_object(text)
    if value is None:
        return _action("stop", [], rationale="the planner returned no JSON object"), [
            RESPONSE_ERROR_PREFIX + "no JSON object found in the response"
        ]
    name = str(value.get("action") or "").strip()
    if name not in ACTIONS:
        return _action("stop", [], rationale="the planner named an action outside the vocabulary"), [
            f"unknown action {name!r}: expected one of {', '.join(ACTIONS)}"
        ]
    rationale = str(value.get("rationale") or "").strip()[:MAX_RATIONALE] or "the planner gave no reason"
    targets = value.get("targets")
    targets = [str(item) for item in targets] if isinstance(targets, list) else []

    if name == "stop":
        return _action("stop", [], rationale=rationale), problems
    if name == "extend_deadline":
        try:
            seconds = float(value.get("seconds"))
        except (TypeError, ValueError):
            return _action("stop", [], rationale=rationale), ["extend_deadline needs a numeric seconds"]
        if seconds <= 0:
            return _action("stop", [], rationale=rationale), ["extend_deadline needs a positive seconds"]
        return _action("extend_deadline", [], rationale=rationale, seconds=seconds), problems
    if name == "stop_producer":
        kept = [item for item in targets if item in set(producers)]
        problems += [f"unknown producer {item!r}" for item in targets if item not in set(producers)]
    elif name == "escalate_tier":
        paths = {str(unit.get("path")) for unit in plan.get("units", ())}
        kept = [item for item in targets if item in paths]
        problems += [f"path {item!r} is not in the plan" for item in targets if item not in paths]
        tier = str(value.get("to_tier") or "").strip().lower()
        if tier not in RISK_TIERS:
            return _action("stop", [], rationale=rationale), [*problems, f"unknown tier {tier!r}"]
        if kept:
            return _action("escalate_tier", sorted(kept), rationale=rationale, to_tier=tier), problems
        kept = []
    else:  # rescan, mark_for_validation
        known = {str(unit.get("unit_id")) for unit in plan.get("units", ())}
        kept = [item for item in targets if item.split("::")[-1] in known]
        problems += [f"unknown unit {item!r}" for item in targets if item.split("::")[-1] not in known]
    if not kept:
        return _action("stop", [], rationale=rationale), [*problems, "every target was dropped"]
    return _action(name, sorted(kept), rationale=rationale), problems


def round_directory(round_index: int) -> str:
    """Where a round's session evidence lives, relative to the unit directory.

    Round 0 keeps today's path exactly: ``unit_id`` deliberately carries no
    tier, so a re-scan of the same unit by the same producer would otherwise
    overwrite the blind first-pass evidence the llm-only metrics depend on.
    """
    return "" if round_index <= 0 else f"r{round_index}"


def ledger(rounds: Sequence[Mapping[str, Any]], *, decider: str, limit: int) -> dict[str, Any]:
    """The document written to ``llm/plan.json``.

    It is evidence about the scan, never an input to one: nothing in the review
    or recovery path reads it, and a run with ``max_replan_rounds = 0`` still
    writes it with its single deterministic round, so "why these units" has the
    same answer shape whether or not re-planning was enabled.
    """
    return {
        "plan_schema_version": PLAN_SCHEMA_VERSION,
        "decider": decider,
        "max_replan_rounds": int(limit),
        "authority": "non-authoritative-scan-provenance",
        "notice": (
            "This file records why the scan ran the units it ran. It is not read by the review, "
            "the audit layer or recover-report, and it never affects an exit code."
        ),
        "rounds": [dict(item) for item in rounds],
    }


def _severe(record: Mapping[str, Any]) -> bool:
    severities = ((record.get("finding_mix") or {}) if isinstance(record.get("finding_mix"), Mapping) else {}).get("severities")
    if not isinstance(severities, Mapping):
        return False
    return any(int(severities.get(name) or 0) > 0 for name in ("critical", "high"))


def _action(name: str, targets: Sequence[str], *, rationale: str, **extra: Any) -> dict[str, Any]:
    return {"action": name, "targets": list(targets), "rationale": rationale, **extra}


def _has_budget(observation: Mapping[str, Any]) -> bool:
    budget = observation.get("budget")
    if not isinstance(budget, Mapping):
        return False
    spent = budget.get("prompt_tokens_spent")
    total = budget.get("total_prompt_tokens")
    if not isinstance(spent, (int, float)) or not isinstance(total, (int, float)):
        return False
    return spent < total


def _first_object(text: str) -> dict[str, Any] | None:
    if not isinstance(text, str) or not text.strip():
        return None
    for candidate in _candidates(text):
        for attempt in (candidate, _drop_trailing_commas(candidate)):
            try:
                value = json.loads(attempt)
            except (json.JSONDecodeError, ValueError, RecursionError):
                continue
            if isinstance(value, dict):
                return value
    return None


Decider = Callable[[Mapping[str, Any], Mapping[str, Any], Sequence[Mapping[str, Any]]], dict[str, Any]]

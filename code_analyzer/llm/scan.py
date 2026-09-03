"""The LLM scan phase: plan, budget, dispatch, evidence.

This is Pipeline B of the design document.  It is deliberately shaped like
``tools/splint.py`` -- one deadline, one budget check before dispatch, a
heartbeat while a unit is in flight, a bounded thread pool, and per-unit
records carrying the same status vocabulary -- because the status algebra,
the ``unscheduled`` bucket and the ``planned == started + unscheduled``
invariant then apply to LLM units for free.

Two rules govern the money side.  A unit that cannot be afforded is recorded
``unscheduled``; its context is never truncated, because a truncated context
lowers finding quality invisibly while ``unscheduled`` shows up in coverage.
And nothing here reaches ``manifest["tools"]``: a model timeout must not be
able to change anybody's exit code.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, ContextManager

from ..control import (
    CANCELLED,
    LLM_JOBS_CEILING,
    RUN,
    SKIP_PRODUCER,
    SKIP_UNIT,
    AdjustableSemaphore,
)
from ..errors import UserError
from ..harness.cordis import cordis_document, tool_allowlist, write_cordis_config
from ..harness.runtime import (
    HarnessRuntime,
    RunOutcome,
    answer_text,
    endpoint_context_length,
    endpoint_url,
    harness_available,
    reasoning_text,
    redact_credential,
    sdk_version,
    unwrap_notification,
)
from ..harness.session import resync_meta_status, run_unit, unit_directory
from ..persist import json_bytes, write_json
from ..status import aggregate_units, counts
from ..tools import LLM_PRODUCERS
from . import replan
from .context import build_unit_prompt, render_blocks
from .doctor import endpoint_reachable
from .risk import tier_rank
from .skills import Skill, load_skill, skills_directory
from .units import build_plan, coverage_report, unit_source

CACHE_DIRECTORY_NAME = ".llm-cache"
CACHE_SCHEMA_VERSION = 1

# Prompt tokens are estimated from characters and completion tokens are
# reserved at the per-unit ceiling: the harness reports no usage counters, and
# an invented measurement would be worse than a declared estimate.
CHARS_PER_TOKEN = 4
# Measured against the real runtime with the skill inlined in the prompt: the
# harness's own system prompt, the skill catalogue reminder and the tool
# schemas add roughly this much on top of the rendered unit.
PROMPT_OVERHEAD_TOKENS = 1900
TOKEN_ACCOUNTING = (
    "budget: estimated (prompt characters / 4, completion reserved at max_completion_tokens); "
    "measured: the provider's own per-request counts, summed"
)
# How much of a unit's prompt the live view is shown.  The whole prompt is a
# skill, a source listing and its context; it is persisted per unit under
# llm/units/ and digested in the session's request.json, and every event also
# lands in events.jsonl -- so what travels through the event stream is a
# bounded preview of each block, not the prompt itself.
PROMPT_PREVIEW_BLOCK_LINES = 24
PROMPT_PREVIEW_CHARS = 4000

Task = tuple[int, str, dict[str, Any]]
OpenRuntime = Callable[[str, str, dict[str, Any]], ContextManager[Any]]


def run(
    source: Path,
    run_dir: Path,
    inventory: list[dict[str, Any]],
    config: dict[str, Any],
    progress: Callable[[str], None] | None = None,
    *,
    cancelled: Callable[[], bool] | None = None,
    unit_event: Callable[..., None] | None = None,
    output_event: Callable[..., None] | None = None,
    open_runtime: OpenRuntime | None = None,
    phase_event: Callable[..., None] | None = None,
    control: Any = None,
) -> dict[str, Any]:
    """Run every selected scanner over every planned unit.

    Returns the record published as ``manifest["llm"]``.  Never raises for a
    model, endpoint or runtime problem: the phase reports its own failure.
    """
    progress = progress or (lambda _message: None)
    unit_event = unit_event or (lambda *_args, **_kwargs: None)
    settings = config["llm"]
    scanners = [name for name in LLM_PRODUCERS if name in set(settings["scanners"])]
    if not scanners:
        return failed(settings, "no LLM scanner is selected")
    try:
        skills = {name: load_skill(name) for name in scanners}
    except UserError as exc:
        return failed(settings, str(exc))
    if open_runtime is None and not harness_available():
        return failed(
            settings,
            "the deepseek-harness runtime is not importable; install it or set [llm] enabled = false",
        )
    if open_runtime is None:
        # Refuse a dead endpoint in seconds.  The last real run spent an hour
        # learning this one unit at a time: every session ended in
        # TRANSPORT / Connection error and the budget went with them.
        reachable, why = endpoint_reachable(settings)
        if not reachable:
            progress(f"llm: endpoint unreachable: {why}")
            return failed(settings, f"endpoint unreachable: {why}")

    plan = build_plan(source, inventory, config=config, cancelled=cancelled)
    (run_dir / "llm").mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "llm" / "index.json", plan)
    units = list(plan["units"])
    prompts = _write_units(source, run_dir, plan, units, scanners)
    progress(f"llm: planned {len(units)} scan units for {len(scanners)} scanner(s)")
    if phase_event is not None:
        phase_event("planned", f"planned {len(units)} scan units for {len(scanners)} scanner(s)", {
            "units": len(units), "scanners": len(scanners), "tasks": len(units) * len(scanners),
            "jobs": int(settings["jobs"]), "model": str(settings.get("model") or ""),
            "endpoint": str(settings.get("endpoint") or ""),
            "tiers": dict((plan.get("risk") or {}).get("tiers") or {}) or None,
        })

    with skills_directory() as skill_dir:
        # The runtime's own session log.  Left to its default it would be
        # ./.sessions inside the scanned tree; it also has to be writable
        # under the process confinement, so it gets a private root of its own.
        session_root = run_dir / "llm" / "dsh-sessions"
        session_root.mkdir(parents=True, exist_ok=True)
        cordis_path = write_cordis_config(
            run_dir / "llm",
            cordis_document(
                settings, skill_dir=skill_dir, session_root=session_root,
                tools=tool_allowlist(skills[name] for name in scanners),
            ),
        )
        state = _Phase(
            source=source,
            run_dir=run_dir,
            settings=settings,
            grace=float(config["run"]["termination_grace_seconds"]),
            cordis_path=cordis_path,
            session_root=session_root,
            skills=skills,
            prompts=prompts,
            cache=_Cache(config, run_dir),
            progress=progress,
            unit_event=unit_event,
            output_event=output_event,
            cancelled=cancelled,
            open_runtime=open_runtime,
            phase_event=phase_event,
            control=control,
        )
        records, rounds = _rounds(state, plan, units, scanners, config, progress, phase_event)
        if control is not None:
            records, rounds = _operator_rounds(state, records, rounds, units, scanners, control, progress, phase_event)

    write_json(
        run_dir.joinpath(*replan.PLAN_PATH),
        replan.ledger(rounds, decider=str(settings.get("replan_decider") or replan.DETERMINISTIC),
                      limit=int(settings.get("max_replan_rounds", 0) or 0)),
    )
    results = [
        {"unit_id": record["id"], "producer": record["producer"], "status": record["status"]}
        for record in records
    ]
    every_unit = list(records)
    # One exit, one guarantee: nothing leaves this phase carrying the key,
    # whichever internal path formatted the provider's text into a reason.
    return redact_credential({
        "requested": True,
        "enabled": True,
        "status": aggregate_units(every_unit, applicable=bool(every_unit)),
        "reason": state.breaker_open,
        "model": str(settings["model"]),
        "endpoint": endpoint_url(settings),
        "sdk_version": _sdk_version(),
        "index": "llm/index.json",
        "cordis": "llm/cordis.json",
        "plan": "/".join(replan.PLAN_PATH),
        "rounds": len(rounds) + 1,
        "jobs": state.jobs,
        "planned_units": len(units),
        "scanners": {
            name: _scanner_record(name, skills[name], settings, [
                record for record in records if record["producer"] == name
            ])
            for name in scanners
        },
        "unit_counts": counts(every_unit),
        "coverage": coverage_report(plan, results, scanners=scanners),
        "budget": state.budget_state(),
        "cache": state.cache.state(),
        "risk": plan["risk"],
        "parse_confidence_low": plan["totals"]["parse_confidence_low"],
    }, settings)


def not_requested() -> dict[str, Any]:
    """The record published when [llm] enabled is false."""
    return _phase_record(requested=False, enabled=False, status="not_requested")


def running(settings: dict[str, Any]) -> dict[str, Any]:
    """The transient record published while the phase runs; never final.

    It is replaced by run()'s record (or failed()'s) before the manifest is
    finalised, and _finish_interrupted rewrites it on cancellation.
    """
    return redact_credential(_phase_record(
        status="running", model=str(settings.get("model", "")), endpoint=endpoint_url(settings),
    ), settings)


def failed(settings: dict[str, Any], reason: str) -> dict[str, Any]:
    """A phase that never dispatched anything, and why.

    A failure here is reported, never raised: it must not reach
    ``status.overall`` and change somebody else's exit code.
    """
    return redact_credential(_phase_record(
        status="failed", reason=reason,
        model=str(settings.get("model", "")), endpoint=endpoint_url(settings),
    ), settings)


def _phase_record(**overrides: Any) -> dict[str, Any]:
    return {
        "requested": True,
        "enabled": True,
        "status": "failed",
        "reason": None,
        "model": "",
        "endpoint": "",
        "sdk_version": None,
        "index": None,
        "cordis": None,
        "jobs": 0,
        "planned_units": 0,
        "scanners": {},
        "unit_counts": counts([]),
        "coverage": {},
        "budget": {},
        "cache": {},
        "risk": {},
        "parse_confidence_low": 0,
        **overrides,
    }


def _rounds(
    state: "_Phase",
    plan: dict[str, Any],
    units: list[dict[str, Any]],
    scanners: list[str],
    config: dict[str, Any],
    progress: Callable[[str], None],
    phase_event: Callable[..., None] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Round 0, then at most ``max_replan_rounds`` bounded follow-ups.

    Round 0 is the deterministic plan and is what every run has always done.
    Each later round is driven by counts the previous round measured -- never
    by a finding's text -- and may only take an action from the vocabulary in
    ``replan.ACTIONS``, aimed at units that already exist.  The ledger records
    every round, including the one that decided to stop.
    """
    limit = int(config["llm"].get("max_replan_rounds", 0) or 0)
    decider = str(config["llm"].get("replan_decider") or replan.DETERMINISTIC)
    records = state.execute_all(_tasks(units, scanners))
    rounds: list[dict[str, Any]] = []
    escalated: set[str] = set()
    active = list(scanners)
    by_id = {unit["unit_id"]: unit for unit in units}
    for index in range(1, limit + 1):
        budget_before = state.budget_state()
        observation = replan.observe(records, plan, budget_before)
        action = replan.decide(observation, plan, records, escalated=escalated)
        entry = {
            "round": index,
            "decided_by": decider if decider == replan.DETERMINISTIC else replan.DETERMINISTIC,
            "observation": observation,
            "action": action["action"],
            "targets": action["targets"],
            "rationale": action["rationale"],
            "budget_before": budget_before,
        }
        follow_up, active, escalated = _apply(action, by_id, active, escalated, state)
        if not follow_up:
            entry["budget_after"] = state.budget_state()
            entry["scheduled"] = 0
            rounds.append(entry)
            break
        progress(f"llm: replan round {index}: {action['action']} on {len(follow_up)} unit(s)")
        if phase_event is not None:
            phase_event("replan", f"replan round {index}: {action['action']} on {len(follow_up)} unit(s)", {
                "round": index, "action": action["action"], "targets": len(follow_up),
                "rationale": str(action.get("rationale") or "")[:300],
            })
        state.round_index = index
        records.extend(state.execute_all(follow_up))
        state.round_index = 0
        entry["budget_after"] = state.budget_state()
        entry["scheduled"] = len(follow_up)
        rounds.append(entry)
    return records, rounds


# How many times an operator may ask for the failed units again in one run.
OPERATOR_ROUNDS = 3


def _operator_rounds(
    state: "_Phase",
    records: list[dict[str, Any]],
    rounds: list[dict[str, Any]],
    units: list[dict[str, Any]],
    scanners: list[str],
    control: Any,
    progress: Callable[[str], None],
    phase_event: Callable[..., None] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The operator's retries, after the planner's rounds and independently of them.

    A retry re-arms the circuit breaker and re-runs the units that never got a
    model's answer -- unscheduled by the breaker, the budget or a skip, or
    failed in transport -- or exactly the units the operator named.  Each
    retry is a ledger round of its own, ``decided_by: "operator"``, with its
    evidence under ``r<N>/`` like a re-planning round.
    """
    for _attempt in range(OPERATOR_ROUNDS):
        asked = control.drain_retries("llm")
        if asked is False or state.is_cancelled():
            break
        latest: dict[tuple[str, str], dict[str, Any]] = {}
        for record in records:
            latest[(str(record.get("producer")), str(record.get("id")))] = record
        wanted = set(asked) if asked is not None else None
        targets = [
            key for key, record in latest.items()
            if (wanted is None and (record.get("status") == "unscheduled" or record.get("failure_class") in {"transport", "provider"}))
            or (wanted is not None and key[1] in wanted)
        ]
        index = len(rounds) + 1
        entry: dict[str, Any] = {
            "round": index, "decided_by": "operator", "action": "retry",
            "targets": [unit_id for _producer, unit_id in targets],
            "rationale": "operator asked for the units that never got an answer" if asked is None else "operator named the units",
            "budget_before": state.budget_state(), "breaker_was_open": state.breaker_open,
        }
        follow_up = [
            task for task in _tasks(units, scanners) if (task[1], task[2]["unit_id"]) in set(targets)
        ]
        if not follow_up:
            entry.update({"scheduled": 0, "budget_after": state.budget_state()})
            rounds.append(entry)
            progress(f"llm: retry round {index}: nothing to retry")
            continue
        state.breaker_open = None
        state._consecutive = 0
        progress(f"llm: retry round {index}: {len(follow_up)} unit(s), asked by the operator")
        if phase_event is not None:
            phase_event("retry", f"retry round {index}: {len(follow_up)} unit(s), asked by the operator", {
                "round": index, "targets": len(follow_up), "decided_by": "operator",
            })
        state.round_index = index
        records.extend(state.execute_all(follow_up))
        state.round_index = 0
        entry.update({"scheduled": len(follow_up), "budget_after": state.budget_state()})
        rounds.append(entry)
    return records, rounds


def _apply(
    action: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
    active: list[str],
    escalated: set[str],
    state: "_Phase",
) -> tuple[list[Task], list[str], set[str]]:
    """Turn one vocabulary action into the next round's tasks.

    ``mark_for_validation`` and ``extend_deadline`` schedule nothing here: the
    first is a note for ``assess`` and the second moves the phase deadline,
    which the scheduler already reads on every dispatch.
    """
    name, targets = action["action"], list(action.get("targets") or [])
    if name == "escalate_tier":
        tier = str(action.get("to_tier") or "high")
        escalated = escalated | set(targets)
        raised = [
            {**unit, "risk_tier": tier}
            for unit in by_id.values() if unit.get("path") in set(targets)
        ]
        return _tasks(raised, active), active, escalated
    if name == "rescan":
        pairs = [item.split("::", 1) for item in targets if "::" in item]
        tasks = [
            (index, producer, by_id[unit_id])
            for index, (producer, unit_id) in enumerate(sorted(pairs), 1)
            if producer in active and unit_id in by_id
        ]
        return tasks, active, escalated
    if name == "stop_producer":
        return [], [item for item in active if item not in set(targets)], escalated
    if name == "extend_deadline":
        state.deadline += float(action.get("seconds") or 0.0)
        return [], active, escalated
    return [], active, escalated


def _tasks(units: list[dict[str, Any]], scanners: list[str]) -> list[Task]:
    """Dispatch order: highest risk first, so a short budget buys the most."""
    ordered = sorted(
        units,
        key=lambda unit: (tier_rank(unit["risk_tier"]), unit["path"], unit["start_byte"], unit["unit_id"]),
    )
    pairs = [(producer, unit) for unit in ordered for producer in scanners]
    return [(index, producer, unit) for index, (producer, unit) in enumerate(pairs, 1)]


def _write_units(
    source: Path,
    run_dir: Path,
    plan: dict[str, Any],
    units: list[dict[str, Any]],
    scanners: list[str],
) -> dict[str, list[dict[str, Any]]]:
    """Persist the rendered payload of every unit and keep its prompt blocks."""
    directory = run_dir / "llm" / "units"
    directory.mkdir(parents=True, exist_ok=True)
    prompts: dict[str, list[dict[str, Any]]] = {}
    for unit in units:
        try:
            text = unit_source(source, unit)
        except OSError as exc:
            text = ""
            unit = {**unit, "read_error": str(exc)}
        payload = {**unit, "source": text}
        blocks = build_unit_prompt(payload, plan, tier=unit["risk_tier"])
        prompts[unit["unit_id"]] = blocks
        write_json(directory / f"{unit['unit_id']}.json", {
            "unit": unit,
            "source": text,
            "prompt": blocks,
            "scanners": list(scanners),
        })
    return prompts


class _Cache:
    """Cross-run unit cache, deliberately outside every run directory.

    A run directory is immutable evidence, so a later run must not write into
    it; a hit is materialised into the new run instead, which keeps every run
    directory self-contained.
    """

    def __init__(self, config: dict[str, Any], run_dir: Path) -> None:
        settings = config["llm"]
        self.enabled = bool(settings["cache"])
        configured = str(settings["cache_directory"] or "").strip()
        root = Path(configured) if configured else Path(config["run"]["output_root"]) / CACHE_DIRECTORY_NAME
        self.directory = root.expanduser()
        self.run_dir = run_dir
        self.hits = 0
        self.misses = 0
        self.stores = 0
        self._lock = threading.Lock()

    def key(
        self,
        producer: str,
        unit: dict[str, Any],
        settings: dict[str, Any],
        skill: Skill,
        prompt: str,
    ) -> str:
        # The rendered prompt, not the unit's bytes, is what the model saw
        # (design 8.5): the risk tier picks a context budget, so one unit
        # renders differently per tier, and a callee signature that moved in
        # another file changes the context without changing this unit.  Keying
        # on the unit alone replays a different scan and leaves request.json
        # digesting a prompt that never produced the response beside it.
        stable = "\0".join(str(value) for value in (
            CACHE_SCHEMA_VERSION,
            unit["unit_sha256"],
            hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            skill.skill_version,
            skill.content_sha256,
            settings["model"],
            endpoint_url(settings),
            settings["temperature"],
            settings["seed"],
            settings["max_completion_tokens"],
            settings["context_window"],
            producer,
        ))
        return hashlib.sha256(stable.encode("utf-8")).hexdigest()

    def path(self, key: str) -> Path:
        return self.directory / key[:2] / f"{key}.json"

    def load(self, key: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        try:
            payload = json.loads(self.path(key).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or payload.get("cache_schema_version") != CACHE_SCHEMA_VERSION:
            return None
        with self._lock:
            self.hits += 1
        return payload

    def miss(self) -> None:
        with self._lock:
            self.misses += 1

    def store(self, key: str, directory: Path, run_id: str) -> None:
        if not self.enabled:
            return
        try:
            response = json.loads((directory / "response.json").read_text(encoding="utf-8"))
            events = [
                json.loads(line)
                for line in (directory / "events.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except (OSError, UnicodeError, json.JSONDecodeError):
            return
        payload = {
            "cache_schema_version": CACHE_SCHEMA_VERSION,
            "key": key,
            "source_run": run_id,
            "final_response": response.get("final_response", ""),
            "finish_reason": response.get("finish_reason", ""),
            "notifications": response.get("notifications", []),
            "events": events,
        }
        target = self.path(key)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.parent / f".{target.name}.{os.getpid()}.{threading.get_ident()}.tmp"
            temporary.write_bytes(json_bytes(payload))
            temporary.replace(target)
        except OSError:
            return
        with self._lock:
            self.stores += 1

    def state(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "directory": str(self.directory) if self.enabled else None,
            "hits": self.hits,
            "misses": self.misses,
            "stores": self.stores,
        }


class _Replay:
    """A runtime stand-in that serves one cached response envelope."""

    def __init__(self, settings: dict[str, Any], payload: dict[str, Any]) -> None:
        self.settings = settings
        self._payload = payload

    def __enter__(self) -> _Replay:
        return self

    def __exit__(self, *_exception: object) -> None:
        return None

    def run(
        self,
        prompt: str | list[dict[str, Any]],
        *,
        session_id: str | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> RunOutcome:
        events = [event for event in self._payload.get("events", []) if isinstance(event, dict)]
        if on_event is not None:
            for event in events:
                on_event(event)
        return RunOutcome(
            session_id=str(self._payload.get("source_run", "")),
            final_response=str(self._payload.get("final_response", "")),
            finish_reason=str(self._payload.get("finish_reason", "")),
            events=events,
            notifications=list(self._payload.get("notifications", [])),
            duration_seconds=0.0,
        )


class _Phase:
    """One LLM phase: budgets, dispatch and the per-unit records it produces."""

    def __init__(
        self,
        *,
        source: Path,
        run_dir: Path,
        settings: dict[str, Any],
        grace: float,
        cordis_path: Path,
        session_root: Path,
        skills: dict[str, Skill],
        prompts: dict[str, list[dict[str, Any]]],
        cache: _Cache,
        progress: Callable[[str], None],
        unit_event: Callable[[str, str, str, str, float | None], None],
        output_event: Callable[..., None] | None,
        cancelled: Callable[[], bool] | None,
        open_runtime: OpenRuntime | None,
        phase_event: Callable[..., None] | None = None,
        control: Any = None,
    ) -> None:
        self.source = source
        self.phase_event = phase_event
        self.control = control
        self.run_dir = run_dir
        self.settings = settings
        self.grace = grace
        self.cordis_path = cordis_path
        self.session_root = session_root
        self.skills = skills
        self.prompts = prompts
        self.cache = cache
        self.progress = progress
        self.unit_event = unit_event
        self.output_event = output_event
        self.cancelled = cancelled
        self.open_runtime = open_runtime or self._runtime
        self.jobs = max(1, int(settings["jobs"]))
        # The gate the operator adjusts live; the pool is sized to the ceiling
        # so a "+" can add a worker, and the gate decides how many run.
        self.gate = control.semaphore("llm") if control is not None else AdjustableSemaphore(self.jobs)
        self.heartbeat_seconds = float(settings["heartbeat_seconds"])
        self.deadline = time.monotonic() + float(settings["total_timeout_seconds"])
        self.prompt_budget = int(settings["total_prompt_tokens"])
        self.effective_context = None if open_runtime is not None else endpoint_context_length(settings)
        self.completion_budget = int(settings["total_completion_tokens"])
        self.prompt_spent = 0
        self.completion_reserved = 0
        self.measured = {"prompt_tokens": 0, "completion_tokens": 0, "requests": 0}
        # Which re-planning round the phase is dispatching.  0 is the
        # deterministic first pass and keeps the historical evidence paths.
        self.round_index = 0
        self.total = 0
        self._cancel = threading.Event()
        self._ledger = threading.Lock()
        # Units that never ran, announced once per (producer, status, reason)
        # rather than once each: a budget that runs out with 250 000 tasks
        # left is one fact, not 250 000 rows.
        self._batches: dict[tuple[str, str, str], dict[str, int]] = {}
        self._batched = 0
        # The circuit breaker: this many consecutive transport failures in a
        # row mean the endpoint is gone, and the rest of the phase is
        # unscheduled at once rather than one dead session at a time.
        self._breaker_limit = int(settings.get("consecutive_failure_limit") or 0)
        self._consecutive = 0
        self.breaker_open: str | None = None
        # What the heartbeat's ETA is computed from: the last sessions'
        # durations and completion tokens, cache replays excluded.
        self._window: deque[tuple[float, int]] = deque(maxlen=20)
        self._settled = 0
        self._in_flight = 0
        self.refunded = {"prompt_tokens": 0, "completion_tokens": 0}

    # --- scheduling ---------------------------------------------------------

    def execute_all(self, tasks: list[Task]) -> list[dict[str, Any]]:
        self.total = len(tasks)
        completed: dict[int, dict[str, Any]] = {}
        jobs = min(LLM_JOBS_CEILING if self.control is not None else self.jobs, max(1, len(tasks)))
        if jobs == 1 or len(tasks) <= 1:
            for task in tasks:
                if self.is_cancelled():
                    self._cancel.set()
                record = self.execute(task)
                completed[task[0]] = record
                if record["status"] == "interrupted":
                    self._cancel.set()
        elif tasks:
            executor = ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="llm")
            futures = {executor.submit(self.execute, task): task[0] for task in tasks}
            try:
                for future in as_completed(futures):
                    if self.is_cancelled():
                        self._cancel.set()
                    record = future.result()
                    completed[futures[future]] = record
                    if record["status"] == "interrupted":
                        self._cancel.set()
            except KeyboardInterrupt:
                self._cancel.set()
                for future in futures:
                    if not future.done():
                        future.cancel()
                for future, index in futures.items():
                    if future.done() and not future.cancelled():
                        try:
                            completed[index] = future.result()
                        except Exception:
                            continue
            finally:
                executor.shutdown(wait=True, cancel_futures=True)
        # A task with no record is one the pool never ran: interrupted, never lost.
        records = [
            completed.get(task[0]) or self._unstarted(task, "interrupted", "run interrupted")
            for task in tasks
        ]
        self.flush_batches()
        return records

    def execute(self, task: Task) -> dict[str, Any]:
        index, producer, unit = task
        unit_id = unit["unit_id"]
        if self.is_cancelled():
            return self._report(task, self._unstarted(task, "interrupted", "run interrupted"))
        action = self.control.checkpoint("llm", producer, unit_id) if self.control is not None else RUN
        if action == CANCELLED:
            return self._report(task, self._unstarted(task, "interrupted", "run interrupted"))
        if action in {SKIP_PRODUCER, SKIP_UNIT}:
            return self._report(task, self._unstarted(task, "unscheduled", "skipped by operator"))
        # Everything from here runs under the concurrency gate: the pool is
        # sized to the ceiling so the operator can add workers, and the gate
        # is what makes "jobs" true -- including for the budget, the deadline
        # and the breaker, which must be judged one unit at a time.
        if not self.gate.acquire(self.is_cancelled):
            return self._report(task, self._unstarted(task, "interrupted", "run interrupted"))
        try:
            return self._execute_gated(task)
        finally:
            self.gate.release()

    def _execute_gated(self, task: Task) -> dict[str, Any]:
        index, producer, unit = task
        unit_id = unit["unit_id"]
        if self.is_cancelled():
            return self._report(task, self._unstarted(task, "interrupted", "run interrupted"))
        if self.breaker_open:
            return self._report(task, self._unstarted(task, "unscheduled", self.breaker_open))
        blocks = [self._directive(producer, unit), *self.prompts[unit_id]]
        prompt = render_blocks(blocks)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return self._report(task, self._unstarted(task, "unscheduled", "total budget exhausted"))
        affordable, reason, estimate = self._reserve(prompt)
        if not affordable:
            return self._report(task, self._unstarted(task, "unscheduled", reason))

        settings = {**self.settings, "request_timeout_seconds": min(
            float(self.settings["request_timeout_seconds"]), max(0.001, remaining)
        ), "shutdown_timeout_seconds": self.grace}
        skill = self.skills[producer]
        key = self.cache.key(producer, unit, settings, skill, prompt)
        cached = self.cache.load(key)
        if cached is None:
            self.cache.miss()
        self.unit_event(
            producer, unit_id, "started", f"{'cached' if cached else 'scanning'} ({unit['risk_tier']})",
            (index - 1) / max(1, self.total),
            data={**self._facts(index, unit), "cached": cached is not None},
        )
        with self._ledger:
            self._in_flight += 1
        stop = threading.Event()
        beat = threading.Thread(
            target=self._heartbeat, args=(stop, index, producer, unit), daemon=True,
            name=f"llm-heartbeat-{index}",
        )
        beat.start()
        self._step(producer, unit_id, "replaying" if cached is not None else "prompting")
        self._prompt_event(producer, unit_id, blocks, prompt)
        try:
            runtime: ContextManager[Any] = (
                _Replay(settings, cached) if cached is not None
                else self.open_runtime(producer, unit_id, settings)
            )
            with runtime as active:
                record = self._session(active, task, prompt, settings, {
                    "hit": cached is not None,
                    "key": key,
                    "source_run": (cached or {}).get("source_run"),
                })
        except Exception as exc:
            record = self._unstarted(task, "failed", f"scanner failure: {type(exc).__name__}: {exc}")
        finally:
            stop.set()
            beat.join(timeout=1.0)
            with self._ledger:
                self._in_flight -= 1
        self._step(producer, unit_id, "validating")
        record, provider_stopped = _provider_stop(record)
        self._release(record, estimate, cached is not None)
        self._observe(record, cached is not None)
        if provider_stopped:
            resync_meta_status(
                unit_directory(self.run_dir, producer, unit_id, self.round_index),
                str(record.get("status", "")),
                str(record.get("reason", "")),
            )
        # A provider stop yields a truncated unit.  Caching it would replay one
        # transient abort into every later run of the same prompt -- the very
        # "operator believes they ran a full scan" hazard the prompt-keyed cache
        # exists to prevent.
        cacheable = record.get("status") in {"completed", "partial"} and not provider_stopped
        if cached is None and cacheable:
            if getattr(self.cache, "enabled", True):
                self._step(producer, unit_id, "caching")
            self.cache.store(key, unit_directory(self.run_dir, producer, unit_id, self.round_index), self.run_dir.name)
        # A replayed unit costs the provider nothing, so its measured usage
        # belongs to the run that paid for it, not to this one.
        if cached is None:
            self.account(record)
        return self._report(task, self._decorate(record, task, skill))

    # --- budget -------------------------------------------------------------

    def _reserve(self, prompt: str) -> tuple[bool, str, int]:
        estimate = max(1, math.ceil(len(prompt) / CHARS_PER_TOKEN))
        reservation = int(self.settings["max_completion_tokens"])
        # A unit the endpoint would truncate is refused, not trimmed: a scanner
        # reviewing a chopped unit reports on code it never saw.  The estimate
        # is widened because the harness adds its own system prompt, the
        # skill text and the tool catalogue on top of the unit.
        window = self.effective_context
        if window is not None and estimate + PROMPT_OVERHEAD_TOKENS + reservation > window:
            return False, (
                f"unit would exceed the endpoint's {window}-token context window "
                f"(Ollama: set OLLAMA_CONTEXT_LENGTH on the host or pin num_ctx in a Modelfile)"
            ), estimate
        with self._ledger:
            if self.prompt_spent + estimate > self.prompt_budget:
                return False, "prompt token budget exhausted", estimate
            if self.completion_reserved + reservation > self.completion_budget:
                return False, "completion token budget exhausted", estimate
            self.prompt_spent += estimate
            self.completion_reserved += reservation
        return True, "", estimate

    def _release(self, record: dict[str, Any], estimate: int, cached: bool) -> None:
        """Give back what a finished session did not use.

        The reservation is made before dispatch and used to stay spent for
        ever: 394 dead sessions of the last real run held 788 000 completion
        tokens they never generated, and 255 648 tasks went unscheduled for a
        budget nobody had consumed.  Refunds follow the provider's own count
        when it reported one; a transport failure never reached a model, so
        its prompt estimate comes back too.
        """
        usage = record.get("usage_measured") if isinstance(record.get("usage_measured"), dict) else {}
        requests = int(usage.get("requests") or 0)
        completion = int(usage.get("completion_tokens") or 0)
        reservation = int(self.settings["max_completion_tokens"])
        with self._ledger:
            if requests > 0 and not cached:
                unused = max(0, reservation - min(reservation, completion))
                self.completion_reserved -= unused
                self.refunded["completion_tokens"] += unused
            if record.get("failure_class") == "transport" and not cached:
                back = min(estimate, self.prompt_spent)
                self.prompt_spent -= back
                self.refunded["prompt_tokens"] += back

    def _observe(self, record: dict[str, Any], cached: bool) -> None:
        """Feed the ETA window and the circuit breaker with one terminal record."""
        tripped: dict[str, Any] | None = None
        usage = record.get("usage_measured") if isinstance(record.get("usage_measured"), dict) else {}
        with self._ledger:
            self._settled += 1
            duration = record.get("duration_seconds")
            if isinstance(duration, (int, float)) and duration > 0 and not cached:
                self._window.append((float(duration), int(usage.get("completion_tokens") or 0)))
            if record.get("failure_class") == "transport" and not cached:
                self._consecutive += 1
                if self._breaker_limit and self._consecutive >= self._breaker_limit and not self.breaker_open:
                    failure = record.get("provider_failure") if isinstance(record.get("provider_failure"), dict) else {}
                    tripped = {
                        "consecutive": self._consecutive, "code": str(failure.get("code") or "TRANSPORT"),
                        "message": str(failure.get("message") or ""),
                    }
                    self.breaker_open = (
                        f"provider unreachable: {tripped['code']} {tripped['message']} "
                        f"(circuit breaker after {tripped['consecutive']} consecutive failures)"
                    ).strip()
            elif record.get("status") in {"completed", "partial"}:
                self._consecutive = 0
        if tripped is not None and self.phase_event is not None:
            self.phase_event(
                "breaker_open",
                f"circuit breaker opened after {tripped['consecutive']} consecutive {tripped['code']} failures",
                tripped,
            )

    def rate(self) -> dict[str, Any]:
        """Throughput and ETA from the recent window, with the basis stated."""
        with self._ledger:
            window = list(self._window)
            settled, in_flight = self._settled, self._in_flight
        remaining = max(0, self.total - settled)
        if not window:
            return {"tok_s": None, "eta_seconds": None, "basis": None, "remaining": remaining, "in_flight": in_flight}
        seconds = sum(duration for duration, _tokens in window)
        tokens = sum(count for _duration, count in window)
        mean = seconds / len(window)
        return {
            "tok_s": round(tokens / seconds, 1) if tokens and seconds else None,
            "eta_seconds": round(remaining * mean / max(1, self.jobs), 1),
            "basis": f"mean of the last {len(window)} session(s) {mean:.1f}s, {self.jobs} at a time, {remaining} remaining",
            "remaining": remaining, "in_flight": in_flight,
        }

    def budget_state(self) -> dict[str, Any]:
        return {
            "accounting": TOKEN_ACCOUNTING,
            "total_timeout_seconds": float(self.settings["total_timeout_seconds"]),
            "total_prompt_tokens": self.prompt_budget,
            "prompt_tokens_spent": self.prompt_spent,
            "endpoint_context_length": self.effective_context,
            "total_completion_tokens": self.completion_budget,
            "completion_tokens_reserved": self.completion_reserved,
            # What the provider says it actually read and wrote.  The estimate
            # above still drives scheduling -- a budget has to be reserved
            # before it is spent -- but the run now records both, so the
            # estimate can be checked against reality instead of trusted.
            "measured": self.measured,
            # Reservations handed back by finished sessions (see _release).
            "refunded": dict(self.refunded),
        }

    def account(self, record: dict[str, Any]) -> None:
        """Add one session's measured usage to the phase ledger."""
        usage = record.get("usage_measured")
        if not isinstance(usage, dict):
            return
        with self._ledger:
            for key in ("prompt_tokens", "completion_tokens", "requests"):
                value = usage.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                    self.measured[key] += value

    # --- plumbing -----------------------------------------------------------

    def is_cancelled(self) -> bool:
        return self._cancel.is_set() or (self.cancelled is not None and self.cancelled())

    def _session(
        self,
        active: Any,
        task: Task,
        prompt: str,
        settings: dict[str, Any],
        cache: dict[str, Any],
    ) -> dict[str, Any]:
        """One session over one task; the validator swaps in its own subject."""
        _index, producer, unit = task
        return run_unit(
            active,
            run_dir=self.run_dir,
            producer=producer,
            unit_id=unit["unit_id"],
            prompt=prompt,
            unit_sha256=str(unit["unit_sha256"]),
            skill_version=self.skills[producer].skill_version,
            input_files=[unit["path"]],
            settings=settings,
            cache=cache,
            cancelled=self.is_cancelled,
            on_event=self._forward(producer, unit["unit_id"]),
            round_index=self.round_index,
        )

    def _runtime(self, producer: str, unit_id: str, settings: dict[str, Any]) -> ContextManager[Any]:
        # One runtime per unit: the scanned repository is untrusted input, so
        # no agent state is carried from one unit (or one expert) to the next.
        return HarnessRuntime(
            settings,
            cwd=self.source,
            session_root=self.session_root,
            cordis_path=self.cordis_path,
            cancelled=self.is_cancelled,
        )

    def _directive(self, producer: str, unit: dict[str, Any]) -> dict[str, Any]:
        # The skill text travels inside the prompt rather than being fetched by
        # the model: a scanner that has to call the skill tool first spends a
        # step on it, sometimes calls it three times over, and a long tool
        # chain is exactly what Ollama's chat template answers with a 500
        # (seen live).  One step, one answer.
        skill = self.skills[producer]
        return {"type": "text", "text": "\n".join([
            "# Scanner",
            "",
            f"skill: {skill.name} (version {skill.skill_version})",
            f"scope: {skill.description}",
            "",
            "The full skill follows. It is already loaded: do not call the skill tool.",
            "",
            "<skill_content>",
            skill.body.strip(),
            "</skill_content>",
            "",
            f"Apply the {skill.name} skill to the scan unit below and report only defects",
            "inside that skill's scope. Return only the JSON object the skill defines.",
            # With reasoning switched off the model reasons in its answer
            # instead, and a budget spent on prose leaves no room for the
            # object; the first character of the reply has to be the brace.
            "Your reply must begin with `{` -- no analysis, heading or fence before it.",
            "Put any rationale inside each finding's description field, not outside the object.",
        ])}

    def _forward(self, producer: str, unit_id: str) -> Callable[[dict[str, Any]], None]:
        """Turn the SDK's notification stream into steps (always) and output rows (live only)."""
        last: dict[str, str] = {"step": ""}

        def step(name: str, detail: str = "") -> None:
            label = f"{name} {detail}".strip()
            if label != last["step"]:
                last["step"] = label
                self._step(producer, unit_id, name, detail)

        def forward(event: dict[str, Any]) -> None:
            kind, data = unwrap_notification(event)
            # The stream names the kind of thing the model did, so a live view
            # can lay the exchange out as a conversation instead of re-parsing
            # a prefixed line: `answer` is the reply itself, `tool` is a call
            # the agent made, `note` is anything said about the request.
            stream = text = None
            if kind == "turn/start":
                step("waiting")
            elif kind == "assistant/chunk":
                # "text-delta" is what the pinned runtime actually sends, one
                # per token group (verified against a live Ollama session on
                # 2026-09-03: 194 of them for one 776-character answer).
                # "text" is accepted beside it because a chunk carrying a whole
                # block in one piece is the same fact.
                if answer_text(data):
                    step("streaming")
                    stream, text = "answer", answer_text(data)[:2000]
                # What the model thought before it answered.  The runtime sends
                # it as its own delta type (`{type: 'reasoning-delta', index,
                # text}`), and it used to be dropped on the floor here -- so a
                # scan with [llm] reasoning set to anything but "off" spent the
                # completion budget on thinking nobody could see.  It stays a
                # separate stream: concatenated onto the answer it would make
                # every unit unparseable.
                elif reasoning_text(data):
                    step("thinking")
                    stream, text = "thinking", reasoning_text(data)[:2000]
            elif kind.startswith("tool/call"):
                name = str(data.get("name") or data.get("tool") or "")
                step("reading", name)
                stream, text = "tool", name.strip()
            elif kind == "llm/retry":
                failure = data.get("failure") if isinstance(data.get("failure"), dict) else {}
                step("retry", f"{data.get('retry')}/{data.get('maxRetries')} {failure.get('code') or ''}".strip())
                stream = "note"
                text = f"retry {data.get('retry')}/{data.get('maxRetries')}: {failure.get('code')} {failure.get('message')}"
            elif kind == "turn/end":
                step("parsing")
            if text is not None and self.output_event is not None:
                self.output_event(producer, unit_id, stream, text, data={"event": kind})

        return forward

    def _prompt_event(self, producer: str, unit_id: str, blocks: list[dict[str, Any]], prompt: str) -> None:
        """Announce the prompt this unit was sent, block by block and bounded.

        A preview, not the prompt: see PROMPT_PREVIEW_CHARS.  Each block keeps
        its own head so the preview has the shape of the real thing -- skill,
        unit header, context, source -- rather than being the skill alone,
        which is what a flat head of a prompt this size always is.
        """
        if self.output_event is None:
            return
        lines: list[str] = []
        omitted = 0
        budget = PROMPT_PREVIEW_CHARS
        for block in blocks:
            body = str(block.get("text", "")).splitlines()
            head = body[:PROMPT_PREVIEW_BLOCK_LINES]
            kept = []
            for line in head:
                if budget - len(line) < 0:
                    break
                budget -= len(line) + 1
                kept.append(line)
            lines.extend(kept)
            rest = len(body) - len(kept)
            if rest > 0:
                omitted += rest
                lines.append(f"…（本段另有 {rest} 行）")
        self.output_event(producer, unit_id, "prompt", "\n".join(lines), data={
            "chars": len(prompt),
            "lines": prompt.count("\n") + 1,
            "omitted_lines": omitted,
            "estimated_tokens": max(1, math.ceil(len(prompt) / CHARS_PER_TOKEN)),
            "blocks": len(blocks),
        })

    def _facts(self, index: int, unit: dict[str, Any]) -> dict[str, Any]:
        return {
            "index": index, "total": self.total, "path": unit["path"], "tier": unit["risk_tier"],
            "attempt": self.round_index + 1,
        }

    def _heartbeat(self, stop: threading.Event, index: int, producer: str, unit: dict[str, Any]) -> None:
        started = time.monotonic()
        while not stop.wait(self.heartbeat_seconds):
            elapsed = time.monotonic() - started
            remaining = max(0.0, self.deadline - time.monotonic())
            message = (
                f"heartbeat; elapsed {elapsed:.1f}s; total budget remaining {remaining:.1f}s; "
                f"prompt tokens spent {self.prompt_spent}"
            )
            self.unit_event(producer, unit["unit_id"], "heartbeat", message, None, data={
                **self._facts(index, unit), "elapsed": round(elapsed, 1),
                "remaining_budget_seconds": round(remaining, 1), "prompt_tokens_estimated": self.prompt_spent,
                "measured": dict(self.measured), "jobs": self.jobs, **self.rate(),
            })

    def _decorate(self, record: dict[str, Any], task: Task, skill: Skill) -> dict[str, Any]:
        _index, producer, unit = task
        record.setdefault("producer", producer)
        record.update({
            "skill_version": skill.skill_version,
            "skill_sha256": skill.content_sha256,
            "model": str(self.settings["model"]),
            "risk_tier": unit["risk_tier"],
            "symbol": unit["name"],
            "unit_sha256": unit["unit_sha256"],
        })
        return record

    def _unstarted(self, task: Task, state: str, reason: str) -> dict[str, Any]:
        _index, producer, unit = task
        return {
            "id": unit["unit_id"],
            "producer": producer,
            "status": state,
            "input_files": [unit["path"]],
            "valid_report": False,
            "reason": reason,
            "evidence_context": "source-only",
            "finding_count": 0,
            "malformed_count": 0,
            "artifacts": [],
            "skill_version": self.skills[producer].skill_version,
            "model": str(self.settings["model"]),
            "risk_tier": unit["risk_tier"],
            "symbol": unit["name"],
            "unit_sha256": unit["unit_sha256"],
        }

    def _report(self, task: Task, record: dict[str, Any]) -> dict[str, Any]:
        index, producer, unit = task
        status = record["status"]
        detail = record.get("reason") or f"{record.get('finding_count', 0)} finding(s)"
        if "artifacts" in record and not record["artifacts"] and status in {"unscheduled", "interrupted"}:
            self._tally(producer, status, str(record.get("reason") or ""), index)
            return record
        cache = record.get("cache") if isinstance(record.get("cache"), dict) else {}
        failure = record.get("provider_failure") if isinstance(record.get("provider_failure"), dict) else {}
        self.unit_event(producer, record["id"], status, f"{status}; {detail}", index / max(1, self.total), data={
            **self._facts(index, unit), "reason": record.get("reason"),
            "finish_reason": record.get("finish_reason") or None,
            "failure_class": record.get("failure_class"), "provider_code": failure.get("code"),
            "duration_seconds": record.get("duration_seconds"),
            "finding_count": record.get("finding_count", 0), "malformed_count": record.get("malformed_count", 0),
            "valid_report": record.get("valid_report"),
            "cache_hit": bool(cache.get("hit")), "source_run": cache.get("source_run"),
            # The provider's own counts for this session, so a live view can
            # state a measured throughput instead of an estimated one.
            "usage": record.get("usage_measured"),
        })
        return record

    def _step(self, producer: str, unit_id: str, step: str, detail: str = "") -> None:
        """Where one unit is: prompting, waiting, thinking, retry k/N, streaming, reading, parsing, validating, caching."""
        label = f"{step} {detail}".strip()
        self.unit_event(producer, unit_id, "step", label, None, data={"step": step, "detail": detail or None})

    def _tally(self, producer: str, status: str, reason: str, index: int) -> None:
        with self._ledger:
            batch = self._batches.setdefault(
                (producer, status, reason), {"count": 0, "first_index": index, "last_index": index}
            )
            batch["count"] += 1
            batch["first_index"] = min(batch["first_index"], index)
            batch["last_index"] = max(batch["last_index"], index)
            self._batched += 1
            due = self._batched % 500 == 0
        if due:
            # Liveness: a long avalanche still shows movement every 500 units.
            self.flush_batches()

    def flush_batches(self) -> None:
        with self._ledger:
            batches, self._batches = self._batches, {}
        for (producer, status, reason), batch in batches.items():
            self.unit_event(
                producer, None, status, f"{batch['count']} unit(s) {status}: {reason}",
                batch["last_index"] / max(1, self.total),
                data={**batch, "reason": reason, "total": self.total}, phase="units",
            )


def _provider_stop(record: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Demote a provider-reported abort from a cancellation to a unit outcome.

    ``harness/runtime.py`` maps the SDK stop reasons ``aborted``/``cancelled``
    onto ``interrupted``, but design 5.2 lists those among the ordinary
    ``SubagentResult.stopReason`` values: the provider stopped generating, the
    operator did not stop the run.  A user cancellation arrives with no
    provider outcome at all -- the token is read before dispatch, or the SDK
    notifier raises out of the run -- so a finish reason is exactly what
    separates the two.  Left alone, one such unit cancels the phase and takes
    the whole review, every static finding included, with it.

    Returns the record and whether it was demoted, because a demoted unit is
    truncated and must stay out of the cross-run cache.
    """
    if record.get("status") != "interrupted" or not record.get("finish_reason"):
        return record, False
    detail = f"provider stopped the scan (finish_reason {record['finish_reason']})"
    existing = record.get("reason")
    record["status"] = "partial" if record.get("valid_report") else "failed"
    record["reason"] = f"{detail}; {existing}" if existing else detail
    return record, True


def _scanner_record(
    name: str, skill: Skill, settings: dict[str, Any], units: list[dict[str, Any]]
) -> dict[str, Any]:
    """One scanner's execution record, shaped like a native tool's."""
    analyzed = sum(bool(unit.get("valid_report")) for unit in units)
    attempted = sum(unit["status"] != "unscheduled" for unit in units)
    total = len(units)
    return {
        "producer": name,
        "requested": True,
        "status": aggregate_units(units, applicable=bool(units)),
        "reason": None,
        "version": str(settings["model"]),
        "executable": None,
        "skill_version": skill.skill_version,
        "skill_sha256": skill.content_sha256,
        "units": units,
        "valid_reports": analyzed,
        "coverage": {
            "metric": "llm_unit_coverage", "covered": analyzed, "total": total,
            "attempted": attempted, "analyzed": analyzed, "excluded": 0,
            "effective_total": total, "ratio": analyzed / total if total else None,
        },
        "excluded_files": [],
        "unit_counts": counts(units),
    }


def _sdk_version() -> str | None:
    try:
        return sdk_version()
    except UserError:
        return None

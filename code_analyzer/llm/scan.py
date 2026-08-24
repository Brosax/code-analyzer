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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable, ContextManager

from ..errors import UserError
from ..harness.cordis import cordis_document, tool_allowlist, write_cordis_config
from ..harness.runtime import (
    HarnessRuntime,
    RunOutcome,
    endpoint_context_length,
    endpoint_url,
    harness_available,
    redact_credential,
    sdk_version,
)
from ..harness.session import resync_meta_status, run_unit, unit_directory
from ..persist import json_bytes, write_json
from ..status import aggregate_units, counts
from ..tools import LLM_PRODUCERS
from . import replan
from .context import build_unit_prompt, render_blocks
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
    unit_event: Callable[[str, str, str, str, float | None], None] | None = None,
    output_event: Callable[[str, str, str, str], None] | None = None,
    open_runtime: OpenRuntime | None = None,
) -> dict[str, Any]:
    """Run every selected scanner over every planned unit.

    Returns the record published as ``manifest["llm"]``.  Never raises for a
    model, endpoint or runtime problem: the phase reports its own failure.
    """
    progress = progress or (lambda _message: None)
    unit_event = unit_event or (lambda _producer, _unit, _status, _message, _progress: None)
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

    plan = build_plan(source, inventory, config=config, cancelled=cancelled)
    (run_dir / "llm").mkdir(parents=True, exist_ok=True)
    write_json(run_dir / "llm" / "index.json", plan)
    units = list(plan["units"])
    prompts = _write_units(source, run_dir, plan, units, scanners)
    progress(f"llm: planned {len(units)} scan units for {len(scanners)} scanner(s)")

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
        )
        records, rounds = _rounds(state, plan, units, scanners, config, progress)

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
        "reason": None,
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
        state.round_index = index
        records.extend(state.execute_all(follow_up))
        state.round_index = 0
        entry["budget_after"] = state.budget_state()
        entry["scheduled"] = len(follow_up)
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
        output_event: Callable[[str, str, str, str], None] | None,
        cancelled: Callable[[], bool] | None,
        open_runtime: OpenRuntime | None,
    ) -> None:
        self.source = source
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

    # --- scheduling ---------------------------------------------------------

    def execute_all(self, tasks: list[Task]) -> list[dict[str, Any]]:
        self.total = len(tasks)
        completed: dict[int, dict[str, Any]] = {}
        jobs = min(self.jobs, max(1, len(tasks)))
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
        return [
            completed.get(task[0]) or self._unstarted(task, "interrupted", "run interrupted")
            for task in tasks
        ]

    def execute(self, task: Task) -> dict[str, Any]:
        index, producer, unit = task
        unit_id = unit["unit_id"]
        if self.is_cancelled():
            return self._report(task, self._unstarted(task, "interrupted", "run interrupted"))
        blocks = [self._directive(producer, unit), *self.prompts[unit_id]]
        prompt = render_blocks(blocks)
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return self._report(task, self._unstarted(task, "unscheduled", "total budget exhausted"))
        affordable, reason = self._reserve(prompt)
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
        self.progress(f"llm {index}/{self.total} {producer} {unit['path']}: {'cached' if cached else 'scanning'}")
        self.unit_event(
            producer, unit_id, "started", f"scanning {unit['path']} ({unit['risk_tier']})",
            (index - 1) / max(1, self.total),
        )
        stop = threading.Event()
        beat = threading.Thread(
            target=self._heartbeat, args=(stop, index, producer, unit), daemon=True,
            name=f"llm-heartbeat-{index}",
        )
        beat.start()
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
        record, provider_stopped = _provider_stop(record)
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
            self.cache.store(key, unit_directory(self.run_dir, producer, unit_id, self.round_index), self.run_dir.name)
        # A replayed unit costs the provider nothing, so its measured usage
        # belongs to the run that paid for it, not to this one.
        if cached is None:
            self.account(record)
        return self._report(task, self._decorate(record, task, skill))

    # --- budget -------------------------------------------------------------

    def _reserve(self, prompt: str) -> tuple[bool, str]:
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
            )
        with self._ledger:
            if self.prompt_spent + estimate > self.prompt_budget:
                return False, "prompt token budget exhausted"
            if self.completion_reserved + reservation > self.completion_budget:
                return False, "completion token budget exhausted"
            self.prompt_spent += estimate
            self.completion_reserved += reservation
        return True, ""

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

    def _forward(self, producer: str, unit_id: str) -> Callable[[dict[str, Any]], None] | None:
        if self.output_event is None:
            return None

        def forward(event: dict[str, Any]) -> None:
            kind = str(event.get("type", "event"))
            text = str(event.get("text") or event.get("message") or event.get("name") or "")
            self.output_event(producer, unit_id, "agent", f"{kind}: {text}".strip())

        return forward

    def _heartbeat(self, stop: threading.Event, index: int, producer: str, unit: dict[str, Any]) -> None:
        started = time.monotonic()
        while not stop.wait(self.heartbeat_seconds):
            elapsed = time.monotonic() - started
            remaining = max(0.0, self.deadline - time.monotonic())
            message = (
                f"heartbeat; elapsed {elapsed:.1f}s; total budget remaining {remaining:.1f}s; "
                f"prompt tokens spent {self.prompt_spent}"
            )
            self.progress(f"llm {index}/{self.total} {producer} {unit['path']}: {message}")
            self.unit_event(producer, unit["unit_id"], "heartbeat", message, None)

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
        self.progress(f"llm {index}/{self.total} {producer} {unit['path']}: {status}; {detail}")
        self.unit_event(producer, record["id"], status, f"{status}; {detail}", index / max(1, self.total))
        return record


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

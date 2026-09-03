"""The operator's hand on a running analysis.

Cancellation used to be the only thing an operator could do to a run, and it
was all-or-nothing.  ``RunControl`` adds the rest -- pause and resume a lane,
skip a producer, change the LLM concurrency, answer a decision the runner is
waiting on -- and does it cooperatively: producers ask ``checkpoint()`` at
unit boundaries, so a paused lane finishes the unit in flight and never has a
process killed under it.  Cancel keeps its old meaning and its old object; a
``RunControl`` wraps a ``CancellationToken`` rather than replacing it.

Every mutation is journalled through ``listener`` as a ``control`` (or
``decision``) event, so what the operator did is in ``events.jsonl`` and
``runner.log`` next to what the analyzers did.  Pure stdlib; the TUI, the
``serve`` page and the CLI each hold one and call the same methods.
"""
from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .analysis import CancellationToken

LANES: tuple[str, ...] = ("static", "llm")
# What a checkpoint may answer.
RUN, SKIP_UNIT, SKIP_PRODUCER, CANCELLED = "run", "skip_unit", "skip_producer", "cancelled"
# The LLM pool is pre-sized to this so a live "+" can add workers; the
# semaphore enforces the number actually in use.
LLM_JOBS_CEILING = 8
ANSWERS: tuple[str, ...] = ("apply", "reject", "defer")

Listener = Callable[[str, str, str, dict[str, Any]], None]


@dataclass(frozen=True)
class DecisionRequest:
    """Something the runner will not do without the operator: a patch, a retry."""

    id: str
    kind: str
    summary: str
    items: tuple[dict[str, Any], ...] = ()
    round: int = 1
    probe: dict[str, Any] | None = None
    evidence_path: str | None = None
    # Which items are ticked when the dialog opens.
    preselected: tuple[int, ...] = ()


@dataclass(frozen=True)
class Decision:
    answer: str
    selected: tuple[int, ...] = ()
    decided_by: str = "operator"
    note: str = ""

    def __post_init__(self) -> None:
        if self.answer not in ANSWERS:
            raise ValueError(f"unknown decision {self.answer!r}")


class AdjustableSemaphore:
    """A counting gate whose limit may change while workers hold it.

    Lowering the limit below the number in flight only blocks new acquires;
    nothing already running is disturbed.
    """

    def __init__(self, limit: int) -> None:
        self._limit = max(1, int(limit))
        self._active = 0
        self._condition = threading.Condition()

    @property
    def limit(self) -> int:
        with self._condition:
            return self._limit

    @property
    def active(self) -> int:
        with self._condition:
            return self._active

    def set_limit(self, limit: int) -> int:
        with self._condition:
            self._limit = max(1, int(limit))
            self._condition.notify_all()
            return self._limit

    def acquire(self, cancelled: Callable[[], bool] | None = None, poll: float = 0.25) -> bool:
        """Wait for a slot; False when ``cancelled`` said to stop waiting."""
        with self._condition:
            while self._active >= self._limit:
                if cancelled is not None and cancelled():
                    return False
                self._condition.wait(poll)
            self._active += 1
            return True

    def release(self) -> None:
        with self._condition:
            self._active = max(0, self._active - 1)
            self._condition.notify_all()

    def __enter__(self) -> AdjustableSemaphore:
        self.acquire()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


@dataclass
class _Pending:
    request: DecisionRequest
    decision: Decision | None = None
    asked_at: float = field(default_factory=time.monotonic)


class RunControl:
    """Pause, skip, jobs, retries and decisions for one run; cancel included."""

    def __init__(
        self,
        cancellation: CancellationToken | None = None,
        *,
        listener: Listener | None = None,
        decider: Callable[[DecisionRequest], Decision] | None = None,
        llm_jobs: int = 1,
    ) -> None:
        self.cancellation = cancellation or CancellationToken()
        self._listener = listener
        self._decider = decider
        self._condition = threading.Condition()
        self._paused: dict[str, bool] = {lane: False for lane in LANES}
        self._skipped: set[str] = set()
        self._skipped_units: set[tuple[str, str]] = set()
        self._retries: dict[str, list[str] | None] = {}
        self._semaphores = {"llm": AdjustableSemaphore(llm_jobs), "static": AdjustableSemaphore(1)}
        self._pending: dict[str, _Pending] = {}
        self._ids = itertools.count(1)

    # --- the journal ---------------------------------------------------------

    def attach(self, listener: Listener | None) -> None:
        """Where control events go; the runner binds this to its event sink."""
        self._listener = listener

    def _announce(self, phase: str, status: str, text: str, **data: Any) -> None:
        listener = self._listener
        if listener is not None:
            listener(phase, status, text, data)

    # --- cancel (unchanged contract) ----------------------------------------

    def cancel(self, by: str = "operator") -> None:
        already = self.cancellation.cancelled
        self.cancellation.cancel()
        with self._condition:
            self._condition.notify_all()
        if not already:
            self._announce("control", "cancel", "safe stop requested", by=by)

    def is_cancelled(self) -> bool:
        return self.cancellation.cancelled

    @property
    def cancelled(self) -> bool:
        return self.cancellation.cancelled

    # --- lanes ---------------------------------------------------------------

    def pause(self, lane: str, by: str = "operator") -> None:
        self._check_lane(lane)
        with self._condition:
            changed = not self._paused[lane]
            self._paused[lane] = True
        if changed:
            self._announce("control", "paused", f"{lane} lane paused; in-flight units finish, nothing new starts", lane=lane, by=by)

    def resume(self, lane: str, by: str = "operator") -> None:
        self._check_lane(lane)
        with self._condition:
            changed = self._paused[lane]
            self._paused[lane] = False
            self._condition.notify_all()
        if changed:
            self._announce("control", "resumed", f"{lane} lane resumed", lane=lane, by=by)

    def paused(self, lane: str) -> bool:
        with self._condition:
            return self._paused.get(lane, False)

    def toggle_pause(self, lane: str, by: str = "operator") -> bool:
        """Flip a lane; returns the new paused state."""
        if self.paused(lane):
            self.resume(lane, by)
            return False
        self.pause(lane, by)
        return True

    # --- skips ---------------------------------------------------------------

    def skip(self, name: str, by: str = "operator") -> None:
        with self._condition:
            new = name not in self._skipped
            self._skipped.add(name)
            self._condition.notify_all()
        if new:
            self._announce("control", "skipped", f"{name} skipped by operator; its remaining units are unscheduled", name=name, by=by)

    def skip_unit(self, producer: str, unit: str, by: str = "operator") -> None:
        with self._condition:
            self._skipped_units.add((producer, unit))
        self._announce("control", "skipped", f"{producer} unit {unit} skipped by operator", name=producer, unit=unit, by=by)

    def skipped(self, name: str) -> bool:
        with self._condition:
            return name in self._skipped

    # --- jobs ----------------------------------------------------------------

    def set_jobs(self, lane: str, jobs: int, by: str = "operator") -> int:
        self._check_lane(lane)
        ceiling = LLM_JOBS_CEILING if lane == "llm" else 64
        value = self._semaphores[lane].set_limit(min(max(1, int(jobs)), ceiling))
        self._announce("control", "jobs", f"{lane} concurrency set to {value}", lane=lane, value=value, by=by)
        return value

    def jobs(self, lane: str) -> int:
        self._check_lane(lane)
        return self._semaphores[lane].limit

    def semaphore(self, lane: str) -> AdjustableSemaphore:
        self._check_lane(lane)
        return self._semaphores[lane]

    # --- retries -------------------------------------------------------------

    def request_retry(self, name: str, unit_ids: list[str] | None = None, by: str = "operator") -> None:
        with self._condition:
            self._retries[name] = list(unit_ids) if unit_ids is not None else None
        self._announce(
            "control", "retry_requested", f"retry requested for {name}",
            name=name, unit_ids=list(unit_ids or []), by=by,
        )

    def drain_retries(self, name: str) -> list[str] | None | bool:
        """The units asked for (None = every failed one), or False when none was asked."""
        with self._condition:
            if name not in self._retries:
                return False
            return self._retries.pop(name)

    # --- the producers' one call --------------------------------------------

    def checkpoint(self, lane: str, producer: str, unit: str | None = None, poll: float = 0.25) -> str:
        """Wait out a pause, then say whether this unit runs.

        Cancel wins over everything; a skipped producer or unit never runs;
        otherwise the call returns as soon as the lane is not paused.
        """
        with self._condition:
            while self._paused.get(lane, False) and not self.cancellation.cancelled:
                self._condition.wait(poll)
            if self.cancellation.cancelled:
                return CANCELLED
            if producer in self._skipped:
                return SKIP_PRODUCER
            if unit is not None and (producer, unit) in self._skipped_units:
                return SKIP_UNIT
            return RUN

    # --- decisions -----------------------------------------------------------

    def request_decision(self, request: DecisionRequest, timeout: float | None = None) -> Decision:
        """Block the caller until someone decides, the timeout passes, or the run is cancelled."""
        if self._decider is not None:
            decision = self._decider(request)
            self._announce_decision(request, decision)
            return decision
        with self._condition:
            self._pending[request.id] = _Pending(request)
        self._announce(
            "decision", "requested", f"decision requested: {request.summary}",
            id=request.id, kind=request.kind, round=request.round, items=len(request.items),
            probe=request.probe, evidence=request.evidence_path,
        )
        deadline = time.monotonic() + timeout if timeout else None
        with self._condition:
            while True:
                pending = self._pending.get(request.id)
                if pending is None or pending.decision is not None:
                    decision = pending.decision if pending is not None else None
                    break
                if self.cancellation.cancelled:
                    decision = Decision("reject", decided_by="run", note="run cancelled")
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    decision = Decision("reject", decided_by="timeout", note="timeout")
                    self._announce("decision", "expired", f"decision {request.id} expired unanswered", id=request.id)
                    break
                self._condition.wait(0.25)
            self._pending.pop(request.id, None)
        decision = decision or Decision("reject", decided_by="run", note="no decision")
        if decision.decided_by in {"run", "timeout"}:
            self._announce_decision(request, decision)
        return decision

    def decide(self, request_id: str, answer: str, selected: tuple[int, ...] = (), decided_by: str = "operator", note: str = "") -> bool:
        """Answer a pending request; False when nothing waits under that id."""
        decision = Decision(answer, tuple(selected), decided_by, note)
        with self._condition:
            pending = self._pending.get(request_id)
            if pending is None:
                return False
            pending.decision = decision
            self._condition.notify_all()
            request = pending.request
        self._announce_decision(request, decision)
        return True

    def pending(self) -> list[DecisionRequest]:
        with self._condition:
            return [item.request for item in self._pending.values() if item.decision is None]

    def new_request_id(self, prefix: str = "d") -> str:
        return f"{prefix}{next(self._ids)}"

    def auto_decide(self, request: DecisionRequest, decision: Decision) -> Decision:
        """Record a decision the policy made on its own, so the journal shows it like any other."""
        self._announce(
            "decision", "requested", f"decision requested: {request.summary}",
            id=request.id, kind=request.kind, round=request.round, items=len(request.items),
            probe=request.probe, evidence=request.evidence_path,
        )
        self._announce_decision(request, decision)
        return decision

    def _announce_decision(self, request: DecisionRequest, decision: Decision) -> None:
        self._announce(
            "decision", "decided", f"decision {request.id}: {decision.answer} by {decision.decided_by}",
            id=request.id, kind=request.kind, answer=decision.answer, selected=list(decision.selected),
            decided_by=decision.decided_by, note=decision.note or None,
        )

    # --- the view ------------------------------------------------------------

    def state(self) -> dict[str, Any]:
        with self._condition:
            return {
                "cancelled": self.cancellation.cancelled,
                "lanes": {lane: {"paused": self._paused[lane], "jobs": self._semaphores[lane].limit} for lane in LANES},
                "skipped": sorted(self._skipped),
                "pending_decisions": [item.request.id for item in self._pending.values() if item.decision is None],
                "retries": {name: (units if units is not None else "all") for name, units in self._retries.items()},
            }

    @staticmethod
    def _check_lane(lane: str) -> None:
        if lane not in LANES:
            raise ValueError(f"unknown lane {lane!r}; expected one of {', '.join(LANES)}")


# --- deciders for a run without a screen ---------------------------------------------


def auto_no(request: DecisionRequest) -> Decision:
    """Headless without consent: record only.  The patch is suggested, never applied."""
    return Decision("reject", decided_by="policy", note="non-interactive run without --build-assist-yes")


def auto_yes(request: DecisionRequest) -> Decision:
    """``--build-assist-yes``: apply everything pre-ticked, exactly as the dialog would offer it."""
    return Decision("apply", tuple(request.preselected), decided_by="cli --build-assist-yes")


def stdin_decider(stdin: Any, stderr: Any) -> Callable[[DecisionRequest], Decision]:
    """The terminal's version of the dialog: a preview, then ``[y/N]``.

    One of the three places this program stops to ask something; all three now
    go through ``ask.Asker`` so a front end renders them one way.  The lines
    are the ones this function printed before, in the same order.
    """
    from .ask import question_from_decision, stdin_asker

    asker = stdin_asker(stdin, stderr, interactive=True)

    def decide(request: DecisionRequest) -> Decision:
        answer = asker(question_from_decision(request))
        if answer.yes:
            return Decision("apply", tuple(request.preselected), decided_by="cli")
        return Decision("reject", decided_by="cli", note="declined at the prompt")

    return decide

"""The batch engine: pull one task at a time, account for every one.

What it keeps from the old scan layer (llm/scan.py): a budget reserved before
dispatch, a circuit breaker for a host that has gone away, and the rule that a
task that never ran is *unscheduled with a reason*, never silently missing.
What changed: tasks are pulled one at a time (batch concurrency 1, measured
in the probe), a task the conversation preempts goes back to the head of the
queue at no cost -- it is not a failure, the breaker does not count it and the
budget is not charged -- and a task may add follow-ups (a second look at an AI
finding) that are planned and accounted like any other.

Invariant (tested, preemption included): planned == started + unscheduled,
where started = done + cached + failed.
"""
from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..model.broker import Preempted
from ..model.client import Cancelled, ModelError

BREAKER_CODES = frozenset({"TRANSPORT", "TIMEOUT", "SERVER", "RATE_LIMIT"})
BREAKER_LIMIT = 3
STARTED = ("done", "cached", "failed")


@dataclass
class Task:
    id: str
    payload: Any


@dataclass
class Attempt:
    status: str                     # done | cached | failed | unscheduled
    reason: str = ""
    gpu_seconds: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)
    follow_ups: list[Task] = field(default_factory=list)


@dataclass
class Summary:
    planned: int = 0
    by_status: dict[str, int] = field(default_factory=dict)
    unscheduled_reasons: dict[str, int] = field(default_factory=dict)
    gpu_seconds: float = 0.0
    preemptions: int = 0
    breaker: str = ""

    @property
    def started(self) -> int:
        return sum(self.by_status.get(s, 0) for s in STARTED)

    @property
    def unscheduled(self) -> int:
        return self.by_status.get("unscheduled", 0)

    def as_dict(self) -> dict[str, Any]:
        return {"planned": self.planned, "started": self.started, "unscheduled": self.unscheduled,
                "by_status": dict(sorted(self.by_status.items())),
                "unscheduled_reasons": dict(sorted(self.unscheduled_reasons.items())),
                "gpu_seconds": round(self.gpu_seconds, 1), "preemptions": self.preemptions, "breaker": self.breaker}


class Engine:
    def __init__(self, work: Callable[[Task], Attempt], *, budget_seconds: float,
                 on_outcome: Callable[[Task, Attempt], None] = lambda _t, _a: None,
                 cancelled: Callable[[], bool] = lambda: False,
                 progress: Callable[[str], None] = lambda _line: None,
                 breaker_limit: int = BREAKER_LIMIT, clock: Callable[[], float] = time.monotonic) -> None:
        self.work = work
        self.budget_seconds = float(budget_seconds)
        self.on_outcome = on_outcome
        self.cancelled = cancelled
        self.progress = progress
        self.breaker_limit = breaker_limit
        self.clock = clock

    def run(self, tasks: list[Task]) -> Summary:
        summary = Summary(planned=len(tasks))
        queue: deque[Task] = deque(tasks)
        consecutive = 0
        started_at = self.clock()
        while queue:
            task = queue.popleft()
            reason = self._blocked(summary)
            if reason:
                self._settle(summary, task, Attempt("unscheduled", reason))
                continue
            try:
                attempt = self.work(task)
            except Preempted:
                summary.preemptions += 1
                queue.appendleft(task)
                self.progress(f"{task.id}: yielded the GPU to the conversation; it runs again when the chat is quiet")
                continue
            except Cancelled as error:
                if error.reason == "preempted":
                    summary.preemptions += 1
                    queue.appendleft(task)
                    continue
                attempt = Attempt("unscheduled", "stopped by the evaluator")
            except ModelError as error:
                attempt = Attempt("failed", f"{error.code}: {error.message[:200]}")
                if error.code == "DISABLED":
                    summary.breaker = "the model lane is off (CODE_ANALYZER_NO_MODEL=1)"
                consecutive = consecutive + 1 if error.code in BREAKER_CODES else 0
                if self.breaker_limit and consecutive >= self.breaker_limit and not summary.breaker:
                    summary.breaker = (f"model host unreachable ({error.code}); circuit breaker after "
                                       f"{consecutive} consecutive failures")
                    self.progress(summary.breaker)
            except Exception as error:  # noqa: BLE001 - one task's failure must not cost the rest of the job
                attempt = Attempt("failed", f"internal error: {type(error).__name__}: {str(error)[:200]}")
            else:
                if attempt.status in ("done", "cached"):
                    consecutive = 0
            summary.gpu_seconds += attempt.gpu_seconds
            if attempt.follow_ups:
                summary.planned += len(attempt.follow_ups)
                queue.extend(attempt.follow_ups)
            self._settle(summary, task, attempt)
            if summary.started and summary.started % 10 == 0:
                elapsed = self.clock() - started_at
                self.progress(f"{summary.started}/{summary.planned} reviewed, {summary.gpu_seconds:.0f}s of "
                              f"{self.budget_seconds:.0f}s GPU budget used, {elapsed:.0f}s elapsed")
        return summary

    def _blocked(self, summary: Summary) -> str:
        if self.cancelled():
            return "stopped by the evaluator"
        if summary.breaker:
            return summary.breaker
        if summary.gpu_seconds >= self.budget_seconds:
            return "GPU budget used up"
        return ""

    def _settle(self, summary: Summary, task: Task, attempt: Attempt) -> None:
        summary.by_status[attempt.status] = summary.by_status.get(attempt.status, 0) + 1
        if attempt.status == "unscheduled":
            summary.unscheduled_reasons[attempt.reason] = summary.unscheduled_reasons.get(attempt.reason, 0) + 1
        self.on_outcome(task, attempt)

"""Jobs: one background task per evaluation at a time, stoppable, observable.

A job is a thread with a cancellation token, a bounded log of progress lines
and a status.  ``J1``, ``J2``... are numbered per evaluation.  Listeners (the
SSE stream) are notified through a version counter, so a slow browser can
never block the job.  The tools the job runs record their own evidence and
ledger entries; the job adds nothing to the ledger itself -- its outcome is
the call it made.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..core.cancel import CancellationToken
from ..errors import UserError

LOG_LINES = 200


@dataclass
class Job:
    id: str
    evaluation: str
    kind: str
    token: CancellationToken = field(default_factory=CancellationToken)
    status: str = "running"
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    exit_code: int | None = None
    error: str = ""
    call_id: str = ""
    lines: deque[str] = field(default_factory=lambda: deque(maxlen=LOG_LINES))

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "status": self.status, "exit_code": self.exit_code,
                "started_at": _iso(self.started_at), "finished_at": _iso(self.finished_at) if self.finished_at else None,
                "elapsed_seconds": round((self.finished_at or time.time()) - self.started_at, 1),
                "progress": list(self.lines)[-50:], "call_id": self.call_id, "error": self.error}


class JobManager:
    def __init__(self, on_finish: Callable[[Job], None] | None = None, *,
                 on_start: Callable[[Job], None] | None = None,
                 seed: Callable[[str], int] = lambda _evaluation: 0) -> None:
        self._lock = threading.Condition()
        self._jobs: dict[str, list[Job]] = {}
        self._numbers: dict[str, int] = {}
        self.version = 0
        self.on_finish = on_finish
        self.on_start = on_start
        # The highest job number an evaluation has already used (from its ledger): numbers continue across
        # restarts of the server, so "J3" names one job for the life of the evaluation.
        self.seed = seed

    def start(self, evaluation: str, kind: str, work: Callable[[Job], int | None]) -> Job:
        with self._lock:
            jobs = self._jobs.setdefault(evaluation, [])
            if any(job.status == "running" for job in jobs):
                raise UserError("a job is already running for this evaluation; stop it or wait for it")
            if evaluation not in self._numbers:
                self._numbers[evaluation] = self.seed(evaluation)
            self._numbers[evaluation] += 1
            job = Job(f"J{self._numbers[evaluation]}", evaluation, kind)
            jobs.append(job)
            self._bump()
        if self.on_start is not None:
            self.on_start(job)
        thread = threading.Thread(target=self._run, args=(job, work), name=f"job-{evaluation}-{job.id}", daemon=True)
        thread.start()
        return job

    def _run(self, job: Job, work: Callable[[Job], int | None]) -> None:
        try:
            job.exit_code = work(job)
            status = "stopped" if job.token.is_cancelled() else ("finished" if job.exit_code in (0, 1, 10) else "failed")
        except BaseException as error:  # noqa: BLE001 - a job must always settle
            job.error = str(error) or type(error).__name__
            status = "stopped" if job.token.is_cancelled() else "failed"
        with self._lock:
            job.status = status
            job.finished_at = time.time()
            self._bump()
        if self.on_finish is not None:
            try:
                self.on_finish(job)
            except Exception:  # noqa: BLE001 - a listener must not break the job
                pass

    def log(self, job: Job, line: str) -> None:
        with self._lock:
            job.lines.append(line)
            self._bump()

    def stop(self, evaluation: str, job_id: str) -> Job:
        job = self.get(evaluation, job_id)
        job.token.cancel()
        with self._lock:
            self._bump()
        return job

    def get(self, evaluation: str, job_id: str) -> Job:
        for job in self._jobs.get(evaluation, []):
            if job.id == job_id:
                return job
        raise KeyError(job_id)

    def jobs(self, evaluation: str) -> list[Job]:
        return list(self._jobs.get(evaluation, []))

    def running(self, evaluation: str) -> Job | None:
        return next((job for job in self._jobs.get(evaluation, []) if job.status == "running"), None)

    def poke(self) -> None:
        """Wake SSE listeners for something that is not a job (a streamed model delta)."""
        with self._lock:
            self._bump()

    def wait(self, version: int, timeout: float) -> int:
        """Block until something changed after ``version`` (or ``timeout``); return the new version."""
        with self._lock:
            self._lock.wait_for(lambda: self.version != version, timeout=timeout)
            return self.version

    def _bump(self) -> None:
        self.version += 1
        self._lock.notify_all()


def _iso(seconds: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))

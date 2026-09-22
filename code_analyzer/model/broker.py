"""The GPU's traffic light: the conversation first, background work when it is quiet.

One GPU serves the conversation and every background job.  Measured on the
host: distinct prompts from four or eight concurrent requests share ~95-126
prompt tok/s in total, so a chat turn that queues behind a batch waits for
all of it -- a "hi" once took 287 s during a scan.  The rule here is blunt:

* an interactive request (P0) freezes background dispatch and **disconnects
  every in-flight background request (P1)**; each one fails with
  ``Preempted``, which its job treats as "put back at the head of the queue,
  refund the budget, do not count it against the circuit breaker";
* background dispatch resumes only after ``resume_after`` seconds with no
  interactive activity (a turn, or the operator typing).

This module decides *when*; the client decides *where* (egress) and *how*.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from ..defaults import RESUME_BACKGROUND_AFTER_SECONDS
from .client import Cancelled, CancelToken, ModelClient, ModelError, Reply

INTERACTIVE = "P0"
BACKGROUND = "P1"


class Preempted(ModelError):
    def __init__(self) -> None:
        super().__init__("PREEMPTED", "yielded the GPU to the conversation")


class Broker:
    def __init__(self, *, resume_after: float = RESUME_BACKGROUND_AFTER_SECONDS,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.resume_after = resume_after
        self.clock = clock
        self._cond = threading.Condition()
        self._interactive = 0
        self._last_activity = float("-inf")
        self._background: set[CancelToken] = set()
        self.preemptions = 0

    # -- interactive -------------------------------------------------------------
    @contextmanager
    def interactive(self) -> Iterator[None]:
        with self._cond:
            self._interactive += 1
            self._last_activity = self.clock()
            victims = list(self._background)
            self.preemptions += len(victims)
        for token in victims:
            token.cancel("preempted")
        try:
            yield
        finally:
            with self._cond:
                self._interactive -= 1
                self._last_activity = self.clock()
                self._cond.notify_all()

    def note_activity(self) -> None:
        """The operator is typing: keep background work paused a little longer."""
        with self._cond:
            self._last_activity = self.clock()

    # -- background --------------------------------------------------------------
    def background_ready(self) -> bool:
        with self._cond:
            return self._ready()

    def _ready(self) -> bool:
        return self._interactive == 0 and self.clock() - self._last_activity >= self.resume_after

    @contextmanager
    def background(self, token: CancelToken, *, stop: CancelToken | None = None,
                   poll: float = 0.5) -> Iterator[None]:
        """Wait for a quiet GPU, then hold a background slot until the block ends."""
        with self._cond:
            while not self._ready():
                if stop is not None and stop.cancelled:
                    raise Cancelled(stop.reason or "stopped")
                self._cond.wait(poll)
            self._background.add(token)
        try:
            yield
        finally:
            with self._cond:
                self._background.discard(token)

    # -- one-call helpers -------------------------------------------------------------
    def chat(self, client: ModelClient, priority: str, *, stop: CancelToken | None = None,
             **kwargs: Any) -> Reply:
        if priority == INTERACTIVE:
            with self.interactive():
                return client.chat(cancel=stop, **kwargs)
        token = CancelToken()
        unregister = stop.on_cancel(lambda: token.cancel(stop.reason or "stopped")) if stop else (lambda: None)
        try:
            with self.background(token, stop=stop):
                try:
                    return client.chat(cancel=token, **kwargs)
                except Cancelled:
                    if token.reason == "preempted":
                        raise Preempted() from None
                    raise
        finally:
            unregister()

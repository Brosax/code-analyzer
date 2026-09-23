"""One conversation per evaluation: a single worker, a queue, and honest interruption.

The worker thread is the only writer of the conversation: it takes one message
at a time and runs a turn.  A message typed while a turn runs is queued and
shown as queued; it is sent after the turn with a note that it was written
during the previous one, so the model does not answer it as if it had seen
nothing since.  Text is never an approval -- cards are decided by buttons.

``interrupt`` cancels the running turn: the socket is shut down, the partial
answer is marked interrupted, and the late reply (if Ollama finishes it
anyway) is discarded by the generation counter.

Events (a job finished) are appended as ``event_said`` and, when the
conversation is idle, wake the agent for one short turn -- at most once per
two minutes per job, and never while the evaluator is typing.
"""
from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..evidence.workspace import Workspace
from ..model.client import Cancelled, CancelToken, ModelError
from .loop import Kernel

WAKE_QUIET_SECONDS = 20.0
WAKE_MIN_INTERVAL = 120.0


@dataclass
class _Message:
    text: str
    queued_during_turn: bool = False
    wake: bool = False


@dataclass
class Conversation:
    workspace: Workspace
    kernel_factory: Callable[[], Kernel]
    on_delta: Callable[[dict[str, Any]], None] = lambda _event: None
    _queue: queue.Queue[_Message] = field(default_factory=queue.Queue)
    _token: CancelToken | None = None
    _busy: bool = False
    _generation: int = 0
    _typing_at: float = 0.0
    _last_wake: dict[str, float] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._work, name=f"chat-{self.workspace.root.name}", daemon=True)
            self._thread.start()

    # -- inputs ----------------------------------------------------------------------------
    def say(self, text: str) -> dict[str, Any]:
        text = text.strip()[:8000]
        if not text:
            raise ValueError("empty message")
        with self._lock:
            busy = self._busy
        if busy:
            record = self.workspace.ledger.append("user_queued", text=text)
            self._queue.put(_Message(text, queued_during_turn=True))
            return {"queued": True, "seq": record["seq"]}
        self._queue.put(_Message(text))
        return {"queued": False}

    def typing(self) -> None:
        self._typing_at = time.monotonic()

    def interrupt(self) -> bool:
        with self._lock:
            token = self._token
        if token is None:
            return False
        token.cancel("interrupted by the evaluator")
        return True

    def event(self, key: str, text: str) -> None:
        """Something happened outside the conversation (a job finished)."""
        self.workspace.ledger.append("event_said", text=text)
        now = time.monotonic()
        with self._lock:
            idle = not self._busy and self._queue.empty()
        quiet = now - self._typing_at > WAKE_QUIET_SECONDS
        if idle and quiet and now - self._last_wake.get(key, -1e9) > WAKE_MIN_INTERVAL:
            self._last_wake[key] = now
            self._queue.put(_Message("", wake=True))

    @property
    def busy(self) -> bool:
        return self._busy

    # -- the worker ------------------------------------------------------------------------------
    def _work(self) -> None:
        while True:
            message = self._queue.get()
            if message.wake and not self._queue.empty():
                continue  # the evaluator said something: answer that instead
            with self._lock:
                self._busy = True
                self._generation += 1
                generation = self._generation
                self._token = CancelToken()
                token = self._token
            try:
                if not message.wake:
                    text = (f"（写于上一回合进行中）{message.text}" if message.queued_during_turn else message.text)
                    self.workspace.ledger.append("user_said", text=text)
                kernel = self.kernel_factory()

                def delta(kind: str, chunk: str, generation: int = generation) -> None:
                    if generation == self._generation:
                        self.on_delta({"kind": kind, "text": chunk})

                outcome = kernel.turn(token=token, on_delta=delta)
                self.workspace.ledger.append("turn_finished", steps=outcome.steps, ended_by=outcome.ended_by)
            except Cancelled as error:
                self.workspace.ledger.append("turn_cancelled", reason=error.reason)
            except ModelError as error:
                self.workspace.ledger.append("agent_error", code=error.code, message=error.message[:300])
            except Exception as error:  # noqa: BLE001 - the conversation must survive a bug
                self.workspace.ledger.append("agent_error", code="INTERNAL", message=f"{type(error).__name__}: {error}"[:300])
            finally:
                with self._lock:
                    self._busy = False
                    self._token = None
                self.on_delta({"kind": "end", "text": ""})

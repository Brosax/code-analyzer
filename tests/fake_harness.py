"""A scripted stand-in for ``code_analyzer.harness``.

CI runs with no model and no network, so every test that touches the LLM path
drives this fake instead of ``dsh``.  It mirrors the real SDK surface -- a
context manager whose ``run()`` hands back a ``RunResult`` -- because a fake
shaped more conveniently than the runtime it replaces lets broken production
code pass.  Scripts are keyed by ``(producer, unit_id)`` and every call is
recorded, so scheduling and budget behaviour is asserted on the calls the
fake actually received rather than on whatever the caller says it did.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from code_analyzer.persist import json_bytes

FIXTURES = Path(__file__).parent / "fixtures" / "llm"

# The scan unit every checked-in envelope was recorded against.  The
# line-out-of-range fixture is only out of range relative to this span.
FIXTURE_UNIT: dict[str, Any] = {
    "unit_id": "src-parser-c-parse_packet",
    "canonical_path": "src/parser.c",
    "symbol": "parse_packet",
    "line_start": 100,
    "line_end": 140,
}

_ENVELOPE_KEYS = frozenset(
    {"session_id", "final_response", "finish_reason", "events", "notifications"}
)


class HarnessError(RuntimeError):
    """Base for the failures the real harness surfaces to its callers."""


class HarnessTimeout(HarnessError):
    """The unit outran its request budget and the session was torn down."""


class HarnessUnavailable(HarnessError):
    """The runtime would not start, or the endpoint refused the session."""


@dataclass(frozen=True)
class RunResult:
    """The SDK result object; ``session_root`` holds the native evidence."""

    session_id: str
    final_response: str
    finish_reason: str
    events: list[dict[str, Any]]
    notifications: list[Any]
    session_root: Path | None


@dataclass(frozen=True)
class Response:
    """One scripted reply, plus how the transport behaves while producing it."""

    final_response: str = ""
    finish_reason: str = "completed"
    events: tuple[dict[str, Any], ...] = ()
    notifications: tuple[Any, ...] = ()
    session_id: str = ""
    delay: float = 0.0
    error: type[BaseException] | None = None
    error_message: str = ""


@dataclass
class Call:
    """One received call.  Mutable so ``calls`` stays in dispatch order."""

    index: int
    attempt: int
    producer: str
    unit_id: str
    request: dict[str, Any] = field(default_factory=dict)
    started_at: float = 0.0
    finished_at: float | None = None
    outcome: str | None = None


def fixture(name: str) -> Response:
    """Load a recorded response envelope by file stem."""
    path = FIXTURES / f"{name}.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    unknown = set(envelope) - _ENVELOPE_KEYS
    if unknown:
        raise ValueError(f"{path.name} has unknown envelope key(s): {sorted(unknown)}")
    return Response(
        final_response=envelope["final_response"],
        finish_reason=envelope["finish_reason"],
        events=tuple(envelope["events"]),
        notifications=tuple(envelope["notifications"]),
        session_id=envelope["session_id"],
    )


def fixture_names() -> tuple[str, ...]:
    return tuple(sorted(path.stem for path in FIXTURES.glob("*.json")))


def response(text: str, *, finish_reason: str = "completed", **overrides: Any) -> Response:
    """An ad-hoc envelope, for shapes no checked-in fixture needs to pin."""
    return Response(final_response=text, finish_reason=finish_reason, **overrides)


def timed_out(
    *, delay: float = 0.0, message: str = "unit exceeded request_timeout_seconds"
) -> Response:
    """A unit that burns ``delay`` seconds of budget and then dies."""
    return Response(
        finish_reason="aborted", delay=delay, error=HarnessTimeout, error_message=message
    )


def unavailable(message: str = "dsh runtime is not installed") -> Response:
    return Response(finish_reason="error", error=HarnessUnavailable, error_message=message)


def transport_failed(*, delay: float = 0.0) -> Response:
    """A session the provider never carried, exactly as the pinned SDK reports it.

    Six requests, five retries, zero tokens, ``finish_reason="error"`` and an
    empty reply: the shape of every one of the 394 sessions of the run that
    motivated the circuit breaker.  ``delay`` is the wall time it burns.
    """
    recorded = fixture("transport-failed")
    return Response(
        final_response=recorded.final_response, finish_reason=recorded.finish_reason,
        events=recorded.events, notifications=recorded.notifications, session_id=recorded.session_id, delay=delay,
    )


def steps(*kinds: str, text: str = "") -> tuple[dict[str, Any], ...]:
    """Script the SDK's step notifications for a display test: ``turn/start``, ``tool/call``, ...

    ``text`` is what an ``assistant/chunk`` text chunk carries.  The chunk is
    shaped as the pinned runtime shapes it -- ``{"type": "text-delta", "text":
    ..., "index": 0}``, verified against a live Ollama session on 2026-09-03.
    A fake that scripted ``{"type": "text"}`` instead let the streaming path
    pass this suite while never firing for a real provider.
    """
    scripted: list[dict[str, Any]] = []
    for index, kind in enumerate(kinds, 1):
        data: dict[str, Any] = {"turn": 1, "step": 1}
        if kind == "assistant/chunk":
            data["chunk"] = {"type": "text-delta", "text": text, "index": 0}
        elif kind == "tool/call":
            data["name"] = "read"
        elif kind == "llm/retry":
            data.update({"retry": 1, "maxRetries": 5, "failure": {"code": "TRANSPORT", "message": "Connection error."}})
        scripted.append({"type": kind, "seq": index, "time": 1788270081000 + index, "data": data})
    return tuple(scripted)


def _session_id(producer: str, unit_id: str, attempt: int) -> str:
    # Derived, never random: session ids reach persisted artifacts.
    stable = f"{producer}\0{unit_id}\0{attempt}".encode()
    return hashlib.sha256(stable).hexdigest()[:16]


class FakeHarness:
    """Serves scripted responses per ``(producer, unit_id)`` and records calls."""

    def __init__(
        self, session_root: Path | None = None, *, default: Response | str | None = None
    ) -> None:
        self.session_root = session_root
        self.calls: list[Call] = []
        self.constructions: list[dict[str, Any]] = []
        self.closed = False
        self._default = _coerce(default) if default is not None else None
        self._scripts: dict[tuple[str, str], list[Response]] = {}
        self._attempts: Counter[tuple[str, str]] = Counter()
        self._lock = threading.Lock()

    def script(self, producer: str, unit_id: str, *responses: Response | str) -> FakeHarness:
        """Queue responses for one unit; a bare ``str`` names a fixture stem."""
        queue = self._scripts.setdefault((producer, unit_id), [])
        queue.extend(_coerce(item) for item in responses)
        return self

    def script_default(self, item: Response | str) -> FakeHarness:
        """Answer any unit with no script left, instead of failing the test."""
        self._default = _coerce(item)
        return self

    def remaining(self) -> dict[tuple[str, str], int]:
        with self._lock:
            return {key: len(queue) for key, queue in self._scripts.items() if queue}

    def calls_for(self, producer: str | None = None, unit_id: str | None = None) -> list[Call]:
        return [
            call
            for call in self.calls
            if (producer is None or call.producer == producer)
            and (unit_id is None or call.unit_id == unit_id)
        ]

    def __enter__(self) -> FakeHarness:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.closed = True

    def run(self, *, producer: str, unit_id: str, **request: Any) -> RunResult:
        if self.closed:
            raise HarnessUnavailable("session is closed")
        key = (producer, unit_id)
        with self._lock:
            queue = self._scripts.get(key) or []
            scripted = queue.pop(0) if queue else self._default
            self._attempts[key] += 1
            # Recorded before it is served: a call the fake refuses is still a
            # call the scheduler made, and budget tests need to see it.
            call = Call(
                index=len(self.calls),
                attempt=self._attempts[key],
                producer=producer,
                unit_id=unit_id,
                request=dict(request),
                started_at=time.monotonic(),
            )
            self.calls.append(call)
        if scripted is None:
            call.finished_at = time.monotonic()
            call.outcome = "unscripted"
            raise AssertionError(f"unscripted harness call for {producer}/{unit_id}")
        if scripted.delay:
            time.sleep(scripted.delay)
        session_id = scripted.session_id or _session_id(producer, unit_id, call.attempt)
        events = [dict(event) for event in scripted.events]
        root = self._write_evidence(producer, unit_id, session_id, scripted, events)
        call.finished_at = time.monotonic()
        if scripted.error is not None:
            call.outcome = scripted.error.__name__
            raise scripted.error(scripted.error_message)
        call.outcome = scripted.finish_reason
        return RunResult(
            session_id=session_id,
            final_response=scripted.final_response,
            finish_reason=scripted.finish_reason,
            events=events,
            notifications=list(scripted.notifications),
            session_root=root,
        )

    def _write_evidence(
        self,
        producer: str,
        unit_id: str,
        session_id: str,
        scripted: Response,
        events: list[dict[str, Any]],
    ) -> Path | None:
        """Land the evidence a real session streams while it runs.

        A torn-down session leaves the events it already streamed but no
        response envelope, so failure cases must not synthesise one.
        """
        if self.session_root is None:
            return None
        root = self.session_root / producer / unit_id
        root.mkdir(parents=True, exist_ok=True)
        (root / "events.jsonl").write_text(
            "".join(
                json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n" for event in events
            ),
            encoding="utf-8",
        )
        if scripted.error is None:
            (root / "response.json").write_bytes(
                json_bytes(
                    {
                        "events": events,
                        "final_response": scripted.final_response,
                        "finish_reason": scripted.finish_reason,
                        "notifications": list(scripted.notifications),
                        "session_id": session_id,
                    }
                )
            )
        return root


def install(
    monkeypatch: pytest.MonkeyPatch,
    target: object,
    name: str,
    fake: FakeHarness | None = None,
    *,
    as_factory: bool = False,
    raising: bool = True,
) -> FakeHarness:
    """Point ``target.name`` at a fake harness and hand it back for assertions.

    ``as_factory`` covers the other plausible call shape, where production code
    constructs a session object rather than calling a module-level function.
    """
    fake = fake if fake is not None else FakeHarness()
    replacement: Any = fake.run
    if as_factory:

        def factory(*args: Any, **kwargs: Any) -> FakeHarness:
            fake.constructions.append({"args": list(args), "kwargs": dict(kwargs)})
            return fake

        replacement = factory
    monkeypatch.setattr(target, name, replacement, raising=raising)
    return fake


def _coerce(item: Response | str) -> Response:
    return fixture(item) if isinstance(item, str) else item

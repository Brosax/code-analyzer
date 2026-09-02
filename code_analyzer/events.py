"""Run-level event log: every AnalysisEvent as one JSON object per line.

This is a progress log, not evidence.  The manifest and the producers' native
reports remain authoritative; the log is excluded from the shareable archive
and from the artifact index because it is still being written after both
are final.
"""
from __future__ import annotations

import threading
from dataclasses import asdict
from pathlib import Path
from typing import IO, Any

from .analysis import AnalysisEvent, EventSink
from .errors import UserError
from .persist import jsonl_bytes
from .progress import single_line

EVENTS_FILE = "events.jsonl"
# The runner announces the run directory with this phase/status pair; the
# event's message is the directory path.  A sink without an explicit path
# opens ``<run_dir>/events.jsonl`` on it and flushes everything buffered so
# far, because `analysis started` and `discovery started` precede the
# directory's creation.
RUN_DIRECTORY_PHASE = ("run", "created")


MAX_DATA_STRING = 2000
MAX_DATA_ITEMS = 200
MAX_DATA_DEPTH = 3
# Lists that are the evidence itself and must not be cut: an argv is only
# meaningful whole.
_UNCAPPED_LISTS = frozenset({"argv"})


def event_record(event: AnalysisEvent) -> dict[str, Any]:
    """The JSON shape of one event, message filtered like terminal output.

    Messages embed analyzer output lines and scanned file names; the same
    control-character filter the progress display applies keeps a
    ``tail -f`` of this file from rewriting the operator's terminal.  The
    ``data`` object gets the same treatment, leaf by leaf, plus size caps so
    one event cannot carry a whole report.
    """
    return {**asdict(event), "message": single_line(event.message), "data": clean_data(event.data)}


def clean_data(value: Any, *, depth: int = 0, key: str = "") -> Any:
    """Sanitise a data payload for the log: strings through single_line, sizes bounded."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return single_line(value)[:MAX_DATA_STRING]
    if depth >= MAX_DATA_DEPTH:
        return single_line(str(value))[:MAX_DATA_STRING]
    if isinstance(value, dict):
        return {str(k): clean_data(v, depth=depth + 1, key=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        items = list(value) if key in _UNCAPPED_LISTS else list(value)[:MAX_DATA_ITEMS]
        cleaned = [clean_data(item, depth=depth + 1) for item in items]
        if key not in _UNCAPPED_LISTS and len(value) > MAX_DATA_ITEMS:
            cleaned.append(f"…(+{len(value) - MAX_DATA_ITEMS})")
        return cleaned
    return single_line(str(value))[:MAX_DATA_STRING]


class JsonlEventSink:
    """JSONL sink holding one run per file; safe to call from worker threads."""

    def __init__(self, path: Path | None = None) -> None:
        self._lock = threading.Lock()
        self._pending: list[AnalysisEvent] = []
        self._stream: IO[bytes] | None = None
        self.path: Path | None = None
        if path is not None:
            self._open(path.expanduser().resolve())

    def __call__(self, event: AnalysisEvent) -> None:
        with self._lock:
            if self._stream is None and (event.phase, event.status) == RUN_DIRECTORY_PHASE:
                self._open(Path(event.message) / EVENTS_FILE)
            if self._stream is None:
                self._pending.append(event)
                return
            self._stream.write(jsonl_bytes(event_record(event)))
            self._stream.flush()

    def _open(self, path: Path) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._stream = path.open("wb")
        except OSError as exc:
            raise UserError(f"cannot open events file {path}: {exc}") from exc
        self.path = path
        for event in self._pending:
            self._stream.write(jsonl_bytes(event_record(event)))
        self._pending.clear()
        self._stream.flush()

    def close(self) -> None:
        with self._lock:
            if self._stream is not None:
                self._stream.close()
                self._stream = None
            self._pending.clear()

    def __enter__(self) -> JsonlEventSink:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def fan_out(*sinks: EventSink | None) -> EventSink:
    """Deliver each event to every given sink, in order; None entries are skipped.

    One event reaches every sink before the next event reaches any of them.
    The static adapters and the LLM phase emit from two threads, and without
    this lock the JSONL file and the caller's own sink could disagree about the
    order of two events -- the log says a tool finished first, the TUI says the
    scanner did.  ``JsonlEventSink`` has a lock of its own for the line itself;
    this one is about the sequence the sinks agree on.
    """
    targets = [sink for sink in sinks if sink is not None]
    # Reentrant on purpose: a sink that reacts to an event by acting on the run
    # (a pause taken inside an event callback) journals that action as another
    # event on the same thread, and a plain lock would deadlock it.
    lock = threading.RLock()

    def deliver(event: AnalysisEvent) -> None:
        with lock:
            for sink in targets:
                sink(event)

    return deliver


def events_file(config: dict[str, Any]) -> Path | None:
    """The configured override, or None for ``<run_dir>/events.jsonl``."""
    configured = str(config["run"]["events_file"] or "").strip()
    return Path(configured) if configured else None

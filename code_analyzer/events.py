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


def event_record(event: AnalysisEvent) -> dict[str, Any]:
    """The JSON shape of one event, message filtered like terminal output.

    Messages embed analyzer output lines and scanned file names; the same
    control-character filter the progress display applies keeps a
    ``tail -f`` of this file from rewriting the operator's terminal.
    """
    return {**asdict(event), "message": single_line(event.message)}


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
    """Deliver each event to every given sink, in order; None entries are skipped."""
    targets = [sink for sink in sinks if sink is not None]

    def deliver(event: AnalysisEvent) -> None:
        for sink in targets:
            sink(event)

    return deliver


def events_file(config: dict[str, Any]) -> Path | None:
    """The configured override, or None for ``<run_dir>/events.jsonl``."""
    configured = str(config["run"]["events_file"] or "").strip()
    return Path(configured) if configured else None

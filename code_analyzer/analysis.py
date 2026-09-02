from __future__ import annotations

import copy
import json
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class AnalysisRequest:
    """An immutable-in-practice request for the headless analysis service."""

    source: Path
    config: dict[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", self.source.expanduser().resolve())
        object.__setattr__(self, "config", copy.deepcopy(self.config))


@dataclass(frozen=True)
class AnalysisEvent:
    phase: str
    status: str
    message: str
    tool: str | None = None
    unit: str | None = None
    progress: float | None = None
    timestamp: float = field(default_factory=time.time)
    stream: str | None = None
    # The structured half of the message: counters, paths, argv, reasons.
    # Consumers read this; the message stays the human line.  ``None`` for an
    # event that has nothing to add, so the JSONL row stays small.
    data: dict[str, Any] | None = None


def started_data() -> dict[str, Any]:
    """What the first event of a run records: how it was invoked."""
    from . import __version__

    return {"argv": list(sys.argv), "cwd": str(Path.cwd()), "version": __version__}


class CancellationToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


@dataclass(frozen=True)
class AnalysisResult:
    exit_code: int
    report_directory: Path | None
    manifest: dict[str, Any] | None


EventSink = Callable[[AnalysisEvent], None]


def run_analysis(
    request: AnalysisRequest,
    *,
    events: EventSink | None = None,
    cancellation: CancellationToken | None = None,
    control: Any | None = None,
) -> AnalysisResult:
    """Run analysis without terminal output, reporting structured events.

    Every event also lands in the run-level events.jsonl (see events.py);
    ``[run] events_file`` relocates it.  ``control`` is the operator's
    ``RunControl``; it wraps the cancellation token and journals every
    action into the same event stream.
    """
    from .control import RunControl
    from .events import JsonlEventSink, events_file, fan_out
    from .runlog import RunLogger
    from .runner import AnalysisCancelled, _analyze

    if control is None:
        control = RunControl(cancellation, llm_jobs=int(request.config["llm"].get("jobs") or 1))
    token = control.cancellation
    started = time.monotonic()
    with JsonlEventSink(events_file(request.config)) as log, RunLogger(request.config["run"]["log_level"]) as run_log:
        sink = fan_out(log, run_log, events)
        control.attach(lambda phase, status, text, data: sink(AnalysisEvent(phase, status, text, data=data)))
        sink(AnalysisEvent("analysis", "started", "analysis started", progress=0.0, data=started_data()))
        if token.cancelled:
            sink(AnalysisEvent("analysis", "interrupted", "analysis cancelled before start", progress=1.0))
            return AnalysisResult(130, None, None)

        # Progress strings are the CLI's channel; the structured events carry
        # the same facts, so the headless service does not echo them.  (The
        # mirror used to double every unit row in events.jsonl.)
        def progress(message: str) -> None:
            return None

        try:
            exit_code, report_directory = _analyze(
                request.source,
                request.config,
                progress,
                cancellation=token,
                event_sink=sink,
                control=control,
            )
        except AnalysisCancelled:
            sink(AnalysisEvent("analysis", "interrupted", "analysis cancelled before report creation", progress=1.0))
            return AnalysisResult(130, None, None)
        manifest = None
        manifest_path = report_directory / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass
        status = "interrupted" if exit_code == 130 else "finished"
        sink(AnalysisEvent(
            "analysis", status, f"analysis finished with exit code {exit_code}", progress=1.0,
            data=finished_data(manifest, exit_code, time.monotonic() - started),
        ))
        return AnalysisResult(exit_code, report_directory, manifest)


def finished_data(manifest: dict[str, Any] | None, exit_code: int, duration: float | None) -> dict[str, Any]:
    """The last event of a run: its verdict, in the words the manifest uses."""
    manifest = manifest or {}
    tools = {
        name: str(record.get("status", "")) for name, record in (manifest.get("tools") or {}).items()
        if isinstance(record, dict) and record.get("requested")
    }
    llm = manifest.get("llm") or {}
    review = manifest.get("review") or {}
    export = manifest.get("export") or {}
    return {
        "status": manifest.get("status", "interrupted" if exit_code == 130 else "unknown"),
        "exit_code": exit_code,
        "duration_seconds": None if duration is None else round(duration, 3),
        "tools": tools,
        "llm": llm.get("status") if llm.get("requested") else None,
        "review": review.get("findings") if review.get("status") in {"completed", "partial"} else review.get("status"),
        "export": export.get("status") if export.get("enabled") else None,
    }

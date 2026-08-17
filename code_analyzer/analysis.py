from __future__ import annotations

import copy
import json
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
) -> AnalysisResult:
    """Run analysis without terminal output, reporting structured events."""
    from .runner import AnalysisCancelled, _analyze

    token = cancellation or CancellationToken()
    sink = events or (lambda _event: None)
    sink(AnalysisEvent("analysis", "started", "analysis started", progress=0.0))
    if token.cancelled:
        sink(AnalysisEvent("analysis", "interrupted", "analysis cancelled before start", progress=1.0))
        return AnalysisResult(130, None, None)

    def progress(message: str) -> None:
        sink(AnalysisEvent("progress", "running", message))

    try:
        exit_code, report_directory = _analyze(
            request.source,
            request.config,
            progress,
            cancellation=token,
            event_sink=sink,
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
    sink(AnalysisEvent("analysis", status, f"analysis finished with exit code {exit_code}", progress=1.0))
    return AnalysisResult(exit_code, report_directory, manifest)

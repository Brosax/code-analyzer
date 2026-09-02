"""``logs/runner.log`` as a projection of the event stream.

The log used to be fifteen hand-written lines: a tool started, a tool ended,
the review counted.  Everything that explained a run -- the argv, why a unit
ended the way it did, how long it took, what the final status was -- lived
only in the manifest or in per-unit raw files.  This sink writes one line per
structured event instead, so the log and ``events.jsonl`` cannot disagree,
and the TUI's log pane draws the very same lines with a local clock.

The grammar is fixed-width for the first columns so ``grep`` and ``cut`` work:

    <UTC ISO-8601 ms>  <LEVEL:5>  <phase:13>  <tool/unit:32>  <status:9>  <message>  key=value ...
       | continuation: error excerpt lines, argv, cwd

``output`` rows never reach the file (they are the analyzers' own streams,
kept raw per unit); heartbeats and LLM steps reach it only at
``[run] log_level = "debug"``.  The last line of a finished run is always the
run's final status, because the runner emits it as the last event.
"""
from __future__ import annotations

import math
import shlex
import threading
import time
from pathlib import Path
from typing import IO, Any

from .analysis import AnalysisEvent
from .events import RUN_DIRECTORY_PHASE
from .progress import single_line
from .tools.common import is_diagnostic

LOG_PATH = ("logs", "runner.log")
LEVELS: tuple[str, ...] = ("debug", "info", "warning", "error")
_RANK = {name: index for index, name in enumerate(LEVELS)}
_LABEL = {"debug": "DEBUG", "info": "INFO", "warning": "WARN", "error": "ERROR"}

ERROR_STATUSES = frozenset({
    "failed", "timed_out", "interrupted", "missing", "incompatible", "breaker_open", "expired",
})
WARNING_STATUSES = frozenset({
    "partial", "unscheduled", "skipped", "paused", "stopping", "rejected", "degraded",
})
DEBUG_STATUSES = frozenset({"heartbeat", "step"})

# Keys shown as key=value, in this order, before every other scalar; the
# right-hand name is what the log prints.
_KEY_ORDER: tuple[tuple[str, str], ...] = (
    ("index", "index"), ("path", "path"), ("label", "label"), ("attempt", "attempt"),
    ("duration_seconds", "duration"), ("exit_code", "exit"), ("failure_class", "class"),
    ("analysis_reached", "analysis_reached"), ("valid_report", "valid_report"),
    ("count", "count"), ("reason", "reason"),
)
# Rendered as continuation lines, never inline.
_CONTINUATION_KEYS = frozenset({"error_excerpt", "argv", "cwd"})
_SKIPPED_KEYS = frozenset({"total", "message", "dir"})
MAX_VALUE_CHARS = 200
MAX_LIST_ITEMS = 8
MAX_MAPPING_ITEMS = 32
# An argv longer than this keeps its head and its tail: the tail is where
# the one argument that varies per unit -- the file -- lives.
MAX_ARGV_CHARS = 600
_ARGV_TAIL_CHARS = 200
# Lines that frame the run are written whatever the level: without them a
# log at "warning" would have no header and no verdict.
_FRAME = frozenset({("run", "created"), ("analysis", "started"), ("analysis", "finished"), ("analysis", "interrupted")})


def level_of(event: AnalysisEvent) -> str:
    """The severity a line carries, derived from the phase and status words."""
    if event.phase == "output" or event.status in DEBUG_STATUSES:
        return "debug"
    if event.phase == "analysis" and event.status in {"finished", "interrupted"}:
        # The verdict is graded by the exit code it announces.
        code = (event.data or {}).get("exit_code") if isinstance(event.data, dict) else None
        if code in (0, None) and event.status == "finished":
            return "info"
        return "warning" if code in (1, 10) else "error"
    if event.status in ERROR_STATUSES:
        return "error"
    if event.status in WARNING_STATUSES:
        return "warning"
    if event.phase == "discovery" and event.status == "info":
        # The compile-database hint: the run continues, but degraded.
        return "warning"
    return "info"


def format_line(event: AnalysisEvent, *, local: bool = False, cwd: bool = True) -> str:
    """One event as its log line(s), continuation lines included.

    ``local`` swaps the UTC ISO stamp for a local ``HH:MM:SS`` clock, which is
    what the TUI pane shows; the columns after it are identical.  ``cwd``
    lets a writer that has already named the working directory skip the
    repetition.  Never raises: a line the formatter cannot make is still a
    line, because the producer thread behind it must not die of a log.
    """
    try:
        return _format_line(event, local=local, cwd=cwd)
    except Exception as exc:  # noqa: BLE001 - the log must not take the run down
        return f"{_stamp(0.0, local)}  ERROR  runlog         -                                 unformattable  {single_line(repr(event))[:400]}  error={_quote(f'{type(exc).__name__}: {exc}')}"


def _stamp(timestamp: Any, local: bool) -> str:
    value = float(timestamp) if isinstance(timestamp, (int, float)) and math.isfinite(float(timestamp)) else 0.0
    value = max(0.0, value)
    if local:
        return time.strftime("%H:%M:%S", time.localtime(value))
    seconds = int(value)
    millis = min(999, int(round((value - seconds) * 1000)))
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(seconds)) + f".{millis:03d}Z"


def _format_line(event: AnalysisEvent, *, local: bool, cwd: bool) -> str:
    stamp = _stamp(event.timestamp, local)
    level = _LABEL[level_of(event)]
    who = single_line(event.tool or "-")
    if event.unit:
        who = f"{who}/{single_line(event.unit)}"
    head = f"{stamp}  {level:<5}  {single_line(event.phase):<13}  {who:<32}  {single_line(event.status):<9}"
    message = single_line(event.message)
    data = event.data if isinstance(event.data, dict) else {}
    pairs = _pairs(data)
    parts = [head]
    if message:
        parts.append(message)
    if pairs:
        parts.append(" ".join(pairs))
    lines = ["  ".join(parts)]
    excerpt = data.get("error_excerpt")
    if isinstance(excerpt, list):
        lines.extend(f"   | {single_line(str(item))[:MAX_VALUE_CHARS * 2]}" for item in excerpt[:10])
    argv = data.get("argv")
    if isinstance(argv, list) and argv:
        joined = single_line(shlex.join(str(item) for item in argv))
        if len(joined) > MAX_ARGV_CHARS:
            joined = joined[: MAX_ARGV_CHARS - _ARGV_TAIL_CHARS] + " … " + joined[-_ARGV_TAIL_CHARS:]
        lines.append(f"   | argv: {joined}")
    if cwd and data.get("cwd"):
        lines.append(f"   | cwd:  {single_line(str(data['cwd']))}")
    return "\n".join(lines)


def _pairs(data: dict[str, Any]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for key, name in _KEY_ORDER:
        if key in data and data[key] is not None:
            seen.add(key)
            if key == "index" and data.get("total") is not None:
                ordered.append(f"index={data['index']}/{data['total']}")
            else:
                ordered.append(f"{name}={_value(key, data[key])}")
    for key in sorted(data, key=str):
        if key in seen or key in _CONTINUATION_KEYS or key in _SKIPPED_KEYS or data[key] is None:
            continue
        ordered.append(f"{single_line(str(key))}={_value(str(key), data[key])}")
    return ordered


def _value(key: str, value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if key == "duration_seconds" and isinstance(value, (int, float)):
        return f"{value:.2f}s"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        items = [_flat(item) for item in value[:MAX_LIST_ITEMS]]
        text = ", ".join(items) + (f", …(+{len(value) - MAX_LIST_ITEMS})" if len(value) > MAX_LIST_ITEMS else "")
        return _quote(text)
    if isinstance(value, dict):
        return _quote(_flat(value))
    return _quote(single_line(str(value)))


def _flat(value: Any) -> str:
    """One list item or mapping as prose: ``k:v k:v`` for a mapping, else its text."""
    if isinstance(value, dict):
        items = list(value.items())
        text = " ".join(f"{k}:{single_line(str(v))}" for k, v in items[:MAX_MAPPING_ITEMS])
        return text + (f" …(+{len(items) - MAX_MAPPING_ITEMS})" if len(items) > MAX_MAPPING_ITEMS else "")
    return single_line(str(value))


def _quote(text: str) -> str:
    """Quote for a reader and for ``grep``, not for a shell.

    Single quotes only when the value has whitespace or a quote of its own;
    inner single quotes become a typographic apostrophe rather than the
    shell's ``'"'"'`` dance, which is unreadable in a log.
    """
    text = text[:MAX_VALUE_CHARS]
    if not text:
        return "''"
    if not any(char.isspace() or char in "'\"" for char in text):
        return text
    return "'" + text.replace("'", "\u2019") + "'"


def error_excerpt(text: str, limit: int = 6) -> list[str]:
    """The lines worth quoting from a tool's output: diagnostics first, else the tail."""
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    diagnostics = [line for line in lines if is_diagnostic(line)]
    chosen = diagnostics[:limit] if diagnostics else lines[-limit:]
    return [single_line(line)[:MAX_VALUE_CHARS * 2] for line in chosen]


class RunLogger:
    """The file sink: opens on ``run/created`` like the JSONL log, buffers before."""

    def __init__(self, level: str = "info", path: Path | None = None) -> None:
        if level not in _RANK:
            raise ValueError(f"unknown log level {level!r}")
        self._threshold = _RANK[level]
        self._lock = threading.Lock()
        self._pending: list[AnalysisEvent] = []
        self._stream: IO[str] | None = None
        self._last_cwd: dict[str, str] = {}
        self.path: Path | None = None
        if path is not None:
            self._open(path)

    def __call__(self, event: AnalysisEvent) -> None:
        with self._lock:
            if self._stream is None and (event.phase, event.status) == RUN_DIRECTORY_PHASE:
                self._open(Path(event.message).joinpath(*LOG_PATH))
            if self._stream is None:
                self._pending.append(event)
                return
            self._write(event)

    def _open(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = path.open("a", encoding="utf-8")
        self.path = path
        for event in self._pending:
            self._write(event)
        self._pending.clear()

    def _write(self, event: AnalysisEvent) -> None:
        if self._stream is None or event.phase == "output":
            return
        framing = (event.phase, event.status) in _FRAME
        if not framing and _RANK[level_of(event)] < self._threshold:
            return
        # The working directory is one fact per tool, not one per unit.
        cwd = (event.data or {}).get("cwd") if isinstance(event.data, dict) else None
        repeat = bool(cwd) and self._last_cwd.get(str(event.tool)) == cwd
        if cwd:
            self._last_cwd[str(event.tool)] = str(cwd)
        try:
            self._stream.write(format_line(event, cwd=not repeat) + "\n")
            self._stream.flush()
        except (OSError, ValueError):
            # A full disk or a closed handle must not stop the analyzers.
            return

    def close(self) -> None:
        with self._lock:
            if self._stream is not None:
                self._stream.close()
                self._stream = None
            self._pending.clear()

    def __enter__(self) -> RunLogger:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

from __future__ import annotations

import os
import sys
import threading
import time
from typing import TextIO


_BRAILLE_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
_ASCII_FRAMES = ("|", "/", "-", "\\")


class ProgressDisplay:
    """Thread-safe line logging with a TTY-only activity spinner.

    Durable progress messages keep their existing one-line format. Between
    those messages, an animated status line makes long analyzer invocations
    visibly alive. Redirected stderr, CI captures, and dumb terminals never
    receive carriage returns or ANSI control sequences.
    """

    def __init__(self, stream: TextIO | None = None, interval_seconds: float = 0.12):
        self._stream = stream or sys.stderr
        self._interval = max(0.02, interval_seconds)
        self._enabled = _supports_animation(self._stream)
        self._frames = _frames_for(self._stream)
        self._unicode = self._frames is _BRAILLE_FRAMES
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._message = "preparing analysis"
        self._started = 0.0
        self._frame_index = 0
        self._drawn = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    def start(self, message: str = "preparing analysis") -> None:
        if not self._enabled or self._thread is not None:
            return
        self._message = _single_line(message)
        self._started = time.monotonic()
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._animate,
            name="code-analyzer-progress",
            daemon=True,
        )
        self._thread.start()

    def emit(self, message: str) -> None:
        message = _single_line(message)
        with self._lock:
            if self._enabled:
                self._clear_locked()
            self._stream.write(f"[code-analyzer] {message}\n")
            self._stream.flush()
            self._message = message

    def close(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.5, self._interval * 3))
        with self._lock:
            if self._enabled:
                self._clear_locked()
                self._stream.flush()
        self._thread = None

    def __enter__(self) -> ProgressDisplay:
        self.start()
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def _animate(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                self._draw_locked()
            self._stop.wait(self._interval)

    def _draw_locked(self) -> None:
        elapsed = max(0, int(time.monotonic() - self._started))
        minutes, seconds = divmod(elapsed, 60)
        frame = self._frames[self._frame_index % len(self._frames)]
        self._frame_index += 1
        separator = " · " if self._unicode else " | "
        status = f"[code-analyzer] {frame} active {minutes:02d}:{seconds:02d}{separator}{self._message}"
        width = _terminal_width(self._stream)
        if len(status) >= width:
            marker = "…" if self._unicode else "..."
            status = status[: max(1, width - len(marker) - 1)] + marker
        self._stream.write("\r\x1b[2K" + status)
        self._stream.flush()
        self._drawn = True

    def _clear_locked(self) -> None:
        if self._drawn:
            self._stream.write("\r\x1b[2K")
            self._drawn = False


def _supports_animation(stream: TextIO) -> bool:
    if os.environ.get("CODE_ANALYZER_NO_ANIMATION", "").strip().lower() in {"1", "true", "yes", "on"}:
        return False
    if os.environ.get("TERM", "").strip().lower() == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, OSError):
        return False


def _frames_for(stream: TextIO) -> tuple[str, ...]:
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        "".join(_BRAILLE_FRAMES).encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return _ASCII_FRAMES
    return _BRAILLE_FRAMES


def _terminal_width(stream: TextIO) -> int:
    try:
        return max(40, os.get_terminal_size(stream.fileno()).columns)
    except (AttributeError, OSError, ValueError):
        return 120


def _single_line(message: str) -> str:
    return " ".join(str(message).replace("\r", " ").replace("\n", " ").split())

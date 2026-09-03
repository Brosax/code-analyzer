"""What the operator asked for, and what came back -- one line per fact.

The same kind of thing ``events.jsonl`` is, for the other half of the run: a
progress log, not evidence.  Every fact a report rests on is already in
``manifest.json`` and the producers' native reports; this file records the
conversation that led there -- what was typed, how it was read, what was
confirmed, which report directory came out -- so that "what did I actually do
last night" has an answer.

It lives outside every run directory, because one conversation can start zero
runs or five, and writing the operator's own words next to a shareable artifact
would be the wrong place for them.  Like ``events.jsonl`` it never enters the
archive and is never an artifact.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import IO, Any

from .persist import jsonl_bytes
from .progress import single_line

SESSIONS_DIRECTORY = Path.home() / ".code-analyzer" / "sessions"
# Enough to read back a session; a prompt or an answer is bounded because a
# pasted stack trace should not become the whole file.
MAX_TEXT = 4000


def session_path(root: Path | None = None, *, now: float | None = None) -> Path:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now if now is not None else time.time()))
    return (root or SESSIONS_DIRECTORY) / f"{stamp}.jsonl"


class Journal:
    """One session's record.  Every failure to write is survivable."""

    def __init__(self, path: Path | None = None, *, root: Path | None = None) -> None:
        self.path = path if path is not None else session_path(root)
        self._stream: IO[bytes] | None = None
        self.disabled_reason = ""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._stream = self.path.open("ab")
        except OSError as exc:
            # A journal is a convenience.  A home directory that cannot be
            # written must not stop somebody scanning a tree.
            self.disabled_reason = str(exc)
            self._stream = None

    @property
    def enabled(self) -> bool:
        return self._stream is not None

    def write(self, record_type: str, /, **fields: Any) -> None:
        if self._stream is None:
            return
        record = {"t": record_type, "at": round(time.time(), 3), **{
            key: (single_line(value)[:MAX_TEXT] if isinstance(value, str) else value)
            for key, value in fields.items()
        }}
        try:
            self._stream.write(jsonl_bytes(record))
            self._stream.flush()
        except OSError as exc:
            self.disabled_reason = str(exc)
            self.close()

    # The four things worth reading back.

    def said(self, text: str) -> None:
        self.write("user", text=text)

    def read_as(self, reading: str, action: str = "", argv: tuple[str, ...] = (), by: str = "parser") -> None:
        self.write("intent", reading=reading, action=action, argv=list(argv), by=by)

    def answered(self, question_id: str, answer: str, *, refused: bool = False) -> None:
        self.write("answer", question=question_id, answer=answer, refused=refused)

    def proposed(self, steps: Any, dropped: Any, unclear: str, seconds: Any, model: Any) -> None:
        """What the model suggested, before anyone ticked anything."""
        def label(step: Any) -> str:
            shown = getattr(step, "label", None)
            return shown() if callable(shown) else str(step)

        self.write("proposal", model=str(model or ""), seconds=seconds,
                   steps=[label(step) for step in steps or []],
                   dropped=list(dropped or [])[:20], unclear=unclear or "")

    def auto_ran(self, action: str, subject: Any, reason: str) -> None:
        """Something ran without a second human beat; the permission is recorded.

        An unattended act must be explicable afterwards, so the clause that
        permitted it is written down rather than inferred from the registry as
        it stands weeks later.
        """
        self.write("auto", action=action, subject=str(subject) if subject else None, reason=reason)

    def finished(self, action: str, exit_code: int, report_directory: Any = None) -> None:
        self.write("result", action=action, exit_code=exit_code,
                   run=str(report_directory) if report_directory else None)

    def close(self) -> None:
        stream, self._stream = self._stream, None
        if stream is not None:
            try:
                stream.close()
            except OSError:
                pass

    def __enter__(self) -> Journal:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def read_session(path: Path) -> list[dict[str, Any]]:
    """Replay one session's records, skipping anything unreadable."""
    import json

    out: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return out
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict):
            out.append(value)
    return out


def recent_sessions(root: Path | None = None, limit: int = 20) -> list[Path]:
    directory = root or SESSIONS_DIRECTORY
    try:
        paths = sorted(directory.glob("*.jsonl"), key=lambda item: item.name, reverse=True)
    except OSError:
        return []
    return paths[:limit]


def disabled_by_env() -> bool:
    """``CODE_ANALYZER_NO_JOURNAL=1`` keeps the conversation out of the home directory."""
    return os.environ.get("CODE_ANALYZER_NO_JOURNAL", "").strip().lower() in {"1", "true", "yes", "on"}

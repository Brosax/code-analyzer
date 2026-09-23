"""Every model exchange, kept as evidence.

One directory per request, numbered in the order requests were *sent*:

    0007/request.json    the body, byte for byte what went on the wire
    0007/response.raw    the stream, byte for byte what came back
    0007/reply.json      the parsed reply (text, tool calls, usage) -- stable fields only
    0007/meta.json       purpose, endpoint, prompt_sha256, timings, error

``request.json`` is written *before* the request is sent, so a request that
hangs, is cancelled or kills the process still left a record of what was
asked.  Timings live only in meta.json, keeping the other files comparable
across reruns.  A credential never reaches disk: the recorder is given the
secret to redact, and the client never puts it in the body anyway.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from ..persist import json_bytes


class Recorder:
    def __init__(self, directory: Path, *, secret: str = "") -> None:
        self.directory = directory
        self._secret = secret.encode("utf-8") if len(secret) >= 8 else b""
        self._lock = threading.Lock()
        self._next = _first_free(directory)

    def begin(self, payload: bytes, meta: dict[str, Any]) -> Exchange:
        # Several clients record into one evaluation's model/ at once (the conversation, a review job, an
        # extraction), each with its own counter: the directory is claimed atomically and a number another
        # recorder took first is skipped, never shared.
        self.directory.mkdir(parents=True, exist_ok=True)
        with self._lock:
            while True:
                number = self._next
                path = self.directory / f"{number:04d}"
                try:
                    path.mkdir(exist_ok=False)
                except FileExistsError:
                    self._next = max(number + 1, _first_free(self.directory))
                    continue
                self._next = number + 1
                break
        _write(path / "request.json", self._redact(payload))
        return Exchange(self, path, dict(meta))

    def _redact(self, data: bytes) -> bytes:
        return data.replace(self._secret, b"<SECRET>") if self._secret else data


class Exchange:
    def __init__(self, recorder: Recorder, path: Path, meta: dict[str, Any]) -> None:
        self.recorder = recorder
        self.path = path
        self.meta = meta
        _write(path / "meta.json", json_bytes({**meta, "state": "sent"}))

    def finish(self, raw: bytes, reply: dict[str, Any] | None, error: dict[str, Any] | None,
               timing: dict[str, Any]) -> None:
        redact = self.recorder._redact  # noqa: SLF001 - same module family
        _write(self.path / "response.raw", redact(raw))
        if reply is not None:
            _write(self.path / "reply.json", redact(json_bytes(reply)))
        state = "error" if error else "complete"
        _write(self.path / "meta.json", redact(json_bytes({**self.meta, "state": state, "error": error, **timing})))


def _first_free(directory: Path) -> int:
    if not directory.is_dir():
        return 1
    numbers = [int(p.name) for p in directory.iterdir() if p.is_dir() and p.name.isdigit()]
    return max(numbers, default=0) + 1


def _write(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)

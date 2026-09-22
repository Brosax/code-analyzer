"""A transport that replays bytes instead of opening a socket.

Probe runs record every real exchange (model/record.py); a recorded
``response.raw`` can be fed straight back through here, so the client's
parsing is tested against what the GPU host actually sent.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

from code_analyzer.model.client import Cancelled, CancelToken, WireRequest, WireResponse


def sse(*chunks: dict[str, Any], done: bool = True) -> bytes:
    lines = [b"data: " + json.dumps(chunk, ensure_ascii=False).encode() + b"\n\n" for chunk in chunks]
    if done:
        lines.append(b"data: [DONE]\n\n")
    return b"".join(lines)


def ndjson(*chunks: dict[str, Any]) -> bytes:
    return b"".join(json.dumps(chunk, ensure_ascii=False).encode() + b"\n" for chunk in chunks)


def delta(**fields: Any) -> dict[str, Any]:
    finish = fields.pop("finish_reason", None)
    return {"choices": [{"index": 0, "delta": fields, "finish_reason": finish}]}


class FakeTransport:
    """Answers each request with the next scripted ``(status, body)``; records what it was sent."""

    def __init__(self, *responses: tuple[int, bytes] | bytes, block: bool = False) -> None:
        self.responses = [r if isinstance(r, tuple) else (200, r) for r in responses]
        self.requests: list[WireRequest] = []
        self.block = block
        self.before_send: Any = None

    @property
    def bodies(self) -> list[dict[str, Any]]:
        return [json.loads(r.body) for r in self.requests]

    def __call__(self, request: WireRequest, cancel: CancelToken) -> WireResponse:
        if self.before_send is not None:
            self.before_send(request)
        self.requests.append(request)
        if self.block:
            def blocked() -> Iterator[bytes]:
                cancel.wait()
                raise Cancelled(cancel.reason)
            return WireResponse(200, blocked())
        status, body = self.responses.pop(0)
        return WireResponse(status, iter(body.splitlines(keepends=True)))

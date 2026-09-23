"""A stdlib chat client for OpenAI-compatible and Ollama-native endpoints.

Why not a framework: the previous runtime spawned a Node process per call,
could not be cancelled before the first token, hid the bytes it sent, and
turned a 3-8 s warm turn into 23-160 s (measured 2026-09-22).  What a review
agent needs from a client is small and has to be exact:

* the request body is serialised once, recorded, and those same bytes are
  sent -- so ``prompt_sha256`` names what the model really read;
* every request passes ``egress.check`` at send time, so no caller can reach a
  host the evaluation forbids;
* ``CODE_ANALYZER_NO_MODEL`` refuses before any socket exists;
* cancellation shuts the socket down from another thread, which is the only
  thing that interrupts a blocked read during a long prefill;
* streamed text, reasoning and tool calls are assembled here, once, for both
  wire protocols.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..core.text import single_line
from ..defaults import endpoint_class
from ..errors import UserError
from ..persist import json_bytes

NO_MODEL_ENV = "CODE_ANALYZER_NO_MODEL"
TRANSPORTS = ("v1", "api_chat")
TOOL_MODES = ("native", "text")
# Failure codes after which trying again can help: nothing reached a model,
# or the provider asked us to slow down.
RETRYABLE = frozenset({"TRANSPORT", "TIMEOUT", "RATE_LIMIT", "SERVER"})
_ERROR_EXCERPT = 500
# One stream line may not exceed this; a server that never sends a newline
# must not make the client buffer without bound.
_MAX_LINE = 4 * 1024 * 1024
_MAX_ERROR_BODY = 64 * 1024
# Connecting is bounded separately: a black-holed host must not hold a turn
# for the whole read timeout, and a cancel cannot interrupt connect().
CONNECT_TIMEOUT = 15.0


def disabled_by_env() -> bool:
    """``CODE_ANALYZER_NO_MODEL=1``: no socket, no provider, for tests and air gaps."""
    return os.environ.get(NO_MODEL_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


class ModelError(Exception):
    """A request that did not produce a reply.  ``code`` is stable; ``message`` is for people."""

    def __init__(self, code: str, message: str, *, status: int | None = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.status = status

    @property
    def retryable(self) -> bool:
        return self.code in RETRYABLE

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "status": self.status, "retryable": self.retryable}


class ModelDisabled(ModelError):
    def __init__(self) -> None:
        super().__init__("DISABLED", f"{NO_MODEL_ENV}=1 turns the model off")


class Cancelled(ModelError):
    def __init__(self, reason: str = "cancelled") -> None:
        super().__init__("CANCELLED", reason)
        self.reason = reason


@dataclass(frozen=True)
class Endpoint:
    """Where requests go and how they are spoken.  Never carries a credential."""

    base_url: str
    model: str
    kind: str = "local"          # "local" | "public" -> defaults.ENDPOINT_CLASSES
    api_key_env: str = ""        # the variable's name
    transport: str = "v1"        # "v1" (SSE) | "api_chat" (Ollama NDJSON)
    tool_mode: str = "native"    # "native" | "text"

    def __post_init__(self) -> None:
        split = urlsplit(self.base_url)
        if split.scheme not in {"http", "https"} or not split.hostname:
            raise UserError(f"model endpoint must be an http(s) URL, got {self.base_url!r}")
        try:
            _ = split.port  # urlsplit validates the port lazily
        except ValueError as error:
            raise UserError(f"model endpoint has an invalid port: {self.base_url!r}") from error
        if split.username or split.password:
            raise UserError("model endpoint must not carry credentials; name an environment variable instead")
        if self.transport not in TRANSPORTS:
            raise UserError(f"transport must be one of {TRANSPORTS}, got {self.transport!r}")
        if self.tool_mode not in TOOL_MODES:
            raise UserError(f"tool_mode must be one of {TOOL_MODES}, got {self.tool_mode!r}")
        endpoint_class(self.kind)
        if not self.model:
            raise UserError("model endpoint needs a model name")

    @property
    def scheme(self) -> str:
        return urlsplit(self.base_url).scheme

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def port(self) -> int:
        split = urlsplit(self.base_url)
        return split.port or (443 if split.scheme == "https" else 80)

    @property
    def root(self) -> str:
        """The server root: ``/v1`` stripped, where Ollama's ``/api/*`` lives."""
        path = urlsplit(self.base_url).path.rstrip("/")
        return path[:-3] if path.endswith("/v1") else path

    @property
    def v1_path(self) -> str:
        path = urlsplit(self.base_url).path.rstrip("/")
        return path if path.endswith("/v1") else f"{path}/v1"

    def describe(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url, "model": self.model, "kind": self.kind,
            "transport": self.transport, "tool_mode": self.tool_mode,
        }


class CancelToken:
    """Set from any thread; interrupts a blocked socket read, not just the next poll."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._hooks: list[Callable[[], None]] = []
        self.reason = ""

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self, reason: str = "cancelled") -> None:
        with self._lock:
            if self._event.is_set():
                return
            self.reason = reason
            self._event.set()
            hooks = list(self._hooks)
        for hook in hooks:
            try:
                hook()
            except Exception:  # noqa: BLE001 - a hook failing must not stop the others
                pass

    def on_cancel(self, hook: Callable[[], None]) -> Callable[[], None]:
        """Register ``hook``; it runs at once if already cancelled.  Returns an unregister."""
        with self._lock:
            if not self._event.is_set():
                self._hooks.append(hook)
                return lambda: self._remove(hook)
        hook()
        return lambda: None

    def _remove(self, hook: Callable[[], None]) -> None:
        with self._lock:
            if hook in self._hooks:
                self._hooks.remove(hook)

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: str  # the JSON text exactly as the model produced it


@dataclass
class Reply:
    text: str
    reasoning: str
    tool_calls: list[ToolCall]
    finish_reason: str
    usage: dict[str, int]
    status: int
    first_token_seconds: float | None
    duration_seconds: float
    prompt_sha256: str
    raw: bytes = field(repr=False, default=b"")

    def summary(self) -> dict[str, Any]:
        """The parsed reply as evidence: stable fields only, no timing, no raw bytes."""
        return {
            "text": self.text, "reasoning": self.reasoning, "finish_reason": self.finish_reason,
            "tool_calls": [{"id": c.id, "name": c.name, "arguments": c.arguments} for c in self.tool_calls],
            "usage": dict(self.usage), "status": self.status, "prompt_sha256": self.prompt_sha256,
        }


# -- transport ------------------------------------------------------------------

@dataclass(frozen=True)
class WireRequest:
    scheme: str
    connect_host: str   # where the socket goes: the validated address whenever egress resolved one
    host_header: str
    port: int
    path: str
    body: bytes
    headers: dict[str, str]
    timeout: float
    tls_name: str = ""  # https only: the name the certificate must carry (SNI and verification)


@dataclass
class WireResponse:
    status: int
    lines: Iterator[bytes]
    close: Callable[[], None] = lambda: None


Transport = Callable[[WireRequest, CancelToken], WireResponse]


def http_transport(request: WireRequest, cancel: CancelToken) -> WireResponse:
    """POST over http.client, streaming the body line by line.

    The socket always goes to ``connect_host`` -- for a pinned host, the
    address egress just validated -- while https still verifies the
    certificate against ``tls_name``.  Connecting a name and letting the
    resolver answer again would reopen the DNS-rebinding hole egress closed.
    """
    name = request.tls_name or request.connect_host
    conn: http.client.HTTPConnection
    if request.scheme == "https":
        conn = http.client.HTTPSConnection(name, request.port, timeout=min(request.timeout, CONNECT_TIMEOUT))
    else:
        conn = http.client.HTTPConnection(name, request.port, timeout=min(request.timeout, CONNECT_TIMEOUT))
    address = (request.connect_host, request.port)
    conn._create_connection = (  # type: ignore[attr-defined]  # noqa: SLF001 - the documented seam
        lambda _address, timeout, source=None: socket.create_connection(address, timeout, source))

    # Hold the socket itself: http.client drops conn.sock once a response
    # that will close is read (any HTTP/1.0 server), after which a hook that
    # looked it up through the connection would find nothing to shut down.
    held: list[socket.socket] = []

    def shut() -> None:
        for sock in held:
            try:
                # The base-class method on purpose: SSLSocket.shutdown would
                # tear down the TLS object under the thread reading from it.
                socket.socket.shutdown(sock, socket.SHUT_RDWR)
            except OSError:
                pass

    unregister = cancel.on_cancel(shut)
    headers = {**request.headers, "Host": request.host_header}
    try:
        conn.connect()
        if conn.sock is not None:
            conn.sock.settimeout(request.timeout)
            held.append(conn.sock)
        if cancel.cancelled:
            shut()
        conn.request("POST", request.path, body=request.body, headers=headers)
        response = conn.getresponse()
    except (OSError, http.client.HTTPException, ValueError) as error:
        unregister()
        conn.close()
        if cancel.cancelled:
            raise Cancelled(cancel.reason) from None
        if isinstance(error, (TimeoutError, socket.timeout)):
            raise ModelError("TIMEOUT", f"no response within {request.timeout:.0f}s") from None
        if isinstance(error, ValueError):
            # http.client refuses an illegal header value; never echo it.
            raise ModelError("PROVIDER", "the request could not be sent: an illegal header value") from None
        raise ModelError("TRANSPORT", single_line(str(error)) or type(error).__name__) from None

    def lines() -> Iterator[bytes]:
        try:
            while True:
                try:
                    line = response.readline(_MAX_LINE + 1)
                except (OSError, http.client.HTTPException) as error:
                    if cancel.cancelled:
                        raise Cancelled(cancel.reason) from None
                    if isinstance(error, (TimeoutError, socket.timeout)):
                        raise ModelError("TIMEOUT", f"stream idle for {request.timeout:.0f}s") from None
                    raise ModelError("TRANSPORT", single_line(str(error)) or type(error).__name__) from None
                if not line:
                    if cancel.cancelled:
                        raise Cancelled(cancel.reason)
                    return
                if len(line) > _MAX_LINE:
                    raise ModelError("PROTOCOL", f"a stream line exceeded {_MAX_LINE} bytes")
                if not line.endswith(b"\n") and cancel.cancelled:
                    raise Cancelled(cancel.reason)  # the socket was shut down mid-line
                yield line
        finally:
            unregister()
            conn.close()

    def close() -> None:
        unregister()
        conn.close()

    return WireResponse(response.status, lines(), close)


# -- the client -----------------------------------------------------------------

Egress = Callable[["Endpoint"], "Any"]  # model.egress.check bound to an evaluation
DeltaSink = Callable[[str, str], None]  # (kind, text): kind in {"text", "reasoning", "tool"}


class ModelClient:
    """One endpoint, one transport, optional recorder.  Thread-safe: holds no per-request state."""

    def __init__(self, endpoint: Endpoint, *, transport: Transport = http_transport,
                 recorder: Any = None, egress: Callable[[Endpoint], Any] | None = None) -> None:
        self.endpoint = endpoint
        self.transport = transport
        self.recorder = recorder
        # Resolves the endpoint to a connect target, raising EgressBlocked when
        # the evaluation forbids it.  None means "no evaluation content" (a
        # probe, a model listing): any configured endpoint, resolved plainly.
        self.egress = egress

    # The one entry point.  Everything a conversation, a lens job or a probe
    # sends goes through here.
    def chat(self, messages: list[dict[str, Any]], *, max_tokens: int, tools: list[dict[str, Any]] | None = None,
             tool_choice: str | None = None, temperature: float = 0.0,
             response_format: dict[str, Any] | None = None, num_ctx: int | None = None,
             cancel: CancelToken | None = None, on_delta: DeltaSink | None = None,
             timeout: float = 300.0, purpose: str = "chat") -> Reply:
        if disabled_by_env():
            raise ModelDisabled()
        # The caller's token is never cancelled by this call: a timeout cancels
        # an inner token, so the caller can retry a retryable TIMEOUT with the
        # token it already holds.  The caller cancelling still reaches the socket.
        outer = cancel or CancelToken()
        token = CancelToken()
        unlink = outer.on_cancel(lambda: token.cancel(outer.reason or "cancelled"))
        body = self.body(messages, max_tokens=max_tokens, tools=tools, tool_choice=tool_choice,
                         temperature=temperature, response_format=response_format, num_ctx=num_ctx)
        payload = json_bytes(body)
        prompt_sha = hashlib.sha256(payload).hexdigest()
        path = f"{self.endpoint.v1_path}/chat/completions" if self.endpoint.transport == "v1" \
            else f"{self.endpoint.root}/api/chat"
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream, application/x-ndjson"}
        try:
            target = self._target()
            secret = self._credential()
        except BaseException:
            unlink()
            raise
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        exchange = self.recorder.begin(payload, {"purpose": purpose, "endpoint": self.endpoint.describe(),
                                                 "prompt_sha256": prompt_sha}) if self.recorder else None
        started = time.monotonic()
        timed_out = threading.Event()

        def expire() -> None:
            timed_out.set()
            token.cancel("timeout")

        timer = threading.Timer(timeout, expire)
        timer.daemon = True
        timer.start()
        raw = bytearray()
        response: WireResponse | None = None
        try:
            request = WireRequest(target.scheme, target.connect_host, target.host_header, target.port,
                                  path, payload, headers, timeout, getattr(target, "tls_name", ""))
            response = self.transport(request, token)
            if response.status != 200:
                for line in response.lines:
                    raw += line
                    if len(raw) > _MAX_ERROR_BODY:
                        break
                raise _http_error(response.status, bytes(raw), secret)
            accumulator = _Accumulator(started, on_delta)
            parse = _parse_sse if self.endpoint.transport == "v1" else _parse_ndjson
            parse(response.lines, raw, accumulator)
            if not accumulator.events:
                excerpt = _redact(single_line(bytes(raw[:200]).decode("utf-8", "replace")), secret)
                raise ModelError("PROTOCOL", f"the response is not a stream: {excerpt!r}")
            if not accumulator.completed:
                raise ModelError("TRANSPORT", "the stream ended before the reply was complete")
            reply = accumulator.reply(response.status, prompt_sha, bytes(raw), time.monotonic() - started)
        except Cancelled as error:
            if outer.cancelled:
                failure: ModelError = Cancelled(outer.reason or "cancelled")
            elif timed_out.is_set():
                failure = ModelError("TIMEOUT", f"no complete reply within {timeout:.0f}s")
            else:
                failure = error
            self._finish(exchange, raw, None, failure, started)
            raise failure from None
        except ModelError as error:
            if secret and secret in error.message:
                error = ModelError(error.code, _redact(error.message, secret), status=error.status)
            self._finish(exchange, raw, None, error, started)
            raise error from None
        except BaseException as error:
            self._finish(exchange, raw, None, ModelError("INTERNAL", type(error).__name__), started)
            raise
        finally:
            timer.cancel()
            unlink()
            if response is not None:
                response.close()
        self._finish(exchange, raw, reply, None, started)
        return reply

    def body(self, messages: list[dict[str, Any]], *, max_tokens: int, tools: list[dict[str, Any]] | None = None,
             tool_choice: str | None = None, temperature: float = 0.0,
             response_format: dict[str, Any] | None = None, num_ctx: int | None = None) -> dict[str, Any]:
        """The request body, exactly as it will be serialised and sent."""
        ep = self.endpoint
        settings = endpoint_class(ep.kind)
        send_tools = bool(tools) and ep.tool_mode == "native" and tool_choice != "none"
        if ep.transport == "v1":
            body: dict[str, Any] = {
                "model": ep.model, "messages": messages, "stream": True,
                "stream_options": {"include_usage": True}, "temperature": temperature,
                settings["max_tokens_field"]: max_tokens, **settings["reasoning"],
            }
            if bool(tools) and ep.tool_mode == "native":
                # tool_choice "none" is honoured by Ollama's /v1 (measured), so
                # the schemas stay in the prompt and the prefix cache survives.
                body["tools"] = tools
                if tool_choice:
                    body["tool_choice"] = tool_choice
            if response_format:
                body["response_format"] = response_format
            return body
        options: dict[str, Any] = {"temperature": temperature, "num_predict": max_tokens}
        if num_ctx:
            options["num_ctx"] = num_ctx
        body = {"model": ep.model, "messages": [_to_ollama(m) for m in messages], "stream": True,
                "think": False, "options": options}
        if send_tools:
            body["tools"] = tools
        if response_format and isinstance(response_format.get("json_schema"), dict):
            body["format"] = response_format["json_schema"].get("schema", "json")
        return body

    def _target(self) -> Any:
        if self.egress is not None:
            return self.egress(self.endpoint)
        from .egress import open_target
        return open_target(self.endpoint)

    def _credential(self) -> str:
        name = self.endpoint.api_key_env
        if not name:
            return ""
        value = os.environ.get(name, "")
        if not value:
            raise UserError(f"environment variable {name} (the model's api_key_env) is unset or empty")
        if not value.isprintable() or any(c in value for c in "\r\n\0 "):
            # Never echo it: http.client's own error would quote the header.
            raise UserError(f"environment variable {name} holds characters a credential cannot contain")
        return value

    def _finish(self, exchange: Any, raw: bytearray, reply: Reply | None, error: ModelError | None,
                started: float) -> None:
        if exchange is None:
            return
        exchange.finish(bytes(raw), reply.summary() if reply else None, error.as_dict() if error else None,
                        {"duration_seconds": round(time.monotonic() - started, 3),
                         "first_token_seconds": reply.first_token_seconds if reply else None})


def _redact(text: str, secret: str) -> str:
    return text.replace(secret, "<SECRET>") if secret else text


def _http_error(status: int, body: bytes, secret: str) -> ModelError:
    text = body.decode("utf-8", "replace")
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            detail = parsed.get("error", parsed)
            text = str(detail.get("message", json.dumps(detail))) if isinstance(detail, dict) else str(detail)
    except ValueError:
        pass
    text = single_line(_redact(text, secret))[:_ERROR_EXCERPT]
    code = "RATE_LIMIT" if status == 429 else "SERVER" if status >= 500 else "PROVIDER"
    return ModelError(code, f"HTTP {status}: {text}", status=status)


# -- stream assembly --------------------------------------------------------------

class _Accumulator:
    def __init__(self, started: float, on_delta: DeltaSink | None) -> None:
        self.started = started
        self.on_delta = on_delta
        self.text: list[str] = []
        self.reasoning: list[str] = []
        self.calls: list[dict[str, str]] = []
        self.by_index: dict[int, int] = {}
        self.finish = ""
        self.usage: dict[str, int] = {}
        self.first: float | None = None
        # How many protocol events arrived, and whether the server said the
        # reply was over.  A stream that just stops is not a complete reply.
        self.events = 0
        self.completed = False

    def _mark(self) -> None:
        if self.first is None:
            self.first = round(time.monotonic() - self.started, 3)

    def add_text(self, value: Any) -> None:
        if isinstance(value, str) and value:
            self._mark()
            self.text.append(value)
            if self.on_delta:
                self.on_delta("text", value)

    def add_reasoning(self, value: Any) -> None:
        if isinstance(value, str) and value:
            self._mark()
            self.reasoning.append(value)
            if self.on_delta:
                self.on_delta("reasoning", value)

    def add_call_delta(self, delta: dict[str, Any], position: int) -> None:
        """OpenAI streams one call in pieces keyed by index; Ollama sends it whole.

        A delta whose id differs from the call already at its index starts a
        new call, so a server that sends two complete calls both at index 0
        does not have their arguments concatenated.
        """
        self._mark()
        index = delta.get("index", position)
        index = index if isinstance(index, int) else position
        function = delta.get("function") if isinstance(delta.get("function"), dict) else {}
        call_id = str(delta.get("id") or "")
        slot = self.by_index.get(index)
        if slot is not None and call_id and self.calls[slot]["id"] and self.calls[slot]["id"] != call_id:
            slot = None
        if slot is None:
            self.calls.append({"id": call_id, "name": "", "arguments": ""})
            slot = len(self.calls) - 1
            self.by_index[index] = slot
        call = self.calls[slot]
        if call_id and not call["id"]:
            call["id"] = call_id
        name = function.get("name")
        if isinstance(name, str) and name and name != call["name"]:
            call["name"] += name
            if self.on_delta:
                self.on_delta("tool", name)
        arguments = function.get("arguments")
        if isinstance(arguments, dict):
            call["arguments"] = json.dumps(arguments, ensure_ascii=False, sort_keys=True)
        elif isinstance(arguments, str):
            call["arguments"] += arguments

    def set_usage(self, prompt: Any, completion: Any, cached: Any = None) -> None:
        for key, value in (("prompt_tokens", prompt), ("completion_tokens", completion), ("cached_tokens", cached)):
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                self.usage[key] = value

    def reply(self, status: int, prompt_sha: str, raw: bytes, duration: float) -> Reply:
        calls = [ToolCall(c["id"] or f"call_{i}", c["name"], c["arguments"] or "{}")
                 for i, c in enumerate(self.calls) if c["name"]]
        finish = self.finish or ("tool_calls" if calls else "stop")
        return Reply("".join(self.text), "".join(self.reasoning), calls, finish, self.usage, status,
                     self.first, round(duration, 3), prompt_sha, raw)


def _parse_sse(lines: Iterator[bytes], raw: bytearray, acc: _Accumulator) -> None:
    for line in lines:
        raw += line
        stripped = line.strip()
        if not stripped or stripped.startswith(b":") or not stripped.startswith(b"data:"):
            continue
        payload = stripped[5:].strip()
        acc.events += 1
        if payload == b"[DONE]":
            acc.completed = True
            break
        try:
            chunk = json.loads(payload)
        except ValueError:
            raise ModelError("PROTOCOL", f"unparseable stream chunk: {payload[:120]!r}") from None
        if not isinstance(chunk, dict):
            continue
        if chunk.get("error"):
            error = chunk["error"]
            message = error.get("message") if isinstance(error, dict) else str(error)
            raise ModelError("SERVER", single_line(str(message))[:_ERROR_EXCERPT])
        usage = chunk.get("usage")
        if isinstance(usage, dict):
            details = usage.get("prompt_tokens_details") if isinstance(usage.get("prompt_tokens_details"), dict) else {}
            acc.set_usage(usage.get("prompt_tokens"), usage.get("completion_tokens"), details.get("cached_tokens"))
        for choice in chunk.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else choice.get("message") or {}
            acc.add_reasoning(delta.get("reasoning") or delta.get("reasoning_content"))
            acc.add_text(delta.get("content"))
            for position, call in enumerate(delta.get("tool_calls") or []):
                if isinstance(call, dict):
                    acc.add_call_delta(call, position)
            if choice.get("finish_reason"):
                acc.finish = str(choice["finish_reason"])
                # Keep reading: the usage chunk follows the finish reason.
                acc.completed = True


def _parse_ndjson(lines: Iterator[bytes], raw: bytearray, acc: _Accumulator) -> None:
    for line in lines:
        raw += line
        stripped = line.strip()
        if not stripped:
            continue
        try:
            chunk = json.loads(stripped)
        except ValueError:
            raise ModelError("PROTOCOL", f"unparseable stream line: {stripped[:120]!r}") from None
        if not isinstance(chunk, dict):
            continue
        acc.events += 1
        if chunk.get("error"):
            raise ModelError("SERVER", single_line(str(chunk["error"]))[:_ERROR_EXCERPT])
        message = chunk.get("message") if isinstance(chunk.get("message"), dict) else {}
        acc.add_reasoning(message.get("thinking"))
        acc.add_text(message.get("content"))
        for call in message.get("tool_calls") or []:
            if isinstance(call, dict):
                # Ollama numbers nothing: every call it sends is complete.
                acc.add_call_delta({**call, "index": len(acc.calls)}, len(acc.calls))
        if chunk.get("done"):
            acc.finish = str(chunk.get("done_reason") or "stop")
            acc.set_usage(chunk.get("prompt_eval_count"), chunk.get("eval_count"))
            acc.completed = True


def _to_ollama(message: dict[str, Any]) -> dict[str, Any]:
    """OpenAI message shape -> /api/chat: arguments are objects, tool results carry a name."""
    out = {key: value for key, value in message.items() if key in {"role", "content"}}
    out.setdefault("content", "")
    calls = message.get("tool_calls")
    if calls:
        converted = []
        for call in calls:
            function = call.get("function", {})
            arguments = function.get("arguments", {})
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments or "{}")
                except ValueError:
                    arguments = {}
            converted.append({"function": {"name": function.get("name", ""), "arguments": arguments}})
        out["tool_calls"] = converted
    if message.get("role") == "tool" and message.get("name"):
        out["tool_name"] = message["name"]
    return out

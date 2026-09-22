from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fake_transport import FakeTransport, delta, ndjson, sse

from code_analyzer.errors import UserError
from code_analyzer.model.client import (
    Cancelled,
    CancelToken,
    Endpoint,
    ModelClient,
    ModelDisabled,
    ModelError,
    http_transport,
)
from code_analyzer.model.egress import open_target
from code_analyzer.model.record import Recorder

LOCAL = Endpoint("http://127.0.0.1:11434/v1", "qwen3.8:27b")
MSGS = [{"role": "user", "content": "hi"}]


@pytest.fixture
def model_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_MODEL", raising=False)


def resolved(address: str = "127.0.0.1"):
    return lambda ep: open_target(ep, resolver=lambda h, p: (address,))


def client(transport: FakeTransport, endpoint: Endpoint = LOCAL, **kwargs: object) -> ModelClient:
    return ModelClient(endpoint, transport=transport, egress=resolved(), **kwargs)


def test_no_model_refuses_before_any_transport() -> None:
    transport = FakeTransport(sse(delta(content="x")))
    with pytest.raises(ModelDisabled):
        client(transport).chat(MSGS, max_tokens=10)
    assert transport.requests == []


def test_sse_text_reasoning_usage_and_deltas(model_on: None) -> None:
    seen: list[tuple[str, str]] = []
    transport = FakeTransport(sse(
        delta(reasoning="let me "), delta(content="Hel"), delta(content="lo", finish_reason="stop"),
        {"choices": [], "usage": {"prompt_tokens": 12, "completion_tokens": 3,
                                  "prompt_tokens_details": {"cached_tokens": 8}}},
    ))
    reply = client(transport).chat(MSGS, max_tokens=10, on_delta=lambda k, t: seen.append((k, t)))
    assert reply.text == "Hello" and reply.reasoning == "let me "
    assert reply.finish_reason == "stop"
    assert reply.usage == {"prompt_tokens": 12, "completion_tokens": 3, "cached_tokens": 8}
    assert seen == [("reasoning", "let me "), ("text", "Hel"), ("text", "lo")]
    assert reply.first_token_seconds is not None and len(reply.prompt_sha256) == 64


def test_body_carries_the_local_class_and_is_what_was_sent(model_on: None) -> None:
    transport = FakeTransport(sse(delta(content="ok")))
    tools = [{"type": "function", "function": {"name": "list", "parameters": {"type": "object"}}}]
    reply = client(transport).chat(MSGS, max_tokens=77, tools=tools, tool_choice="none")
    body = transport.bodies[0]
    assert body["reasoning_effort"] == "none" and body["max_tokens"] == 77
    assert body["stream"] is True and body["stream_options"] == {"include_usage": True}
    # "none" keeps the schemas in the prompt so the prefix cache survives.
    assert body["tools"] == tools and body["tool_choice"] == "none"
    request = transport.requests[0]
    assert request.path == "/v1/chat/completions" and request.connect_host == "127.0.0.1"
    import hashlib
    assert hashlib.sha256(request.body).hexdigest() == reply.prompt_sha256


def test_text_mode_sends_no_tools(model_on: None) -> None:
    transport = FakeTransport(sse(delta(content="ok")))
    text_mode = Endpoint(LOCAL.base_url, LOCAL.model, tool_mode="text")
    client(transport, text_mode).chat(MSGS, max_tokens=5, tools=[{"type": "function", "function": {"name": "x"}}])
    assert "tools" not in transport.bodies[0]


def test_public_class_uses_its_own_fields(model_on: None) -> None:
    transport = FakeTransport(sse(delta(content="ok")))
    public = Endpoint("https://api.example.com/v1", "glm", kind="public")
    ModelClient(public, transport=transport, egress=resolved("203.0.113.5")).chat(MSGS, max_tokens=9)
    body = transport.bodies[0]
    assert body["max_completion_tokens"] == 9 and body["reasoning_effort"] == "low"
    # the socket goes to the resolved address; TLS still verifies the name
    request = transport.requests[0]
    assert (request.connect_host, request.tls_name, request.host_header) == ("203.0.113.5", "api.example.com",
                                                                          "api.example.com")


def test_openai_style_tool_call_pieces_assemble(model_on: None) -> None:
    transport = FakeTransport(sse(
        delta(tool_calls=[{"index": 0, "id": "a", "function": {"name": "show", "arguments": ""}}]),
        delta(tool_calls=[{"index": 0, "function": {"arguments": '{"target":'}}]),
        delta(tool_calls=[{"index": 0, "function": {"arguments": '"PV-1"}'}}], finish_reason="tool_calls"),
    ))
    reply = client(transport).chat(MSGS, max_tokens=10)
    assert [(c.id, c.name, json.loads(c.arguments)) for c in reply.tool_calls] == [("a", "show", {"target": "PV-1"})]
    assert reply.finish_reason == "tool_calls"


def test_two_whole_calls_at_the_same_index_stay_two(model_on: None) -> None:
    transport = FakeTransport(sse(
        delta(tool_calls=[{"index": 0, "id": "c1", "function": {"name": "show", "arguments": '{"target":"a"}'}}]),
        delta(tool_calls=[{"index": 0, "id": "c2", "function": {"name": "show", "arguments": '{"target":"b"}'}}]),
    ))
    reply = client(transport).chat(MSGS, max_tokens=10)
    assert [json.loads(c.arguments)["target"] for c in reply.tool_calls] == ["a", "b"]


def test_ollama_native_ndjson(model_on: None) -> None:
    transport = FakeTransport(ndjson(
        {"message": {"role": "assistant", "content": "", "thinking": ""}},
        {"message": {"role": "assistant", "content": "",
                     "tool_calls": [{"function": {"name": "list", "arguments": {"kind": "pv"}}}]}},
        {"message": {"role": "assistant", "content": "done"}, "done": True, "done_reason": "stop",
         "prompt_eval_count": 40, "eval_count": 5},
    ))
    native = Endpoint("http://127.0.0.1:11434/v1", "qwen", transport="api_chat")
    reply = client(transport, native).chat(
        [{"role": "assistant", "content": "", "tool_calls": [
            {"id": "x", "type": "function", "function": {"name": "show", "arguments": '{"target":"J1"}'}}]},
         {"role": "tool", "tool_call_id": "x", "name": "show", "content": "r"}],
        max_tokens=10, num_ctx=24576)
    body = transport.bodies[0]
    assert transport.requests[0].path == "/api/chat"
    assert body["think"] is False and body["options"] == {"temperature": 0.0, "num_predict": 10, "num_ctx": 24576}
    assert body["messages"][0]["tool_calls"][0]["function"]["arguments"] == {"target": "J1"}
    assert body["messages"][1]["tool_name"] == "show"
    assert reply.text == "done" and reply.tool_calls[0].name == "list"
    assert json.loads(reply.tool_calls[0].arguments) == {"kind": "pv"}
    assert reply.usage == {"prompt_tokens": 40, "completion_tokens": 5}
    assert reply.finish_reason == "stop"


@pytest.mark.parametrize(("status", "code", "retryable"), [(500, "SERVER", True), (429, "RATE_LIMIT", True),
                                                           (400, "PROVIDER", False)])
def test_http_errors_are_classified(model_on: None, status: int, code: str, retryable: bool) -> None:
    transport = FakeTransport((status, b'{"error":{"message":"no user query found in messages"}}'))
    with pytest.raises(ModelError) as caught:
        client(transport).chat(MSGS, max_tokens=5)
    assert caught.value.code == code and caught.value.retryable is retryable
    assert "no user query" in caught.value.message and caught.value.status == status


def test_credential_is_sent_but_never_recorded_or_echoed(model_on: None, monkeypatch: pytest.MonkeyPatch,
                                                         tmp_path: Path) -> None:
    monkeypatch.setenv("PUBLIC_KEY", "sk-supersecret-123")
    public = Endpoint("https://api.example.com/v1", "glm", kind="public", api_key_env="PUBLIC_KEY")
    transport = FakeTransport((401, b'{"error":{"message":"bad key sk-supersecret-123"}}'))
    recorder = Recorder(tmp_path, secret="sk-supersecret-123")
    with pytest.raises(ModelError) as caught:
        ModelClient(public, transport=transport, recorder=recorder, egress=resolved()).chat(MSGS, max_tokens=5)
    assert transport.requests[0].headers["Authorization"] == "Bearer sk-supersecret-123"
    assert "supersecret" not in caught.value.message
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert b"supersecret" not in path.read_bytes(), path


def test_missing_credential_is_a_user_error(model_on: None) -> None:
    public = Endpoint("https://api.example.com/v1", "glm", kind="public", api_key_env="NOPE_UNSET_VAR")
    with pytest.raises(UserError):
        ModelClient(public, transport=FakeTransport(sse()), egress=resolved()).chat(MSGS, max_tokens=5)


def test_request_is_on_disk_before_it_is_sent(model_on: None, tmp_path: Path) -> None:
    transport = FakeTransport(sse(delta(content="ok")))
    seen: list[bool] = []
    transport.before_send = lambda request: seen.append((tmp_path / "0001" / "request.json").read_bytes() == request.body)
    reply = client(transport, recorder=Recorder(tmp_path)).chat(MSGS, max_tokens=5, purpose="probe")
    assert seen == [True]
    exchange = tmp_path / "0001"
    assert (exchange / "response.raw").read_bytes().startswith(b"data: ")
    assert json.loads((exchange / "reply.json").read_text())["text"] == "ok"
    meta = json.loads((exchange / "meta.json").read_text())
    assert meta["state"] == "complete" and meta["purpose"] == "probe" and meta["prompt_sha256"] == reply.prompt_sha256


def test_cancel_interrupts_a_blocked_stream(model_on: None, tmp_path: Path) -> None:
    transport = FakeTransport(block=True)
    token = CancelToken()
    threading.Timer(0.05, lambda: token.cancel("operator")).start()
    with pytest.raises(Cancelled) as caught:
        client(transport, recorder=Recorder(tmp_path)).chat(MSGS, max_tokens=5, cancel=token)
    assert caught.value.reason == "operator"
    assert json.loads((tmp_path / "0001" / "meta.json").read_text())["state"] == "error"


def test_timeout_becomes_a_timeout_error(model_on: None) -> None:
    with pytest.raises(ModelError) as caught:
        client(FakeTransport(block=True)).chat(MSGS, max_tokens=5, timeout=0.05)
    assert caught.value.code == "TIMEOUT" and caught.value.retryable


def test_endpoint_rejects_userinfo_and_unknown_modes() -> None:
    with pytest.raises(UserError):
        Endpoint("http://user:pw@host/v1", "m")
    with pytest.raises(UserError):
        Endpoint("http://host/v1", "m", transport="grpc")
    with pytest.raises(UserError):
        Endpoint("ftp://host/v1", "m")
    assert Endpoint("http://h:11434/v1", "m").root == "" and Endpoint("http://h/x/v1", "m").v1_path == "/x/v1"


# -- the real socket path, against a loopback server -------------------------------------

class _Slow(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(sse(delta(content="first"), done=False))
        self.wfile.flush()
        time.sleep(5)  # a long prefill: nothing arrives

    def log_message(self, *args: object) -> None:
        pass


def test_socket_shutdown_interrupts_a_real_blocked_read(model_on: None) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Slow)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        endpoint = Endpoint(f"http://127.0.0.1:{server.server_address[1]}/v1", "m")
        token = CancelToken()
        got: list[str] = []
        threading.Timer(0.3, lambda: token.cancel("operator")).start()
        started = time.monotonic()
        with pytest.raises(Cancelled):
            ModelClient(endpoint, transport=http_transport).chat(
                MSGS, max_tokens=5, cancel=token, on_delta=lambda k, t: got.append(t))
        assert time.monotonic() - started < 2.0
        assert got == ["first"]
    finally:
        server.shutdown()


# -- regressions from the M0 adversarial review ------------------------------------------

@pytest.mark.parametrize("body", [
    sse(delta(content="The answer is: the buffer is"), done=False),
    sse(delta(tool_calls=[{"index": 0, "id": "c", "function": {"name": "show", "arguments": '{"target":"PV'}}]),
        done=False),
    ndjson({"message": {"role": "assistant", "content": "partial"}, "done": False}),
])
def test_a_stream_that_just_stops_is_not_a_reply(model_on: None, body: bytes) -> None:
    endpoint = Endpoint(LOCAL.base_url, LOCAL.model, transport="api_chat" if body.startswith(b"{") else "v1")
    with pytest.raises(ModelError) as caught:
        client(FakeTransport(body), endpoint).chat(MSGS, max_tokens=5)
    assert caught.value.code == "TRANSPORT" and caught.value.retryable


@pytest.mark.parametrize(("status", "body", "code"), [
    (301, b"<html>Moved</html>", "PROVIDER"),
    (200, b'{"choices":[{"message":{"content":"hello"}}]}', "PROTOCOL"),
    (200, b"", "PROTOCOL"),
])
def test_a_response_that_is_not_a_stream_is_an_error(model_on: None, status: int, body: bytes, code: str) -> None:
    with pytest.raises(ModelError) as caught:
        client(FakeTransport((status, body))).chat(MSGS, max_tokens=5)
    assert caught.value.code == code


def test_a_timeout_leaves_the_callers_token_usable(model_on: None) -> None:
    token = CancelToken()
    blocked = client(FakeTransport(block=True))
    with pytest.raises(ModelError) as caught:
        blocked.chat(MSGS, max_tokens=5, cancel=token, timeout=0.05)
    assert caught.value.code == "TIMEOUT" and not token.cancelled
    retry = client(FakeTransport(sse(delta(content="ok", finish_reason="stop"))))
    assert retry.chat(MSGS, max_tokens=5, cancel=token).text == "ok"


def test_a_credential_with_a_newline_is_refused_without_echoing_it(model_on: None,
                                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BAD_KEY", "sk-secret-value\r\nX-Evil: 1")
    public = Endpoint("https://api.example.com/v1", "glm", kind="public", api_key_env="BAD_KEY")
    with pytest.raises(UserError) as caught:
        ModelClient(public, transport=FakeTransport(sse()), egress=resolved()).chat(MSGS, max_tokens=5)
    assert "sk-secret" not in str(caught.value)


def test_a_non_string_error_message_with_a_secret_set(model_on: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KEY", "sk-abcdefgh1234")
    public = Endpoint("https://api.example.com/v1", "glm", kind="public", api_key_env="KEY")
    with pytest.raises(ModelError) as caught:
        ModelClient(public, transport=FakeTransport((400, b'{"error":{"message":{"detail":"sk-abcdefgh1234"}}}')),
                    egress=resolved()).chat(MSGS, max_tokens=5)
    assert "sk-abcdefgh1234" not in caught.value.message


def test_an_invalid_port_is_a_user_error() -> None:
    with pytest.raises(UserError, match="invalid port"):
        Endpoint("http://host:99999/v1", "m")


class _ChunkedThenGone(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        piece = sse(delta(content="half an ans"), done=False)
        self.wfile.write(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
        self.wfile.flush()
        self.close_connection = True  # the server dies: no terminating 0-chunk

    def log_message(self, *args: object) -> None:
        pass


def test_a_chunked_stream_cut_before_its_last_chunk_is_an_error(model_on: None) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ChunkedThenGone)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        endpoint = Endpoint(f"http://127.0.0.1:{server.server_address[1]}/v1", "m")
        with pytest.raises(ModelError) as caught:
            ModelClient(endpoint, transport=http_transport).chat(MSGS, max_tokens=5, timeout=5)
        assert caught.value.code == "TRANSPORT"
    finally:
        server.shutdown()

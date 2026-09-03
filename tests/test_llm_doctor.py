"""``llm-doctor``: what the provider will really do, not what it claims.

The failures pinned here are the ones observed against a real endpoint: a
server that answers but serves a different model, a server whose context
window is smaller than the prompts the scan will send, and a server that is
reachable but too slow to finish in any reasonable time.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from code_analyzer.config import DEFAULTS, validate_config
from code_analyzer.llm import doctor as llm_doctor


class _Endpoint:
    """A stub OpenAI-compatible endpoint, scripted per test."""

    def __init__(self, models: list[str], *, served: str | None = None, delay: float = 0.0) -> None:
        self.models = models
        self.served = served
        self.delay = delay
        self.paths: list[str] = []
        self.authorization: list[str | None] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def _reply(self, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802  (BaseHTTPRequestHandler API)
                outer.paths.append(self.path)
                outer.authorization.append(self.headers.get("Authorization"))
                self._reply({"data": [{"id": name} for name in outer.models]})

            def do_POST(self) -> None:  # noqa: N802
                outer.paths.append(self.path)
                outer.authorization.append(self.headers.get("Authorization"))
                length = int(self.headers.get("Content-Length") or 0)
                request = json.loads(self.rfile.read(length) or b"{}")
                if outer.delay:
                    import time

                    time.sleep(outer.delay)
                self._reply({
                    "model": outer.served or request.get("model"),
                    "choices": [{"message": {"role": "assistant", "content": "ready"}}],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 8},
                })

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@pytest.fixture()
def endpoint() -> Any:
    made: list[_Endpoint] = []

    def build(models: list[str], **kwargs: Any) -> _Endpoint:
        made.append(_Endpoint(models, **kwargs))
        return made[-1]

    yield build
    for item in made:
        item.close()


def _config(url: str, model: str, **llm: Any) -> dict[str, Any]:
    config = validate_config(json.loads(json.dumps(DEFAULTS)))
    config["llm"].update({"enabled": True, "endpoint": url, "model": model, "api_key_env": "", **llm})
    return config


def _probe(config: dict[str, Any], source: Path | None = None, **kwargs: Any) -> dict[str, Any]:
    return llm_doctor.probe_llm(config, source, **kwargs)


def test_a_healthy_endpoint_is_ok_and_measures_its_own_rate(
    endpoint: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(llm_doctor, "endpoint_context_length", lambda _settings: 32768)
    server = endpoint(["qwen3.8:27b", "other"])

    result = _probe(_config(server.url, "qwen3.8:27b", context_window=32768))

    assert result["ok"] is True
    assert result["models"]["model_present"] is True
    assert result["benchmark"]["ok"] and result["benchmark"]["completion_tokens"] == 8
    assert result["benchmark"]["tokens_per_second"] is not None
    assert result["benchmark"]["served_other_model"] is False
    assert result["context_window"] == {"ok": True, "configured": 32768, "served": 32768, "reason": None}
    assert "/v1/models" in server.paths and "/v1/chat/completions" in server.paths


def test_an_endpoint_that_does_not_serve_the_configured_model_is_not_ok(
    endpoint: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The quiet mis-route: the scan would run against whatever was loaded."""
    monkeypatch.setattr(llm_doctor, "endpoint_context_length", lambda _settings: None)
    server = endpoint(["llama3:8b"])

    result = _probe(_config(server.url, "qwen3.8:27b"))

    assert result["ok"] is False
    assert result["models"]["model_present"] is False
    assert "端点不提供 'qwen3.8:27b'" in result["models"]["reason"]
    assert "llama3:8b" in result["models"]["reason"]


def test_an_endpoint_answering_as_another_model_is_not_ok(
    endpoint: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Listing the model is not proof; the reply is stamped with what ran."""
    monkeypatch.setattr(llm_doctor, "endpoint_context_length", lambda _settings: None)
    server = endpoint(["qwen3.8:27b"], served="llama3:8b")

    result = _probe(_config(server.url, "qwen3.8:27b"))

    assert result["models"]["model_present"] is True
    assert result["benchmark"]["served_other_model"] is True
    assert result["benchmark"]["served_model"] == "llama3:8b"
    assert result["ok"] is False


def test_the_implicit_latest_tag_still_counts_as_served(
    endpoint: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(llm_doctor, "endpoint_context_length", lambda _settings: None)
    server = endpoint(["qwen3.8:latest"])

    assert _probe(_config(server.url, "qwen3.8"))["models"]["model_present"] is True


def test_a_served_window_smaller_than_the_configured_one_is_not_ok(
    endpoint: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ollama truncates past its loaded window without saying so."""
    monkeypatch.setattr(llm_doctor, "endpoint_context_length", lambda _settings: 4096)
    server = endpoint(["qwen3.8:27b"])

    result = _probe(_config(server.url, "qwen3.8:27b", context_window=32768))

    assert result["ok"] is False
    assert result["context_window"]["served"] == 4096
    assert "静默截断" in result["context_window"]["reason"]


def test_a_slow_endpoint_is_reported_as_slow_not_as_unreachable(
    endpoint: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A busy or CPU-bound host is the diagnosis this command exists for."""
    monkeypatch.setattr(llm_doctor, "endpoint_context_length", lambda _settings: None)
    server = endpoint(["qwen3.8:27b"], delay=1.5)

    result = _probe(_config(server.url, "qwen3.8:27b"), timeout=0.4)

    assert result["ok"] is False
    assert result["benchmark"]["ok"] is False
    assert "did not answer within" in result["benchmark"]["reason"]
    assert "unreachable" not in result["benchmark"]["reason"]


def test_the_estimate_counts_the_real_plan_and_names_its_basis(
    tmp_path: Path, endpoint: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(llm_doctor, "endpoint_context_length", lambda _settings: None)
    server = endpoint(["qwen3.8:27b"])
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.c").write_text("int one(void) { return 1; }\nint two(void) { return 2; }\n", encoding="utf-8")
    config = _config(server.url, "qwen3.8:27b", scanners=["llm-memory-safety", "llm-security"], jobs=2)

    result = _probe(config, source)

    estimate = result["estimate"]
    assert estimate["known"] is True
    assert estimate["units"] > 0 and estimate["scanners"] == 2 and estimate["jobs"] == 2
    assert estimate["sessions"] == estimate["units"] * 2
    assert estimate["wall_clock_seconds"] >= 0
    assert "extrapolated from one measured request" in estimate["basis"]

    # Without a source tree there is nothing to estimate, and it says so
    # rather than inventing a number.
    assert _probe(config)["estimate"] == {"known": False, "reason": "no source tree given"}


def test_the_credential_never_reaches_the_output(
    endpoint: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(llm_doctor, "endpoint_context_length", lambda _settings: None)
    monkeypatch.setenv("CODE_ANALYZER_TEST_KEY", "sk-secret-value")
    server = endpoint(["qwen3.8:27b"])

    result = _probe(_config(server.url, "qwen3.8:27b", api_key_env="CODE_ANALYZER_TEST_KEY"))

    assert "sk-secret-value" not in json.dumps(result)
    assert result["credential"] == {"ok": True, "reason": None, "source": "CODE_ANALYZER_TEST_KEY"}
    # It did travel, in the header where it belongs.
    assert "Bearer sk-secret-value" in server.authorization


def test_an_unset_credential_variable_is_one_clear_failure(
    endpoint: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(llm_doctor, "endpoint_context_length", lambda _settings: None)
    monkeypatch.delenv("CODE_ANALYZER_TEST_KEY", raising=False)
    server = endpoint(["qwen3.8:27b"])

    result = _probe(_config(server.url, "qwen3.8:27b", api_key_env="CODE_ANALYZER_TEST_KEY"))

    assert result["ok"] is False
    assert result["credential"]["ok"] is False
    assert "CODE_ANALYZER_TEST_KEY" in result["credential"]["reason"]


def test_models_falls_back_to_ollama_api_tags(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request(url: str, body: Any, key: Any, *, timeout: float) -> tuple[Any, Any]:
        if url.endswith("/models"):
            return None, "HTTP 404 from /models"
        if url.endswith("/api/tags"):
            return {"models": [{"name": "qwen3.8:27b", "details": {"context_length": 262144}}]}, None
        return None, "not found"

    monkeypatch.setattr(llm_doctor, "_request", fake_request)
    res = llm_doctor._models("http://192.168.5.10:11434/v1", None, "qwen3.8:27b", timeout=5.0)
    assert res["reachable"] is True
    assert res["model_present"] is True
    assert res["available"] == ["qwen3.8:27b"]


"""M8: the public model -- only for public code, only when a human allowed it, only for batch jobs."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fake_transport import FakeTransport, delta, sse
from test_evaluate import SOURCE, buildctx_file, fake_tools

from code_analyzer.core.cancel import CancellationToken
from code_analyzer.errors import UserError
from code_analyzer.evidence.analyze import evaluate
from code_analyzer.evidence.buildctx_schema import load_buildctx
from code_analyzer.evidence.workspace import Workspace
from code_analyzer.jobs import lens_job
from code_analyzer.kernel.toolspec import REVIEW, validate
from code_analyzer.model.broker import Broker
from code_analyzer.model.egress import EgressBlocked
from code_analyzer.model.evaluation import client_for, public_allowed
from code_analyzer.settings import Settings

PUBLIC = Settings(public_endpoint="https://203.0.113.10/v1", public_model="glm-5.3-flash",
                  public_api_key_env="TEST_PUBLIC_KEY")


@pytest.fixture(autouse=True)
def model_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_MODEL", raising=False)
    monkeypatch.setenv("TEST_PUBLIC_KEY", "sk-test-secret")


def _evaluation(tmp_path: Path, confidentiality: str) -> Workspace:
    source = tmp_path / "project"
    source.mkdir()
    (source / "a.c").write_text(SOURCE, encoding="utf-8")
    tools_ = fake_tools(tmp_path, source / "a.c")
    workspace = evaluate(source, eval_dir=tmp_path / "eval", profile="generic-sesip",
                         buildctx=load_buildctx(buildctx_file(tmp_path, tools_)), compile_db=False).workspace
    data = workspace.evaluation
    data.update(confidentiality=confidentiality, model_pin={"host": "127.0.0.1", "port": 11434, "addresses": ["127.0.0.1"],
                                                            "model": "qwen", "digest": "", "scheme": "http",
                                                            "public_host_confirmed": False})
    (workspace.root / "evaluation.json").write_text(json.dumps(data), encoding="utf-8")
    return workspace


def test_client_code_never_reaches_the_public_model(tmp_path: Path) -> None:
    workspace = _evaluation(tmp_path, "client")
    with pytest.raises(UserError, match="only a public evaluation"):
        workspace.allow_public_model(True, by="analyst")
    with pytest.raises(EgressBlocked, match="client code only ever goes to the local GPU"):
        client_for(workspace, PUBLIC, review=True, channel="public")
    # even with the flag forced into evaluation.json by hand, the policy refuses to be built
    data = workspace.evaluation
    data["allow_public_model"] = True
    (workspace.root / "evaluation.json").write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(EgressBlocked):
        client_for(workspace, PUBLIC, review=True, channel="public")


def test_a_public_evaluation_needs_the_switch_and_a_configured_model(tmp_path: Path) -> None:
    workspace = _evaluation(tmp_path, "public")
    assert public_allowed(workspace, PUBLIC) == (False, "the evaluator has not allowed the public model for this "
                                                        "evaluation")
    workspace.allow_public_model(True, by="analyst")
    assert public_allowed(workspace, Settings())[0] is False       # nothing configured, nothing to use
    assert public_allowed(workspace, PUBLIC) == (True, "")
    assert workspace.ledger.of("public_model_allowed")[-1] == {**workspace.ledger.of("public_model_allowed")[-1],
                                                               "allow": True, "by": "analyst"}


def test_an_allowed_review_goes_to_the_public_model_with_its_own_limits(tmp_path: Path) -> None:
    workspace = _evaluation(tmp_path, "public")
    workspace.allow_public_model(True, by="analyst")
    client = client_for(workspace, PUBLIC, review=True, channel="public")
    answer = {"verdict": "CONFIRMED", "confidence": 0.9, "decisive_line": 6, "evidence_quote": "return tmp[4];",
              "rationale": "index 4 is one past the end of tmp[4]."}
    client.transport = FakeTransport(sse(delta(content=json.dumps(answer), finish_reason="stop"),
                                         {"choices": [], "usage": {"prompt_tokens": 900, "completion_tokens": 90}}))
    result = lens_job.run(workspace, client=client, broker=Broker(resume_after=0), token=CancellationToken(),
                          job_id="J1", budget_seconds=600, targets=["PV-0001"])
    assert result["started"] == 1 and result["grounding"] == {"verify": [1, 1]}
    [request] = client.transport.requests
    body = json.loads(request.body)
    assert request.connect_host == "203.0.113.10" and request.headers["Authorization"] == "Bearer sk-test-secret"
    assert body["model"] == "glm-5.3-flash" and body["max_completion_tokens"] == 4000
    started = workspace.ledger.of("review_started")[-1]
    assert (started["channel"], started["host"]) == ("public", "203.0.113.10")
    # the key never lands in the evaluation's records
    assert b"sk-test-secret" not in b"".join(p.read_bytes() for p in workspace.root.rglob("*") if p.is_file())


def test_the_model_cannot_ask_for_the_public_channel() -> None:
    assert validate(REVIEW.parameters, {"depth": "quick", "channel": "public"})

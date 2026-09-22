from __future__ import annotations

import json
from pathlib import Path

import pytest
from fake_transport import FakeTransport, delta, sse

from code_analyzer.errors import UserError
from code_analyzer.model.client import Endpoint
from code_analyzer.model.probe import GOLD, Probe, run_probe

EP = Endpoint("http://127.0.0.1:11434/v1", "qwen3.8:27b")
USAGE = {"choices": [], "usage": {"prompt_tokens": 10, "completion_tokens": 2}}


def native_call(name: str, arguments: dict) -> bytes:
    return sse(delta(tool_calls=[{"index": 0, "id": "c", "function": {"name": name, "arguments": json.dumps(arguments)}}],
                     finish_reason="tool_calls"), USAGE)


def json_call(name: str, arguments: dict) -> bytes:
    text = f"好的。\n```call\n{json.dumps({'name': name, 'arguments': arguments})}\n```"
    return sse(delta(content=text, finish_reason="stop"), USAGE)


def test_the_probe_refuses_without_a_model() -> None:
    with pytest.raises(UserError, match="NO_MODEL"):
        run_probe(EP)


def test_p3_scores_each_codec(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_MODEL", raising=False)
    good = {"kind": "pv", "where": {"level": "error"}}
    responses = [native_call("list", good)] * 2 + [native_call("list", {"kind": "pv", "where": {"level": "fatal"}})] \
        + [json_call("list", good)] * 3
    transport = FakeTransport(*responses)
    probe = Probe(EP, repeat=3, fixtures=tmp_path, log=lambda line: None, transport=transport)
    result = probe.p3()
    assert (result["native"]["passed"], result["json"]["passed"]) == (2, 3)
    # the JSON codec sends no tool schemas; the catalogue lives in the prompt
    assert "tools" in transport.bodies[0] and "tools" not in transport.bodies[3]
    assert "- list:" in transport.bodies[3]["messages"][0]["content"]
    assert (tmp_path / "0001" / "request.json").exists()


def test_verdict_prefers_native_only_when_every_measured_check_passes() -> None:
    probe = Probe(EP, log=lambda line: None, transport=FakeTransport())
    probe.results = {
        "P3": {"native": {"rate": 1.0}}, "P4": {"native_7": {"rate": 0.95}},
        "P5": {"answer_after_result": {"rate": 1.0}, "three_step_chain": {"rate": 0.9}},
        "P6": {"rate": 1.0}, "P7": {"injection_ignored": {"rate": 1.0}}, "P8": {"rate": 1.0},
        "P13": {"passed": True}, "P11": {"ttft_by_background": {"0": 3.0, "2": 4.0}},
    }
    verdict = probe.verdict()
    assert verdict["codec"] == "native" and verdict["failed_checks"] == [] and verdict["batch_concurrency"] == 2
    probe.http_500 = 1
    assert probe.verdict()["codec"] == "json"
    probe.http_500 = 0
    probe.results["P4"]["native_7"]["rate"] = 0.8
    assert probe.verdict()["failed_checks"] == ["P4 native_7 >= 0.9"]


def test_gold_sentences_name_real_tools() -> None:
    from code_analyzer.kernel.toolspec import ALT_TOOLS_10, BY_NAME
    alt = {tool.name for tool in ALT_TOOLS_10} | {"none"}
    assert len(GOLD) == 22
    assert all(seven <= set(BY_NAME) | {"none"} and ten <= alt for _, seven, ten in GOLD)
    # every extra tool of the 10-tool set has a sentence only it fits
    assert {"jobs", "mark", "profile_show"} <= set().union(*(ten for _, _, ten in GOLD))


def test_verdict_is_incomplete_without_every_gating_check() -> None:
    probe = Probe(EP, log=lambda line: None, transport=FakeTransport())
    assert probe.verdict()["codec"] == "incomplete"
    probe.results = {"P3": {"native": {"rate": 1.0}}}
    verdict = probe.verdict()
    assert verdict["codec"] == "incomplete" and "P4 native_7 >= 0.9" in verdict["missing_checks"]


def test_p5_runs_every_read_call_and_nudges_the_last_step(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_MODEL", raising=False)
    two_reads = sse(delta(tool_calls=[
        {"index": 0, "id": "a", "function": {"name": "show", "arguments": '{"target":"PV-0042","part":"summary"}'}},
        {"index": 1, "id": "b", "function": {"name": "show", "arguments": '{"target":"PV-0042","part":"evidence"}'}}],
        finish_reason="tool_calls"), USAGE)
    answer = sse(delta(content="越界读，第 209 行。", finish_reason="stop"), USAGE)
    transport = FakeTransport(two_reads, answer)
    probe = Probe(EP, log=lambda line: None, transport=transport)
    detail: list = []
    assert probe._conversation("PV-0042 是什么问题？", max_steps=3, detail=detail)  # noqa: SLF001
    second = transport.bodies[1]["messages"]
    assert [m["role"] for m in second[-3:]] == ["assistant", "tool", "tool"]

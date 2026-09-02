"""The LLM configurator: prompt discipline, strict parsing, the session, and the loop that uses it."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from fake_harness import FakeHarness, response
from test_build_context import INVENTORY, RECORD
from test_reconfigure import _config as _run_config
from test_reconfigure import _tree

from code_analyzer.analysis import (
    AnalysisEvent,
    AnalysisRequest,
    CancellationToken,
    run_analysis,
)
from code_analyzer.build_context import diagnose_units, infer_patch
from code_analyzer.config import load_config
from code_analyzer.control import RunControl, auto_yes
from code_analyzer.harness.runtime import HarnessRunFailed, RunOutcome
from code_analyzer.includes import include_index
from code_analyzer.llm import configure
from code_analyzer.llm.skills import (
    CONFIGURATOR_ROLE,
    CONFIGURATOR_SKILL,
    REQUIRED_INJECTION_CLAUSE,
    load_skill,
    skill_names,
)

PROPOSAL = json.dumps({
    "schema_version": 1,
    "items": [
        {"op": "add_override", "match": "platform/a/**", "include": ["platform/a"], "rationale": "board a builds against its own board.h"},
        {"op": "add_define", "value": "CONFIG_X=1", "rationale": "config.cmake sets it"},
        {"op": "add_include", "path": "include", "rationale": "duplicate of the deterministic patch"},
        {"op": "add_stub_header", "name": "vendor_sdk.h", "rationale": "vendored SDK, not in the tree"},
        {"op": "run_command", "value": "make menuconfig", "rationale": "would be handy"},
        {"op": "add_include", "path": "../../etc", "rationale": "nope"},
    ],
    "unresolved": [{"header": "mbedtls/build_info.h", "why": "vendored dependency"}],
})


class _Runtime:
    def __init__(self, fake: FakeHarness, producer: str, unit_id: str, settings: dict[str, Any]) -> None:
        self.fake, self.producer, self.unit_id, self.settings = fake, producer, unit_id, settings
        self.prompt: Any = None

    def __enter__(self) -> _Runtime:
        return self

    def __exit__(self, *_exception: object) -> None:
        return None

    def run(self, prompt: Any, *, session_id: str | None = None, on_event: Any = None) -> RunOutcome:
        self.prompt = prompt
        try:
            result = self.fake.run(producer=self.producer, unit_id=self.unit_id, prompt=prompt)
        except AssertionError:
            raise
        except Exception as exc:  # pragma: no cover - exercised through the fake's scripted errors
            raise HarnessRunFailed("failed", f"agent runtime error: {type(exc).__name__}: {exc}") from exc
        if on_event is not None:
            for event in result.events:
                on_event(event)
        return RunOutcome(result.session_id, result.final_response, result.finish_reason, result.events, result.notifications, 0.5)


def _seam(fake: FakeHarness):
    prompts: list[str] = []

    def open_runtime(producer: str, unit_id: str, settings: dict[str, Any]) -> _Runtime:
        runtime = _Runtime(fake, producer, unit_id, settings)
        prompts.append(unit_id)
        return runtime

    return open_runtime, prompts


def test_the_skill_is_a_configurator_and_carries_the_injection_clause() -> None:
    skill = load_skill(CONFIGURATOR_SKILL)
    assert skill.metadata["role"] == "configurator" and skill.metadata["allowed-tools"] == ["fs"]
    assert REQUIRED_INJECTION_CLAUSE in skill.body
    assert skill_names(CONFIGURATOR_ROLE) == (CONFIGURATOR_SKILL,)
    assert CONFIGURATOR_SKILL not in skill_names()
    assert [op for op in configure.OPS] == skill.metadata["ops"]


def test_the_prompt_carries_counts_names_and_directories_but_no_source(tmp_path: Path) -> None:
    config = load_config(tmp_path, None, {"run": {"output_root": str(tmp_path / "out")}})
    diagnosis = diagnose_units(RECORD, INVENTORY)
    patch = infer_patch(diagnosis, config, source=tmp_path)
    blocks = configure.build_prompt(diagnosis, patch, config, inventory=INVENTORY, samples=["u1: image.h, cmsis.h"])
    text = "\n".join(block["text"] for block in blocks)
    assert "board.h | 2 | platform/a, platform/b | platform/a (1), platform/b (1)" in text
    assert "- vendor_sdk.h (1 unit(s); e.g. bl1/lib/image.c)" in text
    assert "2 missing header(s) live in exactly one directory each" in text
    assert "2 include root(s): include, bl1/lib" in text and "do not repeat" in text
    assert "cmsis.h" not in text  # unambiguous: the deterministic patch's business
    assert "Your reply must begin with `{`" in text
    assert "int f(" not in text and "DATA" in text


def test_parsing_keeps_validated_items_drops_the_rest_and_dedupes(tmp_path: Path) -> None:
    diagnosis = diagnose_units(RECORD, INVENTORY)
    config = load_config(tmp_path, None, {"run": {"output_root": str(tmp_path / "out")}})
    deterministic = infer_patch(diagnosis, config, source=tmp_path).items
    valid, reason, result, counts = configure.parse_proposal(
        "Sure! Here is my proposal:\n" + PROPOSAL, diagnosis=diagnosis, source=tmp_path, index=include_index(INVENTORY),
        inventory=INVENTORY, deterministic=deterministic,
    )
    assert valid and reason == "5 item(s) dropped"
    assert [(item["op"], item["origin"], item["preselected"]) for item in result["items"]] == [("add_define", "llm", True)]
    # The override, the include and the stub duplicate deterministic items; the
    # command is not an op; the path escapes the tree.
    assert len(result["problems"]) == 5 and sum("duplicates" in p for p in result["problems"]) == 3
    assert result["unresolved"] == [{"header": "mbedtls/build_info.h", "why": "vendored dependency"}]
    assert counts == {"item_count": 1, "dropped_count": 5}
    assert result["authority"].startswith("non-authoritative")
    valid, reason, result, _counts = configure.parse_proposal("I cannot help with that.", diagnosis=diagnosis, source=tmp_path, index=include_index(INVENTORY), inventory=INVENTORY)
    assert not valid and "no parsable JSON" in reason and result["items"] == []
    valid, reason, _result, _counts = configure.parse_proposal(None, diagnosis=diagnosis, source=tmp_path, index=include_index(INVENTORY), inventory=INVENTORY)
    assert not valid and "no response" in reason


def test_propose_runs_one_session_and_leaves_its_evidence(tmp_path: Path) -> None:
    fake = FakeHarness().script(configure.PRODUCER, "r1", response(PROPOSAL))
    open_runtime, _prompts = _seam(fake)
    config = load_config(tmp_path, None, {"run": {"output_root": str(tmp_path / "out")}, "llm": {"endpoint": "http://127.0.0.1:1/v1", "model": "fake"}})
    diagnosis = diagnose_units(RECORD, INVENTORY)
    patch = infer_patch(diagnosis, config, source=tmp_path)
    run_dir = tmp_path / "run"
    steps: list[tuple[str, str]] = []
    proposal = configure.propose(
        tmp_path, run_dir, config, diagnosis=diagnosis, deterministic=patch, inventory=INVENTORY,
        index=include_index(INVENTORY), round_no=1, open_runtime=open_runtime,
        unit_event=lambda producer, unit_id, status, message, value, data=None, **_kw: steps.append((status, message)),
    )
    assert proposal.used and proposal.model == "fake" and [item.op for item in proposal.items] == ["add_define"]
    assert len(proposal.problems) == 5 and proposal.unresolved[0]["header"] == "mbedtls/build_info.h"
    assert proposal.session == "llm/sessions/build-context-configurator/r1"
    session = run_dir / proposal.session
    assert sorted(p.name for p in session.iterdir()) == ["events.jsonl", "meta.json", "proposal.json", "request.json", "response.json"]
    body = json.loads((session / "proposal.json").read_text(encoding="utf-8"))
    assert body["producer"] == configure.PRODUCER and body["round_id"] == "r1" and body["valid_report"] and len(body["items"]) == 1
    request = json.loads((session / "request.json").read_text(encoding="utf-8"))
    assert request["parameters"]["enforced_locally"]["max_steps"] == configure.MAX_STEPS
    assert (run_dir / "llm/configurator/cordis.json").is_file()
    assert [status for status, _ in steps if status in {"started", "completed"}] == ["started", "completed"]
    prompt_sent = fake.calls_for(configure.PRODUCER, "r1")[0].request["prompt"]
    text = prompt_sent if isinstance(prompt_sent, str) else "\n".join(block.get("text", "") for block in prompt_sent)
    assert "# Configurator" in text and "board.h | 2 | platform/a, platform/b" in text


def test_propose_reports_a_model_that_answered_prose(tmp_path: Path) -> None:
    fake = FakeHarness().script(configure.PRODUCER, "r1", response("Let me think about this tree..."))
    open_runtime, _prompts = _seam(fake)
    config = load_config(tmp_path, None, {"run": {"output_root": str(tmp_path / "out")}, "llm": {"endpoint": "http://127.0.0.1:1/v1", "model": "fake"}})
    diagnosis = diagnose_units(RECORD, INVENTORY)
    proposal = configure.propose(
        tmp_path, tmp_path / "run", config, diagnosis=diagnosis, deterministic=infer_patch(diagnosis, config, source=tmp_path),
        inventory=INVENTORY, index=include_index(INVENTORY), round_no=1, open_runtime=open_runtime,
    )
    assert not proposal.used and proposal.status == "failed" and "no parsable JSON" in proposal.reason and proposal.items == []


def test_gate_needs_an_endpoint_and_a_model() -> None:
    assert configure.gate({"llm": {"endpoint": "", "model": "x"}}) == (False, "no [llm] endpoint and model configured")
    assert configure.gate({"llm": {"endpoint": "http://h/v1", "model": "x"}}, open_runtime=lambda *a: None) == (True, None)


def _live(tmp_path: Path, monkeypatch, *responses: Any):
    """A run whose configurator answers through the fake; the gate says the endpoint is up."""
    fake = FakeHarness()
    for index, item in enumerate(responses, 1):
        fake.script(configure.PRODUCER, f"r{index}", item)
    open_runtime, _prompts = _seam(fake)
    real = configure.propose
    monkeypatch.setattr(configure, "gate", lambda config, **_kw: (True, None))
    monkeypatch.setattr(configure, "propose", lambda *args, **kwargs: real(*args, **{**kwargs, "open_runtime": open_runtime}))
    return fake


def test_the_loop_merges_the_models_items_after_the_deterministic_ones_and_records_the_session(tmp_path: Path, monkeypatch) -> None:
    source = _tree(tmp_path)
    proposal = json.dumps({"schema_version": 1, "items": [
        {"op": "add_stub_header", "name": "vendor.h", "rationale": "vendored SDK header"},
        {"op": "add_define", "value": "BOARD_A=1", "rationale": "the only board in the tree"},
    ], "unresolved": []})
    fake = _live(tmp_path, monkeypatch, response(proposal))
    config = _run_config(tmp_path, source, "propose")
    config["llm"].update({"endpoint": "http://127.0.0.1:1/v1", "model": "fake"})
    events: list[AnalysisEvent] = []
    result = run_analysis(AnalysisRequest(source, config), events=events.append, control=RunControl(CancellationToken(), decider=auto_yes))
    block = result.manifest["build_context"]
    round1 = block["rounds"][0]
    assert round1["llm"]["used"] and round1["llm"]["model"] == "fake" and round1["llm"]["items"] == 1 and round1["llm"]["dropped"] == 1
    assert round1["llm"]["session"] == "llm/sessions/build-context-configurator/r1"
    patch = json.loads((result.report_directory / "inputs/build-context/r1/patch.json").read_text(encoding="utf-8"))
    assert [(item["op"], item["origin"]) for item in patch["items"]] == [("add_include", "deterministic"), ("add_stub_header", "deterministic"), ("add_define", "llm")]
    assert (result.report_directory / "inputs/build-context/r1/llm.json").is_file()
    # --build-assist-yes takes the pre-ticked items: the root and the model's define, never the stub.
    assert round1["selected"] == [0, 2] and round1["decided_by"] == "cli --build-assist-yes"
    assert result.manifest["tools"]["splint"]["coverage"]["analysis_reached"] == 4
    statuses = [e.status for e in events if e.phase == "build_context"]
    assert statuses[:3] == ["started", "diagnosed", "inferred"] and "consulting" in statuses and "consulted" in statuses
    consulted = [e for e in events if e.phase == "build_context" and e.status == "consulted"][0]
    assert "fake proposed 1 item(s) (1 dropped" in consulted.message
    awaiting = [e for e in events if e.phase == "build_context" and e.status == "awaiting"][0]
    assert "3 item(s)" in awaiting.message
    assert len(fake.calls_for(configure.PRODUCER)) == 1


def test_the_models_items_survive_a_deterministic_patch_at_the_cap(tmp_path: Path, monkeypatch) -> None:
    from code_analyzer import build_context, reconfigure

    source = _tree(tmp_path)
    proposal = json.dumps({"schema_version": 1, "items": [{"op": "add_define", "value": "BOARD_A=1", "rationale": "x"}], "unresolved": []})
    _live(tmp_path, monkeypatch, response(proposal))
    real_infer = build_context.infer_patch

    def padded(*args, **kwargs):
        patch = real_infer(*args, **kwargs)
        # A tree with more proven roots than the dialog cap.
        patch.items = patch.items + [build_context.PatchItem("add_define", f"PAD_{index}=1") for index in range(build_context.MAX_ITEMS)]
        return patch

    monkeypatch.setattr(reconfigure, "infer_patch", padded)
    config = _run_config(tmp_path, source, "propose")
    config["llm"].update({"endpoint": "http://127.0.0.1:1/v1", "model": "fake"})
    result = run_analysis(AnalysisRequest(source, config), events=lambda _e: None, control=RunControl(CancellationToken(), decider=auto_yes))
    patch = json.loads((result.report_directory / "inputs/build-context/r1/patch.json").read_text(encoding="utf-8"))
    assert len(patch["items"]) > build_context.MAX_ITEMS and patch["items"][-1]["origin"] == "llm"


def test_auto_never_applies_a_patch_with_model_items_on_its_own(tmp_path: Path, monkeypatch) -> None:
    source = _tree(tmp_path)
    proposal = json.dumps({"schema_version": 1, "items": [{"op": "add_define", "value": "BOARD_A=1", "rationale": "x"}], "unresolved": []})
    _live(tmp_path, monkeypatch, response(proposal))
    config = _run_config(tmp_path, source, "auto")
    config["llm"].update({"endpoint": "http://127.0.0.1:1/v1", "model": "fake"})
    control = RunControl(CancellationToken())
    seen: list = []

    def answer() -> None:
        while not control.pending():
            threading.Event().wait(0.05)
        request = control.pending()[0]
        seen.append(request)
        control.decide(request.id, "apply", tuple(request.preselected), "test")

    threading.Thread(target=answer, daemon=True).start()
    result = run_analysis(AnalysisRequest(source, config), events=lambda _e: None, control=control)
    assert seen and seen[0].preselected == (0, 2)
    assert result.manifest["build_context"]["rounds"][0]["decided_by"] == "test"


def test_a_configurator_that_fails_leaves_the_deterministic_patch_to_proceed(tmp_path: Path, monkeypatch) -> None:
    source = _tree(tmp_path)
    _live(tmp_path, monkeypatch, response("no json here"))
    config = _run_config(tmp_path, source, "auto")
    config["llm"].update({"endpoint": "http://127.0.0.1:1/v1", "model": "fake"})
    result = run_analysis(AnalysisRequest(source, config), events=lambda _e: None, control=RunControl(CancellationToken()))
    round1 = result.manifest["build_context"]["rounds"][0]
    assert not round1["llm"]["used"] and round1["llm"]["status"] == "failed" and round1["applied"] and round1["decided_by"] == "auto"


def test_an_unreachable_endpoint_means_the_configurator_is_skipped_with_the_reason(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    config = _run_config(tmp_path, source, "auto")  # endpoint: a closed port
    events: list[AnalysisEvent] = []
    result = run_analysis(AnalysisRequest(source, config), events=events.append, control=RunControl(CancellationToken()))
    round1 = result.manifest["build_context"]["rounds"][0]
    assert not round1["llm"]["used"] and round1["llm"]["status"] == "skipped" and round1["llm"]["reason"]
    assert any(e.status == "consulted" and "skipped" in e.message for e in events if e.phase == "build_context")
    assert round1["applied"] and round1["decided_by"] == "auto"

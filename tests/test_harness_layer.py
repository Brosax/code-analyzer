"""Unit tests for the deepseek-harness isolation layer.

The SDK is stubbed in sys.modules: these tests must run with neither the
optional extra nor a network.
"""
from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from code_analyzer.errors import UserError
from code_analyzer.harness import cordis, runtime, schema, session

GOOD = {
    "file": "src/parser.c",
    "line_range": [118, 121],
    "symbol": "parse_packet",
    "category": "buffer",
    "severity": "high",
    "confidence": 0.8,
    "cwe": "CWE-787",
    "message": "length is copied before validation",
    "description": "The length field is attacker controlled.",
}
RESPONSE = json.dumps({"findings": [GOOD]})


def body(**overrides: object) -> str:
    return json.dumps({"findings": [{**GOOD, **overrides}]})


# --- SDK stub ---------------------------------------------------------------


class FakeConfig:
    def __init__(self, **arguments: object) -> None:
        self.arguments = arguments


class FakeHarness:
    instances: list["FakeHarness"] = []

    response = RESPONSE
    finish_reason = "completed"
    failure: Exception | None = None
    notifications: list[dict] = [{"type": "tool_call", "name": "fs.read"}]

    def __init__(self, config: FakeConfig) -> None:
        self.config = config
        self.started = False
        self.closed = False
        self.prompts: list[object] = []
        FakeHarness.instances.append(self)

    def start(self) -> None:
        self.started = True

    def close(self) -> None:
        self.closed = True

    def run(self, prompt, *, session_id=None, on_notification=None):
        self.prompts.append(prompt)
        if on_notification is not None:
            for notification in FakeHarness.notifications:
                on_notification(notification)
        if FakeHarness.failure is not None:
            raise FakeHarness.failure
        return SimpleNamespace(
            session_id="session-1",
            final_response=FakeHarness.response,
            finish_reason=FakeHarness.finish_reason,
            events=[{"type": "tool_call", "name": "fs.read"}, {"type": "message", "text": "done"}],
            notifications=[{"level": "info", "text": "scanning"}],
            session_root="/home/someone/.dsh/sessions",
        )


@pytest.fixture
def sdk(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    FakeHarness.instances = []
    FakeHarness.response = RESPONSE
    FakeHarness.finish_reason = "completed"
    FakeHarness.failure = None
    FakeHarness.notifications = [{"type": "tool_call", "name": "fs.read"}]
    module = types.ModuleType("deepseek_harness")
    module.DeepSeekHarness = FakeHarness
    module.DeepSeekHarnessConfig = FakeConfig
    module.__version__ = "0.1.1rc1"
    monkeypatch.setitem(sys.modules, "deepseek_harness", module)
    return module


@pytest.fixture
def settings(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    monkeypatch.setenv("CODE_ANALYZER_TEST_LLM_KEY", "sk-super-secret-value")
    return {
        "endpoint": "https://gpu-host.internal:8000/v1",
        "api_key_env": "CODE_ANALYZER_TEST_LLM_KEY",
        "model": "qwen3.6-27b",
        "context_window": 32768,
        "temperature": 0.0,
        "seed": 0,
        "max_completion_tokens": 800,
        "max_steps": 12,
        "max_turns": 8,
        "request_timeout_seconds": 600.0,
    }


def session_event(kind: str, **data: object) -> dict:
    """One SDK notification in the shape the runtime really delivers."""
    return {
        "method": "session.event",
        "payload": {"sessionId": "session-1", "event": {"type": kind, "data": data}},
    }


def scanned_tree(tmp_path: Path) -> Path:
    """The tree under audit. A scope has to bound a directory that exists."""
    source = tmp_path / "src"
    source.mkdir(parents=True, exist_ok=True)
    return source


def cordis_file(tmp_path: Path, settings: dict[str, object]) -> Path:
    """The document a scan phase drafts, before any tree is known."""
    return cordis.write_cordis_config(
        tmp_path / "run" / "llm", cordis.cordis_document(settings, skill_dir=tmp_path / "skills")
    )


def launched_document() -> dict:
    """The cordis document the SDK was actually pointed at."""
    return json.loads(
        Path(FakeHarness.instances[0].config.arguments["cordis"]).read_text(encoding="utf-8")
    )


def scan(tmp_path: Path, settings: dict[str, object], **overrides: object) -> tuple[dict, Path]:
    run_dir = tmp_path / "run"
    active_runtime = runtime.HarnessRuntime(
        settings, cwd=scanned_tree(tmp_path), cordis_path=cordis_file(tmp_path, settings)
    )
    with active_runtime as active:
        unit = session.run_unit(
            active,
            run_dir=run_dir,
            producer="llm-memory-safety",
            unit_id="src__parser_c-parse_packet",
            prompt="review this unit",
            unit_sha256="ab" * 32,
            skill_version="1.0.0",
            input_files=["src/parser.c"],
            **overrides,
        )
    return unit, session.unit_directory(run_dir, "llm-memory-safety", "src__parser_c-parse_packet")


# --- lazy import ------------------------------------------------------------


def test_importing_the_package_does_not_import_the_sdk() -> None:
    assert "deepseek_harness" not in sys.modules


def test_missing_sdk_reports_actionable_user_error(monkeypatch: pytest.MonkeyPatch, settings) -> None:
    monkeypatch.setitem(sys.modules, "deepseek_harness", None)
    assert runtime.harness_available() is False
    with pytest.raises(UserError) as error:
        runtime.HarnessRuntime(settings, cwd=Path(".")).start()
    assert "pip install deepseek-harness-sdk" in str(error.value)


def test_incompatible_sdk_reports_missing_symbols(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "deepseek_harness", types.ModuleType("deepseek_harness"))
    with pytest.raises(runtime.HarnessUnavailable) as error:
        runtime.sdk_version()
    assert "DeepSeekHarness" in str(error.value)


# --- credentials ------------------------------------------------------------


def test_api_key_comes_from_the_environment_only(sdk, settings, tmp_path: Path) -> None:
    scan(tmp_path, settings)
    assert FakeHarness.instances[0].config.arguments["api_key"] == "sk-super-secret-value"


def test_missing_environment_variable_is_a_user_error(sdk, settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_TEST_LLM_KEY")
    with pytest.raises(UserError) as error:
        runtime.api_key(settings)
    assert "CODE_ANALYZER_TEST_LLM_KEY" in str(error.value)


def test_request_and_meta_never_carry_the_credential(sdk, settings, tmp_path: Path) -> None:
    _unit, directory = scan(tmp_path, settings)
    for name in ("request.json", "meta.json"):
        text = (directory / name).read_text(encoding="utf-8")
        assert "sk-super-secret-value" not in text
        assert "CODE_ANALYZER_TEST_LLM_KEY" not in text
    request = json.loads((directory / "request.json").read_text(encoding="utf-8"))
    assert request["model"] == "qwen3.6-27b"
    assert request["base_url"] == "https://gpu-host.internal:8000/v1"
    assert request["skill_version"] == "1.0.0"
    assert request["unit_sha256"] == "ab" * 32
    assert "api_key" not in json.dumps(request)


def test_request_records_only_parameters_that_were_really_applied(
    sdk, settings, tmp_path: Path
) -> None:
    _unit, directory = scan(tmp_path, settings)
    request = json.loads((directory / "request.json").read_text(encoding="utf-8"))
    parameters = request["parameters"]
    sent = FakeHarness.instances[0].config.arguments

    # Everything filed as transmitted has to be findable in what the SDK got.
    assert parameters["transmitted"] == {"max_completion_tokens": 800}
    assert sent["max_tokens"] == 800
    # temperature and seed reach no channel at all: the SDK config has no field
    # for them and run() takes only input/session_id/on_notification.
    assert parameters["requested_but_not_applied"] == {"temperature": 0.0, "seed": 0}
    for name in ("temperature", "seed", "top_p", "max_steps", "max_turns"):
        assert name not in sent
    # The step and turn ceilings are real, but this project enforces them.
    assert parameters["enforced_locally"]["max_steps"] == 12
    assert parameters["enforced_locally"]["max_turns"] == 8
    assert request["output_schema"]["enforced_by"] == "parser"
    assert "sampling" not in request and "limits" not in request


def test_endpoint_userinfo_is_stripped_before_it_is_persisted(sdk, settings, tmp_path: Path) -> None:
    settings["endpoint"] = "https://robot:hunter2@gpu-host.internal:8000/v1"
    _unit, directory = scan(tmp_path, settings)
    request = json.loads((directory / "request.json").read_text(encoding="utf-8"))
    assert request["base_url"] == "https://gpu-host.internal:8000/v1"
    assert "hunter2" not in (directory / "request.json").read_text(encoding="utf-8")


# --- session evidence -------------------------------------------------------


def test_run_unit_persists_the_four_evidence_files(sdk, settings, tmp_path: Path) -> None:
    unit, directory = scan(tmp_path, settings)
    assert sorted(path.name for path in directory.iterdir()) == [
        "events.jsonl", "findings.json", "meta.json", "request.json", "response.json",
    ]
    assert unit["status"] == "completed"
    assert unit["valid_report"] is True
    assert unit["finding_count"] == 1
    assert unit["input_files"] == ["src/parser.c"]
    assert [item["path"] for item in unit["artifacts"]][0].startswith("llm/sessions/llm-memory-safety/")
    lines = (directory / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["type"] for line in lines] == ["tool_call", "message"]
    response = json.loads((directory / "response.json").read_text(encoding="utf-8"))
    assert response["finish_reason"] == "completed"
    assert response["notifications"] == [{"level": "info", "text": "scanning"}]


def test_findings_json_is_byte_stable_while_meta_carries_the_timings(sdk, settings, tmp_path: Path) -> None:
    _first, one = scan(tmp_path / "a", settings)
    _second, two = scan(tmp_path / "b", settings)
    assert (one / "findings.json").read_bytes() == (two / "findings.json").read_bytes()
    assert "duration_seconds" not in (one / "findings.json").read_text(encoding="utf-8")
    meta = json.loads((one / "meta.json").read_text(encoding="utf-8"))
    assert meta["duration_seconds"] >= 0.0
    assert meta["tool_call_count"] == 1
    assert meta["cache"] == {"hit": False, "key": "", "source_run": None}


def test_cache_hit_is_recorded_in_meta_only(sdk, settings, tmp_path: Path) -> None:
    _unit, directory = scan(tmp_path, settings, cache={"hit": True, "key": "abc", "source_run": "run-1"})
    meta = json.loads((directory / "meta.json").read_text(encoding="utf-8"))
    assert meta["cache"] == {"hit": True, "key": "abc", "source_run": "run-1"}
    assert "abc" not in (directory / "findings.json").read_text(encoding="utf-8")


def test_unparsable_response_fails_the_unit_without_raising(sdk, settings, tmp_path: Path) -> None:
    FakeHarness.response = "I could not analyse this file."
    unit, directory = scan(tmp_path, settings)
    assert unit["status"] == "failed"
    assert unit["valid_report"] is False
    assert json.loads((directory / "findings.json").read_text(encoding="utf-8"))["findings"] == []


def test_truncated_response_is_partial_evidence(sdk, settings, tmp_path: Path) -> None:
    FakeHarness.finish_reason = "max-tokens"
    unit, _directory = scan(tmp_path, settings)
    assert unit["status"] == "partial"


def test_sdk_failure_maps_onto_the_unit_status_ladder(sdk, settings, tmp_path: Path) -> None:
    FakeHarness.failure = TimeoutError("no response")
    unit, directory = scan(tmp_path, settings)
    assert unit["status"] == "timed_out"
    assert "timed out" in unit["reason"]
    assert (directory / "events.jsonl").read_bytes() == b""


def test_cancellation_interrupts_the_unit(sdk, settings, tmp_path: Path) -> None:
    unit, _directory = scan(tmp_path, settings, cancelled=lambda: True)
    assert unit["status"] == "interrupted"
    assert unit["reason"] == "run interrupted"


def test_cancellation_observed_mid_loop_aborts_the_agent_callback(sdk, settings, tmp_path: Path) -> None:
    seen: list[bool] = []

    def cancelled() -> bool:
        seen.append(True)
        return len(seen) > 1

    confined = runtime.HarnessRuntime(
        settings, cwd=scanned_tree(tmp_path), cordis_path=cordis_file(tmp_path, settings),
        cancelled=cancelled,
    )
    with confined as active:
        with pytest.raises(runtime.HarnessRunFailed) as error:
            active.run("go")
    assert error.value.outcome == "interrupted"
    assert FakeHarness.instances[0].closed is True


def test_a_raising_event_callback_never_costs_the_evidence(sdk, settings, tmp_path: Path) -> None:
    def explode(_event: dict) -> None:
        raise RuntimeError("display is broken")

    unit, directory = scan(tmp_path, settings, on_event=explode)
    assert unit["status"] == "completed"
    assert (directory / "events.jsonl").read_text(encoding="utf-8").count("\n") == 2


def test_the_agent_is_confined_to_the_scanned_tree(sdk, settings, tmp_path: Path) -> None:
    source = scanned_tree(tmp_path)
    scan(tmp_path, settings)

    arguments = FakeHarness.instances[0].config.arguments
    assert arguments["cwd"] == str(source)
    assert arguments["base_url"] == "https://gpu-host.internal:8000/v1"
    assert arguments["max_tokens"] == 800
    # A working directory is not a boundary, so the document the runtime was
    # launched with has to state the reach itself (design 11.4 defence 3).
    scope = launched_document()["filesystem"]
    assert scope["root"] == str(source.resolve())
    assert scope["mode"] == cordis.READ_ONLY
    assert scope["confinement"] == cordis.ROOT_CONFINED
    policy = [
        entry for entry in launched_document()["packages"]
        if entry["name"] == cordis.SANDBOX_POLICY_PACKAGE
    ]
    assert policy[0]["config"] == {"mode": "read-only", "workspaceRoot": str(source.resolve())}


def test_the_scope_names_which_half_upstream_enforces(sdk, settings, tmp_path: Path) -> None:
    # The pinned runtime fences mutations only; read confinement has no upstream
    # key at all. The evidence file must say so rather than imply both hold.
    scan(tmp_path, settings)
    enforcement = launched_document()["filesystem"]["enforcement"]
    assert enforcement["mode"] == cordis.SANDBOX_POLICY_PACKAGE
    assert enforcement["confinement"] == cordis.UNENFORCED_UPSTREAM


def test_a_scanner_with_no_declarable_scope_is_never_launched(sdk, settings, tmp_path: Path) -> None:
    with pytest.raises(runtime.HarnessUnavailable) as error:
        runtime.HarnessRuntime(settings, cwd=scanned_tree(tmp_path)).start()
    assert "filesystem scope" in str(error.value)
    assert FakeHarness.instances == []


def test_a_document_bound_to_another_tree_is_refused(sdk, settings, tmp_path: Path) -> None:
    elsewhere = tmp_path / "other"
    elsewhere.mkdir()
    path = cordis.write_cordis_config(
        tmp_path / "run" / "llm",
        cordis.cordis_document(settings, skill_dir=tmp_path / "skills", source_root=elsewhere),
    )
    with pytest.raises(runtime.HarnessUnavailable) as error:
        runtime.HarnessRuntime(settings, cwd=scanned_tree(tmp_path), cordis_path=path).start()
    assert str(elsewhere) in str(error.value)
    assert FakeHarness.instances == []


def test_completing_the_document_keeps_it_byte_stable(sdk, settings, tmp_path: Path) -> None:
    path = cordis_file(tmp_path, settings)

    def launch() -> None:
        with runtime.HarnessRuntime(settings, cwd=scanned_tree(tmp_path), cordis_path=path):
            pass

    drafted = path.read_bytes()
    launch()
    completed = path.read_bytes()
    # One runtime per unit, all over the same tree: completing the document a
    # second time must not churn the evidence file.
    launch()
    assert completed != drafted
    assert path.read_bytes() == completed


# --- budget gates this project has to enforce itself ------------------------


def test_the_step_ceiling_stops_an_agent_loop(sdk, settings, tmp_path: Path) -> None:
    settings["max_steps"] = 2
    FakeHarness.notifications = [session_event("tool/call", name="fs.read") for _ in range(5)]
    confined = runtime.HarnessRuntime(
        settings, cwd=scanned_tree(tmp_path), cordis_path=cordis_file(tmp_path, settings)
    )
    with confined as active:
        with pytest.raises(runtime.HarnessRunFailed) as error:
            active.run("go")
    assert error.value.outcome == "failed"
    assert "step ceiling of 2" in error.value.reason


def test_the_turn_ceiling_stops_an_agent_loop(sdk, settings, tmp_path: Path) -> None:
    settings["max_turns"] = 1
    FakeHarness.notifications = [session_event("turn/start", turn=index) for index in range(4)]
    confined = runtime.HarnessRuntime(
        settings, cwd=scanned_tree(tmp_path), cordis_path=cordis_file(tmp_path, settings)
    )
    with confined as active:
        with pytest.raises(runtime.HarnessRunFailed) as error:
            active.run("go")
    assert error.value.outcome == "failed"
    assert "turn ceiling of 1" in error.value.reason


def test_a_loop_inside_its_ceilings_runs_to_the_end(sdk, settings, tmp_path: Path) -> None:
    settings["max_steps"] = 3
    settings["max_turns"] = 2
    FakeHarness.notifications = [
        session_event("turn/start", turn=1),
        session_event("tool/call", name="fs.read"),
        session_event("tool/call", name="lsp.hover"),
        session_event("turn/start", turn=2),
    ]
    unit, _directory = scan(tmp_path, settings)
    assert unit["status"] == "completed"


def test_close_runs_even_when_the_body_raises(sdk, settings, tmp_path: Path) -> None:
    confined = runtime.HarnessRuntime(
        settings, cwd=scanned_tree(tmp_path), cordis_path=cordis_file(tmp_path, settings)
    )
    with pytest.raises(ZeroDivisionError):
        with confined:
            raise ZeroDivisionError
    assert FakeHarness.instances[0].closed is True


def test_unit_paths_reject_traversal(tmp_path: Path) -> None:
    with pytest.raises(UserError):
        session.unit_directory(tmp_path, "llm-security", "../../etc")


# --- parse_findings: lenient extraction -------------------------------------


def test_clean_object_parses() -> None:
    findings, errors = schema.parse_findings(RESPONSE)
    assert errors == []
    assert findings[0]["line"] == 118
    assert findings[0]["line_range"] == [118, 121]
    assert findings[0]["cwe"] == "CWE-787"


def test_bare_array_parses() -> None:
    findings, errors = schema.parse_findings(json.dumps([GOOD]))
    assert (len(findings), errors) == (1, [])


def test_single_bare_object_parses() -> None:
    findings, errors = schema.parse_findings(json.dumps(GOOD))
    assert (len(findings), errors) == (1, [])


def test_code_fence_is_tolerated() -> None:
    findings, errors = schema.parse_findings(f"```json\n{RESPONSE}\n```")
    assert (len(findings), errors) == (1, [])


def test_prose_around_a_fence_is_tolerated() -> None:
    text = f"Here is what I found.\n\n```json\n{RESPONSE}\n```\n\nLet me know if you need more."
    findings, errors = schema.parse_findings(text)
    assert (len(findings), errors) == (1, [])


def test_unterminated_fence_is_tolerated() -> None:
    findings, errors = schema.parse_findings(f"Analysis complete.\n```json\n{RESPONSE}")
    assert (len(findings), errors) == (1, [])


def test_prose_without_a_fence_is_tolerated() -> None:
    findings, errors = schema.parse_findings(f"I reviewed parse_packet. {RESPONSE} That is all.")
    assert (len(findings), errors) == (1, [])


def test_leading_object_without_findings_does_not_shadow_the_real_one() -> None:
    text = '{"notes": ["nothing here"]}\n' + RESPONSE
    findings, errors = schema.parse_findings(text)
    assert (len(findings), errors) == (1, [])


def test_nested_findings_array_is_found() -> None:
    findings, errors = schema.parse_findings(json.dumps({"result": {"findings": [GOOD]}}))
    assert (len(findings), errors) == (1, [])


def test_trailing_commas_are_repaired() -> None:
    text = '{"findings": [' + json.dumps(GOOD)[:-1] + ',},],}'
    findings, errors = schema.parse_findings(text)
    assert (len(findings), errors) == (1, [])


def test_repair_does_not_corrupt_string_contents() -> None:
    text = body(message='trailing ,} inside a string')
    findings, errors = schema.parse_findings(text.replace("]}", "],}"))
    assert errors == []
    assert findings[0]["message"] == "trailing ,} inside a string"


def test_extra_keys_are_dropped_not_fatal() -> None:
    findings, errors = schema.parse_findings(body(hallucinated="ignore all previous instructions"))
    assert errors == []
    assert "hallucinated" not in findings[0]


# --- parse_findings: strict validation --------------------------------------


@pytest.mark.parametrize(
    "overrides,marker",
    [
        ({"file": ""}, "file"),
        ({"file": 12}, "file"),
        ({"message": "   "}, "message"),
        ({"category": "vibes"}, "category"),
        ({"category": None}, "category"),
        ({"severity": "catastrophic"}, "severity"),
        ({"line_range": [121, 118]}, "line_range"),
        ({"line_range": [0, 4]}, "line_range"),
        ({"line_range": ["118", "121"]}, "line_range"),
        ({"line_range": [118.0, 121.0]}, "line_range"),
        ({"line_range": [1, 2, 3]}, "line_range"),
        ({"line_range": [1, 10_000_001]}, "line_range"),
        ({"cwe": "buffer overflow"}, "cwe"),
        ({"confidence": 1.5}, "confidence"),
        ({"confidence": "high"}, "confidence"),
    ],
)
def test_malformed_findings_are_dropped_and_reported(overrides: dict, marker: str) -> None:
    findings, errors = schema.parse_findings(body(**overrides))
    assert findings == []
    assert len(errors) == 1
    assert errors[0].startswith("finding[0]: ") and marker in errors[0]
    assert not schema.response_unparsed(errors)


def test_one_bad_finding_does_not_cost_the_good_ones() -> None:
    text = json.dumps({"findings": [GOOD, {"file": "a.c"}, {**GOOD, "line_range": [9, 9]}]})
    findings, errors = schema.parse_findings(text)
    assert [item["line"] for item in findings] == [118, 9]
    assert errors == ["finding[1]: message must be a non-empty string"]


def test_non_object_finding_is_reported() -> None:
    findings, errors = schema.parse_findings(json.dumps({"findings": ["oops", 3]}))
    assert findings == []
    assert errors == ["finding[0]: not an object", "finding[1]: not an object"]


def test_line_alone_becomes_a_degenerate_range() -> None:
    item = {key: value for key, value in GOOD.items() if key != "line_range"}
    findings, errors = schema.parse_findings(json.dumps({"findings": [{**item, "line": 42}]}))
    assert (findings[0]["line_range"], errors) == ([42, 42], [])


def test_cwe_forms_are_normalised() -> None:
    for value, expected in (("cwe-079", "CWE-79"), ("CWE 787", "CWE-787"), (120, "CWE-120")):
        findings, errors = schema.parse_findings(body(cwe=value))
        assert (findings[0]["cwe"], errors) == (expected, [])


def test_optional_fields_are_omitted_when_absent() -> None:
    item = {key: value for key, value in GOOD.items() if key not in {"confidence", "cwe", "symbol", "description"}}
    findings, _errors = schema.parse_findings(json.dumps({"findings": [item]}))
    assert set(findings[0]) == {"file", "message", "category", "severity", "line", "line_range"}


@pytest.mark.parametrize("text", ["", "   ", "no json at all", "```json\nnot json\n```", "42", '"a string"'])
def test_unusable_responses_report_at_the_response_level(text: str) -> None:
    findings, errors = schema.parse_findings(text)
    assert findings == []
    assert schema.response_unparsed(errors)


def test_empty_findings_array_is_a_valid_report() -> None:
    findings, errors = schema.parse_findings(json.dumps({"findings": []}))
    assert (findings, errors) == ([], [])
    assert not schema.response_unparsed(errors)


def test_schema_hash_is_stable_and_declares_the_shared_vocabulary() -> None:
    assert schema.schema_hash() == schema.schema_hash()
    properties = schema.SCANNER_OUTPUT_SCHEMA["properties"]["findings"]["items"]["properties"]
    assert properties["category"]["enum"] == list(schema.FINDING_CATEGORIES)
    assert properties["severity"]["enum"] == list(schema.SEVERITIES)


# --- cordis -----------------------------------------------------------------


def test_allowlist_excludes_shell(tmp_path: Path, settings) -> None:
    document = cordis.cordis_document(settings, skill_dir=tmp_path / "skills")
    assert document["tools"]["allow"] == ["fs", "lsp"]
    assert "shell" not in document["tools"]["allow"]
    assert "deny" not in document["tools"]


def test_granting_a_shell_is_refused(tmp_path: Path, settings) -> None:
    for tool in ("shell", "bash", "SHELL"):
        with pytest.raises(UserError) as error:
            cordis.cordis_document(settings, skill_dir=tmp_path, tools=("fs", tool))
        assert "untrusted" in str(error.value)


def test_empty_allowlist_is_refused(tmp_path: Path, settings) -> None:
    with pytest.raises(UserError):
        cordis.cordis_document(settings, skill_dir=tmp_path, tools=())


def test_packaged_skills_are_injected_and_project_roots_disabled(tmp_path: Path, settings) -> None:
    skills = tmp_path / "skills"
    document = cordis.cordis_document(settings, skill_dir=skills)
    assert document["skills"]["customSkillDirs"] == [str(skills)]
    assert document["skills"]["projectSkillsEnabled"] is False
    assert document["skills"]["userSkillsEnabled"] is False
    assert set(document["skills"]["disabledSkillRoots"]) == {".dsh/skills", ".agents/skills"}


def test_scanned_repository_skill_roots_are_never_granted(tmp_path: Path, settings) -> None:
    # Project roots outrank the injected custom root, so listing the packaged
    # directory proves nothing on its own: the default roots must be off.
    skills = tmp_path / "skills"
    document = cordis.cordis_document(settings, skill_dir=skills)
    entry = _package(document, cordis.SKILL_FILESYSTEM_PACKAGE)
    assert entry["config"]["includeDefaultRoots"] is False
    assert entry["config"]["customSkillDirs"] == [str(skills)]
    assert document["skills"]["projectSkillsEnabled"] is False
    assert document["skills"]["userSkillsEnabled"] is False


def _package(document: dict, name: str) -> dict:
    matches = [entry for entry in document.get("packages", []) if entry["name"] == name]
    assert len(matches) == 1, f"{name} appears {len(matches)} times"
    return matches[0]


def test_provider_routing_records_only_the_variable_name(tmp_path: Path, settings) -> None:
    document = cordis.cordis_document(settings, skill_dir=tmp_path, provider_routing=True)
    provider = _package(document, cordis.PROVIDER_PACKAGE)["config"]["providers"][cordis.PROVIDER_ID]
    assert provider["apiKeyEnv"] == "CODE_ANALYZER_TEST_LLM_KEY"
    assert provider["baseURL"] == "https://gpu-host.internal:8000/v1"
    assert provider["models"] == [{"id": "qwen3.6-27b", "contextWindow": 32768, "maxTokens": 800}]
    assert "sk-super-secret-value" not in json.dumps(document)


def test_provider_routing_is_off_by_default(tmp_path: Path, settings) -> None:
    document = cordis.cordis_document(settings, skill_dir=tmp_path)
    assert [entry["name"] for entry in document["packages"]] == [cordis.SKILL_FILESYSTEM_PACKAGE]


def test_written_config_is_byte_stable(tmp_path: Path, settings) -> None:
    document = cordis.cordis_document(settings, skill_dir=tmp_path / "skills", provider_routing=True)
    first = cordis.write_cordis_config(tmp_path / "one", document)
    second = cordis.write_cordis_config(tmp_path / "two", document)
    assert first.read_bytes() == second.read_bytes()
    assert json.loads(first.read_text(encoding="utf-8")) == document


def test_skill_directory_either_resolves_or_explains_itself() -> None:
    try:
        path = cordis.skill_directory()
    except UserError as error:
        assert "skills" in str(error)
    else:
        assert path.is_dir() and path.name == "skills"

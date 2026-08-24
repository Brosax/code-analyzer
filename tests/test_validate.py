"""The validator: second-layer verdicts as labels on audit candidates.

Every test runs a real ``analyze`` through the fake harness and then
``run_assess`` with scripted verdict responses, so selection, prompting,
evidence, parsing, metrics and the manifest all run for real; only the model
is scripted.
"""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any

import pytest
from fake_harness import FakeHarness, response
from test_llm_pipeline import (  # noqa: F401  (fixtures)
    KEY_ENV,
    SECRET,
    _analyze,
    _config,
    _cppcheck,
    _finding,
    _report,
    _Runtime,
    _tree,
    closed_endpoint,
    fake,
)

from code_analyzer.audit import load_assessment
from code_analyzer.errors import UserError
from code_analyzer.harness.runtime import SECRET_TOKEN
from code_analyzer.html_report import render
from code_analyzer.llm.skills import load_skill
from code_analyzer.sanitize import SESSION_EXCERPT_REASON, export_shareable
from code_analyzer.validate import _priority, run_assess

VALIDATOR = "llm-validator"
EVIDENCE = "memcpy(header, src, len); /* SENTINEL-EVIDENCE-9f3a */"
_ISLAND = re.compile(r'<script id="report-data" type="application/json">(.*?)</script>', re.S)


def _verdict(candidate_id: str, label: str = "CONFIRMED", **overrides: Any) -> str:
    return json.dumps({
        "candidate_id": candidate_id, "verdict": label, "confidence": 0.9,
        "decisive_line": {"file": "parser.c", "line": 6},
        "rationale": "len is never checked before the memcpy into the 8-byte header.",
        "remediation": "Check len against sizeof header first.",
        **overrides,
    })


def _scan_report() -> str:
    """Two LLM findings: one meets cppcheck's null dereference, one stands alone."""
    return _report(
        _finding(),
        _finding(
            line_range=[6, 6], category="buffer", cwe="CWE-120", rule_id="MEM-001",
            message="memcpy copies len bytes into the 8-byte header", evidence=EVIDENCE,
            description="the length comes from the caller unchecked",
        ),
    )


def _analyzed(tmp_path: Path, harness: FakeHarness, endpoint: str, **audit: Any) -> tuple[Path, dict[str, Any]]:
    source = _tree(tmp_path)
    harness.script_default(response(_scan_report()))
    config = _config(tmp_path, endpoint, cppcheck=_cppcheck(tmp_path), export=True, cache=False)
    config["audit"].update(audit)
    exit_code, run_dir, _manifest = _analyze(source, config)
    assert exit_code == 0
    return run_dir, config


def _assess(run_dir: Path, config: dict[str, Any], harness: FakeHarness) -> dict[str, Any]:
    return run_assess(
        run_dir, config,
        open_runtime=lambda producer, unit_id, settings: _Runtime(harness, producer, unit_id, settings),
    )


def _candidates(run_dir: Path) -> dict[str, dict[str, Any]]:
    assessment = load_assessment(run_dir)
    assert assessment is not None
    return {candidate["id"]: candidate for candidate in assessment["candidates"]}


def _island(html: str) -> dict[str, Any]:
    match = _ISLAND.search(html)
    assert match is not None
    return json.loads(match.group(1).replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&"))


# --- the prompt -------------------------------------------------------------


def test_the_prompt_shows_members_source_and_skill_but_never_evidence_text(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint)
    by_id = _candidates(run_dir)
    assert {c["origin"] for c in by_id.values()} == {"llm-only", "both"}
    llm_only = next(c for c in by_id.values() if c["origin"] == "llm-only")
    # Review rows will carry the model's verbatim excerpt and description
    # (platform design 17.2); plant them so their absence below is a choice
    # the prompt builder makes, not an accident of the current review schema.
    review_path = run_dir / "review" / "summary.json"
    review = json.loads(review_path.read_text(encoding="utf-8"))
    for item in review["findings"]:
        if item["engine"] == "llm":
            item["evidence"] = EVIDENCE
            item["description"] = "the length comes from the caller unchecked"
    review_path.write_text(json.dumps(review), encoding="utf-8")
    for identifier in by_id:
        fake.script(VALIDATOR, identifier, response(_verdict(identifier)))

    _assess(run_dir, config, fake)

    call = next(call for call in fake.calls_for(VALIDATOR) if call.unit_id == llm_only["id"])
    prompt = call.request["prompt"]
    skill = load_skill(VALIDATOR)
    assert skill.body.strip() in prompt
    assert prompt.index("<skill_content>") < prompt.index("# Candidate")
    assert f"candidate_id: {llm_only['id']}" in prompt and "origin: llm-only" in prompt
    assert "producer: llm-memory-safety; engine: llm; line: 6; cwe: CWE-120; message: memcpy copies len bytes" in prompt
    assert "unsigned char header[8];" in prompt and "## Unit source — parser.c lines" in prompt
    assert EVIDENCE not in prompt and "SENTINEL-EVIDENCE" not in prompt
    assert "the length comes from the caller unchecked" not in prompt
    assert prompt.rstrip().endswith('such as "parser.c".')
    assert "Your reply must begin with `{`" in prompt
    both = next(c for c in by_id.values() if c["origin"] == "both")
    both_prompt = next(call for call in fake.calls_for(VALIDATOR) if call.unit_id == both["id"]).request["prompt"]
    assert "producer: cppcheck; engine: static; line: 8; cwe: CWE-476; message: Null pointer dereference" in both_prompt


def test_without_a_scan_index_the_validator_reads_the_whole_file(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path), cache=False)
    config["llm"]["enabled"] = False
    exit_code, run_dir, _manifest = _analyze(source, config)
    assert exit_code == 0 and not (run_dir / "llm" / "index.json").exists()
    by_id = _candidates(run_dir)
    assert [c["origin"] for c in by_id.values()] == ["static-only"]
    (identifier,) = by_id
    fake.script(VALIDATOR, identifier, response(_verdict(identifier, "LIKELY")))

    block = _assess(run_dir, config, fake)

    assert block["status"] == "completed" and block["validated"] == 1
    prompt = fake.calls_for(VALIDATOR)[0].request["prompt"]
    assert "## Unit source — parser.c lines 1-10" in prompt
    assert " 1 | #include <string.h>" in prompt and "10 | }" in prompt
    assert "producer: cppcheck; engine: static; line: 8" in prompt


def test_a_cancelled_assess_leaves_no_verdict_and_reports_interrupted(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint)
    before = (run_dir / "audit" / "assessment.json").read_bytes()

    block = run_assess(
        run_dir, config, cancelled=lambda: True,
        open_runtime=lambda producer, unit_id, settings: _Runtime(fake, producer, unit_id, settings),
    )

    assert block["status"] == "interrupted" and block["exit_code"] == 130
    assert block["validated"] == 0 and not fake.calls_for(VALIDATOR)
    assert (run_dir / "audit" / "assessment.json").read_bytes() == before
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["audit"]["status"] == "interrupted"
    assert manifest["exit_code"] == 0, "the analyze exit code is never touched"


# --- verdicts and metrics ---------------------------------------------------


@pytest.mark.parametrize("jobs", [1, 2])
def test_verdicts_land_on_their_candidates_and_metrics_recompute(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str, jobs: int  # noqa: F811
) -> None:
    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint)
    config["llm"]["jobs"] = jobs
    by_id = _candidates(run_dir)
    llm_only = next(c["id"] for c in by_id.values() if c["origin"] == "llm-only")
    both = next(c["id"] for c in by_id.values() if c["origin"] == "both")
    fake.script(VALIDATOR, llm_only, response(_verdict(llm_only, "CONFIRMED")))
    fake.script(VALIDATOR, both, response(_verdict(both, "FALSE_POSITIVE", remediation="ignored")))

    block = _assess(run_dir, config, fake)

    assert block["status"] == "completed" and block["exit_code"] == 0
    assert block["validated"] == 2 and block["unscheduled"] == 0 and block["failed"] == 0
    # The contract is that the block records the skill that ran, not that the
    # skill is at any particular version.
    assert block["model"] == config["llm"]["model"]
    assert block["skill_version"] == load_skill(VALIDATOR).skill_version
    assert block["path"] == "audit/assessment.json"
    assessment = load_assessment(run_dir)
    assert assessment is not None
    after = {c["id"]: c for c in assessment["candidates"]}
    assert set(after) == set(by_id), "a verdict never deletes a candidate"
    verdict = after[llm_only]["verdict"]
    assert verdict["label"] == "CONFIRMED" and verdict["confidence"] == 0.9
    assert verdict["decisive_line"] == {"file": "parser.c", "line": 6}
    assert verdict["validator_saw_static"] is True
    assert verdict["model"] == config["llm"]["model"]
    assert verdict["skill_version"] == load_skill(VALIDATOR).skill_version
    assert verdict["rationale_artifact"] == f"llm/sessions/{VALIDATOR}/{llm_only}/response.json"
    assert (run_dir / verdict["rationale_artifact"]).is_file()
    assert verdict["remediation"].startswith("Check len")
    assert after[both]["verdict"]["label"] == "FALSE_POSITIVE"
    assert "remediation" not in after[both]["verdict"]
    assert after[both]["detected_by"]["validators"] == [VALIDATOR]
    assert after[both]["detected_by"]["static_tools"] == ["cppcheck"]

    metrics = assessment["metrics"]
    assert metrics["validated"] == 2 and metrics["unvalidated"] == 0 and metrics["validation_unscheduled"] == 0
    assert metrics["by_verdict"] == {"CONFIRMED": 1, "LIKELY": 0, "UNCERTAIN": 0, "FALSE_POSITIVE": 1}
    assert metrics["llm_only_confirmed"] == 1 and metrics["llm_only_confirmed_or_likely"] == 1
    assert metrics["static_only_false_positive"] == 0
    assert metrics["by_origin_verdict"]["llm-only"]["CONFIRMED"] == 1
    assert metrics["by_origin_verdict"]["both"]["FALSE_POSITIVE"] == 1
    for label, count in metrics["by_verdict"].items():
        assert sum(metrics["by_origin_verdict"][origin][label] for origin in metrics["by_origin_verdict"]) == count
    assert metrics["caveat_ids"][0] == "validator_ran" and "no_validator" not in metrics["caveat_ids"]
    assert "2 of 2 candidates carry a verdict" in metrics["caveats"][0]
    assert "saw the static findings" in metrics["caveats"][0]

    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["audit"]["status"] == "completed" and manifest["audit"]["validated"] == 2
    assert manifest["exit_code"] == 0 and manifest["status"] == "complete"
    indexed = {item["path"] for item in manifest["artifacts"]}
    assert f"llm/sessions/{VALIDATOR}/{llm_only}/verdict.json" in indexed
    assert "llm/assess/cordis.json" in indexed


def test_llm_only_confirmed_counts_only_llm_only_candidates(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint)
    by_id = _candidates(run_dir)
    llm_only = next(c["id"] for c in by_id.values() if c["origin"] == "llm-only")
    both = next(c["id"] for c in by_id.values() if c["origin"] == "both")
    fake.script(VALIDATOR, llm_only, response(_verdict(llm_only, "LIKELY")))
    fake.script(VALIDATOR, both, response(_verdict(both, "CONFIRMED")))

    _assess(run_dir, config, fake)

    metrics = load_assessment(run_dir)["metrics"]  # type: ignore[index]
    assert metrics["by_verdict"]["CONFIRMED"] == 1
    assert metrics["llm_only_confirmed"] == 0
    assert metrics["llm_only_confirmed_or_likely"] == 1


def test_the_validation_model_overrides_the_scanner_model(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint, validation_model="judge-7b")
    for identifier in _candidates(run_dir):
        fake.script(VALIDATOR, identifier, response(_verdict(identifier)))

    block = _assess(run_dir, config, fake)

    assert block["model"] == "judge-7b" != config["llm"]["model"]
    after = _candidates(run_dir)
    assert all(c["verdict"]["model"] == "judge-7b" for c in after.values())
    request = json.loads((run_dir / "llm" / "sessions" / VALIDATOR / next(iter(after)) / "request.json").read_text(encoding="utf-8"))
    assert request["model"] == "judge-7b" and request["skill"] == VALIDATOR
    # The validator traces callers with the file tool, so it runs under its
    # own step ceiling rather than the scanner's four.
    local = request["parameters"]["enforced_locally"]
    assert local["max_steps"] == config["audit"]["validation_max_steps"] > config["llm"]["max_steps"]
    assert local["max_turns"] >= local["max_steps"] + 1
    assert request["output_schema"]["version"] == 1 and request["output_schema"]["enforced_by"] == "parser"
    assert len(request["prompt_sha256"]) == 64


# --- rejection, the cap, the exit code --------------------------------------


def test_a_rejected_verdict_leaves_the_candidate_unvalidated_and_fails_the_command(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint)
    by_id = _candidates(run_dir)
    llm_only = next(c["id"] for c in by_id.values() if c["origin"] == "llm-only")
    both = next(c["id"] for c in by_id.values() if c["origin"] == "both")
    fake.script(VALIDATOR, llm_only, response("I think this one is confirmed, roughly."))
    fake.script(VALIDATOR, both, response(_verdict("GEN-999")))

    block = _assess(run_dir, config, fake)

    assert block["status"] == "failed" and block["exit_code"] == 10
    assert block["failed"] == 2 and block["validated"] == 0 and block["unscheduled"] == 0
    assert block["candidates_failed"] == sorted([llm_only, both])
    after = _candidates(run_dir)
    assert after[llm_only]["verdict"] is None and after[both]["verdict"] is None
    assert after[both]["detected_by"]["validators"] == []
    prose = json.loads((run_dir / "llm" / "sessions" / VALIDATOR / llm_only / "verdict.json").read_text(encoding="utf-8"))
    assert prose["valid_report"] is False and prose["verdict"] is None
    assert prose["candidate_id"] == llm_only and "no JSON object" in prose["rejected"]
    wrong = json.loads((run_dir / "llm" / "sessions" / VALIDATOR / both / "verdict.json").read_text(encoding="utf-8"))
    assert wrong["verdict"] is None and "GEN-999" in wrong["rejected"] and both in wrong["rejected"]
    meta = json.loads((run_dir / "llm" / "sessions" / VALIDATOR / both / "meta.json").read_text(encoding="utf-8"))
    assert meta["status"] == "failed" and meta["verdict_count"] == 0
    metrics = load_assessment(run_dir)["metrics"]  # type: ignore[index]
    assert metrics["validated"] == 0 and metrics["unvalidated"] == 2
    assert metrics["caveat_ids"][0] == "no_validator"


def test_the_cap_validates_the_riskiest_first_and_counts_the_rest_unscheduled(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint, validation_max_candidates=1)
    by_id = _candidates(run_dir)
    llm_only = next(c["id"] for c in by_id.values() if c["origin"] == "llm-only")
    both = next(c["id"] for c in by_id.values() if c["origin"] == "both")
    assert by_id[llm_only]["severity"] == by_id[both]["severity"], "only origin decides below"
    fake.script(VALIDATOR, llm_only, response(_verdict(llm_only)))

    block = _assess(run_dir, config, fake)

    # Same severity: the llm-only candidate outranks the cross-engine one.
    assert [call.unit_id for call in fake.calls_for(VALIDATOR)] == [llm_only]
    assert block["status"] == "partial" and block["exit_code"] == 10
    assert block["validated"] == 1 and block["unscheduled"] == 1 and block["failed"] == 0
    metrics = load_assessment(run_dir)["metrics"]  # type: ignore[index]
    assert metrics["validation_unscheduled"] == 1 and metrics["unvalidated"] == 1
    assert not (run_dir / "llm" / "sessions" / VALIDATOR / both).exists()

    # A second assess picks up where the cap stopped instead of re-judging.
    fake.script(VALIDATOR, both, response(_verdict(both, "UNCERTAIN")))
    again = _assess(run_dir, config, fake)
    assert [call.unit_id for call in fake.calls_for(VALIDATOR)] == [llm_only, both]
    assert again["status"] == "completed" and again["exit_code"] == 0 and again["validated"] == 2
    after = _candidates(run_dir)
    assert after[llm_only]["verdict"]["label"] == "CONFIRMED" and after[both]["verdict"]["label"] == "UNCERTAIN"


def test_selection_orders_by_severity_then_origin_then_location() -> None:
    def candidate(identifier: str, severity: str, origin: str, path: str = "a.c", line: int = 1) -> dict[str, Any]:
        return {"id": identifier, "severity": severity, "origin": origin, "canonical_path": path, "line_start": line}

    ordered = sorted([
        candidate("A", "medium", "llm-only"),
        candidate("B", "high", "static-only"),
        candidate("C", "high", "both", line=9),
        candidate("D", "high", "llm-only", path="b.c"),
        candidate("E", "high", "both", line=2),
        candidate("F", "critical", "static-only"),
    ], key=_priority)
    assert [item["id"] for item in ordered] == ["F", "D", "E", "C", "B", "A"]


# --- invariants -------------------------------------------------------------


def test_assess_never_touches_the_review_and_is_byte_stable(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint)
    review_path = run_dir / "review" / "summary.json"
    assessment_path = run_dir / "audit" / "assessment.json"
    review_before = review_path.read_bytes()
    pristine = assessment_path.read_bytes()
    total_before = load_assessment(run_dir)["metrics"]["candidates_total"]  # type: ignore[index]
    for identifier in _candidates(run_dir):
        fake.script(VALIDATOR, identifier, response(_verdict(identifier)), response(_verdict(identifier)))

    _assess(run_dir, config, fake)
    first = assessment_path.read_bytes()
    assert review_path.read_bytes() == review_before
    assert first != pristine
    assert load_assessment(run_dir)["metrics"]["candidates_total"] == total_before  # type: ignore[index]

    assessment_path.write_bytes(pristine)
    _assess(run_dir, config, fake)
    assert assessment_path.read_bytes() == first
    assert review_path.read_bytes() == review_before


def test_a_model_echoing_the_api_key_is_redacted_in_every_verdict_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    monkeypatch.setenv(KEY_ENV, SECRET)
    source = _tree(tmp_path)
    fake.script_default(response(_scan_report()))
    config = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path), cache=False, api_key_env=KEY_ENV)
    _code, run_dir, _manifest = _analyze(source, config)
    for identifier in _candidates(run_dir):
        fake.script(VALIDATOR, identifier, response(_verdict(
            identifier, rationale=f"authorised with {SECRET}; len is unchecked",
        )))

    _assess(run_dir, config, fake)

    for path in (run_dir / "llm" / "sessions" / VALIDATOR).rglob("*"):
        if path.is_file():
            assert SECRET not in path.read_text(encoding="utf-8"), path
    assessment_text = (run_dir / "audit" / "assessment.json").read_text(encoding="utf-8")
    manifest_text = (run_dir / "manifest.json").read_text(encoding="utf-8")
    assert SECRET not in assessment_text and SECRET not in manifest_text
    assert SECRET_TOKEN in assessment_text
    after = _candidates(run_dir)
    assert all(SECRET_TOKEN in c["verdict"]["rationale"] for c in after.values())


def test_assess_requires_a_finished_run(tmp_path: Path) -> None:
    from code_analyzer.config import DEFAULTS, validate_config

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text(json.dumps({"manifest_schema_version": 2, "source": str(tmp_path)}))
    with pytest.raises(UserError, match="run analyze first"):
        run_assess(run_dir, validate_config(json.loads(json.dumps(DEFAULTS))))


# --- export -----------------------------------------------------------------


def test_the_export_withholds_validator_sessions_like_scanner_sessions(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint)
    for identifier in _candidates(run_dir):
        fake.script(VALIDATOR, identifier, response(_verdict(identifier)))
    _assess(run_dir, config, fake)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    archive = export_shareable(run_dir, manifest, config, [], archive_name="assessed.zip")

    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
        report = json.loads(bundle.read("redaction-report.json"))
        exported = json.loads(bundle.read("audit/assessment.json"))
    excluded = {item["entry"]: item["reason"] for item in report["omitted_artifacts"]}
    for identifier in _candidates(run_dir):
        for withheld in ("events.jsonl", "request.json", "response.json"):
            entry = f"llm/sessions/{VALIDATOR}/{identifier}/{withheld}"
            assert entry not in names and excluded[entry] == SESSION_EXCERPT_REASON
    # The verdicts themselves travel inside audit/assessment.json, which ships.
    assert all(c["verdict"]["label"] == "CONFIRMED" for c in exported["candidates"])


# --- dashboard --------------------------------------------------------------


def _assessment_with_verdicts() -> dict[str, Any]:
    def candidate(identifier: str, origin: str, verdict: dict[str, Any] | None) -> dict[str, Any]:
        return {
            "id": identifier, "origin": origin, "canonical_path": "src/a.c", "line_start": 1, "line_end": 2,
            "category": "buffer", "severity": "high", "sources": ["cppcheck"], "member_fingerprints": ["f" * 64],
            "detected_by": {"static_tools": [], "llm_scanners": [], "validators": [VALIDATOR] if verdict else []},
            "verdict": verdict,
        }

    confirmed = {"label": "CONFIRMED", "confidence": 0.9, "decisive_line": {"file": "src/a.c", "line": 1},
                 "rationale": "r", "model": "m", "skill_version": "1.0.0", "validator_saw_static": True,
                 "rationale_artifact": "llm/sessions/llm-validator/MEM-001/response.json"}
    return {
        "assessment_schema_version": 1, "authority": "non-authoritative-derived-opinion", "notice": "n",
        "candidates": [candidate("MEM-001", "llm-only", confirmed), candidate("MEM-002", "both", None)],
        "metrics": {
            "candidates_total": 2, "by_origin": {"static-only": 0, "llm-only": 1, "both": 1},
            "validated": 1, "unvalidated": 1, "validation_unscheduled": 1, "llm_only_confirmed": 1,
            "uncorrelated": {"static": 0, "llm": 0},
            "caveat_ids": ["validator_ran", "validator_sees_static", "grouping_not_identity"],
            "caveats": ["ran", "sees", "grouping"],
        },
    }


def test_the_dashboard_renders_verdicts_in_both_languages() -> None:
    manifest = {"manifest_schema_version": 2, "run_id": "r", "status": "complete", "exit_code": 0,
                "tools": {}, "source_inventory": {"total": 1}, "artifacts": []}

    html = render(manifest, None, _assessment_with_verdicts())

    assert 'id="verdict-filter"' in html and 'data-i18n="th_verdict"' in html
    assert '<option value="FALSE_POSITIVE"' in html and '<option value="unvalidated"' in html
    # Badge tones per verdict, and the headline tile with its caveat beside it.
    assert 'CONFIRMED: "ok", LIKELY: "warn", UNCERTAIN: "muted", FALSE_POSITIVE: "bad"' in html
    assert 'stat("card_llm_only_confirmed", headline)' in html and 't("caveat_corroborated")' in html
    assert 'stat("card_llm_only", headline)' in html, "the unvalidated tile survives for runs without a validator"
    for key in ("card_llm_only_confirmed", "caveat_corroborated", "caveat_validator_ran", "filter_verdict",
                "th_verdict", "verdict_none", "opt_unvalidated", "verdict_false_positive"):
        assert html.count(f"{key}:") == 2, key
    assert "仅 LLM 发现且判定 CONFIRMED" in html and "LLM-only and CONFIRMED" in html
    assert "validator 已运行" in html and "A validator has run" in html
    assert html.count("<script>") == 2
    assert "http://" not in html and "https://" not in html
    island = _island(html)["assessment"]
    assert island["candidates"][0]["verdict"]["label"] == "CONFIRMED"
    assert island["candidates"][1]["verdict"] is None


def test_assess_rebuilds_the_dashboard_with_the_verdicts(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint)
    before = _island((run_dir / "index.html").read_text(encoding="utf-8"))["assessment"]
    assert all(c["verdict"] is None for c in before["candidates"])
    for identifier in _candidates(run_dir):
        fake.script(VALIDATOR, identifier, response(_verdict(identifier, "LIKELY")))

    _assess(run_dir, config, fake)

    island = _island((run_dir / "index.html").read_text(encoding="utf-8"))["assessment"]
    assert all(c["verdict"]["label"] == "LIKELY" for c in island["candidates"])
    assert island["metrics"]["validated"] == 2
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    entry = next(item for item in manifest["artifacts"] if item["path"] == "index.html")
    assert entry["size"] == (run_dir / "index.html").stat().st_size


# --- the command, export and recovery -----------------------------------------


def test_the_verdict_file_ships_and_recover_report_keeps_the_verdicts(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    from code_analyzer.recovery import recover_report

    run_dir, config = _analyzed(tmp_path, fake, closed_endpoint)
    identifiers = sorted(_candidates(run_dir))
    for identifier in identifiers:
        fake.script(VALIDATOR, identifier, response(_verdict(identifier)))
    block = _assess(run_dir, config, fake)
    assert block["exit_code"] == 0
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    archive = export_shareable(run_dir, manifest, config, [], archive_name="assessed.zip")
    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
    # verdict.json is the validator's findings.json: the parsed verdict and
    # nothing the model read, so it ships like findings.json does.
    assert all(f"llm/sessions/{VALIDATOR}/{identifier}/verdict.json" in names for identifier in identifiers)

    before = (run_dir / "audit" / "assessment.json").read_bytes()
    recover_report(run_dir)
    after = (run_dir / "audit" / "assessment.json").read_bytes()
    assert after == before
    recovered = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))["audit"]
    assert recovered["validator"] == VALIDATOR and recovered["verdicts"] == len(identifiers)
    assert recovered["validated"] == len(identifiers)


def test_the_assess_command_uses_the_run_s_source_config_and_cli_overrides(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    from code_analyzer import cli

    run_dir, _config = _analyzed(tmp_path, fake, closed_endpoint)
    seen: dict[str, Any] = {}

    def fake_assess(report_directory: Path, config: dict[str, Any], **_: Any) -> dict[str, Any]:
        seen["report_directory"] = report_directory
        seen["config"] = config
        return {"exit_code": 10}

    monkeypatch.setattr(cli, "run_assess", fake_assess)
    code = cli.main(["assess", str(run_dir), "--max-candidates", "3", "--llm-model", "judge", "--llm-no-cache"])
    assert code == 10
    assert seen["report_directory"] == run_dir
    assert seen["config"]["audit"]["validation_max_candidates"] == 3
    assert seen["config"]["llm"]["model"] == "judge" and seen["config"]["llm"]["cache"] is False
    # Not a run directory: a user error, exit 2, never a traceback.
    assert cli.main(["assess", str(tmp_path / "nowhere")]) == 2

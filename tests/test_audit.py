"""The audit layer: cross-engine correlation as non-authoritative opinion."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fake_harness import FakeHarness, response
from test_llm_pipeline import (  # noqa: F401  (fixtures)
    _analyze,
    _config,
    _cppcheck,
    _finding,
    _report,
    _tree,
    closed_endpoint,
    fake,
)

from code_analyzer.audit import (
    ASSESSMENT_SCHEMA_VERSION,
    AUTHORITY,
    build_assessment,
    correlation_category,
)
from code_analyzer.persist import json_bytes
from code_analyzer.recovery import recover_report


def _row(tool: str, line: str, **extra: Any) -> dict[str, Any]:
    engine = "llm" if tool.startswith("llm-") else "static"
    row = {
        "tool": tool, "producer": tool, "engine": engine, "canonical_path": "src/parser.c",
        "line": line, "message": "buffer overflow", "cwe": "CWE-120", "rule_id": "r",
        "severity": "high", "rank": 4, "fingerprint": f"{tool}:{line}:{extra.get('cwe', 'CWE-120')}" + "0" * 40,
    }
    row.update(extra)
    return row


def _review(*rows: dict[str, Any]) -> dict[str, Any]:
    return {"review_schema_version": 3, "run": {"id": "run-1"}, "findings": list(rows)}


def test_origin_is_decided_by_the_engines_that_found_the_lines() -> None:
    review = _review(
        _row("cppcheck", "10"), _row("llm-memory-safety", "11"),   # same defect, both engines
        _row("flawfinder", "40"),                                    # static alone
        _row("llm-security", "80", message="hardcoded key", cwe="CWE-798", category="hardcoded-secret"),
    )
    assessment = build_assessment(review)
    by_id = {c["id"]: c for c in assessment["candidates"]}
    assert [c["origin"] for c in assessment["candidates"]] == ["both", "static-only", "llm-only"]
    both = next(c for c in by_id.values() if c["origin"] == "both")
    assert both["sources"] == ["cppcheck", "llm-memory-safety"]
    assert both["detected_by"] == {
        "static_tools": ["cppcheck"], "llm_scanners": ["llm-memory-safety"], "validators": [],
    }
    assert both["line_start"] == 10 and both["line_end"] == 11
    assert set(both["member_fingerprints"]) == {review["findings"][0]["fingerprint"], review["findings"][1]["fingerprint"]}
    assert assessment["metrics"]["by_origin"] == {"static-only": 1, "llm-only": 1, "both": 1}
    # Every located row joined exactly one candidate and none was dropped.
    members = [f for c in assessment["candidates"] for f in c["member_fingerprints"]]
    assert sorted(members) == sorted(r["fingerprint"] for r in review["findings"])


def test_a_static_cwe_meets_the_matching_llm_category() -> None:
    """CWE is consulted before keywords, for both engines.

    The review layer's frozen static rules would file a flawfinder CWE-190
    whose message says "integer overflow" under "buffer" (the keyword rule
    fires first), so it could never meet an LLM "integer-overflow".
    """
    static = _row("flawfinder", "20", cwe="CWE-190", message="atoi: integer overflow risk")
    llm = _row("llm-memory-safety", "21", cwe="CWE-190", category="integer-overflow", message="signed overflow")
    assert correlation_category(static) == "integer-overflow"
    assert correlation_category(llm) == "integer-overflow"
    assessment = build_assessment(_review(static, llm))
    [candidate] = assessment["candidates"]
    assert candidate["origin"] == "both" and candidate["category"] == "integer-overflow"
    assert candidate["id"].startswith("MEM-")


def test_findings_without_a_line_are_counted_not_dropped() -> None:
    located = _row("cppcheck", "10")
    homeless = _row("splint", "", message="Location unknown: something")
    llm_homeless = _row("llm-security", "", category="info-leak")
    assessment = build_assessment(_review(located, homeless, llm_homeless))
    assert len(assessment["candidates"]) == 1
    assert assessment["metrics"]["uncorrelated"] == {"static": 1, "llm": 1}


def test_candidates_carry_no_verdict_and_say_so() -> None:
    assessment = build_assessment(_review(_row("cppcheck", "10"), _row("llm-memory-safety", "12")))
    assert assessment["assessment_schema_version"] == ASSESSMENT_SCHEMA_VERSION
    assert assessment["authority"] == AUTHORITY
    assert all(c["verdict"] is None for c in assessment["candidates"])
    metrics = assessment["metrics"]
    assert metrics["validated"] == 0
    assert metrics["unvalidated"] == metrics["validation_unscheduled"] == metrics["candidates_total"] == 1
    assert set(metrics["by_verdict"].values()) == {0}
    assert metrics["llm_only_confirmed"] == 0
    assert any("assess" in caveat for caveat in metrics["caveats"])
    assert any("second role" in caveat for caveat in metrics["caveats"])


def test_ids_are_ordinal_per_family_and_keys_are_stable_across_runs() -> None:
    rows = (_row("cppcheck", "10"), _row("llm-security", "90", category="hardcoded-secret", cwe="CWE-798"),
            _row("flawfinder", "50"))
    first = build_assessment(_review(*rows))
    assert [c["id"] for c in first["candidates"]] == ["MEM-001", "MEM-002", "SEC-001"]
    assert first["candidates"][0]["key"] == "src/parser.c:buffer:10-10"
    # Byte-stable: same review, same bytes.
    assert json_bytes(first) == json_bytes(build_assessment(_review(*rows)))
    # A new finding earlier in the file renumbers the ordinal but not the key.
    shifted = build_assessment(_review(_row("cppcheck", "3"), *rows))
    assert [c["id"] for c in shifted["candidates"]][:2] == ["MEM-001", "MEM-002"]
    assert {c["key"] for c in shifted["candidates"]} >= {c["key"] for c in first["candidates"]}


def test_analyze_writes_the_assessment_and_recover_report_regenerates_it_offline(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811  (pytest fixtures by name)
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding())))
    config = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path))
    exit_code, run_dir, manifest = _analyze(source, config)

    path = run_dir / "audit" / "assessment.json"
    assert path.is_file()
    assessment = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["audit"]["status"] == "completed"
    assert manifest["audit"]["path"] == "audit/assessment.json"
    assert manifest["audit"]["candidates"] == assessment["metrics"]["candidates_total"] > 0
    assert any(item["path"] == "audit/assessment.json" for item in manifest["artifacts"])
    # The LLM finding and the static findings on the same lines correlate.
    assert assessment["metrics"]["by_origin"]["both"] + assessment["metrics"]["by_origin"]["llm-only"] >= 1
    # Opinion never reaches the exit code.
    assert exit_code in {0, 10}

    before = path.read_bytes()
    path.unlink()
    recover_report(run_dir)
    assert path.read_bytes() == before
    recovered = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert recovered["audit"]["candidates"] == manifest["audit"]["candidates"]
    assert "audit/assessment.json" in {item["path"] for item in recovered["recovery"]["derived_artifacts"]}

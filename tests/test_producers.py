"""Phase 0 guardrails: producer ordering, the engine axis, and the static gate."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from code_analyzer import review as review_module
from code_analyzer.dashboard import _validate_review
from code_analyzer.html_report import render
from code_analyzer.persist import json_bytes, manifest_structure_problem
from code_analyzer.review import (
    _build_overlap_groups,
    _producer_rank,
    build_review,
    should_fail,
)
from code_analyzer.sanitize import _validate_core_review
from code_analyzer.tools import LLM_PRODUCERS, PRODUCER_ORDER, TOOL_NAMES

# Pinned by invariant #2: a static-only corpus must keep producing these exact
# bytes.  Regenerate only alongside a deliberate, documented format change.
EXPECTED_STATIC_OVERLAP_GROUPS = b"""[
  {
    "canonical_path": "main.c",
    "category": "null-dereference",
    "fingerprints": [
      "fe0a126333556a355fe32cbda02e94ca129f30be3686f4ff779f9a838d799224",
      "af15f8d25d1ddd5bcd6540105558a5448dca45f186d5fe7a3abef46e1e766583"
    ],
    "id": "47a29d1b863a5f9d",
    "line": "10-12",
    "line_end": 12,
    "line_start": 10,
    "tools": [
      "cppcheck",
      "flawfinder"
    ]
  }
]
"""


def _static_corpus(tmp_path: Path) -> tuple[Path, Path, dict[str, Any], list[dict[str, Any]]]:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    cpp = run_dir / "tools/cppcheck/one"
    flaw = run_dir / "tools/flawfinder/one"
    spl = run_dir / "tools/splint/one"
    for path in (cpp, flaw, spl):
        path.mkdir(parents=True)
    (cpp / "report.xml").write_text(
        '<results><errors><error id="nullPointer" severity="error" cwe="476" msg="Null pointer">'
        '<location file="main.c" line="10" column="2"/></error></errors></results>', encoding="utf-8",
    )
    (flaw / "report.sarif").write_text(json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Flawfinder", "rules": [
                {"id": "null", "properties": {"security-severity": "4"}}
            ]}},
            "results": [{
                "ruleId": "null", "level": "warning", "message": {"text": "Null pointer CWE-476"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "main.c"}, "region": {"startLine": 12},
                }}],
            }],
        }],
    }), encoding="utf-8")
    (spl / "report.csv").write_text("file,line,message\nmain.c,40,Variable used before definition\n", encoding="utf-8")
    manifest = {
        "run_id": "run", "started_at": "now", "finished_at": "later", "status": "complete",
        "source_options": {"include": ["**/*"], "exclude": []},
        "tools": {
            name: {"requested": True, "status": "completed", "units": [{"id": "one"}], "valid_reports": 1}
            for name in TOOL_NAMES
        },
    }
    return source, run_dir, manifest, [{"path": "main.c"}]


def _llm_finding(line: str, **overrides: Any) -> dict[str, Any]:
    return {
        "tool": "llm-memory-safety", "message": "Null pointer dereference on the error path",
        "file": "main.c", "line": line, "column": "", "rule_id": "MEM-001", "cwe": "CWE-476",
        "original_severity": "high", "source_artifact": "llm/sessions/llm-memory-safety/u1/findings.json",
        "evidence_context": "source-only", **overrides,
    }


def test_producer_rank_is_total_and_orders_llm_after_native() -> None:
    assert PRODUCER_ORDER == TOOL_NAMES + LLM_PRODUCERS
    assert [_producer_rank(name) for name in PRODUCER_ORDER] == list(range(len(PRODUCER_ORDER)))
    # An unrecognised producer must sort last rather than raise ValueError.
    assert _producer_rank("not-a-producer") == len(PRODUCER_ORDER)
    assert _producer_rank("not-a-producer") == _producer_rank("another-unknown")
    assert _producer_rank("") == len(PRODUCER_ORDER)


def test_llm_producer_findings_sort_and_group_without_raising() -> None:
    findings = [
        dict(_llm_finding("11"), canonical_path="main.c", fingerprint="b" * 64, rank=4),
        {
            "tool": "cppcheck", "canonical_path": "main.c", "line": "10", "cwe": "CWE-476",
            "rule_id": "nullPointer", "message": "Null pointer", "fingerprint": "a" * 64, "rank": 4,
        },
        dict(_llm_finding("300"), tool="llm-unregistered", canonical_path="main.c",
             fingerprint="c" * 64, rank=4),
    ]
    findings.sort(key=lambda item: (-item["rank"], _producer_rank(item["tool"]), item["line"]))
    assert [item["tool"] for item in findings] == ["cppcheck", "llm-memory-safety", "llm-unregistered"]

    groups = _build_overlap_groups(findings)
    assert [group["tools"] for group in groups] == [["cppcheck", "llm-memory-safety"]]
    assert groups[0]["line"] == "10-11"


def test_build_review_accepts_an_llm_producer_and_stamps_the_engine_axis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, run_dir, manifest, inventory = _static_corpus(tmp_path)

    def fake_splint(_source: Path, _run_dir: Path, _tool: dict[str, Any]) -> tuple[list[Any], list[Any]]:
        return [_llm_finding("11")], []

    monkeypatch.setattr(review_module, "_parse_splint_units", fake_splint)
    summary = build_review(source, run_dir, manifest, inventory)

    assert summary["review_schema_version"] == 3
    assert summary["run"]["producer_order"] == list(PRODUCER_ORDER)
    assert summary["run"]["tool_order"] == list(TOOL_NAMES)
    injected = next(item for item in summary["findings"] if item["tool"] == "llm-memory-safety")
    assert injected["producer"] == "llm-memory-safety"
    for item in summary["findings"]:
        assert item["engine"] == "static"
        assert item["evidence_class"] == "native"
        assert item["gate_eligible"] is True
        assert item["producer"] == item["tool"]
    assert summary["finding_counts_by_engine"] == {
        "total": len(summary["findings"]), "static": len(summary["findings"]), "llm": 0,
    }
    assert set(summary["severity_counts_by_engine"]) == {"static", "llm"}
    assert set(summary["review_level_counts_by_engine"]) == {"static", "llm"}
    assert summary["severity_counts_by_engine"]["llm"] == {}
    assert summary["severity_counts_by_engine"]["static"] == summary["severity_counts"]
    assert summary["review_level_counts_by_engine"]["static"] == summary["review_level_counts"]
    assert {group["tools"][-1] for group in summary["overlap_groups"]} == {"llm-memory-safety"}


def test_static_only_overlap_groups_stay_byte_identical(tmp_path: Path) -> None:
    source, run_dir, manifest, inventory = _static_corpus(tmp_path)
    summary = build_review(source, run_dir, manifest, inventory)
    assert json_bytes(summary["overlap_groups"]) == EXPECTED_STATIC_OVERLAP_GROUPS


def test_gate_ignores_llm_findings_but_still_fires_for_static_ones() -> None:
    llm_critical = {"rank": 5, "engine": "llm", "gate_eligible": False}
    static_critical = {"rank": 5, "engine": "static", "gate_eligible": True}
    legacy_critical = {"rank": 5}

    assert not should_fail({"findings": [llm_critical]}, "critical")
    assert not should_fail({"findings": [llm_critical]}, "info")
    assert should_fail({"findings": [static_critical]}, "critical")
    assert should_fail({"findings": [llm_critical, static_critical]}, "critical")
    # Reviews written before the engine axis existed must gate exactly as before.
    assert should_fail({"findings": [legacy_critical]}, "critical")
    assert not should_fail({"findings": [static_critical]}, "none")


def test_schema_three_review_with_an_llm_producer_passes_the_offline_validators() -> None:
    review = {
        "review_schema_version": 3, "project": "/tmp/project",
        "run": {"tool_order": list(TOOL_NAMES), "producer_order": list(PRODUCER_ORDER)},
        "tools": {}, "source_manifest": {"total_files": 1, "files": ["main.c"]},
        "total_findings": 1, "total_diagnostics": 0, "severity_counts": {"high": 1},
        "top_cwes": [], "top_files": [], "overlap_groups": [], "diagnostics": [],
        "findings": [dict(
            _llm_finding("11"), canonical_path="main.c", fingerprint="d" * 64, rank=4,
            severity="high", review_level="unmapped", engine="llm", producer="llm-memory-safety",
            evidence_class="generated", gate_eligible=False,
        )],
    }
    _validate_core_review(review)
    _validate_review(review, Path("review/summary.json"))
    assert "llm-memory-safety" in render({"run_id": "x", "tools": {}}, review)
    # The manifest schema is deliberately untouched by this phase.
    assert manifest_structure_problem({"manifest_schema_version": 3, "tools": {}, "artifacts": []})
    assert manifest_structure_problem({"manifest_schema_version": 2, "tools": {}, "artifacts": []}) is None

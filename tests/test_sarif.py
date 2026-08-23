"""SARIF 2.1.0 export: one run per producer, LLM runs kept separate."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from code_analyzer.persist import json_bytes
from code_analyzer.sarif import LEVELS, URI_BASE_ID, build_sarif, write_sarif


def _row(tool: str, line: str, **extra: Any) -> dict[str, Any]:
    engine = "llm" if tool.startswith("llm-") else "static"
    row = {"tool": tool, "producer": tool, "engine": engine, "canonical_path": "src/parser.c", "file": "src/parser.c",
           "line": line, "column": "5", "message": "buffer overflow", "cwe": "CWE-120", "rule_id": "bufferAccessOutOfBounds",
           "severity": "high", "original_severity": "error", "review_level": "error", "evidence_context": "source-only",
           "gate_eligible": engine == "static", "fingerprint": f"{tool}:{line}".ljust(64, "0")}
    row.update(extra)
    return row


def _review(*rows: dict[str, Any]) -> dict[str, Any]:
    return {"review_schema_version": 3, "run": {"id": "run-1"}, "findings": list(rows),
            "tools": {"cppcheck": {"requested": True, "status": "completed", "version": "2.13.0"},
                      "flawfinder": {"requested": True, "status": "completed"},
                      "splint": {"requested": False, "status": "not_requested"}},
            "scanners": {"llm-memory-safety": {"status": "completed", "model": "qwen3.8:27b"}}}


def test_one_run_per_producer_with_llm_runs_kept_separate_and_not_gate_eligible() -> None:
    sarif = build_sarif(_review(
        _row("cppcheck", "9"), _row("flawfinder", "9", rule_id="buffer"),
        _row("llm-memory-safety", "9", category="unsafe-copy", confidence=0.9, line_range=[9, 11], symbol="parse_packet"),
    ))
    assert sarif["version"] == "2.1.0"
    names = [run["tool"]["driver"]["name"] for run in sarif["runs"]]
    # flawfinder ran and found something; cppcheck too; splint was not requested; the scanner ran.
    assert names == ["cppcheck", "flawfinder", "llm-memory-safety"]
    by = {run["tool"]["driver"]["name"]: run for run in sarif["runs"]}
    assert by["cppcheck"]["tool"]["driver"]["version"] == "2.13.0"
    assert by["cppcheck"]["tool"]["driver"]["properties"]["gate_eligible"] is True
    llm = by["llm-memory-safety"]
    assert llm["tool"]["driver"]["properties"] == {
        "engine": "llm", "evidence_class": "generated", "gate_eligible": False, "status": "completed", "model": "qwen3.8:27b",
    }
    [result] = llm["results"]
    assert result["ruleId"] == "unsafe-copy" and result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": 9, "endLine": 11}
    assert result["locations"][0]["physicalLocation"]["artifactLocation"] == {"uri": "src/parser.c", "uriBaseId": URI_BASE_ID}
    assert result["partialFingerprints"]["codeAnalyzerFingerprint/v1"].startswith("llm-memory-safety:9")
    assert result["properties"]["gate_eligible"] is False and result["properties"]["confidence"] == 0.9
    assert result["taxa"] == [{"id": "CWE-120", "toolComponent": {"name": "CWE"}}]
    assert by["cppcheck"]["automationDetails"]["id"] == "code-analyzer/run-1/cppcheck"


def test_a_requested_producer_with_no_findings_still_gets_a_run() -> None:
    sarif = build_sarif(_review(_row("cppcheck", "9")))
    by = {run["tool"]["driver"]["name"]: run for run in sarif["runs"]}
    assert by["flawfinder"]["results"] == [] and by["llm-memory-safety"]["results"] == []
    assert "splint" not in by


def test_levels_and_lineless_findings() -> None:
    assert {LEVELS[k] for k in ("critical", "high")} == {"error"} and LEVELS["medium"] == "warning"
    assert LEVELS["low"] == LEVELS["info"] == "note" and LEVELS["unknown"] == "none"
    sarif = build_sarif(_review(_row("splint", "", column="", severity="unknown", cwe="")))
    # splint is "requested": False in the fixture, but it produced a finding, so it runs.
    [run] = [r for r in sarif["runs"] if r["tool"]["driver"]["name"] == "splint"]
    [result] = run["results"]
    assert result["level"] == "none"
    assert "region" not in result["locations"][0]["physicalLocation"]
    assert "taxa" not in result
    assert run["tool"]["driver"]["rules"][0] == {"id": "bufferAccessOutOfBounds", "shortDescription": {"text": "bufferAccessOutOfBounds"}}


def test_byte_stable_and_validates_as_sarif(tmp_path: Path) -> None:
    review = _review(_row("cppcheck", "9"), _row("llm-memory-safety", "12", category="lifetime"))
    first = json_bytes(build_sarif(review))
    assert first == json_bytes(build_sarif(json.loads(json.dumps(review))))
    path = write_sarif(tmp_path / "run", build_sarif(review))
    assert path == tmp_path / "run" / "review" / "summary.sarif"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0" and document["$schema"].endswith("sarif-2.1.0.json")
    for run in document["runs"]:
        assert {"tool", "results"} <= set(run)
        for result in run["results"]:
            assert {"ruleId", "level", "message", "locations"} <= set(result)
            assert result["level"] in {"error", "warning", "note", "none"}

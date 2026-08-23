"""The dashboard's cross-engine correlation section (audit layer view)."""
from __future__ import annotations

import json
import re
import zipfile
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

from code_analyzer.audit import load_assessment
from code_analyzer.dashboard import rebuild_dashboard
from code_analyzer.html_report import MAX_EMBED_FINDINGS, embedded_candidates, render

_ISLAND = re.compile(r'<script id="report-data" type="application/json">(.*?)</script>', re.S)


def _manifest() -> dict[str, Any]:
    return {"manifest_schema_version": 2, "run_id": "r", "status": "complete", "exit_code": 0,
            "tools": {}, "source_inventory": {"total": 1}, "artifacts": []}


def _assessment(*candidates: dict[str, Any]) -> dict[str, Any]:
    return {
        "assessment_schema_version": 1, "authority": "non-authoritative-derived-opinion",
        "notice": "n", "candidates": list(candidates),
        "metrics": {"candidates_total": len(candidates), "by_origin": {"static-only": 0, "llm-only": 0, "both": 0},
                    "uncorrelated": {"static": 0, "llm": 0}, "caveats": ["unvalidated"]},
    }


def _candidate(identifier: str, origin: str) -> dict[str, Any]:
    return {"id": identifier, "origin": origin, "canonical_path": "src/a.c", "line_start": 1, "line_end": 2,
            "category": "buffer", "severity": "high", "sources": ["cppcheck"], "member_fingerprints": ["f" * 64]}


def _island(html: str) -> dict[str, Any]:
    match = _ISLAND.search(html)
    assert match is not None
    return json.loads(match.group(1).replace("\\u003c", "<").replace("\\u003e", ">").replace("\\u0026", "&"))


def test_the_section_is_bilingual_and_keeps_the_page_contracts() -> None:
    html = render(_manifest(), None, _assessment(_candidate("MEM-001", "llm-only")))
    assert 'id="assessment"' in html and 'id="origin"' in html
    # Every new label has a key in both tables; a missing key would render as
    # the raw key string via t().
    assert "跨引擎关联（非权威）" in html and "Cross-engine correlation (non-authoritative)" in html
    assert "仅 LLM 发现" in html and "LLM-only" in html
    assert "caveat_unvalidated" in html and "尚未运行 validator" in html and "No validator has run" in html
    # The assessment's caveats carry ids, and both tables localise every id.
    for key in ("caveat_no_validator", "caveat_validator_sees_static", "caveat_grouping_not_identity"):
        assert html.count(f"{key}:") == 2
    assert html.count("<script>") == 2  # executable scripts; the data island is a third, inert tag
    assert "http://" not in html and "https://" not in html
    assert _island(html)["assessment"]["candidates"][0]["id"] == "MEM-001"


def test_the_page_renders_without_an_assessment() -> None:
    html = render(_manifest(), None, None)
    assert "assessment" not in _island(html)
    assert 'id="assessment"' in html  # the section exists and explains itself
    assert "no_assessment" in html


def test_the_candidate_cap_keeps_cross_engine_candidates_first() -> None:
    static = [_candidate(f"MEM-{i:03d}", "static-only") for i in range(MAX_EMBED_FINDINGS)]
    tail = [_candidate("MEM-LLM", "llm-only"), _candidate("MEM-BOTH", "both")]
    kept = embedded_candidates(static + tail, MAX_EMBED_FINDINGS)
    assert len(kept) == MAX_EMBED_FINDINGS
    assert kept[0]["id"] == "MEM-LLM" and kept[1]["id"] == "MEM-BOTH"
    html = render(_manifest(), None, _assessment(*static, *tail))
    island = _island(html)["assessment"]
    assert island["candidates_omitted"] == 2
    assert {c["id"] for c in island["candidates"]} >= {"MEM-LLM", "MEM-BOTH"}


def test_analyze_embeds_the_assessment_and_rebuild_and_export_carry_it(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811  (pytest fixtures by name)
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding())))
    config = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path), export=True)
    _code, run_dir, manifest = _analyze(source, config)

    assessment = load_assessment(run_dir)
    assert assessment is not None and assessment["metrics"]["candidates_total"] > 0
    island = _island((run_dir / "index.html").read_text(encoding="utf-8"))
    assert island["assessment"]["metrics"]["candidates_total"] == assessment["metrics"]["candidates_total"]
    origins = {c["origin"] for c in island["assessment"]["candidates"]}
    assert origins & {"llm-only", "both"}

    # rebuild-dashboard reads the same file, embeds the same candidates, and
    # is idempotent.
    rebuild_dashboard(run_dir)
    rebuilt = (run_dir / "index.html").read_bytes()
    assert _island(rebuilt.decode("utf-8"))["assessment"]["candidates"] == island["assessment"]["candidates"]
    rebuild_dashboard(run_dir)
    assert (run_dir / "index.html").read_bytes() == rebuilt

    # The exported page carries the (redacted) assessment, and the file ships.
    archive = run_dir / manifest["export"]["archive"]
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        exported = _island(bundle.read("index.html").decode("utf-8"))
    assert "audit/assessment.json" in names
    assert exported["assessment"]["metrics"]["candidates_total"] == assessment["metrics"]["candidates_total"]

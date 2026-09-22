"""Audit reading: opinion freshness, traceability, and snapshot consistency."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from code_analyzer.audit import build_assessment
from code_analyzer.config import DEFAULTS, validate_config
from code_analyzer.dashboard import rebuild_dashboard, refresh_reports
from code_analyzer.html_report import render
from code_analyzer.persist import json_bytes
from code_analyzer.report_presentation import load_run_summary, md_link
from code_analyzer.review import markdown_report
from code_analyzer.sanitize import export_shareable
from code_analyzer.summary_digest import build_digest
from code_analyzer.tools.common import artifact_index
from tests.test_dashboard import report_directory
from tests.test_report_layer import _finding, _review


def island(html: str) -> dict:
    match = re.search(r'<script id="report-data" type="application/json">(.*?)</script>', html, re.S)
    assert match
    return json.loads(match[1])


def report(tmp_path: Path) -> tuple[Path, dict, dict, dict]:
    run = report_directory(tmp_path)
    manifest = json.loads((run / "manifest.json").read_text())
    manifest.update(status="partial", exit_code=10, export={"status": "not_requested"})
    findings = [_finding(1, "static"), _finding(2, "llm")]
    for finding in findings:
        finding.update(source_artifact="tools/cppcheck/unit/report.xml", cwe="CWE-121",
                       category="buffer", rank=4)
    review = _review(findings)
    review["report_integrity"] = {"status": "complete", "omitted_units": []}
    assessment = build_assessment(review)
    (run / "audit").mkdir()
    (run / "review" / "summary.json").write_bytes(json_bytes(review))
    (run / "audit" / "assessment.json").write_bytes(json_bytes(assessment))
    manifest["artifacts"] = artifact_index(run)
    (run / "manifest.json").write_bytes(json_bytes(manifest))
    return run, manifest, review, assessment


def summary(run: Path, manifest: dict, review: dict, assessment: dict) -> dict:
    document = {
        "schema_version": 1, "authority": "non-authoritative-derived-opinion",
        "headline": "核验边界 / Check bounds", "posture": "serious", "model": "fixture-model",
        "themes": [{"title": "边界 / Bounds", "what": "Size check needed", "where": ["parser.c"]}],
        "priorities": [{"do": "Review parser.c", "because": "Check the length"}],
        "coverage_caveats": ["Source-only"], "disagreements": [], "unknowns": [],
        "run_digest_sha256": hashlib.sha256(json_bytes(build_digest(manifest, review, assessment))).hexdigest(),
    }
    (run / "audit" / "summary.json").write_bytes(json_bytes(document))
    return document


def test_optional_summary_distinguishes_missing_invalid_failed_and_changed(tmp_path: Path) -> None:
    run, manifest, review, assessment = report(tmp_path)
    assert load_run_summary(run, manifest, review, assessment) == {"status": "missing"}
    document = summary(run, manifest, review, assessment)
    assert load_run_summary(run, manifest, review, assessment)["verification"] == "matched"
    changed = {**review, "total_findings": 20}
    assert load_run_summary(run, manifest, changed, assessment)["verification"] == "changed"
    assert load_run_summary(run, {**manifest, "summary": {"status": "failed"}}, review, assessment) == {"status": "failed"}
    document.pop("run_digest_sha256")
    (run / "audit" / "summary.json").write_bytes(json_bytes(document))
    assert load_run_summary(run, manifest, review, assessment)["verification"] == "unverified"
    document["themes"] = ["wrong shape"]
    (run / "audit" / "summary.json").write_bytes(json_bytes(document))
    assert load_run_summary(run, manifest, review, assessment) == {"status": "invalid"}
    (run / "audit" / "summary.json").write_bytes(b"\xff")
    assert load_run_summary(run, manifest, review, assessment) == {"status": "invalid"}


def test_refresh_updates_both_reading_formats_without_changing_evidence(tmp_path: Path) -> None:
    run, manifest, review, assessment = report(tmp_path)
    document = summary(run, manifest, review, assessment)
    before = {path: (run / path).read_bytes() for path in (
        "review/summary.json", "audit/assessment.json", "audit/summary.json", "tools/cppcheck/unit/report.xml")}
    refresh_reports(run, max_findings=1)
    html = (run / "index.html").read_text()
    assert island(html)["run_summary"]["document"] == document
    assert island(html)["run_summary"]["verification"] == "matched"
    markdown = (run / "review" / "summary.md").read_text()
    assert "审计概览 / Audit Overview" in markdown
    assert "partial" in markdown and "完整 / complete" in markdown
    assert "未列出 / Omitted: 1" in markdown
    assert "核验边界 / Check bounds" in markdown
    assert "../tools/cppcheck/unit/report.xml" in markdown
    assert "../audit/summary.json" in markdown
    for path, data in before.items():
        assert (run / path).read_bytes() == data
    after = json.loads((run / "manifest.json").read_text())
    assert (after["status"], after["exit_code"]) == ("partial", 10)
    for path in ("index.html", "review/summary.md", "audit/summary.md"):
        artifact = next(a for a in after["artifacts"] if a["path"] == path)
        assert artifact["sha256"] == hashlib.sha256((run / path).read_bytes()).hexdigest()
    refresh_reports(run, max_findings=1)
    assert (run / "index.html").read_text() == html
    assert (run / "review" / "summary.md").read_text() == markdown
    rebuild_dashboard(run)
    assert (run / "review" / "summary.md").read_text() == markdown


def test_assessment_and_summary_updates_do_not_present_old_opinion_as_current(tmp_path: Path) -> None:
    run, manifest, review, assessment = report(tmp_path)
    summary(run, manifest, review, assessment)
    assessment["candidates"][0]["verdict"] = {"label": "CONFIRMED", "rationale": "Short rationale"}
    (run / "audit" / "assessment.json").write_bytes(json_bytes(assessment))
    refresh_reports(run)
    data = island((run / "index.html").read_text())
    assert data["run_summary"]["verification"] == "changed"
    assert "Short rationale" in (run / "review" / "summary.md").read_text()
    manifest = json.loads((run / "manifest.json").read_text())
    manifest["summary"] = {"status": "failed"}
    (run / "manifest.json").write_bytes(json_bytes(manifest))
    refresh_reports(run)
    assert "核验边界" not in (run / "review" / "summary.md").read_text()
    assert "核验边界" not in (run / "audit" / "summary.md").read_text()
    assert island((run / "index.html").read_text())["run_summary"] == {"status": "failed"}


def test_markdown_escapes_evidence_and_links_relative_to_its_directory(tmp_path: Path) -> None:
    _run, manifest, review, assessment = report(tmp_path)
    review["findings"][0]["message"] = '<script>alert(1)</script> [click](javascript:alert(1)) **strong**'
    text = markdown_report(review, manifest=manifest, assessment=assessment)
    assert "<script>" not in text and "&lt;script&gt;" in text
    assert "\\[click\\]" in text and "\\*\\*strong\\*\\*" in text
    path = "tools/审计 evidence.xml"
    manifest["artifacts"].append({"path": path})
    assert "../tools/%E5%AE%A1%E8%AE%A1%20evidence.xml" in md_link("证据", path, manifest)
    assert "unavailable" in md_link("Missing", "missing.xml", manifest)


@pytest.mark.parametrize("path", ["../secret", "a/%2e%2e/secret", "/etc/passwd", "javascript:alert(1)", "a\\b"])
def test_unsafe_evidence_paths_are_never_links(path: str) -> None:
    text = md_link("Evidence", path, {"artifacts": [{"path": path}]})
    assert "](../" not in text


def test_export_uses_overridden_assessment_and_only_links_shipped_evidence(tmp_path: Path) -> None:
    run, manifest, review, assessment = report(tmp_path)
    # This snapshot represents recovery's new assessment, not yet committed.
    assessment["candidates"][0]["verdict"] = {"label": "LIKELY", "rationale": "New snapshot rationale"}
    summary(run, manifest, review, assessment)
    (run / "audit" / "assessment.json").write_text("{old broken assessment")
    secret_session = run / "llm" / "sessions" / "llm-memory-safety" / "unit" / "response.json"
    secret_session.parent.mkdir(parents=True)
    secret_session.write_text('{"text":"private source excerpt"}')
    review["findings"][1]["rationale_artifact"] = secret_session.relative_to(run).as_posix()
    manifest["artifacts"] = artifact_index(run)
    config = validate_config(copy.deepcopy(DEFAULTS))
    archive = export_shareable(run, manifest, config, [], review_override=review,
                               assessment_override=assessment)
    with zipfile.ZipFile(archive) as bundle:
        data = island(bundle.read("index.html").decode())
        assert data["assessment"] == json.loads(bundle.read("audit/assessment.json"))
        assert data["assessment"]["candidates"][0]["verdict"]["rationale"] == "New snapshot rationale"
        assert "New snapshot rationale" in bundle.read("review/summary.md").decode()
        assert data["run_summary"]["verification"] == "matched"
        assert data["artifact_availability"][secret_session.relative_to(run).as_posix()] == "omitted"
        assert secret_session.relative_to(run).as_posix() not in bundle.namelist()
        assert "private source excerpt" not in bundle.read("index.html").decode()
        exported = json.loads(bundle.read("manifest.json"))
        assert exported["export"]["status"] == "completed"
        for artifact in exported["artifacts"]:
            assert artifact["sha256"] == hashlib.sha256(bundle.read(artifact["path"])).hexdigest()


def test_reading_order_and_limits_are_explicit() -> None:
    findings = [_finding(i, "static") for i in range(2005)] + [_finding(2006, "llm")]
    html = render({"tools": {}, "artifacts": []}, _review(findings))
    sections = re.findall(r'<section id="([^"]+)">', html)
    assert sections[:5] == ["overview", "scope", "assessment", "summary", "findings"]
    data = island(html)
    assert data["total_findings"] == 2006 and len(data["findings"]) == 2000
    assert data["findings_omitted"] == 6
    assert any(f["engine"] == "llm" for f in data["findings"])
    assert 'if (buildCount) id("context").value = "build-aware"' not in html


@pytest.mark.skipif(not os.environ.get("CODE_ANALYZER_CDP_URL") or not shutil.which("node"),
                    reason="set CODE_ANALYZER_CDP_URL to a local Chromium DevTools endpoint")
def test_offline_report_in_a_real_browser(tmp_path: Path) -> None:
    findings = [_finding(i, "static") for i in range(2010)] + [_finding(2010, "llm")]
    for index, finding in enumerate(findings[:70]):
        finding["message"] = f"auditprint {index}"
    findings[0]["message"] += '</script><img src=x onerror="window.reportInjected=true">'
    candidates = [{
        "id": f"MEM-{i:03d}", "origin": "both", "canonical_path": "parser.c", "line_start": 1, "line_end": 2,
        "category": "buffer", "severity": "high", "sources": ["cppcheck"],
        "member_fingerprints": ["static-0", "static-2005"] if i == 0 else ["static-0"],
        "verdict": {"label": "LIKELY", "rationale": "Short rationale", "confidence": 0.8},
    } for i in range(60)]
    assessment = {"candidates": candidates, "metrics": {
        "candidates_total": 60, "validated": 60, "unvalidated": 0, "by_origin": {"both": 60}}}
    html = render({"tools": {}, "artifacts": []}, _review(findings), assessment, run_summary={
        "status": "available", "verification": "changed", "document": {
            "headline": "fixture opinion", "posture": "serious", "themes": [],
        }})
    path = tmp_path / "index.html"
    path.write_text(html, encoding="utf-8")
    result = subprocess.run(["node", str(Path(__file__).with_name("report_browser_check.mjs")), str(path)],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr

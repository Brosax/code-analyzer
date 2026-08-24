from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from helpers import run_cli

from code_analyzer.dashboard import rebuild_dashboard
from code_analyzer.errors import UserError
from code_analyzer.html_report import render


def report_directory(tmp_path: Path, *, review: bool = True, interrupted: bool = False) -> Path:
    report = tmp_path / "report"
    native = report / "tools" / "cppcheck" / "unit" / "report.xml"
    native.parent.mkdir(parents=True)
    native.write_bytes(b"<results><errors/></results>\n")
    old_index = report / "index.html"
    old_index.write_text("broken dashboard", encoding="utf-8")
    manifest = {
        "manifest_schema_version": 2,
        "analyzer_version": "2.0.0",
        "run_id": "existing-run",
        "status": "interrupted" if interrupted else "complete",
        "exit_code": 130 if interrupted else 0,
        "source": "/project",
        "tools": {},
        "source_inventory": {"total": 1, "stable": None if interrupted else True},
        "artifacts": [
            {
                "path": native.relative_to(report).as_posix(),
                "size": len(native.read_bytes()),
                "sha256": hashlib.sha256(native.read_bytes()).hexdigest(),
            },
            {"path": "index.html", "size": 16, "sha256": "obsolete"},
        ],
    }
    (report / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    if review:
        summary = {
            "review_schema_version": 1,
            "project": "/project",
            "tools": {},
            "source_manifest": {"total_files": 1, "files": ["main.c"]},
            "findings": [],
            "diagnostics": [],
            "overlap_groups": [],
            "total_findings": 0,
            "total_diagnostics": 0,
        }
        summary_path = report / "review" / "summary.json"
        summary_path.parent.mkdir()
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
    return report


def executable_scripts(html: str) -> list[str]:
    matches = re.finditer(r"<script(?P<attrs>[^>]*)>(?P<body>.*?)</script>", html, re.DOTALL)
    return [match.group("body") for match in matches if 'type="application/json"' not in match.group("attrs")]


def test_all_dashboard_javascript_is_syntax_checked_by_node(tmp_path: Path) -> None:
    if shutil.which("node") is None:
        pytest.skip("node is required to syntax-check the inline dashboard scripts")
    html = render({"artifacts": [], "tools": {}}, None)
    scripts = executable_scripts(html)
    assert len(scripts) == 2
    for index, script in enumerate(scripts):
        path = tmp_path / f"inline-{index}.js"
        path.write_text(script, encoding="utf-8")
        completed = subprocess.run(
            ["node", "--check", str(path)], text=True, capture_output=True, timeout=10
        )
        assert completed.returncode == 0, completed.stderr
    assert html.index("window.__codeAnalyzerDashboard") < html.index('id="report-data"')
    assert "Dashboard initialization failed" in scripts[0]
    assert 'href="http://' not in html and 'href="https://' not in html
    # A stray "</script>" inside script source would terminate the block early
    # and leave more closing tags than opening ones.
    assert html.count("</script>") == html.count("<script")


@pytest.mark.parametrize("with_review", [True, False])
@pytest.mark.parametrize("interrupted", [True, False])
def test_rebuild_dashboard_preserves_evidence_and_run_state(
    tmp_path: Path, with_review: bool, interrupted: bool
) -> None:
    report = report_directory(tmp_path, review=with_review, interrupted=interrupted)
    native = report / "tools/cppcheck/unit/report.xml"
    native_before = native.read_bytes()
    before = json.loads((report / "manifest.json").read_text(encoding="utf-8"))

    completed = run_cli("rebuild-dashboard", report)

    index = report / "index.html"
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == str(index.resolve()) + "\n"
    assert completed.stderr == ""
    assert native.read_bytes() == native_before
    after = json.loads((report / "manifest.json").read_text(encoding="utf-8"))
    assert after["status"] == before["status"]
    assert after["exit_code"] == before["exit_code"]
    assert after["artifacts"][0] == before["artifacts"][0]
    index_artifact = next(item for item in after["artifacts"] if item["path"] == "index.html")
    assert index_artifact["size"] == len(index.read_bytes())
    assert index_artifact["sha256"] == hashlib.sha256(index.read_bytes()).hexdigest()
    assert "broken dashboard" not in index.read_text(encoding="utf-8")
    assert ("main.c" in index.read_text(encoding="utf-8")) is with_review


def test_rebuild_dashboard_creates_a_missing_index_artifact(tmp_path: Path) -> None:
    report = report_directory(tmp_path, review=False)
    (report / "index.html").unlink()
    manifest_path = report / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["artifacts"] = [item for item in manifest["artifacts"] if item["path"] != "index.html"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    rebuilt = rebuild_dashboard(report)

    updated = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert rebuilt.is_file()
    assert [item["path"] for item in updated["artifacts"]].count("index.html") == 1


def test_rebuild_dashboard_is_byte_stable(tmp_path: Path) -> None:
    report = report_directory(tmp_path)

    rebuild_dashboard(report)
    first_index = (report / "index.html").read_bytes()
    first_manifest = (report / "manifest.json").read_bytes()
    rebuild_dashboard(report)

    assert (report / "index.html").read_bytes() == first_index
    assert (report / "manifest.json").read_bytes() == first_manifest


@pytest.mark.parametrize("broken", ["manifest", "summary"])
def test_corrupt_rebuild_input_returns_two_without_changes(tmp_path: Path, broken: str) -> None:
    report = report_directory(tmp_path)
    manifest_path = report / "manifest.json"
    index_path = report / "index.html"
    if broken == "manifest":
        manifest_path.write_text("{bad", encoding="utf-8")
    else:
        (report / "review/summary.json").write_text("[]", encoding="utf-8")
    manifest_before = manifest_path.read_bytes()
    index_before = index_path.read_bytes()

    completed = run_cli("rebuild-dashboard", report)

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "code-analyzer: error:" in completed.stderr
    assert manifest_path.read_bytes() == manifest_before
    assert index_path.read_bytes() == index_before


def test_manifest_replace_failure_rolls_back_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = report_directory(tmp_path)
    manifest_path = report / "manifest.json"
    index_path = report / "index.html"
    manifest_before = manifest_path.read_bytes()
    index_before = index_path.read_bytes()
    original_replace = Path.replace
    failed = False

    def fail_manifest_once(source: Path, target: Path) -> Path:
        nonlocal failed
        if target == manifest_path and not failed:
            failed = True
            raise OSError("simulated manifest replacement failure")
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_manifest_once)
    with pytest.raises(UserError, match="cannot replace dashboard"):
        rebuild_dashboard(report)

    assert failed
    assert manifest_path.read_bytes() == manifest_before
    assert index_path.read_bytes() == index_before
    assert not list(report.glob(".index.html.*"))
    assert not list(report.glob(".manifest.json.*"))


def test_the_print_stylesheet_is_the_pdf_this_project_does_not_ship() -> None:
    """Printing must show what the screen showed, and fit on paper.

    The design rejects a PDF exporter (one more dependency, one more format
    with no machine consumer) in favour of print CSS.  That trade only holds
    if the printed page is actually usable, so the two ways it was observed
    to break are pinned here.
    """
    html = render({"manifest_schema_version": 2, "run_id": "r", "status": "complete", "exit_code": 0,
                   "tools": {}, "source_inventory": {"total": 1}, "artifacts": []}, None, None)
    print_rules = html.split("@media print{", 1)[1].split("\n}", 1)[0]

    # Controls are noise on paper; the report itself is not.
    assert ".nav,.controls,.pagination,button,.mast-actions{display:none!important}" in print_rules
    # Severity and origin are carried by colour: the browser's ink-saving
    # default would erase half the meaning.
    assert "print-color-adjust:exact" in print_rules
    # A wide table scrolls on screen and would be cut off on paper.
    assert ".table-wrap{overflow:visible!important" in print_rules
    # ... but never with a fixed layout: eleven equal columns shred every word
    # into one letter per line, which turned a 15-page report into 71 pages.
    assert "table-layout:fixed" not in print_rules
    # A link to native evidence is useless on paper unless the path prints.
    assert 'content:" (" attr(href) ")"' in print_rules


def test_printing_expands_what_pagination_and_details_hide() -> None:
    """CSS cannot reliably open a <details>, and cannot un-paginate at all."""
    html = render({"manifest_schema_version": 2, "run_id": "r", "status": "complete", "exit_code": 0,
                   "tools": {}, "source_inventory": {"total": 1}, "artifacts": []}, None, None)

    assert 'window.addEventListener("beforeprint"' in html
    assert 'window.addEventListener("afterprint"' in html
    assert 'document.querySelectorAll("details:not([open])")' in html
    # "all" is a real page size, not a print-only sentinel: a reader with 300
    # findings wants it too.
    assert '<option value="all" data-i18n="page_all">' in html
    # Both language tables carry the key: a missing one degrades to the raw key.
    zh, en = html.split("en: {", 1)
    assert 'page_all: "全部"' in zh and 'page_all: "All"' in en
    assert 'id("page-size").value === "all"' in html

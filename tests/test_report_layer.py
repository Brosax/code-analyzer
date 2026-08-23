"""The report layer's engine axis, and what a shareable export may carry.

Three hazards are pinned down here.  The dashboard has to show the LLM engine
without losing a label in either language or letting the embed cap starve one
engine (design 11.2); the export has to keep the source a scan records -- both
session excerpts and the symbol table -- out of the archive it hands to somebody
else (design 11.3); and no credential may ride out inside a failure reason.
"""
from __future__ import annotations

import copy
import json
import re
import zipfile
from pathlib import Path
from typing import Any

import pytest

from code_analyzer.config import DEFAULTS, validate_config
from code_analyzer.html_report import MAX_EMBED_FINDINGS, embedded_findings, render
from code_analyzer.sanitize import (
    EXCERPT_WITHHELD,
    SESSION_EXCERPT_REASON,
    SYMBOL_TABLE_REASON,
    export_shareable,
)

EXCERPT = "memcpy(header, src, len); /* verbatim scan-unit body */"
# llm/index.json holds the audited firmware's whole type, macro and signature
# surface -- the same disclosure as a session log, in structural clothing.
DEFINITION = "typedef struct { unsigned char proprietary_iv[16]; uint32_t rounds; } vault_state_t"
MACRO = "#define PROPRIETARY_KEY_SCHEDULE(x) ((x) ^ 0xDEADBEEF)"
SIGNATURE = "int vault_unseal(vault_state_t *state, const unsigned char *wrapped_dek)"
API_KEY = "sk-fake-4d1c9b7a20e54f83ab6e1d0c7f925e31"

_LABEL = re.compile(r'(?:^|,)\s*([a-z][a-z0-9_]*):\s*"')
_CALL = re.compile(r'\b(?:t|fmt)\(\s*"([a-z][a-z0-9_]*)"')
_DATA_I18N = re.compile(r'data-i18n="([a-z][a-z0-9_]*)"')
_ISLAND = re.compile(
    r'<script id="report-data" type="application/json">(.*?)</script>', re.DOTALL
)


def _table(html: str, language: str) -> set[str]:
    block = html.split("const I18N = {", 1)[1].split(f"{language}: {{", 1)[1]
    return set(_LABEL.findall(block.split("\n    },", 1)[0]))


def _island(html: str) -> dict[str, Any]:
    match = _ISLAND.search(html)
    assert match is not None
    return json.loads(match.group(1))


def _finding(index: int, engine: str) -> dict[str, Any]:
    return {
        "tool": "llm-memory-safety" if engine == "llm" else "cppcheck",
        "producer": "llm-memory-safety" if engine == "llm" else "cppcheck",
        "engine": engine,
        "evidence_class": "generated" if engine == "llm" else "native",
        "gate_eligible": engine == "static",
        "severity": "high" if engine == "static" else "unknown",
        "rank": 4 if engine == "static" else 0,
        "review_level": "error",
        "rule_id": f"R{index}",
        "canonical_path": "parser.c",
        "line": str(index),
        "message": f"finding {index}",
        "fingerprint": f"{engine}-{index}",
        "evidence_context": "source-only",
    }


def _review(findings: list[dict[str, Any]]) -> dict[str, Any]:
    llm = [item for item in findings if item["engine"] == "llm"]
    return {
        "review_schema_version": 3,
        "project": "/project",
        "run": {"id": "run-1"},
        "tools": {"cppcheck": {"status": "completed", "total_findings": len(findings) - len(llm)}},
        "scanners": {"llm-memory-safety": {"status": "completed", "total_findings": len(llm)}},
        "source_manifest": {"total_files": 1, "files": ["parser.c"]},
        "findings": findings,
        "diagnostics": [],
        "overlap_groups": [],
        "total_findings": len(findings),
        "total_diagnostics": 0,
        "severity_counts_by_engine": {"static": {"high": len(findings) - len(llm)}, "llm": {"unknown": len(llm)}},
        "review_level_counts_by_engine": {"static": {"error": len(findings) - len(llm)}, "llm": {"error": len(llm)}},
        "finding_counts_by_engine": {"total": len(findings), "static": len(findings) - len(llm), "llm": len(llm)},
        "llm_coverage": {
            "files": {"scanned": 1, "total": 1, "ratio": 1.0},
            "functions": {"scanned": 3, "total": 4, "ratio": 0.75},
            "bytes": {"scanned": 0, "total": 0, "ratio": 0.0},
            "by_scanner": {"llm-memory-safety": {"units": 1}},
            "risk_tiers": {}, "unscanned_reasons": {},
        },
    }


# --- the dashboard's engine axis --------------------------------------------


def test_every_dashboard_label_exists_in_both_languages() -> None:
    html = render({"artifacts": [], "tools": {}}, _review([_finding(1, "llm")]))

    zh, en = _table(html, "zh"), _table(html, "en")

    assert zh and zh == en
    used = set(_CALL.findall(html)) | set(_DATA_I18N.findall(html))
    assert used <= zh, sorted(used - zh)
    # The engine axis is the new vocabulary; a missing key degrades to the raw
    # key string on screen rather than failing loudly.
    for key in (
        "chart_engine_comp", "legend_static", "legend_llm", "filter_engine",
        "opt_all_engines", "opt_static", "opt_llm", "th_provenance", "card_llm_coverage",
    ):
        assert key in zh and key in en


def test_the_findings_table_filters_and_reports_the_engine() -> None:
    html = render({"artifacts": [], "tools": {}}, _review([_finding(1, "llm")]))

    controls = html.split('<div class="controls">', 1)[1].split("</div>", 1)[0]
    assert '<select id="engine">' in controls
    assert '<option value="static"' in controls and '<option value="llm"' in controls
    assert '"engine", "review-level"' in html
    assert 'x.engine === engine' in html

    header = html.split('<tbody id="finding-body">', 1)[0].rsplit("<thead>", 1)[1]
    assert 'data-i18n="th_provenance"' in header
    assert 'tableEmpty(body, %d, t("no_findings"))' % header.count("<th") in html
    assert 'compPanel("engine-sev-comp"' in html and 'compPanel("engine-rl-comp"' in html
    assert 'id="engine-sev-comp"' in html and 'id="engine-rl-comp"' in html


@pytest.mark.parametrize("llm_count", [1, 7, MAX_EMBED_FINDINGS])
def test_the_embed_cap_reserves_a_share_for_every_engine(llm_count: int) -> None:
    # Sorted by descending rank, exactly as build_review leaves the list: every
    # LLM row sits below every static one and a head slice would drop them all.
    findings = [_finding(index, "static") for index in range(MAX_EMBED_FINDINGS + 500)]
    findings += [_finding(index, "llm") for index in range(llm_count)]

    kept = _island(render({"artifacts": [], "tools": {}}, _review(findings)))

    engines = [item["engine"] for item in kept["findings"]]
    assert len(engines) == MAX_EMBED_FINDINGS
    assert kept["findings_omitted"] == len(findings) - MAX_EMBED_FINDINGS
    assert engines.count("llm") == min(llm_count, MAX_EMBED_FINDINGS // 2)
    assert engines.count("static") == MAX_EMBED_FINDINGS - engines.count("llm")


def test_an_uncapped_or_single_engine_list_is_left_alone() -> None:
    findings = [_finding(index, "static") for index in range(5)]

    assert embedded_findings(findings, MAX_EMBED_FINDINGS) == findings
    assert embedded_findings(findings, 3) == findings[:3]


# --- what the shareable archive may carry ------------------------------------


def _run_directory(tmp_path: Path) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    run_dir = tmp_path / "run"
    session = run_dir / "llm" / "sessions" / "llm-memory-safety" / "unit-1"
    session.mkdir(parents=True)
    (session / "events.jsonl").write_text(
        json.dumps({"type": "tool", "text": EXCERPT}) + "\n", encoding="utf-8"
    )
    (session / "request.json").write_text(json.dumps({"prompt": EXCERPT}), encoding="utf-8")
    (session / "response.json").write_text(json.dumps({"text": EXCERPT}), encoding="utf-8")
    (session / "meta.json").write_text(json.dumps({"stop_reason": "completed"}), encoding="utf-8")
    (session / "findings.json").write_text(
        json.dumps({"findings": [{"rule_id": "MEM-014", "message": "dst dereferenced"}]}),
        encoding="utf-8",
    )
    units = run_dir / "llm" / "units"
    units.mkdir(parents=True)
    (units / "unit-1.json").write_text(json.dumps({"source": EXCERPT}), encoding="utf-8")
    (run_dir / "llm" / "index.json").write_text(
        json.dumps({
            "index_schema_version": 1,
            "units": [{"unit_id": "unit-1", "path": "parser.c"}],
            "symbols": {
                "vault_unseal": {"kind": "function", "path": "parser.c", "line": 41, "signature": SIGNATURE}
            },
            "types": {
                "vault_state_t": {"kind": "typedef", "path": "parser.c", "line": 12, "definition": DEFINITION}
            },
            "macros": {
                "PROPRIETARY_KEY_SCHEDULE": {"kind": "macro", "path": "parser.c", "line": 3, "definition": MACRO}
            },
        }),
        encoding="utf-8",
    )
    native = run_dir / "tools" / "cppcheck" / "unit" / "report.xml"
    native.parent.mkdir(parents=True)
    native.write_text('<?xml version="1.0"?><results version="2"><errors/></results>', encoding="utf-8")

    review = _review([_finding(1, "llm")])
    review_path = run_dir / "review" / "summary.json"
    review_path.parent.mkdir(parents=True)
    review_path.write_text(json.dumps(review), encoding="utf-8")

    manifest = {
        "manifest_schema_version": 2,
        "analyzer_version": "2.0.0",
        "run_id": "run-1",
        "status": "complete",
        "exit_code": 0,
        "source": str(tmp_path / "src"),
        "output_root": str(tmp_path / "out"),
        "tools": {},
        "artifacts": [],
        "source_inventory": {"total": 1, "stable": True},
        "review": {"enabled": True, "status": "completed"},
        "export": {"enabled": True, "status": "pending", "archive": None, "error": None},
        "llm": {"status": "completed", "scanners": {}},
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return run_dir, manifest, review


def _config(*, export_sessions: bool) -> dict[str, Any]:
    config = copy.deepcopy(DEFAULTS)
    config["llm"]["export_sessions"] = export_sessions
    return validate_config(config)


def test_session_source_excerpts_stay_out_of_the_shareable_archive(tmp_path: Path) -> None:
    run_dir, manifest, _review_document = _run_directory(tmp_path)

    archive = export_shareable(run_dir, manifest, _config(export_sessions=False), [])

    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        payload = b"\n".join(bundle.read(name) for name in names)
        report = json.loads(bundle.read("redaction-report.json"))
    # findings.json is the only file the review parser reads, so recover-report
    # still works on an unpacked ZIP.
    assert "llm/sessions/llm-memory-safety/unit-1/findings.json" in names
    for withheld in ("events.jsonl", "request.json", "response.json"):
        assert f"llm/sessions/llm-memory-safety/unit-1/{withheld}" not in names
    assert "llm/units/unit-1.json" not in names
    assert EXCERPT.encode() not in payload

    excluded = {item["entry"]: item["reason"] for item in report["omitted_artifacts"]}
    assert excluded["llm/sessions/llm-memory-safety/unit-1/events.jsonl"] == SESSION_EXCERPT_REASON
    assert excluded["llm/units/unit-1.json"] == SESSION_EXCERPT_REASON
    assert all(item["status"] == "excluded" for item in report["omitted_artifacts"])
    # Withholding excerpts is policy, not failure: the run stays complete.
    assert report["status"] == "completed"
    assert manifest["export"]["status"] == "completed"
    assert manifest["export"]["omitted_artifacts"] == report["omitted_artifacts"]


def test_the_symbol_table_stays_out_of_the_shareable_archive(tmp_path: Path) -> None:
    run_dir, manifest, _review_document = _run_directory(tmp_path)

    archive = export_shareable(run_dir, manifest, _config(export_sessions=False), [])

    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        payload = b"\n".join(bundle.read(name) for name in names)
        report = json.loads(bundle.read("redaction-report.json"))
    # No dashboard, review parser or recovery path reads llm/index.json, so the
    # whole symbol table is withheld rather than stripped field by field.
    assert "llm/index.json" not in names
    for disclosure in (DEFINITION, MACRO, SIGNATURE, "PROPRIETARY_KEY_SCHEDULE", "vault_state_t"):
        assert disclosure.encode() not in payload

    excluded = {item["entry"]: item["reason"] for item in report["omitted_artifacts"]}
    assert excluded["llm/index.json"] == SYMBOL_TABLE_REASON
    # A policy exclusion, not a sanitizer failure: the run stays complete.
    assert report["status"] == "completed"
    assert manifest["export"]["status"] == "completed"


def test_the_api_key_value_never_survives_into_the_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir, manifest, _review_document = _run_directory(tmp_path)
    config = _config(export_sessions=False)
    # The default profile is a keyless Ollama tunnel; this test is about
    # redaction, so it names its own variable rather than relying on one.
    config["llm"]["api_key_env"] = "CODE_ANALYZER_TEST_API_KEY"
    monkeypatch.setenv("CODE_ANALYZER_TEST_API_KEY", API_KEY)
    # The harness formats raw SDK exception text into a unit reason, and a
    # pydantic ValidationError echoes the input value it rejected.
    manifest["llm"]["scanners"] = {
        "llm-memory-safety": {
            "status": "failed",
            "units": [{
                "id": "unit-1",
                "status": "failed",
                "reason": f"HarnessUnavailable: 1 validation error for Provider\n  api_key\n    "
                          f"Input should be a valid token [input_value='{API_KEY}']",
            }],
        }
    }

    archive = export_shareable(run_dir, manifest, config, [])

    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        payload = b"\n".join(bundle.read(name) for name in names)
        report = json.loads(bundle.read("redaction-report.json"))
        exported_manifest = json.loads(bundle.read("manifest.json"))
    assert API_KEY.encode() not in payload
    assert "manifest.json" in names
    reason = exported_manifest["llm"]["scanners"]["llm-memory-safety"]["units"][0]["reason"]
    # The reason survives as evidence; only the credential inside it is gone.
    assert "HarnessUnavailable" in reason and "<SECRET>" in reason
    assert report["rules"]["secret_value"] >= 1


def test_export_sessions_ships_the_whole_session_when_asked(tmp_path: Path) -> None:
    run_dir, manifest, _review_document = _run_directory(tmp_path)

    archive = export_shareable(run_dir, manifest, _config(export_sessions=True), [])

    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        payload = b"\n".join(bundle.read(name) for name in names)
    assert "llm/sessions/llm-memory-safety/unit-1/events.jsonl" in names
    assert "llm/units/unit-1.json" in names
    assert "llm/index.json" in names
    assert EXCERPT.encode() in payload and DEFINITION.encode() in payload
    assert manifest["export"]["omitted_artifacts"] == []


def test_a_findings_evidence_excerpt_is_withheld_from_the_archive(tmp_path: Path) -> None:
    """findings.json ships, but the verbatim source inside it must not.

    Seen live: the model copies the offending line into `evidence`, findings.json
    is the one session file the archive keeps, and so the audited firmware's
    source left in a file labelled shareable.
    """
    run_dir, manifest, review_document = _run_directory(tmp_path)
    findings_path = run_dir / "llm" / "sessions" / "llm-memory-safety" / "unit-1" / "findings.json"
    planted = "memcpy(vault->proprietary_iv, packet, packet_len);  /* PROPRIETARY */"
    findings_path.write_text(json.dumps({"findings": [
        {"rule_id": "MEM-014", "message": "dst dereferenced", "evidence": planted},
    ]}), encoding="utf-8")
    review_document["findings"][0]["evidence"] = planted
    (run_dir / "review" / "summary.json").write_text(json.dumps(review_document), encoding="utf-8")

    archive = export_shareable(run_dir, manifest, _config(export_sessions=False), [])
    with zipfile.ZipFile(archive) as bundle:
        exported = json.loads(bundle.read("llm/sessions/llm-memory-safety/unit-1/findings.json"))
        review = json.loads(bundle.read("review/summary.json"))
        payload = b"\n".join(bundle.read(name) for name in bundle.namelist())
    assert planted.encode() not in payload
    assert exported["findings"][0]["evidence"] == EXCERPT_WITHHELD
    assert exported["findings"][0]["message"] == "dst dereferenced"
    assert review["findings"][0]["evidence"] == EXCERPT_WITHHELD

    # The private run directory is untouched: recover-report still sees it.
    assert planted in findings_path.read_text(encoding="utf-8")

    # Opting in ships the excerpt, as documented.
    run_dir, manifest, _review = _run_directory(tmp_path / "opt-in")
    (run_dir / "llm" / "sessions" / "llm-memory-safety" / "unit-1" / "findings.json").write_text(
        json.dumps({"findings": [{"rule_id": "MEM-014", "message": "dst dereferenced", "evidence": planted}]}),
        encoding="utf-8",
    )
    archive = export_shareable(run_dir, manifest, _config(export_sessions=True), [])
    with zipfile.ZipFile(archive) as bundle:
        exported = json.loads(bundle.read("llm/sessions/llm-memory-safety/unit-1/findings.json"))
    assert exported["findings"][0]["evidence"] == planted

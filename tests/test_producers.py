"""Phase 0 guardrails: producer ordering, the engine axis, and the static gate."""
from __future__ import annotations

import copy
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
    _finding_category,
    _producer_rank,
    build_review,
    should_fail,
)
from code_analyzer.sanitize import _validate_core_review
from code_analyzer.tools import LLM_PRODUCERS, PRODUCER_ORDER, TOOL_NAMES

# Pinned by invariant #2: a static-only corpus must keep producing these exact
# bytes.  Generated from the pre-LLM tree (commit 4dbb5c0) via a git worktree,
# never from the current one -- a self-generated expectation would only pin
# whatever the classifier does today.  Regenerate the same way, and only
# alongside a deliberate, documented format change.
EXPECTED_STATIC_OVERLAP_GROUPS = b"""[
  {
    "canonical_path": "main.c",
    "category": "CWE-190",
    "fingerprints": [
      "8c61f8f25f072b0c16a89bb76531ed092c7eda7380f84f5925d42a42b6da6234",
      "1abce44a9038a510d0f0b8185d7390aa9d50a5f87c9a7b1b02de34199b70402a"
    ],
    "id": "c4d1b4b895b1528b",
    "line": "20-21",
    "line_end": 21,
    "line_start": 20,
    "tools": [
      "cppcheck",
      "flawfinder"
    ]
  },
  {
    "canonical_path": "main.c",
    "category": "CWE-416",
    "fingerprints": [
      "6fd30384746e639a876ccb4a9d690d209e64239e497359ea917d116c3c95efa0",
      "e638f67ee893c997b464e456c1cf32f0efb14c56cd42452443f692e04aa00c6d"
    ],
    "id": "7150f9ea6a8db470",
    "line": "30-31",
    "line_end": 31,
    "line_start": 30,
    "tools": [
      "cppcheck",
      "flawfinder"
    ]
  },
  {
    "canonical_path": "main.c",
    "category": "CWE-807",
    "fingerprints": [
      "2edb3764639f7429494fbaa1ebf17bff143bdfa07499b28e34828e27132c36d6",
      "fa78a7b1bc71ee1ed8d1f881fbb49c433ab7a0538be7967a42e8597fc51065e1"
    ],
    "id": "9ac3724480f18c5d",
    "line": "35-36",
    "line_end": 36,
    "line_start": 35,
    "tools": [
      "cppcheck",
      "flawfinder"
    ]
  },
  {
    "canonical_path": "main.c",
    "category": "format",
    "fingerprints": [
      "e89fc0e874e9b0bc350e781771fc6fe27942451f7b7c69f77f8a16eabcabb161",
      "9985051366159831d2712972f89a072325f83bbf495dfb1e1f206803594ab252"
    ],
    "id": "1e617d24ed2d5bdf",
    "line": "25-26",
    "line_end": 26,
    "line_start": 25,
    "tools": [
      "cppcheck",
      "flawfinder"
    ]
  },
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


# Every entry below feeds a category table that did not exist at 4dbb5c0:
# CWE-190/416/20/807 plus two un-CWE'd wordings ("reset", "race").  Static
# findings must keep classifying exactly as they did before those tables.
_EXTRA_CPPCHECK = (
    ("atoiConversion", "error", "190", "Signed value from atoi is not checked", 20),
    ("invalidScanfArgType", "warning", "20", "format string is not a string literal", 25),
    ("doubleFree", "error", "416", "Memory pointed to by buf is freed twice", 30),
    ("getenvUsage", "warning", "807", "Environment value drives a security decision", 35),
    ("resetHandler", "warning", "", "Peripheral state is not restored after reset", 42),
    ("raceCondition", "warning", "", "Possible race on the shared flag", 52),
)
_EXTRA_FLAWFINDER = (
    ("atoi", "Unchecked atoi result CWE-190", 21),
    ("format_string", "Unvalidated format string CWE-20", 26),
    ("free", "Pointer used after free CWE-416", 31),
    ("getenv", "Environment variable used in a security decision CWE-807", 36),
    ("shared_flag", "Data race on the shared flag", 50),
)
_EXTRA_SPLINT = (
    ("41", "Peripheral not restored after reset"),
    ("51", "Possible race on the shared flag"),
)


def _category_corpus(tmp_path: Path) -> tuple[Path, Path, dict[str, Any], list[dict[str, Any]]]:
    source, run_dir, manifest, inventory = _static_corpus(tmp_path)
    report = run_dir / "tools/cppcheck/one/report.xml"
    errors = "".join(
        '<error id="{0}" severity="{1}"{2} msg="{3}">'
        '<location file="main.c" line="{4}" column="1"/></error>'.format(
            rule, severity, ' cwe="{0}"'.format(cwe) if cwe else "", message, line,
        )
        for rule, severity, cwe, message, line in _EXTRA_CPPCHECK
    )
    report.write_text(
        report.read_text(encoding="utf-8").replace("</errors>", errors + "</errors>"), encoding="utf-8",
    )
    report = run_dir / "tools/flawfinder/one/report.sarif"
    sarif = json.loads(report.read_text(encoding="utf-8"))
    sarif["runs"][0]["results"].extend(
        {
            "ruleId": rule, "level": "warning", "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "main.c"}, "region": {"startLine": line},
            }}],
        }
        for rule, message, line in _EXTRA_FLAWFINDER
    )
    report.write_text(json.dumps(sarif), encoding="utf-8")
    report = run_dir / "tools/splint/one/report.csv"
    report.write_text(
        report.read_text(encoding="utf-8")
        + "".join("main.c,{0},{1}\n".format(line, message) for line, message in _EXTRA_SPLINT),
        encoding="utf-8",
    )
    return source, run_dir, manifest, inventory


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

    # Design 6.1 freezes overlap_groups to native tools; an LLM finding must not
    # join a static cluster and move its line span. Cross-engine correlation is
    # the audit layer's artifact, not this one.
    groups = _build_overlap_groups(findings)
    assert groups == []
    static_pair = [item for item in findings if item["tool"] == "cppcheck"]
    static_pair.append(dict(static_pair[0], tool="flawfinder", line="11", fingerprint="d" * 64))
    native = _build_overlap_groups(static_pair)
    assert [group["tools"] for group in native] == [["cppcheck", "flawfinder"]]
    assert native[0]["line"] == "10-11"


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
    assert all(
        set(group["tools"]) <= set(TOOL_NAMES) for group in summary["overlap_groups"]
    ), "overlap_groups is frozen to native tools (design 6.1)"


def test_static_only_overlap_groups_stay_byte_identical(tmp_path: Path) -> None:
    source, run_dir, manifest, inventory = _category_corpus(tmp_path)
    summary = build_review(source, run_dir, manifest, inventory)
    assert json_bytes(summary["overlap_groups"]) == EXPECTED_STATIC_OVERLAP_GROUPS


def test_llm_findings_still_reach_the_categories_static_findings_must_not(tmp_path: Path) -> None:
    source, run_dir, manifest, inventory = _category_corpus(tmp_path)
    summary = build_review(source, run_dir, manifest, inventory)
    static = sorted(
        (item["tool"], int(item["line"]), _finding_category(item))
        for item in summary["findings"] if item["engine"] == "static"
    )
    # Every entry below was read off the pre-LLM tree (4dbb5c0), not this one.
    assert static == [
        ("cppcheck", 10, "null-dereference"), ("cppcheck", 20, "CWE-190"),
        ("cppcheck", 25, "format"), ("cppcheck", 30, "CWE-416"),
        ("cppcheck", 35, "CWE-807"), ("cppcheck", 42, "unknown"),
        ("cppcheck", 52, "unknown"), ("flawfinder", 12, "null-dereference"),
        ("flawfinder", 21, "CWE-190"), ("flawfinder", 26, "format"),
        ("flawfinder", 31, "CWE-416"), ("flawfinder", 36, "CWE-807"),
        ("flawfinder", 50, "unknown"), ("splint", 40, "uninitialized"),
        ("splint", 41, "unknown"), ("splint", 51, "unknown"),
    ]

    llm = [
        dict(_llm_finding("20"), cwe="CWE-190", message="atoi result is not checked", engine="llm"),
        dict(_llm_finding("30"), cwe="CWE-416", message="pointer used after free", engine="llm"),
        dict(_llm_finding("35"), cwe="CWE-807", message="environment value drives a decision", engine="llm"),
        dict(_llm_finding("42"), cwe="", message="peripheral state is not restored after reset", engine="llm"),
        dict(_llm_finding("52"), cwe="", message="possible race on the shared flag", engine="llm"),
        dict(_llm_finding("60"), cwe="", category="use-after-free", message="freed twice", engine="llm"),
    ]
    assert [_finding_category(item) for item in llm] == [
        "integer-overflow", "lifetime", "trust-boundary", "reset-behavior", "race", "lifetime",
    ]


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


def test_a_team_can_opt_its_own_repository_into_gating_on_llm_findings() -> None:
    """The exclusion is the default, not a law about somebody else's repo.

    A hallucinated critical must never fail a pipeline by surprise -- but a
    team that has read the caveats and wants its own build to stop on a
    generated finding is making an explicit choice, and the flag lives in
    their config where that choice is recorded.
    """
    llm_critical = {"rank": 5, "engine": "llm", "gate_eligible": False}

    assert not should_fail({"findings": [llm_critical]}, "critical")
    assert should_fail({"findings": [llm_critical]}, "critical", include_generated=True)
    # The opt-in widens what counts, never what the policy is: "none" is still
    # "never fail", and a finding below the threshold still does not fire.
    assert not should_fail({"findings": [llm_critical]}, "none", include_generated=True)
    assert not should_fail({"findings": [{"rank": 3, "gate_eligible": False}]}, "critical", include_generated=True)


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


def test_deduplicate_keeps_identical_findings_from_different_producers() -> None:
    """Invariant 1 rests on ``tool`` being part of the dedup key.

    Pre-LLM this was nearly inert: cppcheck and flawfinder rarely emit an
    identical (file, line, column, rule_id, message).  With three scanners
    sharing one output schema over the same units, byte-identical cross-producer
    findings are the expected case, so dropping one would silently merge them.
    """
    shared = {
        "message": "buffer overflow", "file": "main.c", "line": "10", "column": "5",
        "rule_id": "buffer", "evidence_context": "source-only",
    }
    items = [
        dict(shared, tool="llm-memory-safety"),
        dict(shared, tool="llm-security"),
        dict(shared, tool="cppcheck"),
    ]
    kept = review_module._deduplicate(copy.deepcopy(items), diagnostic=False)
    assert [item["tool"] for item in kept] == [
        "llm-memory-safety", "llm-security", "cppcheck",
    ]
    # And genuine duplicates from one producer still collapse.
    twice = [dict(shared, tool="cppcheck"), dict(shared, tool="cppcheck")]
    assert len(review_module._deduplicate(twice, diagnostic=False)) == 1


def test_an_aborted_finish_reason_keeps_its_own_status_word() -> None:
    """The exit code is covered elsewhere; the status word was not.

    Mapping ``aborted`` onto ``completed`` would report a truncated agent run as
    a clean one, and the demotion path would never notice.
    """
    from code_analyzer.harness.runtime import FINISH_REASON_STATUS, finish_status

    assert FINISH_REASON_STATUS["aborted"] == "interrupted"
    assert FINISH_REASON_STATUS["cancelled"] == "interrupted"
    assert finish_status("aborted", True) == "interrupted"
    assert finish_status("completed", True) == "completed"
    assert finish_status("completed", False) == "failed"

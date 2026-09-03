"""The last step: one model session that accounts for a whole finished run.

The guardrails asserted here are the ones the step rests on -- it reads the
run's own account and never its source, every number it may quote is one the
run computed, the document is bounded before it is written, and a provider
that cannot answer costs the report nothing but a recorded failure.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from code_analyzer.config import DEFAULTS, validate_config
from code_analyzer.llm.summarize import (
    MAX_LIST,
    MAX_SAMPLE_FINDINGS,
    build_prompt,
    digest,
    parse_summary,
    render_markdown,
    summarize,
)

ANSWER = json.dumps({
    "headline": "启动链上有 3 处确认的越界写，其余多为缺头文件导致的噪声",
    "posture": "serious",
    "themes": [{
        "title": "长度参数未校验",
        "what": "多个解析函数直接把外部长度用作 memcpy 的大小",
        "where": ["bl1/bl1_1/lib/image.c"],
        "weight": "3 个 high，2 个 medium",
        "why_it_matters": "在启动链上可被镜像内容触发",
    }],
    "priorities": [{"do": "先修 image.c 的长度校验", "because": "两个 producer 都指到同一行"}],
    "coverage_caveats": ["Splint 只到达了 8% 的翻译单元"],
    "disagreements": [],
    "unknowns": ["platform/ 下的板级代码没有被 LLM 覆盖"],
}, ensure_ascii=False)


def _config() -> dict:
    config = validate_config(copy.deepcopy(DEFAULTS))
    config["llm"]["enabled"] = True
    return config


def _findings(count: int) -> list[dict]:
    severities = ("high", "medium", "low", "info")
    return [
        {
            "canonical_path": f"src/file{index}.c", "line": str(index),
            "normalized_severity": severities[index % len(severities)],
            "producer": "cppcheck" if index % 2 else "llm-security",
            "rule_id": f"rule{index}", "cwe": "CWE-787",
            "message": f"finding {index}", "fingerprint": f"f{index}",
        }
        for index in range(count)
    ]


def _run(tmp_path: Path, *, findings: int = 5, candidates: list[dict] | None = None) -> Path:
    run = tmp_path / "20260904T000000Z-abcdef123456"
    (run / "review").mkdir(parents=True)
    (run / "manifest.json").write_text(json.dumps({
        "manifest_schema_version": 2, "run_id": "abcdef123456", "status": "partial",
        "exit_code": 10, "analysis_context": "degraded",
        "analysis_context_reasons": ["compile database not found"],
        "started_at": "2026-09-04T00:00:00Z", "finished_at": "2026-09-04T01:00:00Z",
        "source_inventory": {"total": 3923}, "artifacts": [],
        "build_context": {"status": "applied", "assist": "propose", "reason": None},
        "llm": {"unit_counts": {"planned": 100, "completed": 40, "unscheduled": 60}, "budget": {}},
    }), encoding="utf-8")
    (run / "review" / "summary.json").write_text(json.dumps({
        "project": "/src/fw", "total_findings": findings, "total_diagnostics": 12,
        "severity_counts": {"high": 3, "medium": 2, "low": 1},
        "severity_counts_by_engine": {"static": {"high": 2}, "llm": {"high": 1}},
        "finding_counts": {"source-only": findings, "build-aware": 0, "total": findings},
        "top_files": [{"file": "src/file1.c", "count": 9}],
        "top_rules": [{"rule_id": "rule1", "count": 9}],
        "top_cwes": [{"cwe": "CWE-787", "count": 9}],
        "report_integrity": {"status": "complete", "included_reports": 3},
        "llm_coverage": {"files": {"ratio": 0.4}},
        "tools": {"splint": {"status": "partial", "requested": True, "reason": "preprocessing failed",
                             "finding_counts": {"total": 1},
                             "coverage": {"ratio": 0.077, "analyzed": 123, "total": 1588},
                             "unit_counts": {"planned": 1588, "failed": 1465}}},
        "scanners": {"llm-security": {"status": "completed", "requested": True, "reason": None,
                                      "finding_counts": {"total": 2},
                                      "coverage": {"ratio": 1.0, "analyzed": 40, "total": 40}}},
        "findings": _findings(findings),
    }, ensure_ascii=False), encoding="utf-8")
    if candidates is not None:
        (run / "audit").mkdir(parents=True, exist_ok=True)
        (run / "audit" / "assessment.json").write_text(
            json.dumps({"candidates": candidates}, ensure_ascii=False), encoding="utf-8")
    return run


class _Answers:
    """A runtime that returns one usable summary."""

    reply = ANSWER

    def __enter__(self) -> "_Answers":
        return self

    def __exit__(self, *_exc: object) -> bool:
        return False

    def run(self, _prompt: object, *, session_id: object = None,
            on_event: object = None) -> object:
        from code_analyzer.harness.runtime import RunOutcome

        if on_event is not None:
            on_event({"type": "assistant/chunk",
                      "data": {"chunk": {"type": "reasoning-delta", "index": 0, "text": "先看覆盖率"}}})
        return RunOutcome(session_id="s1", final_response=self.reply, finish_reason="completed",
                          events=[], notifications=[], duration_seconds=2.0)


class _Refuses(_Answers):
    reply = "I cannot help with that."


# --- what the model is shown ------------------------------------------------


def test_the_digest_is_the_run_account_and_never_its_source(tmp_path: Path) -> None:
    run = _run(tmp_path, findings=5)
    body = digest(run)
    prompt = "\n".join(str(block["text"]) for block in build_prompt(body))

    assert body["run"]["project"] == "/src/fw"
    assert body["findings"]["total"] == 5
    assert body["coverage"]["producers"]["splint"]["coverage_ratio"] == 0.077
    # The evidence the run itself could not reach is part of the account.
    assert body["coverage"]["llm_units"]["unscheduled"] == 60
    assert "int main(void)" not in prompt
    assert "<digest>" in prompt


def test_the_sample_is_bounded_but_the_counts_are_complete(tmp_path: Path) -> None:
    """A 100 000-finding run must still fit in one context window."""
    run = _run(tmp_path, findings=MAX_SAMPLE_FINDINGS * 4)
    body = digest(run)

    assert body["findings"]["total"] == MAX_SAMPLE_FINDINGS * 4
    assert len(body["findings"]["sample"]) == MAX_SAMPLE_FINDINGS
    assert str(MAX_SAMPLE_FINDINGS * 4) in body["findings"]["sample_note"]
    # Worst first, so a truncated sample is the useful end of the list.
    assert body["findings"]["sample"][0]["severity"] == "high"


def test_a_verdict_the_audit_layer_attached_reaches_the_summary(tmp_path: Path) -> None:
    run = _run(tmp_path, candidates=[
        {"id": "c1", "canonical_path": "src/a.c", "line": "10", "severity": "high",
         "origin": "both", "producers": ["cppcheck", "llm-security"],
         "verdict": {"label": "CONFIRMED", "rationale": "越界写，长度来自镜像头"}},
        {"id": "c2", "canonical_path": "src/b.c", "verdict": None},
    ])
    body = digest(run)

    assert body["candidates"]["total"] == 2
    assert body["candidates"]["verdicts"] == {"CONFIRMED": 1, "PENDING": 1}
    assert body["candidates"]["sample"][0]["verdict"] == "CONFIRMED"


# --- what may come back -----------------------------------------------------


def test_a_summary_without_a_headline_is_not_a_summary() -> None:
    valid, reason, _result, _counts = parse_summary('{"posture": "clean"}')
    assert not valid and "headline" in str(reason)
    assert parse_summary("no json here")[0] is False


def test_an_invented_posture_becomes_inconclusive_and_says_so() -> None:
    valid, _reason, result, _counts = parse_summary(
        '{"headline": "还行", "posture": "catastrophic"}')
    assert valid
    assert result["summary"]["posture"] == "inconclusive"
    assert any("catastrophic" in item for item in result["dropped"])


def test_the_document_is_bounded_and_every_drop_says_why() -> None:
    body = json.dumps({
        "headline": "x", "posture": "minor",
        "themes": [{"title": f"t{n}"} for n in range(MAX_LIST + 3)],
        "priorities": [{"do": f"p{n}", "because": "b"} for n in range(MAX_LIST + 3)],
        "unknowns": [f"u{n}" for n in range(MAX_LIST + 3)],
    })
    valid, _reason, result, counts = parse_summary(body)

    assert valid and counts["theme_count"] == MAX_LIST
    assert len(result["summary"]["themes"]) == MAX_LIST
    assert len(result["summary"]["priorities"]) == MAX_LIST
    assert len(result["summary"]["unknowns"]) == MAX_LIST
    assert sum("其余已丢弃" in item for item in result["dropped"]) == 2


# --- what it writes ---------------------------------------------------------


def test_a_summary_is_filed_as_opinion_beside_the_assessment(tmp_path: Path) -> None:
    run = _run(tmp_path)
    seen: list[str] = []
    block = summarize(run, _config(), open_runtime=_Answers, on_thinking=seen.append)

    assert block["status"] == "complete" and block["exit_code"] == 0
    assert block["posture"] == "serious"
    assert seen == ["先看覆盖率"] and block["thinking_chars"] == len("先看覆盖率")

    written = json.loads((run / "audit" / "summary.json").read_text(encoding="utf-8"))
    assert written["authority"] == "non-authoritative-derived-opinion"
    assert written["run_digest_sha256"]
    assert "启动链" in written["headline"]

    markdown = (run / "audit" / "summary.md").read_text(encoding="utf-8")
    assert "# 总体汇总" in markdown and "长度参数未校验" in markdown

    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["summary"]["posture"] == "serious"
    assert manifest["summary"]["markdown"] == "audit/summary.md"
    # The evidence layer is untouched, and the exit code it earned still stands.
    assert manifest["exit_code"] == 10
    assert "findings" in json.loads(
        (run / "review" / "summary.json").read_text(encoding="utf-8"))
    assert any(item["path"] == "audit/summary.md" for item in manifest["artifacts"])


def test_a_provider_that_will_not_answer_costs_the_report_nothing(tmp_path: Path) -> None:
    """A refusal is a recorded failure, not an exception and not a summary."""
    run = _run(tmp_path)
    block = summarize(run, _config(), open_runtime=_Refuses)

    assert block["status"] == "failed" and block["exit_code"] == 20
    assert block["headline"] is None
    assert not (run / "audit" / "summary.md").exists()
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["summary"]["status"] == "failed"
    assert manifest["exit_code"] == 10


def test_the_markdown_names_the_run_it_is_about(tmp_path: Path) -> None:
    run = _run(tmp_path)
    body = digest(run)
    _valid, _reason, result, _counts = parse_summary(ANSWER)
    text = render_markdown(result["summary"], body)

    assert "/src/fw" in text
    assert "退出码 10" in text
    assert "model-assisted opinion" in text
    assert "先修 image.c 的长度校验" in text

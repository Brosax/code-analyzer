"""Pure, stable input digest shared by the summarizer and report presentation.

Keep its wire shape stable: existing summaries record a hash of these bytes.
No model runtime or filesystem reads belong here.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .progress import single_line

MAX_SAMPLE_FINDINGS = 60
MAX_CANDIDATES = 40
MAX_MESSAGE_CHARS = 240
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _rank(finding: Mapping[str, Any]) -> tuple[int, str]:
    severity = str(finding.get("normalized_severity") or finding.get("severity") or "").lower()
    return _SEVERITY_RANK.get(severity, len(_SEVERITY_RANK)), str(finding.get("canonical_path") or "")


def _sample(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The rows worth showing: worst first, one per (file, rule), bounded.

    Deduplicated on the pair because a single rule firing 76 times in one file
    is one fact, and spending the whole sample on it would hide the other 30
    rules the run found.  The counts the model is also given say how often each
    one fired, so nothing is lost by showing it once.
    """
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for finding in sorted(findings, key=_rank):
        key = (str(finding.get("canonical_path") or ""), str(finding.get("rule_id") or ""))
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "path": finding.get("canonical_path") or finding.get("file"),
            "line": finding.get("line"),
            "severity": finding.get("normalized_severity") or finding.get("severity"),
            "producer": finding.get("producer") or finding.get("tool") or finding.get("engine"),
            "rule": finding.get("rule_id"),
            "cwe": finding.get("cwe"),
            "message": single_line(str(finding.get("message") or ""))[:MAX_MESSAGE_CHARS],
        })
        if len(out) >= MAX_SAMPLE_FINDINGS:
            break
    return out


def _producers(review: Mapping[str, Any]) -> dict[str, Any]:
    """What each producer reached, from its own coverage block."""
    out: dict[str, Any] = {}
    for group in ("tools", "scanners"):
        for name, block in sorted((review.get(group) or {}).items()):
            if not isinstance(block, dict):
                continue
            coverage = block.get("coverage") if isinstance(block.get("coverage"), dict) else {}
            out[name] = {
                "status": block.get("status"),
                "requested": block.get("requested"),
                "findings": (block.get("finding_counts") or {}).get("total"),
                "reason": block.get("reason"),
                "coverage_ratio": coverage.get("ratio"),
                "analysed": coverage.get("analyzed"),
                "of": coverage.get("total"),
                "unit_counts": block.get("unit_counts"),
            }
    return out


def _verdict_counts(candidates: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in candidates:
        verdict = item.get("verdict")
        label = str(verdict.get("label")) if isinstance(verdict, dict) and verdict.get("label") else "PENDING"
        counts[label] = counts.get(label, 0) + 1
    return counts


def build_digest(manifest: Mapping[str, Any], review: Mapping[str, Any],
                 assessment: Mapping[str, Any]) -> dict[str, Any]:
    findings = [item for item in review.get("findings") or [] if isinstance(item, dict)]
    candidates = [item for item in assessment.get("candidates") or [] if isinstance(item, dict)]
    return {
        "run": {
            "project": review.get("project"),
            "status": manifest.get("status"),
            "exit_code": manifest.get("exit_code"),
            "analysis_context": manifest.get("analysis_context"),
            "analysis_context_reasons": manifest.get("analysis_context_reasons"),
            "started_at": manifest.get("started_at"),
            "finished_at": manifest.get("finished_at"),
            "files_in_inventory": (manifest.get("source_inventory") or {}).get("total"),
            "report_integrity": review.get("report_integrity"),
            "build_context": {
                key: (manifest.get("build_context") or {}).get(key)
                for key in ("status", "assist", "reason")
            },
        },
        "coverage": {
            "producers": _producers(review),
            "llm": review.get("llm_coverage"),
            "llm_units": (manifest.get("llm") or {}).get("unit_counts"),
            "llm_budget": (manifest.get("llm") or {}).get("budget"),
        },
        "findings": {
            "total": review.get("total_findings"),
            "by_severity": review.get("severity_counts"),
            "by_engine": review.get("severity_counts_by_engine"),
            "by_context": review.get("finding_counts"),
            "top_files": (review.get("top_files") or [])[:20],
            "top_rules": (review.get("top_rules") or [])[:20],
            "top_cwes": (review.get("top_cwes") or [])[:20],
            "total_diagnostics": review.get("total_diagnostics"),
            "sample": _sample(findings),
            "sample_note": (
                f"{len(findings)} finding(s) in the evidence layer; the {MAX_SAMPLE_FINDINGS} "
                "shown are the most severe, one per (file, rule). The counts above are complete."
            ),
        },
        "candidates": {
            "total": len(candidates),
            "verdicts": _verdict_counts(candidates),
            "sample": [
                {
                    "id": item.get("id"),
                    "path": item.get("canonical_path"),
                    "line": item.get("line"),
                    "severity": item.get("severity"),
                    "origin": item.get("origin"),
                    "producers": item.get("producers"),
                    "verdict": (item.get("verdict") or {}).get("label") if isinstance(item.get("verdict"), dict) else None,
                    "rationale": single_line(str(
                        (item.get("verdict") or {}).get("rationale") or ""
                        if isinstance(item.get("verdict"), dict) else ""
                    ))[:MAX_MESSAGE_CHARS],
                }
                for item in candidates[:MAX_CANDIDATES]
            ],
        },
    }


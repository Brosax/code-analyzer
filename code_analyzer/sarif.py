"""SARIF 2.1.0 export of the review, one run per producer.

The review is the input, never the native reports: SARIF here is a derived
view with the same non-authoritative standing as review/summary.json, written
through the one canonical JSON encoder so it is byte-stable and re-derivable
offline.  LLM producers get their own ``runs[]`` entries rather than being
folded into the static ones, so a consumer that gates a build on SARIF keeps
the same choice ``gate_eligible`` gives this project: a hallucinated critical
cannot fail anybody's pipeline unless they opt into the LLM runs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import __version__
from .persist import write_json
from .review import _producer_rank
from .tools import TOOL_NAMES

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_PATH = ("review", "summary.sarif")
URI_BASE_ID = "SRCROOT"

# The normalized ladder onto SARIF's four levels; splint's "unknown" stays
# "none" on purpose, the same stance the gate takes with it.
LEVELS: dict[str, str] = {
    "critical": "error", "high": "error", "medium": "warning",
    "low": "note", "info": "note", "unknown": "none",
}


def build_sarif(review: dict[str, Any], manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    """Render a review as a SARIF log with one run per producer."""
    findings = [item for item in review.get("findings", []) if isinstance(item, dict)]
    producers = sorted({str(item.get("producer") or item.get("tool", "")) for item in findings}, key=_producer_rank)
    # A producer that ran but found nothing still gets a run, so "no results"
    # and "did not run" stay distinguishable to a consumer.
    for name in (review.get("tools") or {}):
        if (review["tools"][name] or {}).get("requested") and name not in producers:
            producers.append(name)
    for name in (review.get("scanners") or {}):
        if name not in producers:
            producers.append(name)
    producers.sort(key=_producer_rank)
    run_id = str((review.get("run") or {}).get("id") or (manifest or {}).get("run_id") or "")
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [_run(name, findings, review, run_id) for name in producers],
    }


def write_sarif(run_dir: Path, sarif: dict[str, Any]) -> Path:
    path = Path(run_dir).joinpath(*SARIF_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, sarif)
    return path


def _run(name: str, findings: list[dict[str, Any]], review: dict[str, Any], run_id: str) -> dict[str, Any]:
    mine = [item for item in findings if str(item.get("producer") or item.get("tool", "")) == name]
    static = name in TOOL_NAMES
    execution = (review.get("tools") if static else review.get("scanners")) or {}
    record = execution.get(name) or {}
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for item in mine:
        rule_id = _rule_id(item)
        rules.setdefault(rule_id, _rule(rule_id, item))
        results.append(_result(item, rule_id))
    driver: dict[str, Any] = {
        "name": name,
        "informationUri": "https://github.com/Brosax/code-analyzer",
        "rules": [rules[key] for key in sorted(rules)],
        "properties": {
            "engine": "static" if static else "llm",
            "evidence_class": "native" if static else "generated",
            # The consumer's equivalent of gate_eligible: the LLM runs are
            # opinion and must not fail a build on their own.
            "gate_eligible": static,
            "status": record.get("status"),
        },
    }
    if record.get("version"):
        driver["version"] = str(record["version"])
    if not static and record.get("model"):
        driver["properties"]["model"] = record["model"]
    return {
        "tool": {"driver": driver},
        "automationDetails": {"id": f"code-analyzer/{run_id}/{name}"},
        "originalUriBaseIds": {URI_BASE_ID: {"description": {"text": "the scanned source tree"}}},
        "results": results,
        "properties": {"analyzer_version": __version__, "review_schema_version": review.get("review_schema_version")},
    }


def _rule_id(item: dict[str, Any]) -> str:
    if item.get("engine") == "llm":
        return str(item.get("category") or item.get("rule_id") or "llm-finding")
    return str(item.get("rule_id") or "finding")


def _rule(rule_id: str, item: dict[str, Any]) -> dict[str, Any]:
    rule: dict[str, Any] = {"id": rule_id, "shortDescription": {"text": rule_id}}
    cwe = str(item.get("cwe") or "").strip()
    if cwe:
        rule["relationships"] = [{"target": {"id": cwe, "toolComponent": {"name": "CWE"}}, "kinds": ["relevant"]}]
        rule["properties"] = {"cwe": cwe}
    return rule


def _result(item: dict[str, Any], rule_id: str) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": str(item.get("canonical_path") or item.get("file") or ""), "uriBaseId": URI_BASE_ID},
        }
    }
    region = _region(item)
    if region:
        location["physicalLocation"]["region"] = region
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": LEVELS.get(str(item.get("severity")), "none"),
        "message": {"text": str(item.get("message") or "")},
        "locations": [location],
        "partialFingerprints": {"codeAnalyzerFingerprint/v1": str(item.get("fingerprint") or "")},
        "properties": {
            "producer": item.get("producer") or item.get("tool"),
            "engine": item.get("engine"),
            "severity": item.get("severity"),
            "original_severity": item.get("original_severity"),
            "review_level": item.get("review_level"),
            "evidence_context": item.get("evidence_context"),
            "gate_eligible": bool(item.get("gate_eligible", True)),
        },
    }
    if item.get("cwe"):
        result["taxa"] = [{"id": str(item["cwe"]), "toolComponent": {"name": "CWE"}}]
    if item.get("engine") == "llm":
        for key in ("confidence", "category", "symbol", "model", "skill_version"):
            if item.get(key) not in (None, ""):
                result["properties"][key] = item[key]
    return result


def _region(item: dict[str, Any]) -> dict[str, Any] | None:
    """A SARIF region only when the finding really has a line."""
    span = item.get("line_range")
    if isinstance(span, list) and len(span) == 2 and all(isinstance(value, int) and value > 0 for value in span):
        return {"startLine": span[0], "endLine": span[1]}
    try:
        line = int(str(item.get("line", "")).strip())
    except ValueError:
        return None
    if line <= 0:
        return None
    region: dict[str, Any] = {"startLine": line}
    try:
        column = int(str(item.get("column", "")).strip())
    except ValueError:
        column = 0
    if column > 0:
        region["startColumn"] = column
    return region

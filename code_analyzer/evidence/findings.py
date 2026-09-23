"""Native finding rows: identity, enrichment, and the view class that hides noise.

Identity.  The fingerprint formula is unchanged (review.py ``_fingerprint``:
tool, canonical path, line, column, rule, message) so SARIF
``partialFingerprints`` stay comparable with every earlier run.  It is not
unique on its own -- the same native line reported by a superseded unit and
by the attempt that replaced it has one fingerprint -- so a row's key is
``(fingerprint, call_id, unit_id)``.  Evidence context ("source-only",
"/superseded") is an attribute, never part of identity: folding it into the
fingerprint would make a row's identity change when a later attempt appears.

View class.  One value per row, deciding what the list and the AI see:

    out_of_tree   the path is outside the scanned tree (system headers)
    diagnostic    the analyzer talking about its own configuration, e.g.
                  cppcheck ``--check-library`` hints: 88,211 of TF-M's
                  126,747 rows, none of them about the code
    superseded    a later build-context attempt replaced this unit
    finding       everything else

The row itself is never touched; ``view_class`` lives in the index.  The
analyzer's argv is unchanged as well (decided 2026-09-22): the noise is
recorded, then filtered in the view.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..tools import TOOL_NAMES, adapter
from .parsing import (
    _deduplicate,
    _parse_llm_units,
    _scanner_executions,
    canonical_path,
    enrich_row,
)

VIEW_CLASSES = ("finding", "diagnostic", "out_of_tree", "superseded", "inactive_config")

# Rule ids that are the analyzer describing its own configuration.  They stay
# in the evidence; the view files them with diagnostics.
NOISE_RULES: frozenset[str] = frozenset({
    "checkLibraryFunction", "checkLibraryNoReturn", "checkLibraryUseIgnore", "checkLibraryCheckType",
    "missingInclude", "missingIncludeSystem", "unmatchedSuppression", "checkersReport", "toomanyconfigs",
    "normalCheckLevelMaxBranches", "noValidConfiguration",
})
NOISE_RULES_VERSION = 1


@dataclass(frozen=True)
class ParsedRun:
    run_id: str
    source: Path
    findings: list[dict[str, Any]]
    diagnostics: list[dict[str, Any]]


def parse_run(run_dir: Path, *, source: Path | None = None) -> ParsedRun:
    """Every finding and diagnostic a finished run's native evidence holds.

    Reads the native reports through each adapter's own parser, exactly as the
    review does; nothing is re-run and nothing is written.
    """
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    root = source or Path(str(manifest.get("source") or "."))
    findings: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for tool in TOOL_NAMES:
        execution = dict(manifest.get("tools", {}).get(tool, {}))
        execution["_allow_undeclared_valid"] = manifest.get("manifest_schema_version") is None
        rows, notes = adapter(tool).parse(root, run_dir, execution)
        findings.extend(rows)
        diagnostics.extend(notes)
    for scanner, execution in sorted(_scanner_executions(manifest).items()):
        rows, notes = _parse_llm_units(root, run_dir, {**execution, "producer": scanner})
        findings.extend(rows)
        diagnostics.extend(notes)
    findings = _deduplicate(findings, diagnostic=False)
    diagnostics = _deduplicate(diagnostics, diagnostic=True)
    cache: dict[str, str] = {}

    def canonical(value: Any) -> str:
        key = str(value or "")
        if key not in cache:
            cache[key] = canonical_path(key, root)
        return cache[key]

    run_id = str(manifest.get("run_id") or run_dir.name)
    for row in findings:
        enrich_row(row, canonical)
        row["unit_id"] = unit_of(row)
        row["call_id"] = f"{run_id}:{row['tool']}"
        row["view_class"] = view_class(row)
    for row in diagnostics:
        row["canonical_path"] = canonical(row.get("file", ""))
        row["unit_id"] = str(row.get("unit_id") or unit_of(row))
    return ParsedRun(run_id, root, findings, diagnostics)


def unit_of(row: dict[str, Any]) -> str:
    """The unit a row came from: the directory of its native report.

    ``tools/<tool>/<unit>/report.*`` -> ``<unit>`` (the tool is already in the
    call id); ``llm/<...>/<unit>/response.json`` -> the path under ``llm/``.
    """
    artifact = str(row.get("source_artifact") or "")
    parts = artifact.split("/")
    if len(parts) >= 4 and parts[0] == "tools":
        return "/".join(parts[2:-1])
    if len(parts) >= 3 and parts[0] == "llm":
        return "/".join(parts[1:-1])
    return artifact or str(row.get("tool", ""))


def in_tree(path: str) -> bool:
    return bool(path) and not path.startswith("/") and not path.startswith("../") and path != ".."


def view_class(row: dict[str, Any]) -> str:
    if not in_tree(str(row.get("canonical_path") or "")):
        return "out_of_tree"
    if str(row.get("rule_id") or "") in NOISE_RULES:
        return "diagnostic"
    if str(row.get("evidence_context") or "").endswith("/superseded"):
        return "superseded"
    return "finding"


def key(row: dict[str, Any]) -> tuple[str, str, str]:
    return str(row["fingerprint"]), str(row["call_id"]), str(row["unit_id"])


def line_number(row: dict[str, Any]) -> int:
    try:
        return max(0, int(str(row.get("line") or "0").split("-", 1)[0]))
    except ValueError:
        return 0

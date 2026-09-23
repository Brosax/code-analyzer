"""AI findings that earned a place in the list, as evidence rows beside the tools' own.

A finding from a lens is promoted only when it was grounded (its line and
verbatim quote are in the code the model was shown) *and* a second, separate
look through the ``verify`` lens called it CONFIRMED or LIKELY.  The promotion
is a ledger record (``ai_promoted``); on every index build it becomes one
finding row -- engine ``llm``, evidence class ``generated``, never gate-eligible
-- and clusters with tool findings on the same lines like any other row.

Code moves.  The record keeps the hash of the evidence line; if that line is
no longer where it was, the row follows the nearest line with the same text,
and a promotion whose line text is gone from the file is left out (and
counted), never pinned to whatever now sits at the old number.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .findings import view_class
from .parsing import enrich_row
from .triage import SourceLines
from .workspace import Workspace

AI_TOOL = "ai"
AI_CALL = "ai-review"


def rows(workspace: Workspace, lines: SourceLines, canonical: Callable[[Any], str]) -> tuple[list[dict[str, Any]], int]:
    """(finding rows for every live promotion, promotions whose line text is gone)."""
    out: list[dict[str, Any]] = []
    stale = 0
    for record in workspace.ledger.of("ai_promoted"):
        path = str(record["path"])
        line = _relocate(lines, path, int(record["line"]), str(record.get("line_text_sha") or ""))
        if line is None:
            stale += 1
            continue
        end = max(line, line + int(record.get("end_line", record["line"])) - int(record["line"]))
        row = {
            "tool": AI_TOOL, "producer": f"ai:{record['lens']}", "engine": "llm", "message": record["message"],
            "file": path, "line": str(line), "column": "", "rule_id": f"ai-{record['category']}",
            "cwe": record.get("cwe", ""), "original_severity": "unknown", "source_artifact": f"ledger/{record['seq']}",
            "evidence_context": "ai-review", "category": record["category"], "confidence": record.get("confidence"),
            "symbol": record.get("function", ""), "line_range": [line, end], "af_id": record["af"],
            "verdict": record.get("verdict", ""), "lens": record["lens"], "evidence_quote": record.get("evidence_quote", ""),
        }
        enrich_row(row, canonical)
        row["unit_id"] = f"{record['af']}.{record.get('member', 0)}"
        row["call_id"] = AI_CALL
        row["view_class"] = view_class(row)
        out.append(row)
    return out, stale


def _relocate(lines: SourceLines, path: str, line: int, sha: str) -> int | None:
    current = lines.line_text_sha(path, line)
    if not sha:
        return line if current else None
    if current == sha:
        return line
    matches = [n for n in range(1, lines.line_count(path) + 1) if lines.line_text_sha(path, n) == sha]
    return min(matches, key=lambda n: (abs(n - line), n)) if matches else None

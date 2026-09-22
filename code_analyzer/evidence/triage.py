"""Deterministic triage: group finding rows into clusters an evaluator can read.

A cluster is one probable defect, not one line.  Its key is
``(path, enclosing function, family)``, and members chain only while each is
within ``near`` lines of the previous one.

Different rules -- or different tools -- merge only when the family is a
*correlating* one: a named security category (buffer, null-dereference,
uninitialized, resource-leak, format, randomness, ...) that the row reached
through a CWE, or that a model declared.  Everything else is keyed by its rule
as well.  Measured on a 50-cluster TF-M sample (2026-09-23, two independent
judges): a function-wide 30-line window and keyword-derived families put
"constParameter" with "variableScope" (both CWE-398) and four unrelated splint
prototype warnings under "crypto-misuse" -- the message named a crypto
function -- and only 84% of clusters were one defect.

Functions come from the repository index's stdlib parser (llm/index.py);
the family from ``audit.correlation_category``, the same vocabulary both
engines already correlate under.  Only rows whose view class is ``finding``
are clustered: noise, superseded attempts and system headers never become a
list entry.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..audit import correlation_category
from ..llm.index import decode_source, parse_source
from .findings import key, line_number

CLUSTER_GAP_LINES = 3
NEAR_LINES = 3
# Categories a CWE or a model can put a row in and that mean one kind of
# defect whichever tool reports it.  Generic buckets ("CWE-398" code quality,
# "dead-code", "unknown") never merge different rules.
CORRELATING_FAMILIES = frozenset({
    "buffer", "null-dereference", "uninitialized", "resource-leak", "format", "randomness",
    "integer-overflow", "use-after-free", "double-free", "race", "injection", "crypto-misuse",
    "division-by-zero", "out-of-bounds",
})


def clustering_rule(row: dict[str, Any], family: str) -> str:
    """The rule a row must share with its cluster, or "" when its family correlates across rules."""
    anchored = bool(row.get("cwe")) or row.get("engine") == "llm"
    return "" if family in CORRELATING_FAMILIES and anchored else str(row.get("rule_id") or "")


@dataclass
class Cluster:
    id: str
    path: str
    function: str
    family: str
    rule_id: str
    line_start: int
    line_end: int
    members: list[tuple[str, str, str]] = field(default_factory=list)
    tools: set[str] = field(default_factory=set)

    def as_row(self) -> dict[str, Any]:
        return {"cluster_id": self.id, "path": self.path, "function": self.function, "family": self.family,
                "rule_id": self.rule_id, "line_start": self.line_start, "line_end": self.line_end,
                "members": len(self.members), "tools": ",".join(sorted(self.tools))}


class SourceLines:
    """Reads each scanned file once: its functions and the hash of every line."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._functions: dict[str, list[tuple[int, int, str]]] = {}
        self._lines: dict[str, list[str]] = {}

    def _load(self, path: str) -> None:
        if path in self._lines:
            return
        try:
            data = (self.root / path).read_bytes()
        except OSError:
            self._lines[path], self._functions[path] = [], []
            return
        text = decode_source(data)
        self._lines[path] = text.splitlines()
        try:
            symbols = parse_source(text)
            spans = [(int(f["line_start"]), int(f["line_end"]), str(f["name"])) for f in symbols.functions]
        except Exception:  # noqa: BLE001 - the stdlib parser is best effort; no function is a valid answer
            spans = []
        self._functions[path] = sorted(spans)

    def function_at(self, path: str, line: int) -> str:
        self._load(path)
        best = ""
        for start, end, name in self._functions[path]:
            if start > line:
                break
            if start <= line <= end:
                best = name
        return best

    def line_text_sha(self, path: str, line: int) -> str:
        self._load(path)
        lines = self._lines[path]
        if not 1 <= line <= len(lines):
            return ""
        text = "".join(lines[line - 1].split())
        return hashlib.sha256(text.encode("latin-1", "replace")).hexdigest()[:16] if text else ""


def cluster(rows: Iterable[dict[str, Any]], root: Path, *, gap: int = CLUSTER_GAP_LINES,
            near: int = NEAR_LINES, lines: SourceLines | None = None) -> list[Cluster]:
    """Cluster the ``finding``-class rows; annotate every row with its function, family and cluster."""
    source = lines or SourceLines(root)
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        path = str(row["canonical_path"])
        line = line_number(row)
        row["family"] = correlation_category(row)
        # Never read outside the scanned tree: a system header is not evidence here.
        tree = row.get("view_class") != "out_of_tree"
        row["function"] = source.function_at(path, line) if tree else ""
        row["line_text_sha"] = source.line_text_sha(path, line) if tree else ""
        if row.get("view_class") != "finding":
            continue
        groups[(path, row["function"], row["family"], clustering_rule(row, row["family"]))].append(row)
    clusters: list[Cluster] = []
    seen: dict[str, int] = defaultdict(int)
    for (path, function, family, rule), members in sorted(groups.items()):
        members.sort(key=lambda r: (line_number(r), key(r)))
        limit = gap if function else near
        current: list[dict[str, Any]] = []
        for row in members:
            if current and line_number(row) - line_number(current[-1]) > limit:
                clusters.append(_close(path, function, family, rule, current, seen))
                current = []
            current.append(row)
        if current:
            clusters.append(_close(path, function, family, rule, current, seen))
    return clusters


def _close(path: str, function: str, family: str, rule: str, members: list[dict[str, Any]],
           seen: dict[str, int]) -> Cluster:
    first = members[0]
    # Two clusters of one key can start on lines with identical text (a
    # closing brace, a repeated call); the occurrence number keeps their ids
    # apart and is still a pure function of the rows.
    anchor = "\0".join((path, function, family, rule, first.get("line_text_sha") or str(line_number(first))))
    occurrence = seen[anchor]
    seen[anchor] += 1
    digest = hashlib.sha256(f"{anchor}\0{occurrence}".encode("utf-8")).hexdigest()
    result = Cluster(f"K{digest[:12]}", path, function, family, rule,
                     line_number(first), line_number(members[-1]))
    for row in members:
        row["cluster_id"] = result.id
        result.members.append(key(row))
        result.tools.add(str(row["tool"]))
    return result

"""The SQLite index over one evaluation's evidence: fast, paged, rebuildable.

``index.sqlite`` is derived data.  The truth is the native reports (and, from
M2, the ledger); ``rebuild`` recreates the index from them with no network,
and ``dump()`` renders the whole index as canonical JSON lines so two builds
can be compared byte for byte -- SQLite's own page layout is not stable, the
content is.

Queries return at most one page (20 rows) plus totals and a level
distribution: what a tool result given to the model, or a list pane, needs.
"""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..persist import jsonl_bytes
from .findings import ParsedRun, key, line_number
from .triage import Cluster

SCHEMA_VERSION = 2
PAGE_SIZE = 20

_FINDING_COLUMNS = (
    "fingerprint", "call_id", "unit_id", "tool", "producer", "engine", "path", "line", "col", "rule_id",
    "message", "original_severity", "severity", "review_level", "cwe", "evidence_context", "view_class",
    "function", "family", "cluster_id", "line_text_sha", "level_rank", "row",
)
_SCHEMA = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE findings(
  fingerprint TEXT NOT NULL, call_id TEXT NOT NULL, unit_id TEXT NOT NULL,
  tool TEXT, producer TEXT, engine TEXT, path TEXT, line INTEGER, col TEXT, rule_id TEXT, message TEXT,
  original_severity TEXT, severity TEXT, review_level TEXT, cwe TEXT, evidence_context TEXT, view_class TEXT,
  function TEXT, family TEXT, cluster_id TEXT, line_text_sha TEXT, level_rank INTEGER NOT NULL, row TEXT NOT NULL,
  UNIQUE (fingerprint, call_id, unit_id));
-- Each index serves one query shape's filter AND its order, so a page is a
-- seek, not a sort of every match.
CREATE INDEX findings_view ON findings(view_class, level_rank DESC, path, line);
CREATE INDEX findings_view_level ON findings(view_class, review_level, level_rank DESC, path, line);
CREATE INDEX findings_view_tool ON findings(view_class, tool, level_rank DESC, path, line);
CREATE INDEX findings_path ON findings(view_class, path, line);
CREATE INDEX findings_rule ON findings(tool, rule_id);
CREATE INDEX findings_cluster ON findings(cluster_id);
CREATE TABLE diagnostics(
  seq INTEGER PRIMARY KEY, tool TEXT, unit_id TEXT, path TEXT, line TEXT, category TEXT, message TEXT, row TEXT);
CREATE TABLE clusters(
  cluster_id TEXT PRIMARY KEY, path TEXT, function TEXT, family TEXT, rule_id TEXT,
  line_start INTEGER, line_end INTEGER, members INTEGER, tools TEXT, top_level TEXT,
  top_rank INTEGER NOT NULL) WITHOUT ROWID;
CREATE INDEX clusters_rank ON clusters(top_rank DESC, members DESC, path, line_start);
CREATE INDEX clusters_path ON clusters(path, line_start);
CREATE TABLE pvs(
  pv_id TEXT PRIMARY KEY, partition TEXT NOT NULL, level TEXT, level_rank INTEGER NOT NULL, level_basis TEXT,
  proposed_level TEXT, module TEXT, sfr TEXT, sfr_ids TEXT, anchor TEXT, cluster_id TEXT, path TEXT,
  function TEXT, family TEXT, line_start INTEGER, line_end INTEGER, members INTEGER, tools TEXT,
  priority INTEGER NOT NULL, priority_why TEXT, multi_engine INTEGER, match TEXT, status TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '', row TEXT NOT NULL) WITHOUT ROWID;
CREATE INDEX pvs_rank ON pvs(partition, priority DESC, path, line_start);
CREATE TABLE triage(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
"""


class DuplicateKey(Exception):
    pass


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA cache_size = -65536")
        self.db.execute("PRAGMA mmap_size = 268435456")

    @classmethod
    def build(cls, path: Path, parsed: ParsedRun, clusters: Iterable[Cluster], *,
              pvs: Iterable[Any] = (), triage: dict[str, int] | None = None) -> Store:
        """Write a fresh index atomically: a half-built index never replaces a good one."""
        temporary = path.with_name(path.name + ".building")
        if temporary.exists():
            temporary.unlink()
        store = cls(temporary)
        store.db.executescript(_SCHEMA)
        store._load(parsed, list(clusters))
        store._load_pvs(list(pvs), triage or {})
        store.db.commit()
        store.db.close()
        os.replace(temporary, path)
        return cls(path)

    def _load(self, parsed: ParsedRun, clusters: list[Cluster]) -> None:
        seen: set[tuple[str, str, str]] = set()
        duplicates = [k for k in (key(row) for row in parsed.findings) if k in seen or seen.add(k)]
        if duplicates:
            raise DuplicateKey(f"{len(duplicates)} duplicate (fingerprint, call_id, unit_id) keys, e.g. {duplicates[0]}")
        self.db.executemany(
            f"INSERT INTO findings({', '.join(_FINDING_COLUMNS)}) VALUES ({', '.join('?' * len(_FINDING_COLUMNS))})",
            (_finding_values(row) for row in parsed.findings))
        self.db.executemany(
            "INSERT INTO diagnostics(tool, unit_id, path, line, category, message, row) VALUES (?,?,?,?,?,?,?)",
            ((str(d.get("tool", "")), str(d.get("unit_id", "")), str(d.get("canonical_path", "")),
              str(d.get("line", "")), str(d.get("category", "")), str(d.get("message", "")), _json(d))
             for d in parsed.diagnostics))
        top: dict[str, str] = {}
        for row in parsed.findings:
            cluster_id = row.get("cluster_id")
            if cluster_id and _rank(row.get("review_level")) > _rank(top.get(cluster_id)):
                top[cluster_id] = str(row.get("review_level"))
        self.db.executemany(
            "INSERT INTO clusters VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            ((c.id, c.path, c.function, c.family, c.rule_id, c.line_start, c.line_end, len(c.members),
              ",".join(sorted(c.tools)), top.get(c.id, "unmapped"), _rank(top.get(c.id))) for c in clusters))
        for name, value in (("schema_version", SCHEMA_VERSION), ("run_id", parsed.run_id), ("source", str(parsed.source))):
            self.db.execute("INSERT INTO meta VALUES (?, ?)", (name, str(value)))

    def _load_pvs(self, entries: list[Any], triage: dict[str, int]) -> None:
        self.db.executemany(
            "INSERT INTO pvs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ((e.pv_id, e.partition, e.level, _rank(e.level), e.level_basis, e.proposed_level, e.module, _json(e.sfr),
              "," + ",".join(s["id"] for s in e.sfr) + ",", e.anchor, e.cluster_id, e.path, e.function, e.family,
              e.line_start, e.line_end, len(e.members), ",".join(e.tools), e.priority, _json(e.priority_why),
              int(e.multi_engine), e.match, "open", "", _json(e.as_row()))
             for e in entries if e.pv_id))
        self.db.executemany("INSERT INTO triage VALUES (?, ?)", sorted(triage.items()))

    # -- queries -----------------------------------------------------------------------
    def counts(self) -> dict[str, Any]:
        view = {r[0]: r[1] for r in self.db.execute("SELECT view_class, COUNT(*) FROM findings GROUP BY view_class")}
        return {
            "findings": sum(view.values()), "by_view_class": view,
            "diagnostics": self.db.execute("SELECT COUNT(*) FROM diagnostics").fetchone()[0],
            "clusters": self.db.execute("SELECT COUNT(*) FROM clusters").fetchone()[0],
        }

    def list_findings(self, where: dict[str, Any] | None = None, *, sort: str = "level", page: int = 1) -> dict[str, Any]:
        """One page of rows.  Without an explicit ``view_class`` only real findings are listed:
        noise, superseded attempts and system headers are there when asked for, never by default."""
        filters = dict(where or {})
        if filters.get("view_class") == "*":
            filters.pop("view_class")
        else:
            filters.setdefault("view_class", "finding")
        clause, args = _where(filters, _FINDING_FILTERS)
        order = {"level": "level_rank DESC, path, line", "path": "path, line"}.get(sort, "path, line")
        total = self.db.execute(f"SELECT COUNT(*) FROM findings{clause}", args).fetchone()[0]
        rows = self.db.execute(
            f"SELECT fingerprint, tool, path, line, rule_id, review_level, view_class, cluster_id, message "
            f"FROM findings{clause} ORDER BY {order} LIMIT ? OFFSET ?", [*args, PAGE_SIZE, (page - 1) * PAGE_SIZE])
        levels = dict(self.db.execute(f"SELECT review_level, COUNT(*) FROM findings{clause} GROUP BY review_level", args)
                      .fetchall())
        return {"total": total, "page": page, "rows": [dict(r) for r in rows], "by_level": levels}

    def list_clusters(self, where: dict[str, Any] | None = None, *, sort: str = "level", page: int = 1) -> dict[str, Any]:
        clause, args = _where(where or {}, _CLUSTER_FILTERS)
        order = {"level": "top_rank DESC, members DESC, path, line_start",
                 "path": "path, line_start"}.get(sort, "path, line_start")
        total = self.db.execute(f"SELECT COUNT(*) FROM clusters{clause}", args).fetchone()[0]
        rows = self.db.execute(f"SELECT * FROM clusters{clause} ORDER BY {order} LIMIT ? OFFSET ?",
                               [*args, PAGE_SIZE, (page - 1) * PAGE_SIZE])
        return {"total": total, "page": page, "rows": [dict(r) for r in rows]}

    def list_pvs(self, where: dict[str, Any] | None = None, *, sort: str = "priority", page: int = 1) -> dict[str, Any]:
        """One page of the vulnerability list, with totals by partition and level."""
        clause, args = _where(where or {}, _PV_FILTERS)
        order = {"priority": "priority DESC, path, line_start", "level": "level_rank DESC, priority DESC, path",
                 "path": "path, line_start"}.get(sort, "priority DESC, path, line_start")
        total = self.db.execute(f"SELECT COUNT(*) FROM pvs{clause}", args).fetchone()[0]
        rows = self.db.execute(
            f"SELECT pv_id, partition, level, level_basis, proposed_level, module, sfr, path, function, family, "
            f"line_start, line_end, members, tools, priority, status, note FROM pvs{clause} ORDER BY {order} "
            f"LIMIT ? OFFSET ?", [*args, PAGE_SIZE, (page - 1) * PAGE_SIZE])
        partitions = dict(self.db.execute(f"SELECT partition, COUNT(*) FROM pvs{clause} GROUP BY partition", args)
                          .fetchall())
        levels = dict(self.db.execute(f"SELECT level, COUNT(*) FROM pvs{clause} GROUP BY level", args).fetchall())
        out = []
        for row in rows:
            item = dict(row)
            item["sfr"] = json.loads(item["sfr"] or "[]")
            out.append(item)
        return {"total": total, "page": page, "rows": out, "by_partition": partitions, "by_level": levels}

    def pv(self, pv_id: str) -> dict[str, Any] | None:
        row = self.db.execute("SELECT row, status, note, partition, level, level_basis FROM pvs WHERE pv_id = ?",
                              (pv_id,)).fetchone()
        if row is None:
            return None
        return {**json.loads(row[0]), "status": row[1], "note": row[2], "partition": row[3], "level": row[4],
                "level_basis": row[5]}

    def all_pvs(self) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT row, status, note, partition, level, level_basis FROM pvs ORDER BY pv_id")
        return [{**json.loads(r[0]), "status": r[1], "note": r[2], "partition": r[3], "level": r[4],
                 "level_basis": r[5]} for r in rows]

    def set_status(self, pv_id: str, status: str, note: str) -> bool:
        with self.db:
            return self.db.execute("UPDATE pvs SET status = ?, note = ? WHERE pv_id = ?",
                                   (status, note, pv_id)).rowcount == 1

    def set_level(self, pv_id: str, level: str, basis: str, partition: str) -> bool:
        with self.db:
            return self.db.execute(
                "UPDATE pvs SET level = ?, level_rank = ?, level_basis = ?, partition = ? WHERE pv_id = ?",
                (level, _rank(level), basis, partition, pv_id)).rowcount == 1

    def triage_counts(self) -> dict[str, int]:
        return dict(self.db.execute("SELECT key, value FROM triage ORDER BY key").fetchall())

    def cluster_members(self, cluster_id: str) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT row FROM findings WHERE cluster_id = ? ORDER BY line, fingerprint", (cluster_id,))
        return [json.loads(r[0]) for r in rows]

    def dump(self) -> bytes:
        """The whole index as canonical JSON lines, in key order.  Equal content, equal bytes."""
        out = bytearray()
        for row in self.db.execute(f"SELECT {', '.join(_FINDING_COLUMNS)} FROM findings "
                                   "ORDER BY fingerprint, call_id, unit_id"):
            out += jsonl_bytes({"findings": dict(row)})
        for row in self.db.execute("SELECT tool, unit_id, path, line, category, message, row FROM diagnostics "
                                   "ORDER BY tool, unit_id, path, line, category, message, row"):
            out += jsonl_bytes({"diagnostics": dict(row)})
        for row in self.db.execute("SELECT * FROM clusters ORDER BY cluster_id"):
            out += jsonl_bytes({"clusters": dict(row)})
        for row in self.db.execute("SELECT pv_id, row FROM pvs ORDER BY pv_id"):
            out += jsonl_bytes({"pvs": dict(row)})
        for row in self.db.execute("SELECT * FROM triage ORDER BY key"):
            out += jsonl_bytes({"triage": dict(row)})
        for row in self.db.execute("SELECT * FROM meta ORDER BY key"):
            out += jsonl_bytes({"meta": dict(row)})
        return bytes(out)

    def schema_version(self) -> int:
        try:
            row = self.db.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        except sqlite3.DatabaseError:
            return 0
        return int(row[0]) if row else 0

    def close(self) -> None:
        self.db.close()


def index_current(path: Path) -> bool:
    """Whether ``path`` holds an index this code can read; derived data is rebuilt, never migrated."""
    if not path.exists():
        return False
    store = Store(path)
    try:
        return store.schema_version() == SCHEMA_VERSION
    finally:
        store.close()


_FINDING_FILTERS = {"tool": "tool = ?", "rule": "rule_id = ?", "level": "review_level = ?",
                    "view_class": "view_class = ?", "family": "family = ?", "cluster": "cluster_id = ?",
                    "path": "path GLOB ?", "function": "function = ?"}
_PV_FILTERS = {"partition": "partition = ?", "level": "level = ?", "module": "module = ?", "family": "family = ?",
               "path": "path GLOB ?", "sfr": "sfr_ids LIKE '%,' || ? || ',%'", "status": "status = ?"}
_CLUSTER_FILTERS = {"path": "path GLOB ?", "family": "family = ?", "level": "top_level = ?",
                    "function": "function = ?", "tool": "(',' || tools || ',') LIKE '%,' || ? || ',%'"}


def _where(where: dict[str, Any], allowed: dict[str, str]) -> tuple[str, list[Any]]:
    parts, args = [], []
    for name, value in sorted(where.items()):
        if value in (None, ""):
            continue
        if name not in allowed:
            raise ValueError(f"unknown filter {name!r}; known: {', '.join(sorted(allowed))}")
        parts.append(allowed[name])
        args.append(value)
    return (" WHERE " + " AND ".join(parts)) if parts else "", args


def _rank(level: Any) -> int:
    return {"error": 4, "warning": 3, "style": 2, "information": 1}.get(str(level or ""), 0)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _finding_values(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(row["fingerprint"]), str(row["call_id"]), str(row["unit_id"]), str(row.get("tool", "")),
        str(row.get("producer", "")), str(row.get("engine", "")), str(row.get("canonical_path", "")),
        line_number(row), str(row.get("column", "")), str(row.get("rule_id", "")), str(row.get("message", "")),
        str(row.get("original_severity", "")), str(row.get("severity", "")), str(row.get("review_level", "")),
        str(row.get("cwe", "")), str(row.get("evidence_context", "")), str(row.get("view_class", "")),
        str(row.get("function", "")), str(row.get("family", "")), str(row.get("cluster_id", "")),
        str(row.get("line_text_sha", "")), _rank(row.get("review_level")), _json(row),
    )

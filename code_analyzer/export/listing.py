"""The vulnerability list as files: xlsx (four sheets), Markdown by SFR, CSV.

Column names and generated text are English (ETRs are written in English;
decided 2026-09-22); analyst notes are kept as written.  Ordering: the main
partition first, then "unmapped -- verify manually", each by level then
priority.  Entries an analyst dispositioned as false positive or not
exploitable move to the "Dispositioned" sheet with their notes; nothing is
dropped.

``shareable`` withholds what could carry source text (AI rationale, evidence
quotes, exploit notes -- none exist before AI review) and every export is
checked for leaks: no absolute local path, no home directory, no scanned-tree
root may appear in any file, including inside the xlsx XML.  A shareable
export that fails the check is not written.
"""
from __future__ import annotations

import csv
import hashlib
import io
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..evidence.store import Store
from ..evidence.workspace import Workspace, _atomic
from ..sesip.active import active_profile
from ..sesip.profile import STRONG_SFR_BASES
from .xlsx import workbook

COLUMNS = ("PV ID", "Title", "Partition", "TOE Module", "SFR", "TSFI", "Location", "Function", "Level (§7.4.1)",
           "Level Basis", "Category (§7.4.2)", "CWE", "Engines", "AI Opinion", "AI Level Suggestion", "AI Rationale",
           "Exploit Note", "Analyst Status", "Analyst Note", "Priority", "Proposed Level", "Profile")
WITHHELD_IN_SHAREABLE = ("AI Rationale", "Exploit Note")
DISPOSITIONED = frozenset({"false_positive", "not_exploitable"})
FORMATS = ("xlsx", "md", "csv")
_LEVEL_RANK = {"error": 4, "warning": 3, "style": 2, "information": 1}


class LeakFound(Exception):
    pass


def export(workspace: Workspace, variant: str, formats: list[str]) -> dict[str, Any]:
    if variant not in ("internal", "shareable"):
        raise ValueError("variant must be internal or shareable")
    formats = [f for f in FORMATS if f in formats] or list(FORMATS)
    from ..evidence.analyze import (
        ensure_index,  # noqa: PLC0415 - analyze imports the runner stack
    )

    if not ensure_index(workspace):
        raise ValueError("no list yet: run the tools first")
    store = Store(workspace.index_path)
    try:
        rows, members = _rows(store)
        triage = store.triage_counts()
    finally:
        store.close()
    profile = active_profile(workspace)
    table = [_line(entry, members.get(entry["pv_id"], []), profile.name, variant) for entry in rows]
    if variant == "shareable":
        # Tool messages can quote a path; the shareable list names paths relative to the tree only.
        replacements = [(str(workspace.source), "<SOURCE>"), (str(workspace.root), "<EVALUATION>"),
                        (str(Path.home()), "~")]
        table = [[_redact(cell, replacements) for cell in line] for line in table]
    listed = [t for t, e in zip(table, rows, strict=True) if e["status"] not in DISPOSITIONED]
    disposed = [t for t, e in zip(table, rows, strict=True) if e["status"] in DISPOSITIONED]
    files: dict[str, bytes] = {}
    if "xlsx" in formats:
        files["pv-list.xlsx"] = workbook([
            ("PV List", COLUMNS, listed), ("Dispositioned", COLUMNS, disposed),
            ("Coverage", ("Measure", "Count"), sorted(triage.items())),
            ("Profile", ("Field", "Value"), _profile_rows(profile)),
        ])
    if "csv" in formats:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(COLUMNS)
        writer.writerows(listed)
        files["pv-list.csv"] = buffer.getvalue().encode("utf-8")
    if "md" in formats:
        files["pv-list.md"] = _markdown(listed, disposed, triage, profile).encode("utf-8")
    forbidden = _forbidden(workspace)
    leaks = [name for name, data in files.items() if _leaks(name, data, forbidden)]
    if leaks and variant == "shareable":
        raise LeakFound(f"the shareable export would disclose a local path in: {', '.join(leaks)}")
    export_id = f"E{len(workspace.ledger.of('export_written')) + 1}"
    directory = workspace.root / "exports" / export_id
    directory.mkdir(parents=True, exist_ok=False)
    listing = []
    for name, data in sorted(files.items()):
        _atomic(directory / name, data)
        listing.append({"name": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    result = {"id": export_id, "variant": variant, "files": listing, "leak_check": "failed" if leaks else "passed",
              "entries": len(listed), "dispositioned": len(disposed), "profile_sha256": profile.sha256}
    workspace.ledger.append("export_written", export_id=export_id, variant=variant, files=listing,
                            leak_check=result["leak_check"], entries=len(listed), dispositioned=len(disposed))
    return result


def _rows(store: Store) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    entries = store.all_pvs()
    entries.sort(key=lambda e: (e["partition"] != "main", -_LEVEL_RANK.get(e["level"], 0), -int(e["priority"]),
                                e["path"], int(e["line_start"])))
    members: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in entries:
        members[entry["pv_id"]] = store.cluster_members(entry["cluster_id"])
    return entries, members


def _line(entry: dict[str, Any], members: list[dict[str, Any]], profile: str, variant: str) -> list[Any]:
    top = max(members, key=lambda m: (_LEVEL_RANK.get(str(m.get("review_level")), 0), -_int(m.get("line"))),
              default={})
    title = f"{top.get('rule_id', entry['family'])}: {str(top.get('message', '')).strip()}"[:160]
    cwes = sorted({str(m.get("cwe")) for m in members if m.get("cwe")})
    sfr = ", ".join(s["id"] for s in entry.get("sfr", []) if s["basis"] in STRONG_SFR_BASES)
    line = entry["line_start"] if entry["line_start"] == entry["line_end"] else \
        f"{entry['line_start']}-{entry['line_end']}"
    values = {
        "PV ID": entry["pv_id"], "Title": title,
        "Partition": "main" if entry["partition"] == "main" else "unmapped - verify manually",
        "TOE Module": entry.get("module", ""), "SFR": sfr, "TSFI": entry.get("tsfi") or "",
        "Location": f"{entry['path']}:{line}", "Function": entry.get("function", ""),
        "Level (§7.4.1)": entry["level"], "Level Basis": entry["level_basis"], "Category (§7.4.2)": "",
        "CWE": ", ".join(f"CWE-{c}" if c.isdigit() else c for c in cwes), "Engines": ", ".join(entry.get("tools", [])),
        "AI Opinion": "", "AI Level Suggestion": "", "AI Rationale": "", "Exploit Note": "",
        "Analyst Status": entry["status"], "Analyst Note": entry.get("note", ""), "Priority": int(entry["priority"]),
        "Proposed Level": entry.get("proposed_level", ""), "Profile": profile,
    }
    if variant == "shareable":
        for column in WITHHELD_IN_SHAREABLE:
            values[column] = "withheld" if values[column] else ""
    return [values[column] for column in COLUMNS]


def _markdown(listed: list[list[Any]], disposed: list[list[Any]], triage: dict[str, int], profile: Any) -> str:
    index = {name: i for i, name in enumerate(COLUMNS)}
    by_sfr: dict[str, list[list[Any]]] = defaultdict(list)
    for row in listed:
        for sfr in (row[index["SFR"]] or "No strong SFR link").split(", "):
            by_sfr[sfr].append(row)
    lines = ["# Vulnerability list", "", f"Profile: {profile.name} ({profile.status}), sha256 {profile.sha256[:16]}", "",
             f"Listed: {len(listed)}; dispositioned: {len(disposed)}; in-TOE clusters {triage.get('in_toe', 0)} = "
             f"{triage.get('partition_main', 0)} main + {triage.get('partition_unmapped', 0)} unmapped + "
             f"{triage.get('partition_below', 0)} below threshold.", ""]
    for sfr in sorted(by_sfr, key=lambda s: (s == "No strong SFR link", s)):
        lines += [f"## {sfr}", "", "| PV | Level | Location | Title | Status |", "|---|---|---|---|---|"]
        for row in by_sfr[sfr]:
            cells = [row[index[c]] for c in ("PV ID", "Level (§7.4.1)", "Location", "Title", "Analyst Status")]
            lines.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in cells) + " |")
        lines.append("")
    return "\n".join(lines)


def _profile_rows(profile: Any) -> list[tuple[str, str]]:
    rows = [("Profile", profile.name), ("Status", profile.status), ("SHA-256", profile.sha256)]
    rows += [(f"Document ({d.get('role')})", f"{d.get('title') or d.get('file')} sha256 {d.get('sha256', '')}")
             for d in profile.data.get("documents", [])]
    rows += [(f"Grading rule {i + 1}", f"{r.get('match')} -> {r.get('level')} [{r.get('basis')}]")
             for i, r in enumerate(profile.data.get("grading_rule", []))]
    return rows


def _forbidden(workspace: Workspace) -> list[bytes]:
    values = {str(workspace.source), str(workspace.root), str(Path.home()), "/home/", "C:\\Users"}
    return sorted({v.encode("utf-8") for v in values if v and v != "/"}, key=len, reverse=True)


def _leaks(name: str, data: bytes, forbidden: list[bytes]) -> bool:
    blobs = [data]
    if name.endswith(".xlsx"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            blobs = [archive.read(member) for member in archive.namelist()]
    return any(needle in blob for blob in blobs for needle in forbidden)


def _redact(value: Any, replacements: list[tuple[str, str]]) -> Any:
    if not isinstance(value, str):
        return value
    for needle, replacement in replacements:
        value = value.replace(needle, replacement)
    return value


def _int(value: Any) -> int:
    try:
        return int(str(value).split("-")[0])
    except ValueError:
        return 0

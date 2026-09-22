"""The vulnerability list: one entry per in-TOE cluster, numbered once and for good.

Partition (deterministic; AI never moves an entry out of the list):

    main       graded by a provable rule at or above ``pv_min_level``, or below it
               but reported by two or more engines at the same place
    unmapped   no provable grade -- flawfinder notes, splint, anything the test
               plan does not name.  Listed as "needs manual verification",
               never dropped (the grading charter: unmapped means verify)
    below      graded, below the threshold, one engine: counted, not numbered,
               can be promoted by an analyst

Conservation, tested: in-TOE clusters == main + unmapped + below.

Numbering.  ``PV-0007`` is never reused.  A new triage is matched one-to-one
against the last numbering: first by shared member fingerprints (greedy,
most shared first), then by anchor, then as "moved" -- same file, function
and family, and the old decisive line's text still inside the cluster.  So an
edit above a finding shifts its line numbers (new fingerprints) but keeps its
number.  What matches nothing gets the next number; an old entry that
matches nothing is retired, never deleted.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from ..evidence.findings import line_number
from .profile import PROVABLE_BASES, STRONG_SFR_BASES, UNMAPPED, Profile

SECURITY_FAMILIES = frozenset({
    "buffer", "null-dereference", "uninitialized", "resource-leak", "format", "randomness", "integer-overflow",
    "use-after-free", "double-free", "race", "injection", "crypto-misuse", "division-by-zero", "out-of-bounds",
})


@dataclass
class Entry:
    cluster_id: str
    anchor: str
    path: str
    function: str
    family: str
    line_start: int
    line_end: int
    module: str
    partition: str
    level: str
    level_basis: str
    proposed_level: str
    sfr: list[dict[str, str]]
    tools: list[str]
    members: list[str]              # member fingerprints, sorted
    member_line_shas: list[str]
    decisive_line_sha: str
    priority: int
    priority_why: dict[str, int]
    multi_engine: bool
    pv_id: str = ""
    match: str = ""                 # how the number was kept: fingerprint | anchor | moved | new

    def as_row(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Triage:
    entries: list[Entry]
    outside_toe: int
    counts: dict[str, int] = field(default_factory=dict)


def build_entries(clusters: Iterable[dict[str, Any]], members_of: dict[str, list[dict[str, Any]]],
                  profile: Profile) -> Triage:
    """One entry per cluster in the TOE, graded and partitioned by the profile."""
    minimum = profile.rank(profile.min_level)
    entries: list[Entry] = []
    outside = 0
    for cluster in clusters:
        members = members_of.get(cluster["cluster_id"], [])
        module = profile.module_of(str(cluster["path"]))
        if module is None or not members:
            outside += 1
            continue
        grades = [(profile.grade(row), row) for row in members]
        provable = [(g, row) for g, row in grades if g[1] in PROVABLE_BASES]
        if provable:
            (level, basis, _), _ = max(provable, key=lambda item: (profile.rank(item[0][0]), -line_number(item[1])))
            proposed = ""
        else:
            level, basis = UNMAPPED, UNMAPPED
            suggestions = [g[2] for g, _ in grades if g[2]]
            proposed = max(suggestions, key=profile.rank) if suggestions else ""
        tools = sorted({str(row["tool"]) for row in members})
        multi = len(tools) >= 2
        rank = profile.rank(level) if level != UNMAPPED else 0
        if level == UNMAPPED:
            partition = "unmapped"
        elif rank >= minimum or multi:
            partition = "main"
        else:
            partition = "below"
        decisive = max(members, key=lambda row: (profile.rank(profile.grade(row)[0]), -line_number(row)))
        decisive_sha = str(decisive.get("line_text_sha") or "")
        family = str(cluster["family"])
        anchor = hashlib.sha256("\0".join((str(cluster["path"]), str(cluster["function"]), family,
                                          decisive_sha or str(line_number(decisive)))).encode()).hexdigest()[:16]
        links: dict[str, str] = {}
        for row in members:
            for link in profile.sfrs_for(row, module):
                if link["id"] not in links or (link["basis"] in STRONG_SFR_BASES
                                               and links[link["id"]] not in STRONG_SFR_BASES):
                    links[link["id"]] = link["basis"]
        sfr = [{"id": k, "basis": v} for k, v in sorted(links.items())]
        why = {
            "level": 4 * rank,
            "strong_sfr": 3 * int(any(v in STRONG_SFR_BASES for v in links.values())),
            "tsfi_near": 0,
            "security_family": 2 * int(family in SECURITY_FAMILIES),
            "engines_agree": int(multi),
            "build_aware": int(any(str(row.get("evidence_context", "")).startswith("build-aware") for row in members)),
        }
        entries.append(Entry(
            str(cluster["cluster_id"]), anchor, str(cluster["path"]), str(cluster["function"]), family,
            int(cluster["line_start"]), int(cluster["line_end"]), module, partition, level, basis, proposed, sfr,
            tools, sorted({str(row["fingerprint"]) for row in members}),
            sorted({str(row.get("line_text_sha") or "") for row in members} - {""}), decisive_sha,
            sum(why.values()), why, multi,
        ))
    counts = {"main": 0, "unmapped": 0, "below": 0}
    for entry in entries:
        counts[entry.partition] += 1
    return Triage(entries, outside, counts)


def number(entries: list[Entry], previous: list[dict[str, Any]]) -> tuple[list[Entry], list[dict[str, Any]]]:
    """Give every listed entry (main, unmapped) a stable PV number; return (entries, retired)."""
    listed = [e for e in entries if e.partition in ("main", "unmapped")]
    old = sorted(previous, key=lambda p: _num(p["pv_id"]))
    taken_old: set[str] = set()
    taken_new: set[int] = set()

    def bind(new_index: int, old_record: dict[str, Any], how: str) -> None:
        listed[new_index].pv_id = str(old_record["pv_id"])
        listed[new_index].match = how
        taken_old.add(str(old_record["pv_id"]))
        taken_new.add(new_index)

    # 1. shared member fingerprints, most shared first
    by_fingerprint: dict[str, list[int]] = defaultdict(list)
    for index, entry in enumerate(listed):
        for fingerprint in entry.members:
            by_fingerprint[fingerprint].append(index)
    pairs = []
    for record in old:
        shared: dict[int, int] = defaultdict(int)
        for fingerprint in record.get("members", []):
            for index in by_fingerprint.get(fingerprint, ()):
                shared[index] += 1
        pairs += [(-count, _num(record["pv_id"]), index, record) for index, count in shared.items()]
    for _, _, index, record in sorted(pairs, key=lambda p: (p[0], p[1], p[2])):
        if index not in taken_new and record["pv_id"] not in taken_old:
            bind(index, record, "fingerprint")
    # 2. anchor
    by_anchor: dict[str, list[int]] = defaultdict(list)
    for index, entry in enumerate(listed):
        by_anchor[entry.anchor].append(index)
    for record in old:
        if record["pv_id"] in taken_old:
            continue
        for index in by_anchor.get(str(record.get("anchor", "")), ()):
            if index not in taken_new:
                bind(index, record, "anchor")
                break
    # 3. moved: same file, function and family; the old decisive line's text is still in the cluster
    by_place: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for index, entry in enumerate(listed):
        by_place[(entry.path, entry.function, entry.family)].append(index)
    for record in old:
        if record["pv_id"] in taken_old or not record.get("decisive_line_sha"):
            continue
        place = (str(record.get("path")), str(record.get("function")), str(record.get("family")))
        for index in by_place.get(place, ()):
            if index not in taken_new and record["decisive_line_sha"] in listed[index].member_line_shas:
                bind(index, record, "moved")
                break
    # 4. new numbers, in a deterministic order
    highest = max([_num(r["pv_id"]) for r in old] + [0])
    for index in sorted(set(range(len(listed))) - taken_new,
                        key=lambda i: (listed[i].path, listed[i].line_start, listed[i].anchor)):
        highest += 1
        listed[index].pv_id = f"PV-{highest:04d}"
        listed[index].match = "new"
    retired = [record for record in old if record["pv_id"] not in taken_old]
    return entries, retired


def numbering_record(entry: Entry) -> dict[str, Any]:
    """What the next triage needs to find this entry again."""
    return {"pv_id": entry.pv_id, "anchor": entry.anchor, "members": entry.members, "path": entry.path,
            "function": entry.function, "family": entry.family, "decisive_line_sha": entry.decisive_line_sha}


def _num(pv_id: str) -> int:
    try:
        return int(str(pv_id).split("-", 1)[1])
    except (IndexError, ValueError):
        return 0

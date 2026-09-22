"""M2: the vulnerability list -- partitions, conservation, and numbers that survive edits."""
from __future__ import annotations

from typing import Any

from code_analyzer.sesip.profile import load_profile
from code_analyzer.sesip.pv import build_entries, number, numbering_record

RT700 = load_profile("rt700-tp-v1.1")


def member(fingerprint: str, line: int, *, severity: str = "error", tool: str = "cppcheck",
           sha: str = "") -> dict[str, Any]:
    return {"fingerprint": fingerprint, "line": str(line), "original_severity": severity, "tool": tool,
            "rule_id": "r", "family": "buffer", "canonical_path": "a.c", "function": "f",
            "line_text_sha": sha or f"sha-{fingerprint}", "evidence_context": "source-only"}


def cluster(cid: str, line: int = 1, *, path: str = "a.c", family: str = "buffer") -> dict[str, Any]:
    return {"cluster_id": cid, "path": path, "function": "f", "family": family, "line_start": line, "line_end": line}


def test_partitions_follow_provable_levels_and_are_conserved() -> None:
    clusters = [cluster(f"K{i}", i) for i in range(5)]
    members = {
        "K0": [member("a", 0, severity="error")],                                   # main
        "K1": [member("b", 1, severity="style")],                                   # below
        "K2": [member("c", 2, severity="style"), member("d", 2, severity="style", tool="flawfinder")],  # main: 2 engines
        "K3": [member("e", 3, severity="note", tool="flawfinder")],                 # unmapped
        "K4": [member("f", 4, severity="unknown", tool="splint")],                  # unmapped
    }
    triage = build_entries(clusters, members, RT700)
    by = {e.cluster_id: e for e in triage.entries}
    assert [by[f"K{i}"].partition for i in range(5)] == ["main", "below", "main", "unmapped", "unmapped"]
    assert by["K2"].multi_engine and by["K0"].level_basis == "native-exact" and by["K3"].level == "unmapped"
    assert triage.counts == {"main": 2, "unmapped": 2, "below": 1}
    assert len(triage.entries) == sum(triage.counts.values())
    assert by["K0"].priority > by["K1"].priority


def test_clusters_outside_the_toe_are_counted_not_listed() -> None:
    from code_analyzer.sesip.profile import parse_profile
    profile = parse_profile(
        '[[level]]\nid = "error"\nrank = 4\n[[toe_module]]\nid = "m"\npaths = ["in/**"]\n'
        '[[grading_rule]]\nmatch = {native = "error"}\nlevel = "error"\nbasis = "native-exact"\n')
    triage = build_entries([cluster("A", path="in/x.c"), cluster("B", path="out/y.c")],
                           {"A": [member("a", 1)], "B": [member("b", 1)]}, profile)
    assert [e.cluster_id for e in triage.entries] == ["A"] and triage.outside_toe == 1


def triage_of(specs: list[tuple[str, list[dict[str, Any]]]]) -> list[Any]:
    clusters = [cluster(cid, members[0]["line"] and int(members[0]["line"])) for cid, members in specs]
    return build_entries(clusters, dict(specs), RT700).entries


def test_numbers_are_kept_by_fingerprint_anchor_or_move_and_never_reused() -> None:
    first, retired = number(triage_of([("K1", [member("a", 10)]), ("K2", [member("b", 20)]),
                                       ("K3", [member("c", 30)])]), [])
    assert [e.pv_id for e in first] == ["PV-0001", "PV-0002", "PV-0003"] and retired == []
    previous = [numbering_record(e) for e in first]
    # K1 unchanged (same fingerprint); K2 moved 20 lines down (new fingerprint, same line text);
    # K3 fixed (gone); a new finding appears.
    second, retired = number(triage_of([("N1", [member("a", 10)]), ("N2", [member("b2", 40, sha="sha-b")]),
                                        ("N4", [member("z", 90)])]), previous)
    ids = {e.cluster_id: (e.pv_id, e.match) for e in second}
    assert ids["N1"] == ("PV-0001", "fingerprint")
    assert ids["N2"][0] == "PV-0002" and ids["N2"][1] in ("anchor", "moved")
    assert ids["N4"] == ("PV-0004", "new")  # PV-0003 is retired, never reused
    assert [r["pv_id"] for r in retired] == ["PV-0003"]


def test_one_old_number_goes_to_one_new_entry_when_a_cluster_splits() -> None:
    first, _ = number(triage_of([("K1", [member("a", 10), member("b", 11)])]), [])
    previous = [numbering_record(e) for e in first]
    second, _ = number(triage_of([("S1", [member("a", 10)]), ("S2", [member("b", 11)])]), previous)
    assert sorted(e.pv_id for e in second) == ["PV-0001", "PV-0002"]


def test_numbering_is_deterministic() -> None:
    specs = [(f"K{i}", [member(f"f{i}", i * 7)]) for i in range(20)]
    one, _ = number(triage_of(specs), [])
    two, _ = number(triage_of(list(reversed(specs))), [])
    assert {e.cluster_id: e.pv_id for e in one} == {e.cluster_id: e.pv_id for e in two}

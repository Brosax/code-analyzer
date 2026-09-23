"""M1: the evidence index -- identity, view classes, clusters, paging, rebuild stability."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from helpers import executable, run_analyze
from test_core import write_config

from code_analyzer.evidence.findings import (
    NOISE_RULES,
    ParsedRun,
    parse_run,
    unit_of,
    view_class,
)
from code_analyzer.evidence.store import DuplicateKey, Store
from code_analyzer.evidence.triage import SourceLines, cluster

SOURCE = """\
#include <string.h>
int copy(char *dst, const char *src, int n) {
    char tmp[4];
    memcpy(tmp, src, n);
    strcpy(dst, tmp);
    return tmp[4];
}

int helper(void) { return 0; }
"""


def row(line: int, rule: str = "arrayIndexOutOfBounds", *, path: str = "a.c", tool: str = "cppcheck",
        level: str = "error", message: str | None = None, context: str = "source-only", unit: str = "fallback",
        cwe: str = "") -> dict[str, Any]:
    fingerprint = f"{tool}:{path}:{line}:{rule}:{message or rule}:{context.split('/')[0]}"
    data = {"tool": tool, "producer": tool, "engine": "static", "canonical_path": path, "file": path,
            "line": str(line), "column": "1", "rule_id": rule, "message": message or f"{rule} here",
            "review_level": level, "original_severity": level, "evidence_context": context, "cwe": cwe,
            "fingerprint": fingerprint, "call_id": f"run:{tool}", "unit_id": unit,
            "source_artifact": f"tools/{tool}/{unit}/report.xml"}
    data["view_class"] = view_class(data)
    return data


@pytest.mark.parametrize(("changes", "expected"), [
    ({}, "finding"),
    ({"canonical_path": "/usr/include/string.h"}, "out_of_tree"),
    ({"canonical_path": "../elsewhere.c"}, "out_of_tree"),
    ({"rule_id": "checkLibraryFunction"}, "diagnostic"),
    ({"evidence_context": "source-only/superseded"}, "superseded"),
    # a system header is out of tree before it is anything else
    ({"canonical_path": "/usr/include/x.h", "rule_id": "checkLibraryNoReturn"}, "out_of_tree"),
])
def test_view_class(changes: dict[str, str], expected: str) -> None:
    assert view_class({**row(3), **changes}) == expected
    assert {"checkLibraryFunction", "checkLibraryNoReturn", "missingIncludeSystem"} <= NOISE_RULES


def test_unit_of_reads_the_report_directory() -> None:
    assert unit_of({"source_artifact": "tools/splint/bl2__main.c-3cdf/report.csv"}) == "bl2__main.c-3cdf"
    assert unit_of({"source_artifact": "tools/cppcheck/fallback/report.xml"}) == "fallback"
    assert unit_of({"source_artifact": "llm/units/u-17/response.json", "tool": "llm-security"}) == "units/u-17"


def write_source(root: Path, body: str = SOURCE) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "a.c").write_text(body, encoding="utf-8")
    return root


def test_clusters_follow_function_family_and_gap(tmp_path: Path) -> None:
    root = write_source(tmp_path / "src", SOURCE + "\n" * 60 + "int far(char *p) {\n" + "  p[9]=0;\n" * 3 + "}\n")
    rows = [
        row(4, "bufferAccessOutOfBounds", cwe="CWE-788"), row(6, "arrayIndexOutOfBounds", cwe="CWE-788"),
        row(5, "strcpy", tool="flawfinder", level="warning", cwe="CWE-120"),
        row(9, "unusedFunction", level="style"),                          # helper(): its own function
        row(4, "checkLibraryFunction", level="information"),              # noise: never clustered
        row(4, "nestcomment", tool="splint", level="unmapped", context="source-only/superseded"),
    ]
    clusters = cluster(rows, root)
    by_function: dict[str, list[Any]] = {}
    for item in clusters:
        by_function.setdefault(item.function, []).append(item)
    assert set(by_function) == {"copy", "helper"}
    buffer = [c for c in by_function["copy"] if c.family == "buffer"]
    assert len(buffer) == 1 and len(buffer[0].members) == 3 and buffer[0].tools == {"cppcheck", "flawfinder"}
    assert rows[4].get("cluster_id") is None and rows[5].get("cluster_id") is None
    assert all(r["function"] for r in rows[:4]) and all(len(r["line_text_sha"]) == 16 for r in rows[:4])
    assert len({c.id for c in clusters}) == len(clusters)
    # the same rows cluster to the same ids
    assert [c.id for c in cluster([dict(r) for r in rows], root)] == [c.id for c in clusters]


def test_members_chain_only_within_three_lines(tmp_path: Path) -> None:
    body = "void long_fn(char *p) {\n" + "".join(f"  p[{i}] = 0;\n" for i in range(80)) + "}\n"
    root = write_source(tmp_path / "src", body)
    rows = [row(3), row(5), row(8), row(30), row(70)]
    clusters = cluster(rows, root)
    assert [(c.line_start, c.line_end, len(c.members)) for c in clusters] == [(3, 8, 3), (30, 30, 1), (70, 70, 1)]


def test_generic_and_keyword_families_never_merge_different_rules(tmp_path: Path) -> None:
    root = write_source(tmp_path / "src")
    quality = [row(4, "constParameter", level="style", cwe="CWE-398"), row(5, "variableScope", level="style", cwe="CWE-398")]
    assert len(cluster(quality, root)) == 2
    # no CWE: a family found by a keyword in the message is not evidence of one defect
    keyword = [row(4, "exportfcn", tool="splint", level="unmapped", message="Function exported: crypto_init"),
               row(4, "fcnuse", tool="splint", level="unmapped", message="Function crypto_init declared but not used")]
    assert len(cluster(keyword, root)) == 2
    # a CWE-anchored security family does merge across tools on one statement
    security = [row(4, "bufferAccessOutOfBounds", cwe="CWE-788"), row(4, "memcpy", tool="flawfinder", cwe="CWE-120")]
    assert len(cluster(security, root)) == 1


def test_outside_functions_rows_cluster_within_three_lines(tmp_path: Path) -> None:
    root = write_source(tmp_path / "src", "\n".join(f"int g{i} = {i};" for i in range(20)) + "\n")
    clusters = cluster([row(2), row(4), row(12), row(13)], root)
    assert [(c.line_start, c.line_end) for c in clusters] == [(2, 4), (12, 13)]


def test_unknown_family_keeps_rules_apart(tmp_path: Path) -> None:
    root = write_source(tmp_path / "src")
    clusters = cluster([row(4, "exportfcn", tool="splint", level="unmapped"),
                        row(4, "paramuse", tool="splint", level="unmapped")], root)
    assert sorted(c.rule_id for c in clusters) == ["exportfcn", "paramuse"]


def test_nothing_outside_the_tree_is_read(tmp_path: Path) -> None:
    root = write_source(tmp_path / "src")
    lines = SourceLines(root)
    cluster([row(1, path="/etc/passwd")], root, lines=lines)
    assert "/etc/passwd" not in lines._lines  # noqa: SLF001


def build(tmp_path: Path, rows: list[dict[str, Any]], name: str = "index.sqlite") -> Store:
    root = write_source(tmp_path / "src")
    parsed = ParsedRun("run", root, rows, [{"tool": "splint", "unit_id": "u", "canonical_path": "a.c",
                                            "line": "1", "category": "parsing", "message": "parse error"}])
    return Store.build(tmp_path / name, parsed, cluster(rows, root))


def test_store_lists_findings_by_default_and_everything_on_request(tmp_path: Path) -> None:
    store = build(tmp_path, [row(4), row(6, "uninitvar", level="warning"), row(4, "checkLibraryFunction", level="information"),
                             row(1, path="/usr/include/x.h")])
    assert store.counts() == {"findings": 4, "by_view_class": {"finding": 2, "diagnostic": 1, "out_of_tree": 1},
                              "diagnostics": 1, "clusters": 2}
    default = store.list_findings()
    assert default["total"] == 2 and [r["review_level"] for r in default["rows"]] == ["error", "warning"]
    assert default["by_level"] == {"error": 1, "warning": 1}
    assert store.list_findings({"view_class": "*"})["total"] == 4
    assert store.list_findings({"view_class": "diagnostic"})["rows"][0]["rule_id"] == "checkLibraryFunction"
    assert store.list_findings({"path": "a.*", "level": "warning"})["total"] == 1
    with pytest.raises(ValueError, match="unknown filter"):
        store.list_findings({"colour": "red"})
    clusters = store.list_clusters()
    assert clusters["total"] == 2 and clusters["rows"][0]["top_level"] == "error"
    members = store.cluster_members(clusters["rows"][0]["cluster_id"])
    assert [m["rule_id"] for m in members] == ["arrayIndexOutOfBounds"]


def test_store_pages_twenty_rows(tmp_path: Path) -> None:
    store = build(tmp_path, [row(i, message=f"m{i}") for i in range(1, 46)])
    pages = [store.list_findings(page=p) for p in (1, 2, 3)]
    assert [len(p["rows"]) for p in pages] == [20, 20, 5] and pages[0]["total"] == 45


def test_duplicate_keys_are_refused(tmp_path: Path) -> None:
    with pytest.raises(DuplicateKey):
        build(tmp_path, [row(4), row(4)])


def test_the_same_native_line_in_two_attempts_is_two_rows_with_one_fingerprint(tmp_path: Path) -> None:
    first = row(4, unit="u-1", context="source-only/superseded")
    second = {**row(4, unit="u-2"), "fingerprint": first["fingerprint"]}
    store = build(tmp_path, [first, second])
    assert store.list_findings({"view_class": "*"})["total"] == 2
    assert {r["view_class"] for r in store.list_findings({"view_class": "*"})["rows"]} == {"finding", "superseded"}


def test_rebuild_dump_is_byte_identical(tmp_path: Path) -> None:
    rows = [row(4), row(6, "uninitvar", level="warning"), row(5, "strcpy", tool="flawfinder", level="warning")]
    first = build(tmp_path, [dict(r) for r in rows], "one.sqlite").dump()
    second = build(tmp_path, [dict(r) for r in reversed(rows)], "two.sqlite").dump()
    assert first == second and first.count(b"\n") == 3 + 1 + 3 + 3  # rows + diagnostic + clusters + meta


# -- a real run, end to end -----------------------------------------------------------

def test_a_finished_run_imports_with_view_classes(tmp_path: Path) -> None:
    source = write_source(tmp_path / "project")
    tools = tmp_path / "fake tools"
    tools.mkdir()
    file_a = source / "a.c"
    cppcheck = executable(tools / "cppcheck", f"""
        import pathlib, sys
        if '--version' in sys.argv: print('Cppcheck 2.13.0'); raise SystemExit()
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        checkers = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--checkers-report=')))
        def err(i, sev, msg, f, line):
            return (f'<error id="{{i}}" severity="{{sev}}" msg="{{msg}}" verbose="{{msg}}" cwe="788">'
                    f'<location file="{{f}}" line="{{line}}" column="5"/></error>')
        report.write_text('<?xml version="1.0"?><results version="2"><cppcheck version="2.13.0"/><errors>'
            + err('arrayIndexOutOfBounds', 'error', 'Array tmp[4] accessed at index 4', {json.dumps(str(file_a))}, 6)
            + err('checkLibraryFunction', 'information', 'no configuration for memcpy', {json.dumps(str(file_a))}, 4)
            + err('nullPointer', 'warning', 'Possible null', '/usr/include/string.h', 40)
            + '</errors></results>')
        checkers.write_text('checked\\n')
    """)
    flawfinder = executable(tools / "flawfinder", """
        import json
        print(json.dumps({'version':'2.1.0','$schema':'x','runs':[{'tool':{'driver':{'name':'Flawfinder'}},'results':[]}]}))
    """)
    splint = executable(tools / "splint", """
        import pathlib, sys
        if '-help' in sys.argv: print('Splint 3.1.2'); raise SystemExit()
        report = pathlib.Path(sys.argv[sys.argv.index('+csv') + 1])
        report.write_text('Warning,Flag Code,Flag Name,Priority,File,Line,Column,Warning Text,Additional Text\\n')
        raise SystemExit(0)
    """)
    config = write_config(tmp_path / "config.toml", {"cppcheck": cppcheck, "flawfinder": flawfinder, "splint": splint},
                          export=False)
    completed = run_analyze(source, "--config", config, "--output-root", tmp_path / "reports", "--no-compile-db")
    assert completed.returncode in (0, 10), completed.stderr
    run_dir = Path(completed.stdout.strip())
    parsed = parse_run(run_dir)
    classes = {r["rule_id"]: r["view_class"] for r in parsed.findings}
    assert classes == {"arrayIndexOutOfBounds": "finding", "checkLibraryFunction": "diagnostic",
                       "nullPointer": "out_of_tree"}
    assert all(r["call_id"].endswith(":cppcheck") and r["unit_id"] == "fallback" for r in parsed.findings)
    store = Store.build(tmp_path / "index.sqlite", parsed, cluster(parsed.findings, parsed.source))
    page = store.list_findings()
    assert page["total"] == 1 and page["rows"][0]["path"] == "a.c"
    [entry] = store.list_clusters()["rows"]
    assert entry["function"] == "copy" and entry["family"] == "buffer" and entry["top_level"] == "error"

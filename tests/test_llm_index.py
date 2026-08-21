"""Golden tests for the repository index and the scan-unit planner.

Fixtures are written to ``tmp_path`` rather than checked in, matching the
repository's convention of shipping no .c files.  Every fixture is asserted
twice: once for the exact symbol extents, once for the completeness invariant
of design doc 4.5 — every byte lands in exactly one scan unit.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from code_analyzer.config import load_config
from code_analyzer.inventory import discover
from code_analyzer.llm.index import (
    LOW_CONFIDENCE,
    StdlibParser,
    build_index,
    decode_source,
    mask_source,
)
from code_analyzer.llm.risk import (
    RiskProfile,
    classify,
    parse_overrides,
    profile_from_config,
)
from code_analyzer.llm.units import (
    build_plan,
    coverage_gaps,
    coverage_report,
    plan_units,
    unit_source,
)
from code_analyzer.persist import json_bytes
from code_analyzer.tools import LLM_PRODUCERS

FIXTURES: dict[str, str] = {
    "string_brace.c": (
        'int with_brace(void)\n'
        '{\n'
        '    const char *s = "}";\n'
        '    return (int)s[0];\n'
        '}\n'
    ),
    "comment_brace.c": (
        '/* { this brace is not code */\n'
        '// } neither is this one\n'
        'int after_comments(void) { return 1; }\n'
    ),
    "string_comment.c": (
        'const char *not_a_comment(void)\n'
        '{\n'
        '    char *s = "/* not a comment */";\n'
        '    return s;\n'
        '}\n'
    ),
    "nested_struct.c": (
        'struct outer {\n'
        '    struct inner { int x; } in;\n'
        '    int y;\n'
        '};\n'
        '\n'
        'int use_outer(struct outer *o)\n'
        '{\n'
        '    return o->in.x + o->y;\n'
        '}\n'
    ),
    "if_zero.c": (
        '#if 0\n'
        'int disabled(void) { return 1;\n'
        '#endif\n'
        '\n'
        'int enabled(void) { return 2; }\n'
    ),
    "kr.c": (
        'int kr_add(a, b)\n'
        'int a;\n'
        'int b;\n'
        '{\n'
        '    return a + b;\n'
        '}\n'
    ),
    "macro_header.c": (
        '#define MODULE_INIT(name) void name##_init(void)\n'
        '\n'
        'MODULE_INIT(radio)\n'
        '{\n'
        '    return;\n'
        '}\n'
    ),
    "static_inline.c": (
        'static inline int imax(int a, int b)\n'
        '{\n'
        '    return a > b ? a : b;\n'
        '}\n'
    ),
    "init_list.cpp": (
        'class Widget {\n'
        'public:\n'
        '    Widget(int a);\n'
        '    int a_;\n'
        '};\n'
        '\n'
        'Widget::Widget(int a) : a_(a)\n'
        '{\n'
        '}\n'
    ),
    "unbalanced.c": (
        'int fine(void) { return 0; }\n'
        '\n'
        'int truncated(void)\n'
        '{\n'
        '    if (1) {\n'
    ),
    "blank.c": "\n\n   \n",
    "api.h": (
        '#ifndef API_H\n'
        '#define API_H\n'
        'void api_reset(void);\n'
        '#endif\n'
    ),
    "caller.c": (
        '#include "api.h"\n'
        '\n'
        'void api_reset(void)\n'
        '{\n'
        '}\n'
        '\n'
        'void boot_isr(void)\n'
        '{\n'
        '    api_reset();\n'
        '}\n'
    ),
}

# (name, start_byte, end_byte) as the stdlib parser must report them.
EXPECTED_FUNCTIONS: dict[str, list[tuple[str, int, int]]] = {
    "api.h": [],
    "blank.c": [],
    "caller.c": [("api_reset", 18, 42), ("boot_isr", 44, 84)],
    "comment_brace.c": [("after_comments", 56, 94)],
    "if_zero.c": [("enabled", 45, 76)],
    "init_list.cpp": [("Widget::Widget", 58, 91)],
    "kr.c": [("kr_add", 0, 52)],
    "macro_header.c": [("MODULE_INIT", 50, 84)],
    "nested_struct.c": [("use_outer", 62, 123)],
    "static_inline.c": [("imax", 0, 66)],
    "string_brace.c": [("with_brace", 0, 71)],
    "string_comment.c": [("not_a_comment", 0, 86)],
    "unbalanced.c": [("fine", 0, 28)],
}


@pytest.fixture(scope="module")
def tree(tmp_path_factory: pytest.TempPathFactory) -> Path:
    source = tmp_path_factory.mktemp("fixtures")
    for name, text in FIXTURES.items():
        (source / name).write_text(text, encoding="utf-8")
    return source


@pytest.fixture(scope="module")
def plan(tree: Path) -> dict[str, Any]:
    config = load_config(tree, None)
    return build_plan(tree, discover(tree, config, tree / "out"), config=config)


def _units(plan: dict[str, Any], path: str) -> list[dict[str, Any]]:
    return [unit for unit in plan["units"] if unit["path"] == path]


def test_masking_preserves_every_byte_offset() -> None:
    text = decode_source(
        b'char *s = "}";  /* { */ // }\n'
        b"char c = '\\'';\nint x;\n"
    )
    masked = mask_source(text)
    assert len(masked) == len(text)
    assert masked.count("\n") == text.count("\n")
    assert "}" not in masked and "{" not in masked
    assert masked.index("char *s") == text.index("char *s")
    assert masked.index("int x;") == text.index("int x;")
    # Delimiters survive; only the contents are blanked.
    assert '" "' in masked and "'  '" in masked


def test_string_containing_a_comment_opener_is_not_a_comment() -> None:
    text = decode_source(FIXTURES["string_comment.c"].encode())
    masked = mask_source(text)
    assert "not a comment" not in masked
    assert masked.index("return s;") == text.index("return s;")


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_function_extents_are_exact(name: str) -> None:
    text = decode_source(FIXTURES[name].encode())
    symbols = StdlibParser().parse(text)
    found = [(item["name"], item["start_byte"], item["end_byte"]) for item in symbols.functions]
    assert found == EXPECTED_FUNCTIONS[name]
    for _, start, end in found:
        body = FIXTURES[name][start:end]
        assert body.endswith("}")
        assert body.count("{") >= 1


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_every_byte_lands_in_exactly_one_unit(plan: dict[str, Any], name: str) -> None:
    raw = FIXTURES[name]
    spans = sorted((unit["start_byte"], unit["end_byte"]) for unit in _units(plan, name))
    assert spans, f"{name} produced no scan unit"
    assert spans[0][0] == 0
    assert spans[-1][1] == len(raw)
    assert all(left[1] == right[0] for left, right in zip(spans, spans[1:], strict=False))
    assert "".join(raw[start:end] for start, end in spans) == raw


def test_coverage_gaps_is_empty_for_the_whole_tree(plan: dict[str, Any]) -> None:
    assert coverage_gaps(plan) == {}
    assert {unit["kind"] for unit in plan["units"]} <= {"function", "module-scope", "raw-span"}


def test_unit_identity_is_stable_and_content_addressed(tree: Path, plan: dict[str, Any]) -> None:
    identifiers = [unit["unit_id"] for unit in plan["units"]]
    assert len(identifiers) == len(set(identifiers))
    for unit in plan["units"]:
        body = FIXTURES[unit["path"]][unit["start_byte"]:unit["end_byte"]]
        assert unit["unit_sha256"] == hashlib.sha256(body.encode("utf-8")).hexdigest()
        assert unit["byte_length"] == unit["end_byte"] - unit["start_byte"]
        assert unit_source(tree, unit) == body
    # The identity must not move when bytes above the unit shift.
    config = load_config(tree, None)
    again = plan_units(build_index(tree, discover(tree, config, tree / "out")), tree)
    assert [unit["unit_id"] for unit in again] == identifiers


def test_module_scope_claims_the_inactive_preprocessor_branch(plan: dict[str, Any]) -> None:
    units = _units(plan, "if_zero.c")
    dead = FIXTURES["if_zero.c"].index("int disabled")
    owner = next(unit for unit in units if unit["start_byte"] <= dead < unit["end_byte"])
    assert owner["kind"] == "module-scope"
    assert owner["dead"] is True
    assert [unit["name"] for unit in units if unit["kind"] == "function"] == ["enabled"]


def test_unparsable_tail_becomes_a_raw_span(plan: dict[str, Any]) -> None:
    units = _units(plan, "unbalanced.c")
    assert [unit["kind"] for unit in units] == ["function", "raw-span"]
    assert units[0]["name"] == "fine"
    assert units[1]["start_byte"] == FIXTURES["unbalanced.c"].index("int truncated")
    assert plan["files"]["unbalanced.c"]["parse_confidence"] < LOW_CONFIDENCE
    assert "unbalanced braces" in plan["files"]["unbalanced.c"]["parse_problems"]


def test_approximate_headers_lower_parse_confidence(plan: dict[str, Any]) -> None:
    assert plan["files"]["kr.c"]["functions"][0]["kr_style"] is True
    assert plan["files"]["macro_header.c"]["functions"][0]["macro_header"] is True
    for name in ("kr.c", "macro_header.c"):
        assert plan["files"][name]["parse_confidence"] < 1.0
    assert plan["files"]["static_inline.c"]["parse_confidence"] == 1.0


def test_index_records_preprocessor_and_declarations(plan: dict[str, Any]) -> None:
    header = plan["files"]["api.h"]
    assert [item["name"] for item in header["macros"]] == ["API_H"]
    assert [item["kind"] for item in header["conditionals"]] == ["ifndef"]
    assert [item["target"] for item in plan["files"]["caller.c"]["includes"]] == ["api.h"]
    assert ("outer", "struct") in {
        (item["name"], item["kind"]) for item in plan["files"]["nested_struct.c"]["types"]
    }
    assert plan["types"]["outer"]["path"] == "nested_struct.c"


def test_call_graph_resolves_and_inverts(plan: dict[str, Any]) -> None:
    assert plan["call_graph"]["callees"]["caller.c::boot_isr"] == ["api_reset"]
    assert plan["call_graph"]["callers"]["api_reset"] == ["caller.c::boot_isr"]
    unit = next(unit for unit in _units(plan, "caller.c") if unit["name"] == "boot_isr")
    assert unit["callees"] == ["api_reset"]
    assert unit["callers"] == []
    called = next(unit for unit in _units(plan, "caller.c") if unit["name"] == "api_reset")
    assert called["callers"] == ["boot_isr"]


def test_plan_is_byte_stable(tree: Path) -> None:
    config = load_config(tree, None)
    inventory = discover(tree, config, tree / "out")
    first = build_plan(tree, inventory, config=config)
    second = build_plan(tree, inventory, config=config)
    assert json_bytes(first) == json_bytes(second)


def test_coverage_report_matches_the_llm_coverage_shape(plan: dict[str, Any]) -> None:
    units = plan["units"]
    results = [
        {"unit_id": unit["unit_id"], "producer": LLM_PRODUCERS[0], "status": "completed"}
        for unit in units if unit["path"] == "static_inline.c"
    ]
    results.append({"unit_id": units[0]["unit_id"], "producer": LLM_PRODUCERS[1], "status": "unscheduled"})
    coverage = coverage_report(plan, results, scanners=LLM_PRODUCERS)
    assert set(coverage) == {
        "files", "functions", "bytes", "by_scanner", "risk_tiers", "unscanned_reasons",
    }
    assert coverage["files"] == {"scanned": 1, "total": len(FIXTURES), "ratio": round(1 / len(FIXTURES), 4)}
    assert coverage["functions"]["total"] == sum(len(item) for item in EXPECTED_FUNCTIONS.values())
    assert coverage["functions"]["scanned"] == 1
    assert coverage["bytes"]["total"] == sum(len(text) for text in FIXTURES.values())
    assert coverage["by_scanner"][LLM_PRODUCERS[0]] == {
        "units": 1, "functions": 1, "bytes": len(FIXTURES["static_inline.c"]), "files": 1,
    }
    assert coverage["by_scanner"][LLM_PRODUCERS[2]] == {"units": 0, "functions": 0, "bytes": 0, "files": 0}
    assert list(coverage["risk_tiers"]) == ["critical", "high", "medium", "low"]
    assert sum(item["planned"] for item in coverage["risk_tiers"].values()) == len(units)
    assert coverage["unscanned_reasons"]["unscheduled"] == 1
    assert coverage["unscanned_reasons"]["no_result"] == len(units) - 2
    assert coverage["unscanned_reasons"]["parse_confidence_low"] == len(_units(plan, "unbalanced.c"))


def test_risk_tiering_follows_the_signal_table() -> None:
    critical = {"path": "src/bootloader/boot.c", "name": "main", "kind": "function"}
    assert classify(critical)[0] == "critical"
    assert classify({"path": "src/net/parser.c", "name": "read", "kind": "function"})[0] == "high"
    assert classify({"path": "src/app.c", "name": "compute", "kind": "function"})[0] == "medium"
    assert classify({"path": "src/app.c", "name": "led_on", "kind": "function"})[0] == "low"
    assert classify({"path": "src/app.c", "name": "", "kind": "module-scope"})[0] == "low"
    # Substring matching would call this LED code; fragments do not.
    assert classify({"path": "src/app.c", "name": "enabled", "kind": "function"})[0] == "medium"
    opaque = {
        "path": "src/app.c", "name": "copy_in", "kind": "function",
        "signature": "int copy_in(void *dst, unsigned len)",
    }
    assert classify(opaque)[0] == "critical"
    profile = RiskProfile(overrides=parse_overrides(["src/app.c=critical"]))
    tier, reasons = classify({"path": "src/app.c", "name": "led_on", "kind": "function"}, profile=profile)
    assert tier == "critical"
    assert "override:src/app.c=critical" in reasons
    floor = RiskProfile(min_tier="high")
    assert classify({"path": "src/app.c", "name": "led_on", "kind": "function"}, profile=floor)[0] == "high"


def test_risk_profile_reads_configuration() -> None:
    assert profile_from_config(None) == RiskProfile()
    assert profile_from_config({}) == RiskProfile()
    resolved = profile_from_config(
        {"llm": {"risk_profile": "auto", "min_tier": "medium", "risk_overrides": ["a/*.c=low"]}}
    )
    assert resolved == RiskProfile(profile="auto", min_tier="medium", overrides=(("a/*.c", "low"),))

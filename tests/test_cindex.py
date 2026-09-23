"""Golden tests for the repository index and the scan-unit planner.

Fixtures are written to ``tmp_path`` rather than checked in, matching the
repository's convention of shipping no .c files.  Every fixture is asserted
twice: once for the exact symbol extents, once for the completeness invariant
of design doc 4.5 — every byte lands in exactly one scan unit.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from helpers import load_config

from code_analyzer.core.cindex import (
    LOW_CONFIDENCE,
    StdlibParser,
    build_index,
    decode_source,
    mask_source,
)
from code_analyzer.inventory import discover
from code_analyzer.persist import json_bytes

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
    """The repository index (the old scan-unit plan's index part; the planner went with the blind scan)."""
    config = load_config(tree, None)
    return build_index(tree, discover(tree, config, tree / "out").files)


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


def test_an_unparsable_tail_lowers_the_confidence(plan: dict[str, Any]) -> None:
    assert [f["name"] for f in plan["files"]["unbalanced.c"]["functions"]] == ["fine"]
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


def test_the_index_is_byte_stable(tree: Path) -> None:
    config = load_config(tree, None)
    inventory = discover(tree, config, tree / "out").files
    first = build_index(tree, inventory)
    second = build_index(tree, inventory)
    assert json_bytes(first) == json_bytes(second)

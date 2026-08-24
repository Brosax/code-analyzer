"""The include graph and the header pairing it makes possible.

A unit's *contract* is not in its body.  The bound a caller must respect lives
in the prototype, and a function the header never declares has no callers
outside its own file at all.  Neither fact is reachable from the implementation
alone, so both have to be index-level facts and both have to reach the prompt.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from code_analyzer.config import DEFAULTS, validate_config
from code_analyzer.inventory import discover
from code_analyzer.llm.context import build_unit_prompt, render_blocks
from code_analyzer.llm.index import build_index
from code_analyzer.llm.units import build_plan, unit_source


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _index(root: Path) -> dict[str, Any]:
    config = validate_config(json.loads(json.dumps(DEFAULTS)))
    return build_index(root, discover(root, config, root.parent / "out"))


def _plan(root: Path) -> dict[str, Any]:
    config = validate_config(json.loads(json.dumps(DEFAULTS)))
    return build_plan(root, discover(root, config, root.parent / "out"), config=config)


def _prompt(root: Path, plan: dict[str, Any], name: str, tier: str = "high") -> str:
    [unit] = [item for item in plan["units"] if item.get("name") == name]
    payload = {**unit, "source": unit_source(root, unit)}
    return render_blocks(build_unit_prompt(payload, plan, tier=tier))


def test_includes_resolve_inside_the_tree_and_system_headers_stay_unresolved(tmp_path: Path) -> None:
    root = _tree(tmp_path / "src-tree", {
        "src/parser.c": '#include "parser.h"\n#include <string.h>\n#include "../include/common.h"\nint parse(void) { return 0; }\n',
        "src/parser.h": "int parse(void);\n",
        "include/common.h": "#define COMMON 1\n",
    })

    graph = _index(root)["include_graph"]

    # Relative ("..") and same-directory targets both resolve; a target naming
    # no file in the tree is recorded as external rather than guessed at.
    assert graph["edges"] == {"src/parser.c": ["include/common.h", "src/parser.h"]}
    assert graph["unresolved"] == {"src/parser.c": ["string.h"]}
    assert graph["included_by"] == {
        "include/common.h": ["src/parser.c"], "src/parser.h": ["src/parser.c"],
    }


def test_an_ambiguous_tail_match_is_not_an_edge(tmp_path: Path) -> None:
    """Two files ending "config.h" must not silently become one edge."""
    root = _tree(tmp_path / "ambiguous", {
        "a/config.h": "#define A 1\n",
        "b/config.h": "#define B 1\n",
        "src/main.c": '#include "config.h"\nint main(void) { return 0; }\n',
    })

    graph = _index(root)["include_graph"]

    assert graph["edges"] == {}
    assert graph["unresolved"] == {"src/main.c": ["config.h"]}


def test_the_pairing_prefers_the_included_header_and_falls_back_to_the_name(tmp_path: Path) -> None:
    root = _tree(tmp_path / "pairs", {
        # Includes its own header: the edge is the evidence.
        "src/parser.c": '#include "parser.h"\nint parse(void) { return 0; }\n',
        "src/parser.h": "int parse(void);\n",
        # Includes no header from the tree: the name match is enough on its own.
        "src/lonely.c": "int lonely(void) { return 1; }\n",
        "src/lonely.h": "int lonely(void);\n",
        # Includes somebody else's header and has none of its own: no pair, and
        # no pretending the neighbour's header states this file's contract.
        "src/user.c": '#include "parser.h"\nint use(void) { return parse(); }\n',
    })

    pairs = _index(root)["include_graph"]["pairs"]

    assert pairs == {"src/lonely.c": "src/lonely.h", "src/parser.c": "src/parser.h"}


def test_the_prompt_carries_the_contract_the_body_does_not_show(tmp_path: Path) -> None:
    root = _tree(tmp_path / "contract", {
        "src/parser.c": (
            '#include "parser.h"\n#include <string.h>\n'
            "int parse_packet(const unsigned char *raw, unsigned short raw_len) { (void)raw; return raw_len; }\n"
            "static int helper(void) { return 0; }\n"
        ),
        "src/parser.h": "#ifndef P_H\n#define P_H\nint parse_packet(const unsigned char *raw, unsigned short raw_len);\n#endif\n",
    })
    plan = _plan(root)

    exported = _prompt(root, plan, "parse_packet")
    internal = _prompt(root, plan, "helper")

    # The prototype states the caller-visible parameter types, which is where
    # an off-by-one bound is usually decided.
    assert "declared in src/parser.h:3 as `int parse_packet(const unsigned char *raw, unsigned short raw_len);`" in exported
    assert "includes from this tree: src/parser.h" in exported
    assert "includes from outside this tree: string.h" in exported
    # A symbol the header does not declare cannot be reached from outside the
    # file, which bounds every reachability claim about it.
    assert "not declared in src/parser.h" in internal
    assert "nothing outside this file" in internal
    # It is a declaration, never a body: the no-callee-bodies rule still holds.
    assert "return raw_len" not in exported.split("## Unit source")[0]


def test_the_interface_survives_the_smallest_context_budget(tmp_path: Path) -> None:
    """Two lines that change what a finding means outrank a callee signature."""
    root = _tree(tmp_path / "budget", {
        "src/a.c": '#include "a.h"\nint exported(void) { return 0; }\n',
        "src/a.h": "int exported(void);\n",
    })
    plan = _plan(root)

    for tier in ("low", "medium", "high", "critical"):
        assert "declared in src/a.h:1" in _prompt(root, plan, "exported", tier=tier), tier


def test_an_index_without_an_include_graph_still_renders(tmp_path: Path) -> None:
    """Older run directories are replayed by resume and recover-report."""
    root = _tree(tmp_path / "old", {"src/a.c": "int a(void) { return 0; }\n"})
    plan = _plan(root)
    plan.pop("include_graph")

    [unit] = [item for item in plan["units"] if item.get("name") == "a"]
    text = render_blocks(build_unit_prompt({**unit, "source": unit_source(root, unit)}, plan, tier="high"))

    assert "### Interface" not in text and "int a(void)" in text

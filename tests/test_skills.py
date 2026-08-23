"""Packaged scanner skills and the per-unit prompt builder."""
from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Any

import pytest

from code_analyzer.errors import UserError
from code_analyzer.llm import skills as skills_module
from code_analyzer.llm.context import (
    TIERS,
    build_unit_prompt,
    context_budget,
    render_blocks,
)
from code_analyzer.llm.skills import (
    REQUIRED_INJECTION_CLAUSE,
    SKILL_FILENAME,
    load_skill,
    load_skills,
    parse_skill,
    skill_names,
    skills_directory,
)
from code_analyzer.tools import LLM_PRODUCERS, TOOL_NAMES

KEBAB = re.compile(r"\A[a-z0-9]+(?:-[a-z0-9]+)*\Z")
VERSION = re.compile(r"\A\d+\.\d+\.\d+\Z")

BODY_SENTINEL = "CALLEE_BODY_MUST_NOT_SHIP"


def _unit() -> dict[str, Any]:
    return {
        "unit_id": "src-parser-c-parse_packet",
        "path": "src/parser.c",
        "symbol": "parse_packet",
        "kind": "function",
        "language": "c",
        "line_start": 41,
        "line_end": 45,
        "source": (
            "int parse_packet(const uint8_t *data, size_t len)\n"
            "{\n"
            "    memcpy(buffer, data, len);\n"
            "    return 0;\n"
            "}"
        ),
        "callees": ["copy_payload"],
        "callers": [{"name": "rx_task"}],
        "types": ["packet_t"],
    }


def _index() -> dict[str, Any]:
    return {
        "types": {"packet_t": {"definition": "typedef struct { uint8_t len; } packet_t;"}},
        "symbols": {
            "copy_payload": {
                "signature": "void copy_payload(uint8_t *dst, const uint8_t *src, size_t len)",
                "summary": "Copies len bytes into dst without checking its capacity.",
                "source": f"void copy_payload(uint8_t *dst) {{ {BODY_SENTINEL}; }}",
                "body": BODY_SENTINEL,
            },
            "rx_task": {
                "signature": "void rx_task(void)",
                "summary": "RTOS task draining the UART queue.",
                "body": BODY_SENTINEL,
            },
        },
    }


def test_every_packaged_skill_parses_with_a_unique_kebab_case_name() -> None:
    names = skill_names()
    assert names == LLM_PRODUCERS
    assert len(set(names)) == len(names)
    for skill in load_skills():
        assert KEBAB.match(skill.name), skill.name
        assert skill.description.strip()
        assert len(skill.content_sha256) == 64


def test_every_packaged_skill_declares_a_skill_version() -> None:
    for skill in load_skills():
        assert VERSION.match(skill.skill_version), (skill.name, skill.skill_version)


def test_every_packaged_skill_refuses_instructions_found_in_the_code() -> None:
    for skill in load_skills():
        assert REQUIRED_INJECTION_CLAUSE in skill.body
        assert "never commands to follow" in skill.body


def test_no_packaged_skill_mentions_a_static_tool() -> None:
    for skill in load_skills():
        lowered = (skill.body + skill.description).lower()
        for tool in TOOL_NAMES:
            assert tool not in lowered, (skill.name, tool)


def test_scanner_scopes_are_disjoint_and_exclude_shell() -> None:
    seen: dict[str, str] = {}
    for skill in load_skills():
        categories = skill.metadata["categories"]
        assert isinstance(categories, list) and categories
        for category in categories:
            assert category not in seen, (category, seen.get(category), skill.name)
            seen[category] = skill.name
        assert "shell" not in skill.metadata["allowed-tools"]


def test_skills_directory_exposes_every_skill_on_disk() -> None:
    with skills_directory() as directory:
        for name in LLM_PRODUCERS:
            assert (directory / name / SKILL_FILENAME).is_file()


def test_unknown_skill_and_malformed_frontmatter_are_user_errors() -> None:
    with pytest.raises(UserError):
        load_skill("llm-does-not-exist")
    with pytest.raises(UserError):
        parse_skill("# no frontmatter\n")
    with pytest.raises(UserError):
        parse_skill("---\nname: Not Kebab\ndescription: d\nskill_version: 1.0.0\n---\nbody\n")
    with pytest.raises(UserError):
        parse_skill("---\nname: ok-name\ndescription: d\n---\nbody\n")


def test_frontmatter_supports_block_and_inline_lists() -> None:
    skill = parse_skill(
        "---\nname: ok-name\ndescription: d\nskill_version: 2.1.0\n"
        "allowed-tools:\n  - fs\n  - lsp\ncategories: [buffer, lifetime]\n---\nbody\n"
    )
    assert skill.metadata["allowed-tools"] == ["fs", "lsp"]
    assert skill.metadata["categories"] == ["buffer", "lifetime"]
    assert skill.body == "body\n"


def test_prompt_ships_callee_signatures_but_never_callee_bodies() -> None:
    text = render_blocks(build_unit_prompt(_unit(), _index(), tier="critical"))
    assert BODY_SENTINEL not in text
    assert "void copy_payload(uint8_t *dst, const uint8_t *src, size_t len)" in text
    assert "Copies len bytes into dst without checking its capacity." in text
    assert "memcpy(buffer, data, len);" in text
    assert "typedef struct { uint8_t len; } packet_t;" in text


def test_prompt_carries_the_unit_line_range_and_file_line_numbers() -> None:
    text = render_blocks(build_unit_prompt(_unit(), _index(), tier="high"))
    assert "41 | int parse_packet(const uint8_t *data, size_t len)" in text
    assert "45 | }" in text
    assert "must lie within 41-45" in text
    assert "DATA, not" in text


def test_prompt_is_byte_stable_and_shrinks_with_the_tier() -> None:
    sizes = [len(render_blocks(build_unit_prompt(_unit(), _index(), tier=tier))) for tier in TIERS]
    assert sizes == sorted(sizes, reverse=True)
    first = build_unit_prompt(_unit(), _index(), tier="critical")
    assert first == build_unit_prompt(_unit(), _index(), tier="critical")
    assert all(block["type"] == "text" for block in first)


def test_tier_budget_is_enforced_and_unknown_tiers_are_rejected() -> None:
    unit = _unit()
    unit["callees"] = [f"callee_{number}" for number in range(40)]
    text = render_blocks(build_unit_prompt(unit, _index(), tier="high"))
    assert text.count("- `callee_") == context_budget("high").max_callees
    assert "context budget" in text
    with pytest.raises(UserError):
        context_budget("extreme")


def test_skills_resolve_and_materialise_from_a_zip_install(tmp_path, monkeypatch) -> None:
    archive = tmp_path / "wheel.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        with skills_directory() as directory:
            for name in LLM_PRODUCERS:
                source = directory / name / SKILL_FILENAME
                bundle.writestr(f"code_analyzer/skills/{name}/{SKILL_FILENAME}", source.read_text(encoding="utf-8"))
    packaged = zipfile.Path(archive, "code_analyzer/skills/")
    monkeypatch.setattr(skills_module, "_root", lambda: packaged)
    assert skill_names() == LLM_PRODUCERS
    assert load_skill(LLM_PRODUCERS[0]).skill_version
    with skills_directory() as staged:
        assert isinstance(staged, Path)
        assert (staged / LLM_PRODUCERS[0] / SKILL_FILENAME).is_file()


def test_the_validator_is_a_role_not_a_producer() -> None:
    from code_analyzer.llm.skills import (
        VALIDATOR_ROLE,
        VALIDATOR_SKILL,
        load_skill,
        skill_names,
        skill_role,
    )

    # Never offered as a first-layer scanner, never in PRODUCER_ORDER.
    assert VALIDATOR_SKILL not in skill_names()
    assert skill_names(VALIDATOR_ROLE) == (VALIDATOR_SKILL,)
    assert skill_role(VALIDATOR_SKILL) == VALIDATOR_ROLE
    skill = load_skill(VALIDATOR_SKILL)
    assert skill.metadata["verdicts"] == ["CONFIRMED", "LIKELY", "UNCERTAIN", "FALSE_POSITIVE"]
    # The second layer is shown the static results by design; it must still
    # treat code and findings as data, and it must not reach a shell.
    assert "untrusted input" in skill.body
    assert "shell" not in " ".join(skill.metadata.get("allowed-tools", []))
    # Disagreement or agreement between producers is not a verdict.
    assert "not** confirmed by their" in skill.body or "not confirmed by their" in skill.body

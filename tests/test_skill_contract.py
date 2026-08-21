"""The contract between what a skill tells the model to emit and what the
parser accepts.

Every other test builds its fixtures in the parser's shape, so the skills were
free to document a different shape entirely.  These tests read the documented
shape out of each SKILL.md and put it through the real parser.
"""
from __future__ import annotations

import json
import re
from typing import Any

import pytest

from code_analyzer.harness import schema
from code_analyzer.llm.skills import Skill, load_skills

_JSON_FENCE = re.compile(r"```json[ \t]*\r?\n(.*?)```", re.S)
_TABLE_CATEGORY = re.compile(r"^\|[ \t]*`([a-z0-9-]+)`[ \t]*\|", re.M)

SKILLS = load_skills()


def _example(skill: Skill) -> dict[str, Any]:
    """The output example the skill shows the model, as JSON."""
    blocks = _JSON_FENCE.findall(skill.body)
    assert len(blocks) == 1, (skill.name, len(blocks))
    return json.loads(blocks[0])


def _findings(skill: Skill) -> list[dict[str, Any]]:
    documented = _example(skill)["findings"]
    assert documented, skill.name
    return documented


def _scope_table(skill: Skill) -> set[str]:
    return set(_TABLE_CATEGORY.findall(skill.body.split("## Out of scope")[0]))


@pytest.mark.parametrize("skill", SKILLS, ids=lambda skill: skill.name)
def test_the_documented_example_is_accepted_verbatim(skill: Skill) -> None:
    documented = _findings(skill)
    findings, errors = schema.parse_findings(json.dumps(_example(skill)))
    assert errors == []
    assert len(findings) == len(documented)
    for parsed, item in zip(findings, documented, strict=True):
        assert parsed["file"] == item["file"]
        assert parsed["category"] == item["category"]
        assert parsed["severity"] == item["severity"]
        assert parsed["message"] == item["message"]
        assert parsed["line_range"] == list(item["line_range"])
        assert parsed["cwe"] == item["cwe"]


@pytest.mark.parametrize("skill", SKILLS, ids=lambda skill: skill.name)
def test_the_documented_example_emits_only_declared_keys(skill: Skill) -> None:
    """A key the model is told to emit must be one the schema declares."""
    assert set(_example(skill)) <= set(schema.SCANNER_OUTPUT_SCHEMA["properties"])
    declared = set(schema.FINDING_SCHEMA["properties"])
    for item in _findings(skill):
        assert set(item) <= declared, (skill.name, sorted(set(item) - declared))
        assert set(schema.FINDING_SCHEMA["required"]) <= set(item)


@pytest.mark.parametrize("skill", SKILLS, ids=lambda skill: skill.name)
def test_every_advertised_category_is_accepted(skill: Skill) -> None:
    template = _findings(skill)[0]
    for category in skill.metadata["categories"]:
        findings, errors = schema.parse_findings(
            json.dumps({"findings": [{**template, "category": category}]})
        )
        assert errors == [], (skill.name, category)
        assert findings[0]["category"] == category


@pytest.mark.parametrize("skill", SKILLS, ids=lambda skill: skill.name)
def test_the_scope_table_advertises_the_frontmatter_categories(skill: Skill) -> None:
    assert _scope_table(skill) == set(skill.metadata["categories"])


@pytest.mark.parametrize("skill", SKILLS, ids=lambda skill: skill.name)
def test_a_finding_the_model_cannot_attribute_to_a_cwe_survives(skill: Skill) -> None:
    template = _findings(skill)[0]
    for value in ({}, {"cwe": ""}, {"cwe": "   "}, {"cwe": None}):
        item = {key: entry for key, entry in template.items() if key != "cwe"} | value
        findings, errors = schema.parse_findings(json.dumps({"findings": [item]}))
        assert errors == [], (skill.name, value)
        assert "cwe" not in findings[0]


def test_the_line_shape_the_unit_prompt_names_is_tolerated() -> None:
    """The prompt's closing block still asks for line_start/line_end."""
    template = _findings(SKILLS[0])[0]
    item = {key: value for key, value in template.items() if key != "line_range"}
    findings, errors = schema.parse_findings(
        json.dumps({"findings": [{**item, "line_start": 118, "line_end": 121}]})
    )
    assert errors == []
    assert findings[0]["line_range"] == [118, 121]


@pytest.mark.parametrize("spelling,canonical", sorted(schema.CATEGORY_SPELLINGS.items()))
def test_a_spelling_variant_is_normalised_not_discarded(spelling: str, canonical: str) -> None:
    template = _findings(SKILLS[0])[0]
    findings, errors = schema.parse_findings(
        json.dumps({"findings": [{**template, "category": spelling}]})
    )
    assert errors == []
    assert findings[0]["category"] == canonical
    assert canonical in schema.FINDING_CATEGORIES
    assert spelling not in schema.FINDING_CATEGORIES, "one concept, one token in the vocabulary"

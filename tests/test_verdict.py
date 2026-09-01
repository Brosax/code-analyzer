"""The validator's output contract."""
from __future__ import annotations

import json
import re

from code_analyzer.harness.verdict import VERDICTS, parse_verdict
from code_analyzer.llm.skills import VALIDATOR_SKILL, load_skill

GOOD = {
    "candidate_id": "MEM-001", "verdict": "CONFIRMED", "confidence": 0.85,
    "decisive_line": {"file": "src/parser.c", "line": 9},
    "rationale": "raw_len is unchecked before the memcpy on line 9; tmp is 32 bytes.",
    "remediation": "Check raw_len against sizeof tmp first.",
}


def test_a_quoted_decisive_line_is_the_same_line() -> None:
    """The spelling the parser forgives, and the ones it does not.

    Two models on 2026-09-01 filed correct verdicts with "line": "7" and lost
    them; a float or prose is still a different value, not a spelling.
    """
    verdict, reason = parse_verdict(
        json.dumps({**GOOD, "decisive_line": {"file": "a.c", "line": " 15 "}}),
        candidate_id="MEM-001",
    )

    assert reason is None
    assert verdict["decisive_line"] == {"file": "a.c", "line": 15}

    for bad in (9.0, "nine", "9.0", True, ""):
        _rejected, why = parse_verdict(
            json.dumps({**GOOD, "decisive_line": {"file": "a.c", "line": bad}}),
            candidate_id="MEM-001",
        )
        assert why == "decisive_line must name a file and a 1-based line", bad


def test_the_skills_own_example_round_trips() -> None:
    body = load_skill(VALIDATOR_SKILL).body
    example = re.search(r"```json\s*(\{.*?\})\s*```", body, re.S).group(1)
    verdict, reason = parse_verdict(example, candidate_id=json.loads(example)["candidate_id"])
    assert reason is None and verdict["verdict"] == "CONFIRMED"
    assert set(verdict) == {"candidate_id", "verdict", "confidence", "decisive_line", "rationale", "remediation"}


def test_lenient_parse_strict_validate() -> None:
    fenced = "Here is my verdict:\n```json\n" + json.dumps({**GOOD, "remediation": "x,"}) + "\n```\nThanks."
    verdict, reason = parse_verdict(fenced, candidate_id="MEM-001")
    assert reason is None and verdict["confidence"] == 0.85
    trailing = '{"candidate_id":"MEM-001","verdict":"likely","confidence":0.5,"decisive_line":{"file":"a.c","line":3},"rationale":"r",}'
    verdict, reason = parse_verdict(trailing, candidate_id="MEM-001")
    assert reason is None and verdict["verdict"] == "LIKELY"

    for broken, expect in (
        ({**GOOD, "verdict": "MAYBE"}, "verdict must be one of"),
        ({**GOOD, "confidence": 1.7}, "confidence"),
        ({**GOOD, "decisive_line": {"file": "a.c", "line": 0}}, "1-based"),
        ({**GOOD, "decisive_line": "line 9"}, "decisive_line"),
        ({**GOOD, "rationale": ""}, "rationale"),
        ({**GOOD, "candidate_id": "SEC-009"}, "names candidate"),
    ):
        verdict, reason = parse_verdict(json.dumps(broken), candidate_id="MEM-001")
        assert verdict is None and expect in reason, (broken, reason)
    assert parse_verdict("", candidate_id="MEM-001")[1].startswith("response: ")
    assert parse_verdict("no json here", candidate_id="MEM-001")[1].startswith("response: ")


def test_a_false_positive_carries_no_remediation_and_extra_keys_are_dropped() -> None:
    text = json.dumps({**GOOD, "verdict": "FALSE_POSITIVE", "remediation": "n/a", "model": "x", "producer": "y"})
    verdict, reason = parse_verdict(text, candidate_id="MEM-001")
    assert reason is None
    assert "remediation" not in verdict and "model" not in verdict and "producer" not in verdict
    assert verdict["verdict"] == "FALSE_POSITIVE" and verdict["verdict"] in VERDICTS


def test_a_missing_candidate_id_is_filled_from_the_request() -> None:
    text = json.dumps({k: v for k, v in GOOD.items() if k != "candidate_id"})
    verdict, reason = parse_verdict(text, candidate_id="MEM-001")
    assert reason is None and verdict["candidate_id"] == "MEM-001"

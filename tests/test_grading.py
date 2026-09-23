"""The reference review level: the RT700 AVA test plan's grading of a native severity (exact match only)."""
from __future__ import annotations

from code_analyzer.evidence.grading import UNMAPPED_REVIEW_LEVEL, reference_review_level


def test_reference_review_level_is_an_exact_match_mapping() -> None:
    assert reference_review_level("Error") == "error"
    assert reference_review_level(" style ") == "style"
    assert reference_review_level("warning") == "warning"
    assert reference_review_level("information") == "information"
    for unmapped in ("4", "performance", "", None, "critical"):
        assert reference_review_level(unmapped) == UNMAPPED_REVIEW_LEVEL

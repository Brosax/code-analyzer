"""M7: an AI claim counts only when it is anchored in the code it was shown."""
from __future__ import annotations

from code_analyzer.evidence.grounding import Shown, ground

SHOWN = Shown("bl2/ext/mcuboot/bootutil/src/image_validate.c", {
    205: "static int bootutil_cmp_hash(const uint8_t *hash, const uint8_t *expected)",
    206: "{",
    207: "    int i; uint8_t acc = 0;",
    209: "    for (i = 0; i <= HASH_LEN; i++) {   /* HASH_LEN == 32, hash[32] */",
    210: "        acc |= hash[i] ^ expected[i];",
    211: "    }",
}, function="bootutil_cmp_hash", function_span=(205, 214))
PROFILE = {"sfr_ids": {"SFR.SIP"}, "levels": {"error", "warning"}, "categories": {"memory-safety"}}


def claim(**changes: object) -> dict[str, object]:
    base = {"file": SHOWN.path, "line": 209, "decisive_line": 209, "symbol": "bootutil_cmp_hash",
            "evidence_quote": "for (i = 0; i <=  HASH_LEN; i++)", "sfr": "SFR.SIP", "level": "error",
            "category": "memory-safety"}
    return {**base, **changes}


def test_a_real_off_by_one_is_grounded() -> None:
    verdict = ground(claim(), SHOWN, **PROFILE)
    assert verdict.grounded and verdict.problems == []


def test_an_invented_timing_side_channel_is_not() -> None:
    invented = claim(evidence_quote="if (memcmp(hash, expected, HASH_LEN) == 0) return 0;", decisive_line=212)
    verdict = ground(invented, SHOWN, **PROFILE)
    assert not verdict.grounded
    assert any("does not appear" in p for p in verdict.problems)
    assert any("outside the lines shown" in p for p in verdict.problems)


def test_every_checkable_field_is_checked() -> None:
    problems = ground(claim(file="other.c", line=400, symbol="verify_image", sfr="SFR.NOPE", level="critical",
                            category="made-up", evidence_quote="x"), SHOWN, **PROFILE).problems
    joined = " ".join(problems)
    for expected in ("not the unit", "outside the lines", "too short", "is not defined in the profile"):
        assert expected in joined
    assert ground(claim(line=True), SHOWN, **PROFILE).grounded is False


def test_a_quote_may_span_lines() -> None:
    spanning = claim(evidence_quote="i++) {   /* HASH_LEN == 32, hash[32] */ acc |= hash[i]")
    assert ground(spanning, SHOWN, **PROFILE).grounded

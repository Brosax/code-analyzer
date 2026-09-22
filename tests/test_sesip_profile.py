"""M2: profiles -- builtins, validation, TOE membership, provable grading, SFR links, and the TOML writer."""
from __future__ import annotations

import tomllib

import pytest

from code_analyzer.core.tomlw import dumps
from code_analyzer.errors import UserError
from code_analyzer.sesip.profile import BUILTINS, load_profile, parse_profile

MINIMAL = """
[evaluation]
status = "confirmed"
[advanced]
pv_min_level = "warning"
[[sfr]]
id = "SFR-BOOT"
catalogue = "Secure Initialization of Platform"
[[sfr]]
id = "SFR-CRYPTO"
catalogue = "Cryptographic Operation"
[[toe_module]]
id = "bl2"
paths = ["bl2/**"]
sfr = ["SFR-BOOT"]
[[toe_module]]
id = "spm"
paths = ["secure_fw/spm/**/*.c"]
[[exclude]]
paths = ["bl2/ext/mcuboot/boot/zephyr/**"]
reason = "not in the TOE (ST 1.4)"
[[level]]
id = "error"
rank = 4
[[level]]
id = "warning"
rank = 3
[[level]]
id = "style"
rank = 2
[[grading_rule]]
match = {native = "error"}
level = "error"
basis = "native-exact"
[[grading_rule]]
match = {tool = "flawfinder", native = ["note"]}
level = "warning"
basis = "evaluator-rule"
by = "fgt"
[[grading_rule]]
match = {tool = "splint", rule = "buffer*"}
level = "warning"
basis = "proposed"
"""


def row(**fields: str) -> dict[str, str]:
    return {"tool": "cppcheck", "original_severity": "style", "rule_id": "x", "family": "", "canonical_path": "a.c",
            "function": "", **fields}


@pytest.mark.parametrize("name", BUILTINS)
def test_builtins_load_and_are_read_only_references(name: str) -> None:
    profile = load_profile(name)
    assert profile.status == "builtin" and len(profile.sha256) == 64
    assert [level["id"] for level in profile.levels] == ["error", "warning", "style", "information"]
    assert profile.module_of("any/where/x.c") == "all"
    assert profile.grade(row(original_severity="error")) == ("error", "native-exact", "")
    assert profile.grade(row(original_severity="Warning ")) == ("warning", "native-exact", "")


def test_generic_proposes_but_never_grades_the_tool_specific_scales() -> None:
    generic, rt700 = load_profile("generic-sesip"), load_profile("rt700-tp-v1.1")
    note = row(tool="flawfinder", original_severity="note")
    assert generic.grade(note) == ("unmapped", "unmapped", "information")
    assert rt700.grade(note) == ("unmapped", "unmapped", "")
    splint_buffer = row(tool="splint", original_severity="unknown", family="buffer")
    assert generic.grade(splint_buffer) == ("unmapped", "unmapped", "warning")


def test_toe_membership_uses_git_globs_and_excludes() -> None:
    profile = parse_profile(MINIMAL)
    assert profile.module_of("bl2/bl2_main.c") == "bl2"
    assert profile.module_of("bl2/ext/mcuboot/boot/zephyr/main.c") is None
    assert profile.module_of("secure_fw/spm/core/spm.c") == "spm"
    assert profile.module_of("secure_fw/spm/core/spm.h") is None
    assert profile.module_of("platform/ext/x.c") is None


def test_grading_is_provable_first_match_and_evaluator_rules_count() -> None:
    profile = parse_profile(MINIMAL)
    assert profile.grade(row(tool="flawfinder", original_severity="note")) == ("warning", "evaluator-rule", "")
    assert profile.grade(row(tool="splint", rule_id="bufferoverflowhigh")) == ("unmapped", "unmapped", "warning")
    assert profile.grade(row(original_severity="portability")) == ("unmapped", "unmapped", "")


def test_sfr_links_carry_their_basis() -> None:
    profile = parse_profile(MINIMAL)
    crypto = profile.sfrs_for(row(family="crypto-misuse", canonical_path="bl2/boot.c"), "bl2")
    assert crypto == [{"id": "SFR-BOOT", "basis": "keyword"}, {"id": "SFR-CRYPTO", "basis": "family"}]
    plain = profile.sfrs_for(row(canonical_path="bl2/x.c"), "bl2")
    assert {"id": "SFR-BOOT", "basis": "keyword"} in plain  # "bl2" is a Secure Initialization keyword


@pytest.mark.parametrize(("patch", "message"), [
    ("[colour]\nx = 1\n", "unknown section"),
    ("[[level]]\nid = \"error\"\nrank = 9\n", "ids must be unique"),
    ("[[grading_rule]]\nmatch = {native = \"x\"}\nlevel = \"error\"\nbasis = \"guess\"\n", "basis must be"),
    ("[[grading_rule]]\nmatch = {native = \"x\"}\nlevel = \"fatal\"\nbasis = \"native-exact\"\n", "is not defined"),
    ("[[grading_rule]]\nmatch = {native = \"x\"}\nlevel = \"error\"\nbasis = \"evaluator-rule\"\n", "needs 'by'"),
    ("[[grading_rule]]\nmatch = {colour = \"x\"}\nlevel = \"error\"\nbasis = \"native-exact\"\n", "unknown match key"),
    ("[[toe_module]]\nid = \"x\"\npaths = [\"a/**\"]\nsfr = [\"SFR-NOPE\"]\n", "unknown SFR"),
])
def test_invalid_profiles_say_why(patch: str, message: str) -> None:
    with pytest.raises(UserError, match=message):
        parse_profile(MINIMAL + patch)


def test_toml_writer_round_trips_and_is_stable() -> None:
    data = {"title": "a \"quoted\"\tvalue\u0001", "n": 3, "f": 0.5, "ok": True, "none": None,
            "table": {"list": [1, 2], "nested": {"k": "v"}},
            "rows": [{"match": {"tool": "splint", "native": ["a", "b"]}, "level": "x"}, {"level": "y"}],
            "weird key": "z"}
    text = dumps(data)
    expected = {k: v for k, v in data.items() if v is not None}
    assert tomllib.loads(text) == expected
    assert dumps(data) == text

"""M4: from ST and test-plan text to a draft profile, with every item quoted and checked."""
from __future__ import annotations

import json

from code_analyzer.core.tomlw import dumps
from code_analyzer.sesip.documents import Page
from code_analyzer.sesip.extract import deterministic, merge, model_pass, unverified
from code_analyzer.sesip.profile import parse_profile

ST = [
    Page(1, "p1", "Security Target for the Example Platform\n1 Introduction"),
    Page(2, "p2", "5 Security Functional Requirements\nSFR.SU  Secure Update of Platform: images are authenticated\n"
                  "The platform provides Secure Initialization of Platform through ROM verification.\n"
                  "Cryptographic   KeyStore keeps keys outside the application domain."),
    Page(3, "p3", "6 TOE Summary Specification\nThe bootloader (BL2) verifies the image signature.\n"
                  "The attacker is assumed to have physical access to the device."),
]
TP = [
    Page(25, "p25", "7.4 Code analysis\nSome text."),
    Page(26, "p26", "7.4.1 Security Levels\nError: Requires immediate review because the issue may cause serious "
                    "runtime failures.\nWarning: Potentially compromises code during execution.\n"
                    "Style - Coding-practice concern without direct security impact.\n"
                    "Information: Often caused by incomplete external dependencies."),
    Page(27, "p27", "7.4.2 Issue Categorization\nCategory | Definition\nMemory safety | Out-of-bounds access, use "
                    "after free and similar defects\nInput validation | Missing or wrong checks on external input\n"
                    "7.4.3 Reporting\nNot part of this table: whatever"),
]


def test_matching_finds_catalogue_sfrs_levels_and_categories_with_quotes() -> None:
    result = deterministic(ST, TP)
    by_name = {s["catalogue"]: s for s in result.sfr}
    assert {"Secure Update of Platform", "Secure Initialization of Platform", "Cryptographic KeyStore"} <= set(by_name)
    assert by_name["Secure Update of Platform"]["id"] == "SFR.SU"
    assert by_name["Cryptographic KeyStore"]["source"] == {"doc": "st", "page": 2, "loc": "p2", "verified": True,
        "quote": "Cryptographic   KeyStore keeps keys outside the application domain."}
    assert [(level["id"], level["rank"]) for level in result.level] == [
        ("error", 4), ("warning", 3), ("style", 2), ("information", 1)]
    assert result.level[0]["source"]["page"] == 26
    assert [c["id"] for c in result.category] == ["memory-safety", "input-validation"]


def test_model_items_are_kept_only_with_their_quote_checked() -> None:
    reply = {
        "sfr": [{"id": "SFR.ATT", "title": "Attestation of Platform State", "quote": "not in the document at all"}],
        "toe_modules": [{"id": "BL2", "description": "bootloader", "quote": "The bootloader (BL2) verifies the image"}],
        "tsfi": [],
        "attacker": {"physical": True, "quote": "physical access to the device"},
    }
    prompts: list[str] = []
    result = model_pass(ST, lambda prompt: prompts.append(prompt) or json.dumps(reply))
    assert "<data source=\"st\" trust=\"untrusted\">" in prompts[0]
    assert result.toe_module[0]["source"]["verified"] and result.toe_module[0]["source"]["page"] == 3
    assert result.attacker["physical"] is True and result.attacker["source"]["verified"]
    assert result.sfr[0]["source"]["verified"] is False
    assert unverified(result) == ["sfr SFR.ATT"]


def test_unreadable_model_output_is_a_problem_not_a_crash() -> None:
    result = model_pass(ST, lambda prompt: "I cannot do that")
    assert result.problems and not result.sfr


def test_the_merged_draft_is_a_valid_profile_that_is_not_yet_confirmed() -> None:
    reply = {"sfr": [{"id": "SFR.SU", "title": "Secure Update of Platform", "quote": "images are authenticated"}],
             "toe_modules": [{"id": "BL2", "description": "bootloader", "quote": "The bootloader (BL2) verifies"}],
             "tsfi": [], "attacker": {"physical": False, "quote": "physical access to the device"}}
    merged = merge(deterministic(ST, TP), model_pass(ST, lambda _p: json.dumps(reply)))
    catalogue_names = [s.get("catalogue") for s in merged.sfr]
    assert catalogue_names.count("Secure Update of Platform") == 1  # the model's duplicate is dropped
    data = merged.profile([{"role": "security_target", "file": "st.pdf", "sha256": "0" * 64}])
    profile = parse_profile(dumps(data))
    assert profile.status == "draft"
    assert profile.module_of("anything/x.c") == "all"  # no module mapped to paths yet
    assert [m["id"] for m in data["toe_module"]] == ["all", "bl2"]


def test_a_draft_without_a_test_plan_borrows_the_generic_levels_and_says_so() -> None:
    result = deterministic(ST, None)
    data = result.profile([{"role": "security_target", "file": "st.pdf", "sha256": "0" * 64}])
    profile = parse_profile(dumps(data))
    assert [level["id"] for level in profile.levels] == ["error", "warning", "style", "information"]
    assert profile.grade({"original_severity": "error", "tool": "cppcheck"}) == ("error", "native-exact", "")
    assert any("generic SESIP levels" in problem for problem in result.problems)

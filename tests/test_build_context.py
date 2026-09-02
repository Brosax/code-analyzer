"""The build-context loop's pure parts: diagnosis, inference, validation, application, evidence."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from code_analyzer.build_context import (
    AUTHORITY,
    ConfigPatch,
    PatchItem,
    diagnose_units,
    infer_patch,
    manifest_block,
    select_probe_files,
    suggested_toml,
    validate_patch,
    write_round,
    write_stubs,
)
from code_analyzer.config import load_config
from code_analyzer.errors import UserError
from code_analyzer.includes import candidate_dirs, include_index, scan_includes
from code_analyzer.tools.common import effective_units, merge_attempt

INVENTORY = [
    {"path": "bl1/main.c"}, {"path": "bl1/lib/image.c"}, {"path": "bl1/lib/image.h"},
    {"path": "platform/a/board.h"}, {"path": "platform/b/board.h"},
    {"path": "platform/a/init.c"}, {"path": "platform/b/init.c"}, {"path": "include/cmsis.h"},
]


def _unit(unit_id: str, file: str, missing: list[str], *, cls: str = "include", reached: bool = False) -> dict:
    return {
        "id": unit_id, "status": "completed" if reached else "failed", "input_files": [file],
        "analysis_reached": reached, "failure_class": None if reached else cls,
        "diagnosis": {"category": None if reached else cls, "missing_includes": missing, "error_directives": [], "parse_errors": 0, "reserved_name_warnings": 0},
    }


RECORD = {"units": [
    _unit("u1", "bl1/main.c", ["image.h", "cmsis.h"]),
    _unit("u2", "bl1/lib/image.c", ["cmsis.h", "vendor_sdk.h"]),
    _unit("u3", "platform/a/init.c", ["board.h"]),
    _unit("u4", "platform/b/init.c", ["board.h"]),
    _unit("u5", "include/cmsis.h", [], reached=True),
]}


def _config(tmp_path: Path, **build: object) -> dict:
    return load_config(tmp_path, None, {"run": {"output_root": str(tmp_path / "out")}, "build": build})


def test_diagnosis_aggregates_missing_headers_and_classifies_them() -> None:
    diagnosis = diagnose_units(RECORD, INVENTORY)
    assert diagnosis.units_total == 5 and diagnosis.units_failed == 4 and diagnosis.units_analysis_reached == 1
    by_name = {item.name: item for item in diagnosis.missing_headers}
    assert by_name["cmsis.h"].kind == "unambiguous" and by_name["cmsis.h"].candidates == ("include",)
    assert by_name["image.h"].candidates == ("bl1/lib",)
    assert by_name["board.h"].kind == "ambiguous" and set(by_name["board.h"].candidates) == {"platform/a", "platform/b"}
    assert by_name["vendor_sdk.h"].kind == "external" and by_name["vendor_sdk.h"].candidates == ()
    assert diagnosis.counts["unambiguous"] == 2 and diagnosis.counts["ambiguous"] == 1 and diagnosis.counts["external"] == 1
    assert diagnosis.classes == {"include": 4}
    # The most-shared headers come first, so the probe samples what the patch fixes.
    assert [item.units for item in diagnosis.missing_headers] == [2, 2, 1, 1]


def test_inference_proves_include_roots_resolves_ambiguity_per_tree_and_never_preticks_a_stub(tmp_path: Path) -> None:
    patch = infer_patch(diagnose_units(RECORD, INVENTORY), _config(tmp_path), source=tmp_path)
    ops = [(item.op, item.value) for item in patch.items]
    assert ops[0] == ("add_include", "include")  # two units, ranked first
    assert ("add_include", "bl1/lib") in ops
    overrides = [item for item in patch.items if item.op == "add_override"]
    assert {item.match: item.value["include"] for item in overrides} == {"platform/a/**": ["platform/a"], "platform/b/**": ["platform/b"]}
    stubs = [item for item in patch.items if item.op == "add_stub_header"]
    assert [item.value for item in stubs] == ["vendor_sdk.h"] and not stubs[0].preselected
    assert all(item.preselected for item in patch.items if item.op != "add_stub_header")
    assert all(item.origin == "deterministic" and item.evidence for item in patch.items)


def test_inference_skips_roots_already_configured_and_stubs_when_disallowed(tmp_path: Path) -> None:
    config = _config(tmp_path, include=[str(tmp_path / "include")], stub_headers=False)
    patch = infer_patch(diagnose_units(RECORD, INVENTORY), config, source=tmp_path)
    assert ("add_include", "include") not in [(item.op, item.value) for item in patch.items]
    assert not [item for item in patch.items if item.op == "add_stub_header"]


def test_reserved_names_alone_turn_into_the_typed_splint_switch(tmp_path: Path) -> None:
    record = {"units": [{
        "id": "u", "status": "failed", "input_files": ["bl1/main.c"], "analysis_reached": False, "failure_class": "configuration",
        "diagnosis": {"category": "configuration", "missing_includes": [], "error_directives": [], "parse_errors": 0, "reserved_name_warnings": 12},
    }]}
    patch = infer_patch(diagnose_units(record, INVENTORY), _config(tmp_path), source=tmp_path)
    assert [(item.op, item.value) for item in patch.items] == [("set_splint_option", ("report_reserved_names", False))]


def test_apply_returns_a_validated_copy_and_leaves_the_input_alone(tmp_path: Path) -> None:
    config = _config(tmp_path)
    before = copy.deepcopy(config)
    patch = infer_patch(diagnose_units(RECORD, INVENTORY), config, source=tmp_path)
    selected = [index for index, item in enumerate(patch.items) if item.preselected]
    patched = patch.apply(config, tmp_path / "run", tmp_path, selected)
    assert config == before
    assert patched["build"]["include"] == [str((tmp_path / "include").resolve()), str((tmp_path / "bl1/lib").resolve())]
    assert [override["match"] for override in patched["build"]["overrides"]] == ["platform/a/**", "platform/b/**"]
    assert patched["build"]["overrides"][0]["include"] == [str((tmp_path / "platform/a").resolve())]
    # Selecting the stub appends the stub directory last, so real headers win.
    stub_index = next(index for index, item in enumerate(patch.items) if item.op == "add_stub_header")
    with_stub = patch.apply(config, tmp_path / "run", tmp_path, [*selected, stub_index])
    assert with_stub["build"]["include"][-1] == str((tmp_path / "run/inputs/build-context/r1/stubs").resolve())
    assert patch.selected_stubs([*selected, stub_index]) == ["vendor_sdk.h"]


def test_apply_rejects_an_item_the_schema_rejects(tmp_path: Path) -> None:
    patch = ConfigPatch(1, [PatchItem("set_splint_option", ("mode", "nuclear"))])
    with pytest.raises(UserError):
        patch.apply(_config(tmp_path), tmp_path / "run", tmp_path)


def test_validation_keeps_what_the_tree_can_stand_behind_and_names_the_rest(tmp_path: Path) -> None:
    diagnosis = diagnose_units(RECORD, INVENTORY)
    index = include_index(INVENTORY)
    proposed = [
        {"op": "add_include", "path": "include", "rationale": "cmsis.h lives here"},
        {"op": "add_include", "path": "../outside"},
        {"op": "add_include", "path": "/usr/include"},
        {"op": "add_include", "path": "bl1/lib/nothere"},
        {"op": "add_define", "value": "CONFIG_X=1"},
        {"op": "add_define", "value": "rm -rf /"},
        {"op": "set_standard", "value": "c99"},
        {"op": "set_standard", "value": "c2x"},
        {"op": "add_override", "match": "platform/a/**", "include": ["platform/a"]},
        {"op": "add_override", "match": "nowhere/**", "include": ["platform/a"]},
        {"op": "set_splint_option", "name": "mode", "value": "weak"},
        {"op": "set_splint_option", "name": "mode", "value": "nuclear"},
        {"op": "set_splint_option", "name": "system_dirs", "value": "/tmp"},
        {"op": "add_stub_header", "name": "vendor_sdk.h"},
        {"op": "add_stub_header", "name": "cmsis.h"},
        {"op": "run_command", "value": "make"},
        "not an object",
    ]
    kept, problems = validate_patch(proposed, diagnosis=diagnosis, source=tmp_path, index=index, inventory=INVENTORY)
    assert [(item.op, item.value if item.op != "add_override" else item.match) for item in kept] == [
        ("add_include", "include"), ("add_define", "CONFIG_X=1"), ("set_standard", "c99"),
        ("add_override", "platform/a/**"), ("set_splint_option", ("mode", "weak")), ("add_stub_header", "vendor_sdk.h"),
    ]
    assert all(item.origin == "llm" for item in kept) and kept[0].rationale == "cmsis.h lives here"
    assert not kept[-1].preselected
    assert len(problems) == 11
    assert any("not tree-relative" in text for text in problems)
    assert any("not a directory in the tree" in text for text in problems)
    assert any("names no file" in text for text in problems)
    assert any("unknown op 'run_command'" in text for text in problems)
    assert any("not a header the tree lacks" in text for text in problems)


def test_probe_sampling_prefers_units_the_patch_can_fix() -> None:
    diagnosis = diagnose_units(RECORD, INVENTORY)
    # Unambiguous-only units first, then ambiguous, then those needing a header the tree lacks.
    assert select_probe_files(diagnosis, RECORD, 2) == ["bl1/main.c", "platform/a/init.c"]
    assert select_probe_files(diagnosis, RECORD, 10)[-1] == "bl1/lib/image.c"
    assert len(select_probe_files(diagnosis, RECORD, 10)) == 4


def test_stubs_are_empty_guarded_headers_under_the_run_directory(tmp_path: Path) -> None:
    root = write_stubs(tmp_path / "run", 2, ["vendor_sdk.h", "sdk/hal.h"], run_id="abc")
    assert root == tmp_path / "run/inputs/build-context/r2/stubs"
    text = (root / "sdk/hal.h").read_text(encoding="utf-8")
    assert "#ifndef CODE_ANALYZER_STUB_SDK_HAL_H" in text and "declares nothing" in text
    assert not any(line.strip() and not line.startswith(("#", "/*", "   ")) for line in text.splitlines())


def test_round_evidence_and_suggested_toml(tmp_path: Path) -> None:
    config = _config(tmp_path)
    patch = infer_patch(diagnose_units(RECORD, INVENTORY), config, source=tmp_path)
    patched = patch.apply(config, tmp_path / "run", tmp_path, [0, 1])
    root = write_round(tmp_path / "run", 1, diagnosis={"a": 1}, patch=patch.as_dict(), probe=None, applied_config="x = 1\n")
    assert sorted(path.name for path in root.iterdir()) == ["applied-config.toml", "diagnosis.json", "meta.json", "patch.json"]
    assert patch.as_dict()["authority"] == AUTHORITY
    toml = suggested_toml(config, patched, tmp_path)
    assert 'include = ["include", "bl1/lib"]' in toml and "[[build.overrides]]" not in toml
    block = manifest_block("propose", "applied", [{"round": 1, "applied": True}])
    assert block["suggested_config"] == "suggested-config.toml" and block["authority"] == AUTHORITY
    with pytest.raises(UserError):
        manifest_block("sometimes", "applied", [])


def test_merge_attempt_keeps_the_old_unit_and_ranks_the_new_one(tmp_path: Path) -> None:
    previous = {
        "status": "partial", "units": copy.deepcopy(RECORD["units"]),
        "unit_counts": {"planned": 5, "completed": 1, "partial": 0, "failed": 4},
        "coverage": {"total": 5, "analysis_reached": 1},
    }
    rerun = {"status": "completed", "units": [
        _unit("u1-a2", "bl1/main.c", [], reached=True),
        _unit("u2-a2", "bl1/lib/image.c", ["vendor_sdk.h"]),
    ]}
    merged = merge_attempt(previous, rerun, attempt=2)
    units = {unit["id"]: unit for unit in merged["units"]}
    assert units["u1"]["superseded_by"] == "u1-a2" and units["u1-a2"]["supersedes"] == "u1"
    # A re-run that fails again still stands for its file: the latest attempt is the current truth.
    assert units["u2"]["superseded_by"] == "u2-a2" and units["u2-a2"]["supersedes"] == "u2"
    assert len(merged["units"]) == 7 and merged["unit_counts"]["superseded"] == 2
    assert [unit["id"] for unit in effective_units(merged["units"])] == ["u3", "u4", "u5", "u1-a2", "u2-a2"]
    assert merged["coverage"]["analysis_reached"] == 2


def test_include_scan_predicts_the_roots_before_a_run(tmp_path: Path) -> None:
    (tmp_path / "bl1").mkdir()
    (tmp_path / "include").mkdir()
    (tmp_path / "bl1/main.c").write_text('#include "cmsis.h"\n#include "missing.h"\n#include <stdio.h>\n', encoding="utf-8")
    (tmp_path / "include/cmsis.h").write_text("", encoding="utf-8")
    inventory = [{"path": "bl1/main.c"}, {"path": "include/cmsis.h"}]
    scan = scan_includes(tmp_path, inventory, {"include": [], "system_include": []})
    assert scan["scanned_files"] == 1
    assert scan["unresolved"] == {"cmsis.h": 1, "missing.h": 1}
    assert scan["predicted_roots"][0] == ("include", 1)
    assert scan["external"] == {"missing.h": 1}
    assert candidate_dirs("cmsis.h", include_index(inventory)) == ["include"]

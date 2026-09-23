from __future__ import annotations

import json
from pathlib import Path

from helpers import load_config

from code_analyzer.compile_db import (
    discover_candidate_paths,
    read_presets,
    resolve_compile_db,
)


def write_db(path: Path, source: Path, names: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([
        {"directory": str(path.parent), "file": str(source / name), "arguments": ["cc", "-c", str(source / name)]}
        for name in names
    ]), encoding="utf-8")


def test_auto_discovery_scores_adjacent_tfm_style_database_by_coverage(tmp_path: Path) -> None:
    source = tmp_path / "project"
    source.mkdir()
    for name in ("one.c", "two.cpp"):
        (source / name).write_text("int value;\n", encoding="utf-8")
    write_db(source / "build-small" / "compile_commands.json", source, ["one.c"])
    best = tmp_path / "build" / "board" / "compile_commands.json"
    write_db(best, source, ["one.c", "two.cpp"])

    config = load_config(source, None)
    selected, entries, reasons, discovery = resolve_compile_db(source, config)

    assert selected == best.resolve()
    assert len(entries) == 2 and reasons == []
    assert discovery["selected"] == str(best.resolve())
    winner = next(item for item in discovery["candidates"] if item["path"] == str(best.resolve()))
    assert winner["source_coverage_ratio"] == 1.0


def test_discovery_is_bounded_and_does_not_follow_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    shallow = source / "build" / "a" / "b" / "c" / "compile_commands.json"
    shallow.parent.mkdir(parents=True)
    shallow.write_text("[]", encoding="utf-8")
    too_deep = source / "build" / "a" / "b" / "c" / "d" / "compile_commands.json"
    too_deep.parent.mkdir()
    too_deep.write_text("[]", encoding="utf-8")
    link = source / "out"
    link.symlink_to(too_deep.parent, target_is_directory=True)
    paths = discover_candidate_paths(source)
    assert shallow in paths
    assert too_deep not in paths


def test_configure_presets_are_read_with_inherited_binary_dirs(tmp_path: Path) -> None:
    """The compile_db job offers only a preset the project declares (read_presets)."""
    (tmp_path / "CMakePresets.json").write_text(json.dumps({"version": 3, "configurePresets": [
        {"name": "base", "hidden": True, "binaryDir": "${sourceDir}/build/${presetName}"},
        {"name": "debug", "inherits": "base"},
        {"name": "plain"},
    ]}), encoding="utf-8")
    presets = read_presets(tmp_path)
    assert presets["presets"] == [{"name": "debug", "binaryDir": "${sourceDir}/build/${presetName}"},
                                  {"name": "plain", "binaryDir": None}]

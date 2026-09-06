"""Nested .gitignore handling, measured against Git rather than against taste.

The sample below is fixed and its expectation is written out in full, so a
change in the matcher shows up as a diff instead of as a judgement call.  The
same sample is replayed through ``git ls-files --others --exclude-standard``
whenever Git is on the host, which is what keeps the written expectation
honest: the table is the test, and Git is the table's own regression test.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from code_analyzer.config import load_config
from code_analyzer.inventory import discover

# A rule of every shape Git defines, spread over three levels of ignore file.
TREE: dict[str, str] = {
    ".gitignore": (
        "# a comment line\n"
        "\n"
        "*.tmp.c\n"              # suffix glob, any depth
        "/rooted.c\n"            # anchored to this directory only
        "logs/\n"                # directory only
        "vendor/\n"              # excluded subtree ...
        "!vendor/keep/\n"        # ... that a negation must not reopen
        "docs/**/generated.c\n"  # ** spanning zero or more directories
        "deep/**\n"              # everything inside, not the directory itself
        "space\\ kept.c\n"       # escaped space, so the name keeps it
        "\\#hash.c\n"            # escaped hash, so the line is not a comment
        "[ab]choice.c\n"         # character class
        "qmark?.c\n"             # single-character wildcard
        "trailing   \n"          # unescaped trailing spaces are dropped
        "**/anywhere.c\n"
        "mid/**/target.c\n"
        "\\!bang.c\n"            # escaped bang, so the line is not a negation
        "num[0-9].c\n"
        "blocked/\n"
        "/sub/anchored.c\n"
        "file[[:digit:]].c\n"     # POSIX bracket expression
        "[[:upper:]]init.c\n"
    ),
    "a.c": "", "rooted.c": "", "x.tmp.c": "",
    "plain/.gitignore": "/local.c\n",
    "plain/rooted.c": "", "plain/a.tmp.c": "", "plain/local.c": "", "plain/deeper/local.c": "",
    "sub/.gitignore": "*.c\n!important.c\n",
    "sub/plain.c": "", "sub/important.c": "", "sub/anchored.c": "",
    "sub/nested/.gitignore": "!plain.c\n",
    "sub/nested/plain.c": "", "sub/nested/other.c": "",
    "logs/keep.c": "",
    "vendor/lib.c": "", "vendor/keep/kept.c": "",
    "docs/api/generated.c": "", "docs/api/manual.c": "", "docs/generated.c": "",
    "deep/one/two.c": "",
    "space kept.c": "", "#hash.c": "", "achoice.c": "", "cchoice.c": "", "qmarkZ.c": "",
    "trailing.c": "", "trailing/inside.c": "",
    "anywhere.c": "", "deepdir/anywhere.c": "", "deepdir/elsewhere.c": "",
    "mid/target.c": "", "mid/x/y/target.c": "", "mid/x/keep.c": "",
    "!bang.c": "", "num7.c": "", "numX.c": "",
    "blocked/.gitignore": "!inside.c\n", "blocked/inside.c": "",
    "file7.c": "", "fileX.c": "", "Ainit.c": "", "binit.c": "",
}
KEPT = {
    "a.c",
    "binit.c",
    "cchoice.c",
    "deepdir/elsewhere.c",
    "docs/api/manual.c",
    "fileX.c",
    "mid/x/keep.c",
    "numX.c",
    "plain/deeper/local.c",
    "plain/rooted.c",
    "sub/important.c",
    "sub/nested/plain.c",
    "trailing.c",
}


def _build(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    for relative, body in TREE.items():
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return source


def _config(source: Path, tmp_path: Path, **overrides: Any) -> dict[str, Any]:
    config = load_config(source, None, {"run": {"output_root": str(tmp_path / "out")}})
    config["source"]["respect_gitignore"] = True
    config["source"].update(overrides)
    return config


def _found(source: Path, config: dict[str, Any], tmp_path: Path) -> set[str]:
    return {item["path"] for item in discover(source, config, tmp_path / "out").files}


def test_the_fixed_sample_resolves_to_exactly_these_files(tmp_path: Path) -> None:
    source = _build(tmp_path)

    assert _found(source, _config(source, tmp_path), tmp_path) == KEPT


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed on this host")
def test_the_fixed_sample_agrees_with_git(tmp_path: Path) -> None:
    source = _build(tmp_path)
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    listed = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=source, capture_output=True, text=True, check=True,
    )

    assert {name for name in listed.stdout.split("\0") if name.endswith(".c")} == KEPT


def test_posix_bracket_expressions_match_the_way_git_matches_them(tmp_path: Path) -> None:
    """``[[:digit:]]`` is Git's syntax, not Python's; unexpanded it used to
    read as the literal characters of its own name and match nothing."""
    source = _build(tmp_path)
    found = _found(source, _config(source, tmp_path), tmp_path)

    assert "file7.c" not in found and "fileX.c" in found
    assert "Ainit.c" not in found and "binit.c" in found


def test_the_ignore_file_of_a_directory_governs_only_that_subtree(tmp_path: Path) -> None:
    source = _build(tmp_path)
    found = _found(source, _config(source, tmp_path), tmp_path)

    # sub/.gitignore hides every .c below it; the root's own files are untouched.
    assert "sub/plain.c" not in found and "a.c" in found
    # ... and a deeper file overrides the shallower one that hid the name.
    assert "sub/nested/plain.c" in found and "sub/nested/other.c" not in found
    # An anchored rule binds to the directory its file was read in.
    assert "plain/local.c" not in found and "plain/deeper/local.c" in found


def test_a_negation_cannot_reopen_an_excluded_directory(tmp_path: Path) -> None:
    source = _build(tmp_path)
    found = _found(source, _config(source, tmp_path), tmp_path)

    # `!vendor/keep/` follows `vendor/`, and `blocked/.gitignore` re-includes
    # its own file: Git never descends into either, and neither do we.
    assert "vendor/keep/kept.c" not in found
    assert "blocked/inside.c" not in found


def test_gitignore_is_opt_in_and_nested_files_are_inert_while_it_is_off(tmp_path: Path) -> None:
    source = _build(tmp_path)
    config = _config(source, tmp_path)
    config["source"]["respect_gitignore"] = False

    found = _found(source, config, tmp_path)

    assert {"sub/plain.c", "vendor/lib.c", "rooted.c"} <= found


def test_explicit_and_default_exclusions_outrank_a_gitignore_negation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    output = source / "reports"
    for directory in ("keepme", "node_modules", "reports"):
        (source / directory).mkdir(parents=True)
        (source / directory / "unit.c").write_text("", encoding="utf-8")
    # Ignore everything, then hand each of the three directories back: whatever
    # keeps them out now is doing so over an explicit Git re-inclusion.
    (source / ".gitignore").write_text(
        "*\n!keepme/\n!keepme/unit.c\n!node_modules/\n!node_modules/unit.c\n!reports/\n!reports/unit.c\n",
        encoding="utf-8",
    )
    config = load_config(source, None, {"run": {"output_root": str(output)}})
    config["source"]["respect_gitignore"] = True

    found = {item["path"] for item in discover(source, config, output).files}

    # The negation is real: without a competing rule the file comes back.
    assert found == {"keepme/unit.c"}
    # A default-excluded directory name and the report directory both outrank it.
    assert "node_modules/unit.c" not in found and "reports/unit.c" not in found
    # So does a user exclusion.
    config["source"]["exclude"] = ["keepme/**"]
    assert discover(source, config, output).files == []


def test_an_unreadable_nested_ignore_file_names_its_own_directory(tmp_path: Path) -> None:
    source = _build(tmp_path)
    (source / "plain" / ".gitignore").unlink()
    (source / "plain" / ".gitignore").mkdir()

    found = discover(source, _config(source, tmp_path), tmp_path / "out")

    assert [(item.path, item.operation) for item in found.anomalies] == [
        ("plain/.gitignore", "gitignore"),
    ]
    assert not found.complete

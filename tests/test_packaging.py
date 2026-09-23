"""v3 M9: a real install carries its data files and pulls in nothing."""
from __future__ import annotations

import contextlib
import shutil
import tomllib
import zipfile
from pathlib import Path

REPOSITORY = Path(__file__).parents[1]


def test_the_runtime_needs_nothing_but_the_standard_library() -> None:
    project = tomllib.loads((REPOSITORY / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["dependencies"] == []


def test_a_built_wheel_carries_the_lenses_profiles_and_the_page(tmp_path: Path) -> None:
    """Data files that are not Python modules exist only in a checkout unless package-data names them."""
    build_root = tmp_path / "tree"
    build_root.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        if (REPOSITORY / name).exists():
            shutil.copy2(REPOSITORY / name, build_root / name)
    shutil.copytree(REPOSITORY / "code_analyzer", build_root / "code_analyzer",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    from setuptools import build_meta

    destination = tmp_path / "dist"
    destination.mkdir()
    with contextlib.chdir(build_root):
        wheel = destination / build_meta.build_wheel(str(destination))
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        metadata = next(archive.read(n).decode() for n in names if n.endswith(".dist-info/METADATA"))
    lenses = {f"code_analyzer/aireview/lenses/{p.name}" for p in (REPOSITORY / "code_analyzer/aireview/lenses").glob("*.md")}
    assert len(lenses) == 15 and lenses <= names
    assert {"code_analyzer/sesip/builtin/rt700-tp-v1.1.toml", "code_analyzer/sesip/builtin/generic-sesip.toml",
            "code_analyzer/web/static/index.html", "code_analyzer/web/static/app.js",
            "code_analyzer/web/static/app.css", "code_analyzer/kernel/method.md"} <= names
    # Only the dev extra declares anything; a plain install pulls in nothing.
    assert all('extra == "dev"' in line for line in metadata.splitlines() if line.startswith("Requires-Dist"))
    assert not any(name.startswith(("code_analyzer/skills/", "code_analyzer/harness/", "code_analyzer/llm/"))
                   for name in names)

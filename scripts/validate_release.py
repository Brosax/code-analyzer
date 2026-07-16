#!/usr/bin/env python3
"""Validate the Code Analyzer plugin distribution and optional mirror."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List


ROOT = Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
IGNORED_PARTS = frozenset((".git", "__pycache__"))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--compare", type=Path, help="Compare this release tree with another plugin copy.")
    return result


def distribution_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in IGNORED_PARTS for part in relative.parts):
            continue
        if path.is_file() and path.suffix not in (".pyc", ".pyo"):
            yield path


def file_hashes(root: Path) -> Dict[str, str]:
    hashes = {}
    for path in distribution_files(root):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        hashes[path.relative_to(root).as_posix()] = digest
    return hashes


def frontmatter(path: Path) -> Dict[str, str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise ValueError("missing YAML frontmatter")
    try:
        end = lines.index("---", 1)
    except ValueError as exc:
        raise ValueError("unterminated YAML frontmatter") from exc
    values = {}
    for line in lines[1:end]:
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    return values


def validate(root: Path) -> List[str]:
    errors: List[str] = []
    required = (
        ".codex-plugin/plugin.json", "README.md", "LICENSE",
        "skills/code-analyzer/SKILL.md", "skills/code-analyzer/agents/openai.yaml",
        "skills/code-analyzer/references/ai-review-protocol.md",
        "skills/code-analyzer/scripts/run_code_analyzer.py",
        "skills/code-analyzer/scripts/code_analyzer_ai.py",
        "skills/code-analyzer/scripts/code_analyzer_core.py",
        "skills/code-analyzer/scripts/code_analyzer_runtime.py",
        "skills/code-analyzer/scripts/code_analyzer_adapters.py",
        "skills/code-analyzer/scripts/code_analyzer_dashboard.py",
        "skills/code-analyzer/scripts/code_analyzer_reporting.py",
        "skills/code-analyzer/scripts/code_analyzer_cli.py",
        "skills/code-analyzer/scripts/install_code_analyzer.py",
    )
    for relative in required:
        if not (root / relative).is_file():
            errors.append("missing required file: %s" % relative)

    manifest_path = root / ".codex-plugin/plugin.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append("invalid plugin manifest: %s" % exc)
        else:
            if manifest.get("name") != "code-review-suite":
                errors.append("plugin name must be code-review-suite")
            if not SEMVER.match(str(manifest.get("version", ""))):
                errors.append("plugin version must be semantic x.y.z")
            elif manifest.get("version") != "0.6.0":
                errors.append("plugin version must be 0.6.0 for this release")
            if manifest.get("skills") != "./skills/":
                errors.append("plugin skills path must be ./skills/")

    skill_files = list((root / "skills").rglob("SKILL.md")) if (root / "skills").is_dir() else []
    if len(skill_files) != 1:
        errors.append("exactly one discoverable SKILL.md is required")
    elif skill_files:
        try:
            metadata = frontmatter(skill_files[0])
        except ValueError as exc:
            errors.append("invalid SKILL.md: %s" % exc)
        else:
            if metadata.get("name") != "code-analyzer":
                errors.append("skill name must be code-analyzer")
            if not metadata.get("description", "").startswith("Use when"):
                errors.append("skill description must start with 'Use when'")

    skill_root = root / "skills" / "code-analyzer"
    installer = skill_root / "scripts" / "install_code_analyzer.py"
    if installer.is_file():
        installer_text = installer.read_text(encoding="utf-8")
        if "content_hash(source)" not in installer_text or "path.rglob" not in installer_text:
            errors.append("installer must content-hash the complete skill tree")

    for path in distribution_files(root):
        if path.suffix == ".py":
            try:
                compile(path.read_text(encoding="utf-8"), str(path), "exec")
            except (OSError, SyntaxError, UnicodeError) as exc:
                errors.append("invalid Python file %s: %s" % (path.relative_to(root), exc))
    return errors


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    errors = validate(ROOT)
    if args.compare:
        comparison = args.compare.expanduser().resolve()
        if not comparison.is_dir():
            errors.append("comparison tree does not exist: %s" % comparison)
        else:
            expected = file_hashes(ROOT)
            actual = file_hashes(comparison)
            for relative in sorted(set(expected) | set(actual)):
                if expected.get(relative) != actual.get(relative):
                    errors.append("distribution mismatch: %s" % relative)
    if errors:
        for error in errors:
            print("error: %s" % error, file=sys.stderr)
        return 1
    print("release validation passed: %s" % ROOT)
    if args.compare:
        print("distribution matches: %s" % args.compare.expanduser().resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

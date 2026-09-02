"""Where a ``#include`` target could come from, answered from the tree alone.

Two callers need the same resolution: the LLM index (which edge does a unit's
include make) and the build-context diagnosis (which ``-I`` root would have
satisfied the header Splint could not find).  Both are textual and tree-local
on purpose -- there is no preprocessor here -- so a target that names no file
in the scanned tree is *external*, never guessed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

INCLUDE_TARGET = re.compile(r"^\s*#\s*include\s*([<\"])([^>\"]*)[>\"]", re.M)


def normalize_include(target: str) -> str:
    parts: list[str] = []
    for part in target.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == ".." and parts:
            parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


@dataclass(frozen=True)
class IncludeIndex:
    """Every path in the tree, and every path tail that names one."""

    by_path: dict[str, str] = field(default_factory=dict)
    by_suffix: dict[str, list[str]] = field(default_factory=dict)


def include_index(inventory: Sequence[Mapping[str, Any]] | Mapping[str, Any]) -> IncludeIndex:
    """Build the lookup once; ``inventory`` is the run's file list or an index's ``files``."""
    paths = sorted(str(item["path"]) for item in inventory) if not isinstance(inventory, Mapping) else sorted(inventory)
    by_path = {path: path for path in paths}
    by_suffix: dict[str, list[str]] = {}
    for path in paths:
        parts = path.split("/")
        for depth in range(len(parts)):
            by_suffix.setdefault("/".join(parts[depth:]), []).append(path)
    return IncludeIndex(by_path, by_suffix)


def resolve_include(
    target: str, directory: str, by_path: dict[str, str], by_suffix: dict[str, list[str]]
) -> str | None:
    """Resolve one include target to a file in the tree, or ``None``."""
    normalized = normalize_include(f"{directory}/{target}" if directory else target)
    if normalized in by_path:
        return normalized
    plain = normalize_include(target)
    if plain in by_path:
        return plain
    # A tail match is the last resort and only when it is unambiguous: two
    # files ending "config.h" must not silently become one edge.
    matches = by_suffix.get(plain, ())
    return matches[0] if len(matches) == 1 else None


def candidate_dirs(name: str, index: IncludeIndex) -> list[str]:
    """The tree-relative directories ``D`` such that ``D/name`` is a file.

    That is exactly the set of ``-I`` roots that would satisfy the include;
    ``""`` is the tree root.  Empty means the header exists nowhere in the
    tree (a vendored or system dependency the tree does not carry).
    """
    plain = normalize_include(name)
    if not plain:
        return []
    result = []
    for path in index.by_suffix.get(plain, ()):
        if path == plain:
            result.append("")
        elif path.endswith("/" + plain):
            result.append(path[: -len(plain) - 1])
    return sorted(dict.fromkeys(result))


def file_includes(path: Path) -> list[tuple[str, bool]]:
    """``(target, is_system)`` for every include directive in one file."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [(match.group(2).strip(), match.group(1) == "<") for match in INCLUDE_TARGET.finditer(text)]


def scan_includes(
    source: Path, inventory: Sequence[Mapping[str, Any]], build: Mapping[str, Any], *, limit: int = 400,
) -> dict[str, Any]:
    """Predict, before any tool runs, which quoted includes the tree cannot satisfy.

    Only the ``"quoted"`` form is judged: a ``<system>`` include belongs to
    the toolchain.  A target is satisfiable when it resolves from the file's
    own directory, from a configured include directory, or from any matching
    override; otherwise it is counted, with the roots that would satisfy it.
    """
    index = include_index(inventory)
    roots = [str(Path(item).resolve()) for item in list(build.get("include") or []) + list(build.get("system_include") or [])]
    root_rel: list[str] = []
    for root in roots:
        try:
            root_rel.append(Path(root).resolve().relative_to(source.resolve()).as_posix())
        except ValueError:
            continue
    unresolved: dict[str, int] = {}
    predicted: dict[str, int] = {}
    external: dict[str, int] = {}
    scanned = 0
    for item in inventory:
        path = str(item["path"])
        if not path.endswith(".c") or scanned >= limit:
            continue
        scanned += 1
        directory = path.rsplit("/", 1)[0] if "/" in path else ""
        for target, is_system in file_includes(source / path):
            if is_system or not target:
                continue
            if resolve_include(target, directory, index.by_path, index.by_suffix) is not None and normalize_include(f"{directory}/{target}" if directory else target) in index.by_path:
                continue
            if any(normalize_include(f"{root}/{target}") in index.by_path for root in root_rel):
                continue
            unresolved[target] = unresolved.get(target, 0) + 1
            dirs = candidate_dirs(target, index)
            if len(dirs) == 1:
                predicted[dirs[0]] = predicted.get(dirs[0], 0) + 1
            elif not dirs:
                external[target] = external.get(target, 0) + 1
    return {
        "scanned_files": scanned,
        "unresolved": dict(sorted(unresolved.items(), key=lambda kv: (-kv[1], kv[0]))),
        "predicted_roots": sorted(predicted.items(), key=lambda kv: (-kv[1], kv[0])),
        "external": dict(sorted(external.items(), key=lambda kv: (-kv[1], kv[0]))),
    }

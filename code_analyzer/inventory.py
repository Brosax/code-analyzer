from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

EXTENSIONS = {".c", ".C", ".cc", ".cpp", ".cxx", ".c++", ".h", ".H", ".hh", ".hpp", ".hxx", ".h++"}
DEFAULT_DIRS = {
    ".git", ".hg", ".svn", ".agents", ".codex", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", ".nox", ".venv", "venv", "env", "node_modules", "build", "out", "dist",
    "CMakeFiles",
}


def source_slug(source: Path) -> str:
    absolute = str(source.resolve())
    drive, tail = os.path.splitdrive(absolute)
    raw = tail.strip("/\\").replace("/", "__").replace("\\", "__")
    if drive:
        raw = drive.rstrip(":") + "__" + raw
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", raw) or "source"
    # A replaced character can collide with a literal underscore.  Appending a
    # short path digest makes the mapping deterministic without global state.
    if slug != raw or any("__" in part for part in source.resolve().parts):
        slug = slug.rstrip("._-") + "-" + hashlib.sha256(absolute.encode()).hexdigest()[:8]
    if len(slug) > 120:
        slug = slug[:111].rstrip("._-") + "-" + hashlib.sha256(absolute.encode()).hexdigest()[:8]
    return slug


def discover(
    source: Path,
    config: dict[str, Any],
    output_root: Path,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    follow = config["source"]["follow_symlinks"]
    custom_excludes = list(config["source"]["exclude"])
    custom_includes = list(config["source"]["include"])
    gitignore = _gitignore_patterns(source) if config["source"]["respect_gitignore"] else []
    dynamic: Path | None = None
    try:
        dynamic = output_root.resolve().relative_to(source.resolve())
    except ValueError:
        pass
    records: list[dict[str, Any]] = []
    for root, dirs, files in os.walk(source, followlinks=follow):
        if cancelled is not None and cancelled():
            raise InterruptedError("run interrupted")
        root_path = Path(root)
        rel_root = root_path.relative_to(source)
        kept = []
        for dirname in dirs:
            rel = (rel_root / dirname).as_posix()
            excluded = dirname in DEFAULT_DIRS or dirname.startswith("cmake-build-")
            excluded |= dynamic is not None and (Path(rel) == dynamic or dynamic in Path(rel).parents)
            excluded |= _matches(rel, custom_excludes) or _gitignored(rel + "/", gitignore)
            child = root_path / dirname
            excluded |= child.is_symlink() and not follow
            if not excluded:
                kept.append(dirname)
        dirs[:] = sorted(kept)
        for filename in sorted(files):
            if cancelled is not None and cancelled():
                raise InterruptedError("run interrupted")
            path = root_path / filename
            rel = path.relative_to(source).as_posix()
            included = "**/*" in custom_includes or not custom_includes or _matches(rel, custom_includes)
            if path.suffix not in EXTENSIONS or not included or _matches(rel, custom_excludes) or _gitignored(rel, gitignore):
                continue
            if path.is_symlink() and not follow:
                continue
            try:
                data = path.read_bytes()
                stat = path.stat()
            except OSError:
                continue
            is_header = path.suffix in {".h", ".H", ".hh", ".hpp", ".hxx", ".h++"}
            records.append({
                "path": rel,
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "sha256": hashlib.sha256(data).hexdigest(),
                "language": "header" if is_header else "c" if path.suffix == ".c" else "cpp",
                "is_header": is_header,
            })
    return sorted(records, key=lambda item: item["path"])


def _matches(relative: str, patterns: list[str]) -> bool:
    path = Path(relative)
    return any(
        path.match(pattern)
        or (pattern.startswith("**/") and path.match(pattern[3:]))
        or relative == pattern.rstrip("/")
        or relative.startswith(pattern.rstrip("/") + "/")
        for pattern in patterns
    )


def _gitignore_patterns(source: Path) -> list[str]:
    path = source / ".gitignore"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return []
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def _gitignored(relative: str, patterns: list[str]) -> bool:
    ignored = False
    relative = relative.rstrip("/")
    path = Path(relative)
    for raw in patterns:
        negate = raw.startswith("!")
        pattern = raw[1:] if negate else raw
        directory_only = pattern.endswith("/")
        pattern = pattern.rstrip("/")
        anchored = pattern.startswith("/")
        pattern = pattern.lstrip("/")
        if not pattern:
            continue
        if "/" not in pattern:
            matched = pattern in path.parts or path.match(pattern)
        elif anchored:
            matched = relative == pattern or relative.startswith(pattern + "/") or path.match(pattern)
        else:
            matched = path.match(pattern) or path.match("**/" + pattern) or relative.startswith(pattern + "/")
        if directory_only:
            matched |= any(Path(*path.parts[:index]).as_posix() == pattern for index in range(1, len(path.parts) + 1))
        if matched:
            ignored = not negate
    return ignored


def git_state(source: Path) -> dict[str, Any]:
    env = {**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}
    try:
        top = subprocess.run(["git", "-C", str(source), "rev-parse", "--show-toplevel"], capture_output=True, text=True, timeout=5, env=env)
        if top.returncode:
            return {"available": False, "commit": None, "dirty": None}
        commit = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, env=env)
        dirty = subprocess.run(["git", "-C", str(source), "status", "--porcelain"], capture_output=True, text=True, timeout=10, env=env)
        return {"available": True, "commit": commit.stdout.strip() if not commit.returncode else None, "dirty": bool(dirty.stdout)}
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "commit": None, "dirty": None}

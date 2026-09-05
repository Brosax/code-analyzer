from __future__ import annotations

import errno
import hashlib
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

EXTENSIONS = {".c", ".C", ".cc", ".cpp", ".cxx", ".c++", ".h", ".H", ".hh", ".hpp", ".hxx", ".h++"}
DEFAULT_DIRS = {
    ".git", ".hg", ".svn", ".agents", ".codex", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", ".nox", ".venv", "venv", "env", "node_modules", "build", "out", "dist",
    "CMakeFiles",
}
# The operations source discovery can fail at, in the one set of words the
# manifest, the event log, the dashboard and the live page all use.
READ, STAT, WALK, IGNORE_RULES = "read", "stat", "walk", "gitignore"


@dataclass(frozen=True)
class ScopeAnomaly:
    """One thing source discovery could not read.

    ``path`` is relative to the source root (``.`` is the root itself), so the
    record names a file inside the scanned tree and never a host path, and
    ``reason`` is the operating system's own sentence for the failure rather
    than a message that would embed one.
    """

    path: str
    operation: str
    error: str | None
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "operation": self.operation, "error": self.error, "reason": self.reason}


@dataclass(frozen=True)
class Discovery:
    """What one walk of the source tree read, and what it could not read.

    ``files`` is what the analyzers receive: the files that were read whole.
    ``anomalies`` is everything the walk failed on, so a file missing from the
    inventory is a recorded fact instead of a silent omission.  A discovery
    carrying anomalies describes an incomplete scope: the run continues on the
    evidence it has, but it must not claim to have covered the tree.
    """

    files: list[dict[str, Any]]
    anomalies: tuple[ScopeAnomaly, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.anomalies


def scope_summary(initial: Discovery, recheck: Discovery | None = None) -> dict[str, Any]:
    """The manifest's completeness block: counts, not the anomaly records.

    The records themselves live in ``inputs/source-inventory.json``; what the
    manifest carries is what a reader needs in order to decide whether the run
    covered the tree.  ``recheck`` is the post-analysis stability walk, absent
    on a run that never reached it.
    """
    unique = {
        (item.path, item.operation): item
        for item in (*initial.anomalies, *(recheck.anomalies if recheck is not None else ()))
    }
    operations = [item.operation for item in unique.values()]
    return {
        "complete": initial.complete and (recheck is None or recheck.complete),
        "discovery_complete": initial.complete,
        "recheck_complete": None if recheck is None else recheck.complete,
        "unreadable_files": sum(1 for name in operations if name in {READ, STAT}),
        "unreadable_directories": operations.count(WALK),
        "unreadable_ignore_files": operations.count(IGNORE_RULES),
        "anomalies": len(unique),
    }


def scope_sentence(total: int, scope: dict[str, Any]) -> str:
    """The one line about scan scope that every front end repeats.

    It always names the inventory first, because that is the number every
    downstream count is relative to, and it names the gaps second, because a
    coverage figure computed over an unknown denominator is worse than one
    the reader knows is partial.
    """
    head = f"inventory ready: {total} files"
    gaps: list[str] = []
    if scope.get("unreadable_files"):
        gaps.append(_plural(int(scope["unreadable_files"]), "file", "files") + " could not be read")
    if scope.get("unreadable_directories"):
        gaps.append(_plural(int(scope["unreadable_directories"]), "directory", "directories") + " could not be traversed")
    if scope.get("unreadable_ignore_files"):
        gaps.append(_plural(int(scope["unreadable_ignore_files"]), ".gitignore", ".gitignore files") + " could not be read")
    if not gaps:
        return head
    unknown = "; the number of source files inside them is unknown" if scope.get("unreadable_directories") else ""
    return f"{head}; {', '.join(gaps)}{unknown}; scan scope is incomplete"


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


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
) -> Discovery:
    """Walk the source tree and report both halves of what it found.

    A file that cannot be read, a file whose attributes cannot be read and a
    directory that cannot be traversed each become a :class:`ScopeAnomaly`.
    They used to be skipped without a trace, which made "120 files" and "120
    files this process was allowed to read" the same sentence.
    """
    follow = config["source"]["follow_symlinks"]
    custom_excludes = list(config["source"]["exclude"])
    custom_includes = list(config["source"]["include"])
    anomalies: list[ScopeAnomaly] = []
    gitignore = _gitignore_patterns(source, anomalies) if config["source"]["respect_gitignore"] else []
    dynamic: Path | None = None
    try:
        dynamic = output_root.resolve().relative_to(source.resolve())
    except ValueError:
        pass
    records: list[dict[str, Any]] = []

    def untraversable(exc: OSError) -> None:
        anomalies.append(_anomaly(_relative(source, exc.filename), WALK, exc))

    for root, dirs, files in os.walk(source, onerror=untraversable, followlinks=follow):
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
            try:
                excluded |= child.is_symlink() and not follow
            except OSError as exc:
                # Undecidable is not the same as excluded: we are declining to
                # enter a directory whose contents therefore stay unknown, and
                # that is exactly what an untraversable directory means here.
                anomalies.append(_anomaly(rel, WALK, exc))
                excluded = True
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
            try:
                symlink = path.is_symlink()
            except OSError as exc:
                anomalies.append(_anomaly(rel, STAT, exc))
                continue
            if symlink and not follow:
                continue
            # Read and stat are separate failures on purpose: "the bytes were
            # unreadable" and "the size was unreadable" send an operator to
            # different places.
            try:
                data = path.read_bytes()
            except OSError as exc:
                anomalies.append(_anomaly(rel, READ, exc))
                continue
            try:
                stat = path.stat()
            except OSError as exc:
                anomalies.append(_anomaly(rel, STAT, exc))
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
    return Discovery(
        sorted(records, key=lambda item: item["path"]),
        tuple(sorted(anomalies, key=lambda item: (item.path, item.operation))),
    )


def _anomaly(relative: str, operation: str, exc: BaseException) -> ScopeAnomaly:
    code = None
    if isinstance(exc, OSError) and exc.errno is not None:
        code = errno.errorcode.get(exc.errno) or str(exc.errno)
    reason = getattr(exc, "strerror", None) or type(exc).__name__
    return ScopeAnomaly(relative, operation, code, str(reason))


def _relative(source: Path, target: Any) -> str:
    """A failure's filename as a source-relative path; ``.`` for the root."""
    if target is None:
        return "."
    try:
        value = Path(os.fsdecode(target))
    except (TypeError, ValueError):
        return "."
    try:
        return value.relative_to(source).as_posix() or "."
    except ValueError:
        return value.name or "."


def _matches(relative: str, patterns: list[str]) -> bool:
    path = Path(relative)
    return any(
        path.match(pattern)
        or (pattern.startswith("**/") and path.match(pattern[3:]))
        or relative == pattern.rstrip("/")
        or relative.startswith(pattern.rstrip("/") + "/")
        for pattern in patterns
    )


def _gitignore_patterns(source: Path, anomalies: list[ScopeAnomaly]) -> list[str]:
    path = source / ".gitignore"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError) as exc:
        # An unreadable rule file leaves the scope undecidable rather than
        # empty: without it we cannot say which paths Git would have hidden.
        anomalies.append(_anomaly(".gitignore", IGNORE_RULES, exc))
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

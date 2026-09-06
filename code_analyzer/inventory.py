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

    The three ``unreadable_*`` figures count distinct paths, so one file that
    failed at ``read`` in the first walk and at ``stat`` in the second is one
    unreadable file rather than two; ``anomalies`` counts the records, which
    is the number of rows a reader will find in the inventory document.
    """
    unique = {
        (item.path, item.operation): item
        for item in (*initial.anomalies, *(recheck.anomalies if recheck is not None else ()))
    }

    def paths(*operations: str) -> set[str]:
        return {item.path for item in unique.values() if item.operation in operations}

    return {
        "complete": initial.complete and (recheck is None or recheck.complete),
        "discovery_complete": initial.complete,
        "recheck_complete": None if recheck is None else recheck.complete,
        "unreadable_files": len(paths(READ, STAT)),
        "unreadable_directories": len(paths(WALK)),
        "unreadable_ignore_files": len(paths(IGNORE_RULES)),
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
    respect_gitignore = bool(config["source"]["respect_gitignore"])
    anomalies: list[ScopeAnomaly] = []
    # One entry per visited directory: the rules in force there, ancestors
    # first.  os.walk is top-down, so a directory's parent is always already
    # in the map, and a directory with no rules of its own shares its parent's
    # tuple rather than copying it.
    rules_by_directory: dict[str, tuple[_IgnoreRule, ...]] = {}
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
        here = "" if rel_root == Path(".") else rel_root.as_posix()
        rules: tuple[_IgnoreRule, ...] = ()
        if respect_gitignore:
            inherited = rules_by_directory.get(here.rpartition("/")[0], ()) if here else ()
            own = _ignore_rules(root_path / ".gitignore", here, anomalies)
            rules = (*inherited, *own) if own else inherited
            rules_by_directory[here] = rules
        kept = []
        for dirname in dirs:
            rel = (rel_root / dirname).as_posix()
            excluded = dirname in DEFAULT_DIRS or dirname.startswith("cmake-build-")
            excluded |= dynamic is not None and (Path(rel) == dynamic or dynamic in Path(rel).parents)
            excluded |= _matches(rel, custom_excludes) or _gitignored(rel, rules, directory=True)
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
            if path.suffix not in EXTENSIONS or not included or _matches(rel, custom_excludes) or _gitignored(rel, rules, directory=False):
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


@dataclass(frozen=True)
class _IgnoreRule:
    """One .gitignore line, bound to the directory whose file it was read in.

    Git resolves a path against the rules of every directory from the
    repository root down to the one holding it, with the deeper file winning
    and, within one file, the last matching line winning.  ``base`` is what
    makes that possible: a rule from ``vendor/.gitignore`` applies only under
    ``vendor/`` and matches relative to it, which is why a single flat list of
    root patterns was never able to express a nested ignore file.
    """

    base: str
    negate: bool
    directory_only: bool
    regex: re.Pattern[str]

    def matches(self, relative: str, *, directory: bool) -> bool:
        if self.directory_only and not directory:
            return False
        if self.base:
            if not relative.startswith(self.base + "/"):
                return False
            relative = relative[len(self.base) + 1:]
        return self.regex.fullmatch(relative) is not None


def _ignore_rules(path: Path, base: str, anomalies: list[ScopeAnomaly]) -> tuple[_IgnoreRule, ...]:
    """Compile one .gitignore file, or record why its rules are unknown.

    Only ``.gitignore`` files inside the scanned tree are read.  Git's other
    rule sources -- ``.git/info/exclude``, ``core.excludesFile``, the skip-worktree
    bits in the index -- are deliberately not consulted: they live outside the
    tree being analysed, so honouring them would make the same source produce
    different scopes on two machines.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ()
    except (OSError, UnicodeError) as exc:
        # An unreadable rule file leaves the scope undecidable rather than
        # empty: without it we cannot say which paths Git would have hidden.
        anomalies.append(_anomaly(f"{base}/.gitignore" if base else ".gitignore", IGNORE_RULES, exc))
        return ()
    compiled = (_compile_ignore(line, base) for line in text.splitlines())
    return tuple(rule for rule in compiled if rule is not None)


def _gitignored(relative: str, rules: tuple[_IgnoreRule, ...], *, directory: bool) -> bool:
    """Whether Git would ignore ``relative``; the last matching rule decides.

    Directories are pruned by the walk when this says yes, which is also how
    Git behaves: a file whose parent directory is excluded cannot be brought
    back by a negation on the file itself, because Git never descends far
    enough to read one.
    """
    ignored = False
    for rule in rules:
        if rule.matches(relative, directory=directory):
            ignored = not rule.negate
    return ignored


def _compile_ignore(line: str, base: str) -> _IgnoreRule | None:
    """One raw line as a rule, or None when it is a comment or blank."""
    pattern = _without_trailing_spaces(line)
    if not pattern or pattern.startswith("#"):
        return None
    negate = pattern.startswith("!")
    if negate:
        pattern = pattern[1:]
    elif pattern[:1] == "\\" and pattern[1:2] in {"#", "!"}:
        pattern = pattern[1:]
    directory_only = pattern.endswith("/") and not _escaped_at(pattern, len(pattern) - 1)
    if directory_only:
        pattern = pattern.rstrip("/")
    # A separator anywhere but the end anchors the pattern to ``base``; without
    # one it is a name matched at any depth below it.
    anchored = "/" in pattern
    pattern = pattern.lstrip("/")
    if not pattern:
        return None
    body = _ignore_regex(pattern)
    try:
        regex = re.compile(("" if anchored else "(?:.+/)?") + body)
    except re.error:
        regex = re.compile(("" if anchored else "(?:.+/)?") + re.escape(pattern))
    return _IgnoreRule(base, negate, directory_only, regex)


def _ignore_regex(pattern: str) -> str:
    """Git's glob for a whole path: ``**`` spans directories, ``*`` does not."""
    segments = pattern.split("/")
    parts: list[str] = []
    separator = False
    for index, segment in enumerate(segments):
        if segment == "**":
            if index == len(segments) - 1:
                # A trailing ``/**`` matches everything inside, not the
                # directory itself.
                parts.append("/.+" if separator else ".+")
            else:
                # ``**/`` in front, or ``a/**/b`` in the middle: zero or more
                # directories, so ``a/**/b`` still matches ``a/b``.
                parts.append("/(?:.+/)?" if separator else "(?:.+/)?")
            separator = False
            continue
        piece = _segment_regex(segment)
        parts.append("/" + piece if separator else piece)
        separator = True
    return "".join(parts)


# The POSIX bracket expressions Git accepts inside ``[...]``.  Python's re has
# no equivalent, so each is expanded into the characters it names.
_POSIX_CLASSES = {
    "alnum": "a-zA-Z0-9",
    "alpha": "a-zA-Z",
    "blank": r" \t",
    "cntrl": r"\x00-\x1f\x7f",
    "digit": "0-9",
    "graph": r"\x21-\x7e",
    "lower": "a-z",
    "print": r"\x20-\x7e",
    "punct": r"!-/:-@\[-`{-~",
    "space": r" \t\n\r\f\v",
    "upper": "A-Z",
    "xdigit": "0-9A-Fa-f",
}


def _segment_regex(segment: str) -> str:
    """One path segment's glob; nothing here may match a separator."""
    out: list[str] = []
    index = 0
    while index < len(segment):
        char = segment[index]
        if char == "\\" and index + 1 < len(segment):
            out.append(re.escape(segment[index + 1]))
            index += 2
            continue
        if char == "*":
            while index + 1 < len(segment) and segment[index + 1] == "*":
                index += 1
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[":
            end = _class_end(segment, index)
            body = None if end is None else _class_body(segment[index + 1:end])
            if body is None:
                out.append(re.escape(char))
            else:
                out.append("[" + body + "]")
                index = end
        else:
            out.append(re.escape(char))
        index += 1
    return "".join(out)


def _class_body(body: str) -> str | None:
    """A bracket expression's contents as a Python class, or None if unusable.

    ``[[:digit:]]`` and its eleven siblings are Git's, not Python's, so they
    are expanded here rather than passed through -- an unexpanded one used to
    read as the literal characters of its own name.  A name Git does not
    define either leaves the whole pattern to the literal fallback.
    """
    if not body:
        return None
    negated = body[0] in {"!", "^"}
    out: list[str] = ["^"] if negated else []
    index = 1 if negated else 0
    while index < len(body):
        char = body[index]
        if char == "\\" and index + 1 < len(body):
            out.append(re.escape(body[index + 1]))
            index += 2
            continue
        if body.startswith("[:", index):
            closing = body.find(":]", index + 2)
            if closing == -1:
                return None
            expansion = _POSIX_CLASSES.get(body[index + 2:closing])
            if expansion is None:
                return None
            out.append(expansion)
            index = closing + 2
            continue
        out.append("\\" + char if char in {"]", "\\"} else char)
        index += 1
    return "".join(out) or None


def _class_end(segment: str, start: int) -> int | None:
    """Index of the ``]`` closing a bracket expression opened at ``start``."""
    index = start + 1
    if index < len(segment) and segment[index] in {"!", "^"}:
        index += 1
    if index < len(segment) and segment[index] == "]":
        index += 1
    while index < len(segment) and segment[index] != "]":
        if segment[index] == "\\":
            index += 2
            continue
        # A POSIX class carries a ``]`` of its own; it does not close the
        # bracket expression that holds it.
        if segment.startswith("[:", index):
            closing = segment.find(":]", index + 2)
            if closing == -1:
                return None
            index = closing + 2
            continue
        index += 1
    return index if index < len(segment) else None


def _without_trailing_spaces(line: str) -> str:
    """Git drops trailing spaces unless a backslash quotes them."""
    index = len(line)
    while index > 0 and line[index - 1] == " " and not _escaped_at(line, index - 1):
        index -= 1
    return line[:index]


def _escaped_at(value: str, index: int) -> bool:
    backslashes = 0
    while index - backslashes > 0 and value[index - backslashes - 1] == "\\":
        backslashes += 1
    return backslashes % 2 == 1


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

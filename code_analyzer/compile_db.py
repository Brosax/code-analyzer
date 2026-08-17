from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Iterable

from .errors import UserError


_DATABASE_NAME = "compile_commands.json"
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"}
_MAX_CANDIDATES = 64
_MAX_DEPTH = 3


def resolve_compile_db(
    source: Path, config: dict[str, Any]
) -> tuple[Path | None, list[dict[str, Any]], list[str], dict[str, Any]]:
    """Resolve an explicit or automatically discovered compilation database.

    Discovery is deliberately read-only and bounded.  Explicit paths remain
    strict input: any validation failure is a user error.  Automatic discovery
    records bad candidates, but can continue to a better candidate.
    """
    source = source.resolve()
    build = config["build"]
    mode = build["compile_database_mode"]
    if mode == "disabled":
        discovery = _discovery_result(source, [], None, "disabled")
        return None, [], ["compile database disabled"], discovery

    explicit = Path(build["compile_database"]).expanduser().resolve() if build.get("compile_database") else None
    candidate_paths = [explicit] if explicit is not None else discover_candidate_paths(source)
    candidates = [inspect_compile_db(path, source) for path in candidate_paths]
    valid = [item for item in candidates if item["usable"]]

    if explicit is not None:
        selected = valid[0] if valid else None
        if selected is None:
            reason = candidates[0]["issues"][0] if candidates else "file does not exist"
            raise UserError(f"invalid compile database {explicit}: {reason}")
    else:
        selected = max(valid, key=_candidate_score, default=None)

    discovery = _discovery_result(source, candidates, selected, mode)
    if selected is None:
        # Keep the historical strictness for a corrupt database at the
        # conventional source-root location. Other unusable discovered files
        # are diagnostics and do not prevent fallback analysis.
        conventional = source / _DATABASE_NAME
        direct = next((item for item in candidates if Path(item["path"]) == conventional), None)
        if direct is not None and direct["exists"] and not direct["valid"]:
            raise UserError(f"invalid compile database {conventional}: {direct['issues'][0]}")
        reason = "compile database not found; fallback analysis has reduced build context"
        if candidates:
            reason = "no valid compile database found; fallback analysis has reduced build context"
        return None, [], [reason], discovery

    path = Path(selected["path"])
    entries = _load_normalized(path)
    degraded: list[str] = []
    if selected["missing_files"]:
        degraded.append(f"compile database references {selected['missing_files']} missing source file(s)")
    if selected["invalid_directories"]:
        degraded.append(f"compile database has {selected['invalid_directories']} invalid working directorie(s)")
    if selected["possibly_stale"]:
        degraded.append("compile database may be stale")
    return path, entries, degraded, discovery


def discover_candidate_paths(source: Path, *, limit: int = _MAX_CANDIDATES) -> list[Path]:
    """Return bounded candidates in deterministic order without following links."""
    source = source.resolve()
    result: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        if len(result) >= limit or path.is_symlink():
            return
        absolute = path.absolute()
        if absolute not in seen and path.is_file():
            seen.add(absolute)
            result.append(absolute)

    add(source / _DATABASE_NAME)
    roots: list[Path] = []
    try:
        children = sorted(source.iterdir(), key=lambda item: item.name)
    except OSError:
        children = []
    for child in children:
        if child.is_symlink() or not child.is_dir():
            continue
        if child.name == "out" or child.name.startswith("build") or child.name.startswith("cmake-build-"):
            roots.append(child)
    for name in ("build", "out"):
        adjacent = source.parent / name
        if not adjacent.is_symlink() and adjacent.is_dir():
            roots.append(adjacent)
    for root in roots:
        for path in _bounded_named_files(root, _DATABASE_NAME, _MAX_DEPTH):
            add(path)
            if len(result) >= limit:
                return result
    return result


def _bounded_named_files(root: Path, name: str, max_depth: int) -> Iterable[Path]:
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        candidate = directory / name
        if not candidate.is_symlink() and candidate.is_file():
            yield candidate
        if depth >= max_depth:
            continue
        try:
            children = sorted(
                (item for item in directory.iterdir() if not item.is_symlink() and item.is_dir()),
                key=lambda item: item.name,
                reverse=True,
            )
        except OSError:
            continue
        stack.extend((child, depth + 1) for child in children)


def inspect_compile_db(path: Path, source: Path) -> dict[str, Any]:
    path = path.expanduser().absolute()
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.is_file() and not path.is_symlink(),
        "valid": False,
        "usable": False,
        "entries": 0,
        "translation_units": 0,
        "covered_source_tus": 0,
        "database_translation_units": 0,
        "source_coverage_ratio": 0.0,
        "coverage": {"covered_source_tus": 0, "database_translation_units": 0, "ratio": 0.0},
        "valid_directories": 0,
        "invalid_directories": 0,
        "valid_directory_ratio": 0.0,
        "missing_files": 0,
        "possibly_stale": False,
        "mtime": None,
        "issues": [],
    }
    if not result["exists"]:
        result["issues"].append("file does not exist")
        return result
    try:
        result["mtime"] = path.stat().st_mtime
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        result["issues"].append(str(exc))
        return result
    if not isinstance(data, list):
        result["issues"].append("root must be an array")
        return result
    if not data:
        result["issues"].append("database contains no entries")
        return result

    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(data):
        issue = _entry_issue(entry)
        if issue:
            result["issues"].append(f"entry {index} {issue}")
            continue
        assert isinstance(entry, dict)
        normalized.append(_normalize_entry(path, entry))
    if result["issues"]:
        return result

    files = {item["file"] for item in normalized}
    result["entries"] = len(normalized)
    result["translation_units"] = len(files)
    result["database_translation_units"] = len(files)
    directory_status = {value: Path(value).is_dir() for value in {item["directory"] for item in normalized}}
    result["valid_directories"] = sum(directory_status[item["directory"]] for item in normalized)
    result["invalid_directories"] = len(normalized) - result["valid_directories"]
    result["valid_directory_ratio"] = round(result["valid_directories"] / len(normalized), 6)
    result["missing_files"] = sum(not Path(value).is_file() for value in files)
    source_files = [Path(value) for value in files if _within(Path(value), source) and Path(value).suffix.lower() in _SOURCE_SUFFIXES]
    result["covered_source_tus"] = sum(item.is_file() for item in source_files)
    result["source_coverage_ratio"] = round(result["covered_source_tus"] / len(files), 6) if files else 0.0
    newest_source = max((item.stat().st_mtime for item in source_files if item.is_file()), default=None)
    result["possibly_stale"] = bool(newest_source is not None and result["mtime"] is not None and newest_source > result["mtime"])
    if result["invalid_directories"]:
        result["issues"].append(f"{result['invalid_directories']} working directorie(s) do not exist")
    if result["missing_files"]:
        result["issues"].append(f"{result['missing_files']} referenced source file(s) do not exist")
    if result["possibly_stale"]:
        result["issues"].append("database is older than at least one covered source file")
    result["valid"] = True
    result["usable"] = bool(result["valid_directories"] and result["covered_source_tus"])
    if not result["usable"]:
        if not result["valid_directories"]:
            result["issues"].append("database has no valid working directory")
        if not result["covered_source_tus"]:
            result["issues"].append("database covers no existing translation unit in the source tree")
    result["coverage"] = {
        "covered_source_tus": result["covered_source_tus"],
        "database_translation_units": result["database_translation_units"],
        "ratio": result["source_coverage_ratio"],
    }
    return result


def _entry_issue(entry: Any) -> str | None:
    if not isinstance(entry, dict):
        return "must be an object"
    if not isinstance(entry.get("file"), str) or not entry["file"]:
        return "lacks a non-empty file"
    if not isinstance(entry.get("directory"), str) or not entry["directory"]:
        return "lacks a non-empty directory"
    valid_arguments = (
        isinstance(entry.get("arguments"), list)
        and bool(entry["arguments"])
        and all(isinstance(x, str) for x in entry["arguments"])
    )
    valid_command = isinstance(entry.get("command"), str) and bool(entry["command"])
    if "arguments" not in entry and "command" not in entry:
        return "lacks arguments/command"
    if not valid_arguments and not valid_command:
        return "has invalid arguments/command"
    return None


def _normalize_entry(database: Path, entry: dict[str, Any]) -> dict[str, Any]:
    directory = Path(entry["directory"])
    if not directory.is_absolute():
        directory = (database.parent / directory).resolve()
    else:
        directory = directory.resolve()
    file_path = Path(entry["file"])
    if not file_path.is_absolute():
        file_path = (directory / file_path).resolve()
    else:
        file_path = file_path.resolve()
    item: dict[str, Any] = {"directory": str(directory), "file": str(file_path)}
    if isinstance(entry.get("arguments"), list) and entry["arguments"] and all(isinstance(x, str) for x in entry["arguments"]):
        item["arguments"] = list(entry["arguments"])
    else:
        item["command"] = entry["command"]
    if isinstance(entry.get("output"), str):
        item["output"] = entry["output"]
    return item


def _load_normalized(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [_normalize_entry(path, entry) for entry in data]


def _candidate_score(candidate: dict[str, Any]) -> tuple[int, float, float]:
    return (
        int(candidate["covered_source_tus"]),
        float(candidate["valid_directory_ratio"]),
        float(candidate["mtime"] or 0.0),
    )


def _discovery_result(
    source: Path, candidates: list[dict[str, Any]], selected: dict[str, Any] | None, mode: str
) -> dict[str, Any]:
    return {
        "mode": mode,
        "source": str(source),
        "selected": selected["path"] if selected else None,
        "candidate_count": len(candidates),
        "candidates": candidates,
    }


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def filter_database(source: Path, inventory: list[dict[str, Any]], entries: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], set[str]]:
    allowed = {str((source / item["path"]).resolve()): item["path"] for item in inventory if not item["is_header"]}
    filtered: list[dict[str, Any]] = []
    covered: set[str] = set()
    for entry in entries:
        absolute = str(Path(entry["file"]).resolve())
        if absolute in allowed:
            filtered.append(entry)
            covered.add(allowed[absolute])
    return filtered, covered


def arguments(entry: dict[str, Any]) -> list[str]:
    if "arguments" in entry:
        return list(entry["arguments"])
    try:
        return shlex.split(entry["command"])
    except ValueError:
        return []


def splint_flags(entry: dict[str, Any]) -> list[str]:
    """Translate only include and preprocessor options from a compilation command."""
    args = arguments(entry)[1:]
    directory = Path(entry["directory"])
    result: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in {"-I", "-isystem", "-iquote"} and index + 1 < len(args):
            result.append("-I" + _include_path(args[index + 1], directory))
            index += 2
            continue
        matched_include = next((prefix for prefix in ("-isystem", "-iquote", "-I") if arg.startswith(prefix) and len(arg) > len(prefix)), None)
        if matched_include:
            result.append("-I" + _include_path(arg[len(matched_include):], directory))
            index += 1
            continue
        if arg in {"-D", "-U"} and index + 1 < len(args):
            result.append(arg + args[index + 1])
            index += 2
            continue
        if any(arg.startswith(prefix) and len(arg) > len(prefix) for prefix in ("-D", "-U")):
            result.append(arg)
        elif arg == "-include":
            index += 2
            continue
        index += 1
    return result


def _include_path(value: str, directory: Path) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = directory / path
    return str(path.resolve())

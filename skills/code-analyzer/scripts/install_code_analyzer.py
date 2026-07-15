#!/usr/bin/env python3
"""Install the shared Code Analyzer skill for supported local agent hosts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


HOST_DIRS = {
    "codex": Path(".agents/skills"),
    "pi": Path(".agents/skills"),
    "claude": Path(".claude/skills"),
    "hermes": Path(".hermes/skills"),
}
LEGACY_NAMES = ("c-cpp-review-suite", "cppcheck-analysis", "flawfinder-analysis", "splint-analysis")
MARKER = ".code-analyzer-source.json"


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--hosts", default="auto", help="auto or comma-separated codex,claude,pi,hermes")
    modes = result.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true")
    modes.add_argument("--uninstall", action="store_true")
    result.add_argument("--copy", action="store_true", help="Copy instead of creating symbolic links.")
    result.add_argument("--migrate-legacy", action="store_true")
    return result


def source_skill() -> Path:
    return Path(__file__).resolve().parents[1]


def select_hosts(value: str, home: Path) -> List[str]:
    if value == "auto":
        detected = [name for name in ("codex", "claude", "pi", "hermes") if (home / HOST_DIRS[name].parent).exists()]
        return detected or ["codex"]
    hosts = [item.strip().lower() for item in value.split(",") if item.strip()]
    invalid = [item for item in hosts if item not in HOST_DIRS]
    if invalid:
        raise ValueError("unsupported host(s): %s" % ", ".join(invalid))
    if not hosts:
        raise ValueError("--hosts must select at least one host")
    if len(hosts) != len(set(hosts)):
        raise ValueError("--hosts contains duplicate host names")
    return hosts


def destinations(hosts: Iterable[str], home: Path) -> Dict[Path, List[str]]:
    grouped: Dict[Path, List[str]] = {}
    for host in hosts:
        grouped.setdefault(home / HOST_DIRS[host] / "code-analyzer", []).append(host)
    return grouped


def _marker_matches(path: Path, source: Path) -> bool:
    marker = path / MARKER
    try:
        payload = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(payload, dict) and payload.get("source") == str(source)


def _marker_payload(path: Path) -> Dict[str, str]:
    try:
        payload = json.loads((path / MARKER).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def content_hash(path: Path) -> str:
    digest = hashlib.sha256()
    for candidate in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = candidate.relative_to(path)
        if MARKER == candidate.name or "__pycache__" in relative.parts or candidate.suffix in (".pyc", ".pyo"):
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        if candidate.is_symlink():
            digest.update(b"L")
            digest.update(os.readlink(str(candidate)).encode("utf-8"))
        elif candidate.is_file():
            digest.update(b"F")
            digest.update(b"X" if candidate.stat().st_mode & 0o111 else b"-")
            with candidate.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        elif candidate.is_dir():
            digest.update(b"D")
        digest.update(b"\0")
    return digest.hexdigest()


def ownership(path: Path, source: Path) -> str:
    if path.is_symlink():
        try:
            return "owned" if path.resolve(strict=False) == source else "conflict"
        except OSError:
            return "conflict"
    if path.exists():
        return "owned" if path.is_dir() and _marker_matches(path, source) else "conflict"
    return "missing"


def legacy_paths(skill_parent: Path) -> List[Path]:
    return [skill_parent / name for name in LEGACY_NAMES if (skill_parent / name).exists() or (skill_parent / name).is_symlink()]


def _copy_ignore(_: str, names: List[str]) -> List[str]:
    return [name for name in names if name == MARKER or name == "__pycache__" or name.endswith((".pyc", ".pyo"))]


def install_copy(source: Path, destination: Path, source_hash: Optional[str] = None) -> None:
    temporary = destination.parent / (".%s.copying-%s" % (destination.name, os.getpid()))
    if temporary.exists() or temporary.is_symlink():
        if temporary.is_symlink():
            temporary.unlink()
        else:
            shutil.rmtree(str(temporary))
    try:
        shutil.copytree(str(source), str(temporary), symlinks=True, ignore=_copy_ignore)
        payload = {"source": str(source), "content_sha256": source_hash or content_hash(source)}
        (temporary / MARKER).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(str(temporary), str(destination))
    finally:
        if temporary.exists():
            shutil.rmtree(str(temporary))


def install_link(source: Path, destination: Path) -> None:
    temporary = destination.parent / (".%s.linking-%s" % (destination.name, os.getpid()))
    if temporary.exists() or temporary.is_symlink():
        _remove_path(temporary)
    try:
        temporary.symlink_to(source, target_is_directory=True)
        os.replace(str(temporary), str(destination))
    finally:
        if temporary.is_symlink():
            temporary.unlink()


def _remove_path(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        path.unlink()
    elif path.exists():
        shutil.rmtree(str(path))


def _unique_sibling(path: Path, label: str) -> Path:
    candidate = path.with_name(".%s.%s" % (path.name, label))
    counter = 1
    while candidate.exists() or candidate.is_symlink():
        candidate = path.with_name(".%s.%s-%d" % (path.name, label, counter))
        counter += 1
    return candidate


def _legacy_backup(path: Path, stamp: str) -> Path:
    candidate = path.with_name("%s.legacy-%s" % (path.name, stamp))
    counter = 1
    while candidate.exists() or candidate.is_symlink():
        candidate = path.with_name("%s.legacy-%s-%d" % (path.name, stamp, counter))
        counter += 1
    return candidate


def _refresh_marker(path: Path, source: Path, source_hash: str) -> None:
    payload = {"source": str(source), "content_sha256": source_hash}
    temporary = path / (".%s.tmp-%s" % (MARKER, os.getpid()))
    try:
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(str(temporary), str(path / MARKER))
    finally:
        if temporary.exists():
            temporary.unlink()


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    source = source_skill()
    home = Path.home().resolve()
    try:
        hosts = select_hosts(args.hosts, home)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    grouped = destinations(hosts, home)

    # Validate every target before migrating or mutating any path.
    ownership_states = {path: ownership(path, source) for path in grouped}
    conflicts = [path for path, state in ownership_states.items() if state == "conflict"]
    if conflicts:
        for path in conflicts:
            print("error: refusing to overwrite non-plugin path: %s" % path, file=sys.stderr)
        return 2

    try:
        source_hash = content_hash(source)
    except OSError as exc:
        print("error: unable to hash source skill: %s" % exc, file=sys.stderr)
        return 2
    states: Dict[Path, str] = {}
    for path, state in ownership_states.items():
        if state != "owned":
            states[path] = state
        elif path.is_symlink():
            states[path] = "current"
        else:
            try:
                states[path] = "current" if content_hash(path) == source_hash else "stale"
            except OSError as exc:
                print("error: unable to verify installed skill %s: %s" % (path, exc), file=sys.stderr)
                return 2

    if args.check:
        missing = [path for path, state in states.items() if state != "current"]
        for path, host_names in grouped.items():
            print("%s: %s (%s)" % (",".join(host_names), states[path], path))
        return 1 if missing else 0

    if args.uninstall:
        for path, state in ownership_states.items():
            if state != "owned":
                continue
            _remove_path(path)
            print("removed: %s" % path)
        return 0

    all_legacy = sorted(
        {path for destination in grouped for path in legacy_paths(destination.parent)},
        key=lambda path: str(path),
    )
    if all_legacy and not args.migrate_legacy:
        print(
            "error: legacy skills found; use --migrate-legacy: %s"
            % ", ".join(str(path) for path in all_legacy),
            file=sys.stderr,
        )
        return 2

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    migrated: List[Tuple[Path, Path]] = []
    replaced: List[Tuple[Path, Path]] = []
    installed: List[Path] = []
    markers_to_refresh: List[Path] = []
    try:
        for destination in grouped:
            destination.parent.mkdir(parents=True, exist_ok=True)
        for legacy in all_legacy:
            backup = _legacy_backup(legacy, stamp)
            os.replace(str(legacy), str(backup))
            migrated.append((legacy, backup))

        for destination, host_names in grouped.items():
            if states[destination] == "current":
                if not destination.is_symlink():
                    marker = _marker_payload(destination)
                    if marker.get("content_sha256") != source_hash:
                        markers_to_refresh.append(destination)
                print("already installed: %s (%s)" % (destination, ",".join(host_names)))
                continue
            if states[destination] == "stale":
                rollback = _unique_sibling(destination, "rollback-%s" % os.getpid())
                os.replace(str(destination), str(rollback))
                replaced.append((destination, rollback))
            if args.copy or os.name == "nt":
                install_copy(source, destination, source_hash)
            else:
                install_link(source, destination)
            installed.append(destination)
            print("installed: %s (%s)" % (destination, ",".join(host_names)))
    except (OSError, shutil.Error) as exc:
        rollback_errors = []
        for destination in reversed(installed):
            try:
                _remove_path(destination)
            except OSError as rollback_error:
                rollback_errors.append(str(rollback_error))
        for destination, rollback in reversed(replaced):
            try:
                if destination.exists() or destination.is_symlink():
                    _remove_path(destination)
                os.replace(str(rollback), str(destination))
            except OSError as rollback_error:
                rollback_errors.append(str(rollback_error))
        for legacy, backup in reversed(migrated):
            try:
                os.replace(str(backup), str(legacy))
            except OSError as rollback_error:
                rollback_errors.append(str(rollback_error))
        suffix = " (rollback incomplete: %s)" % "; ".join(rollback_errors) if rollback_errors else ""
        print("error: installation failed and was rolled back: %s%s" % (exc, suffix), file=sys.stderr)
        return 2

    for destination in markers_to_refresh:
        try:
            _refresh_marker(destination, source, source_hash)
        except OSError as exc:
            print("warning: could not refresh install marker %s: %s" % (destination, exc), file=sys.stderr)
    for _, rollback in replaced:
        try:
            _remove_path(rollback)
        except OSError as exc:
            print("warning: could not remove transaction backup %s: %s" % (rollback, exc), file=sys.stderr)
    for legacy, backup in migrated:
        print("migrated: %s -> %s" % (legacy, backup))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

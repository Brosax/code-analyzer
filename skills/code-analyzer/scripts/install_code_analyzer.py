#!/usr/bin/env python3
"""Install the shared Code Analyzer skill for supported local agent hosts."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Sequence


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
    return payload.get("source") == str(source)


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


def backup_legacy(paths: Sequence[Path], stamp: str) -> None:
    if not paths:
        return
    backup = paths[0].parent.parent / ("skills-backup-%s" % stamp)
    backup.mkdir(parents=True, exist_ok=True)
    for path in paths:
        destination = backup / path.name
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("backup destination exists: %s" % destination)
        shutil.move(str(path), str(destination))


def install_copy(source: Path, destination: Path) -> None:
    temporary = destination.parent / (".%s.copying-%s" % (destination.name, os.getpid()))
    if temporary.exists():
        shutil.rmtree(str(temporary))
    shutil.copytree(str(source), str(temporary), symlinks=True)
    (temporary / MARKER).write_text(json.dumps({"source": str(source)}, indent=2), encoding="utf-8")
    os.replace(str(temporary), str(destination))


def install_link(source: Path, destination: Path) -> None:
    temporary = destination.parent / (".%s.linking-%s" % (destination.name, os.getpid()))
    temporary.symlink_to(source, target_is_directory=True)
    os.replace(str(temporary), str(destination))


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
    states = {path: ownership(path, source) for path in grouped}
    conflicts = [path for path, state in states.items() if state == "conflict"]
    if conflicts:
        for path in conflicts:
            print("error: refusing to overwrite non-plugin path: %s" % path, file=sys.stderr)
        return 2

    if args.check:
        missing = [path for path, state in states.items() if state != "owned"]
        for path, host_names in grouped.items():
            print("%s: %s (%s)" % (",".join(host_names), states[path], path))
        return 1 if missing else 0

    if args.uninstall:
        for path, state in states.items():
            if state != "owned":
                continue
            if path.is_symlink():
                path.unlink()
            else:
                shutil.rmtree(str(path))
            print("removed: %s" % path)
        return 0

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for destination, host_names in grouped.items():
        destination.parent.mkdir(parents=True, exist_ok=True)
        if states[destination] == "owned":
            print("already installed: %s (%s)" % (destination, ",".join(host_names)))
            continue
        legacy = legacy_paths(destination.parent)
        if legacy and not args.migrate_legacy:
            print("error: legacy skills found; use --migrate-legacy: %s" % ", ".join(str(path) for path in legacy), file=sys.stderr)
            return 2
        if legacy:
            backup_legacy(legacy, stamp)
        if args.copy or os.name == "nt":
            install_copy(source, destination)
        else:
            install_link(source, destination)
        print("installed: %s (%s)" % (destination, ",".join(host_names)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Canonical JSON persistence and manifest structure checks.

Every JSON artifact in a report directory uses one byte representation so
that rebuilds stay byte-stable and hashes stay comparable across the runner
and the offline rebuild-dashboard / recover-report commands.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(json_bytes(value))


def manifest_structure_problem(manifest: Any) -> str | None:
    """Return why a parsed manifest is structurally unusable, or None."""
    if not isinstance(manifest, dict) or manifest.get("manifest_schema_version") != 2:
        return "unsupported or missing manifest schema version"
    if not isinstance(manifest.get("tools"), dict) or not all(
        isinstance(item, dict) for item in manifest["tools"].values()
    ):
        return "tools must be an object of objects"
    if not isinstance(manifest.get("artifacts"), list) or not all(
        isinstance(item, dict) for item in manifest["artifacts"]
    ):
        return "artifacts must be a list of objects"
    return None

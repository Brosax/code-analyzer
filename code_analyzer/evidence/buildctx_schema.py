"""The evaluation-level analysis configuration ("build context"), and its validation.

A build context is the ``[build]`` and ``[tools.*]`` part of the old config:
include paths, defines, compile database, analyzer timeouts.  It is not a
setting the operator tunes; each version (``buildctx/buildctx.vN.toml``) is
produced by an approved patch card and recorded in the ledger, and every tool
call records the sha256 of the version it ran with.

Validation is the old ``config.validate_config`` -- the same rules a patch has
always had to pass (build_context.py ``ConfigPatch.apply``) -- applied to the
defaults with the context merged in.  Anything outside [build] and [tools] is
refused: a build context cannot turn the model on or change where output goes.
"""
from __future__ import annotations

import copy
import hashlib
import tomllib
from pathlib import Path
from typing import Any

from ..config import DEFAULTS, validate_config
from ..core.tomlw import dumps
from ..errors import UserError

SECTIONS = ("build", "tools")


def default_buildctx() -> dict[str, Any]:
    return {"build": copy.deepcopy(DEFAULTS["build"]), "tools": copy.deepcopy(DEFAULTS["tools"])}


def parse_buildctx(text: str, *, name: str = "buildctx") -> dict[str, Any]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise UserError(f"{name}: {error}") from error
    return validate_buildctx(data, name=name)


def validate_buildctx(data: dict[str, Any], *, name: str = "buildctx") -> dict[str, Any]:
    extra = sorted(set(data) - set(SECTIONS))
    if extra:
        raise UserError(f"{name}: only [build] and [tools] belong in a build context, not {', '.join(extra)}")
    merged = copy.deepcopy(DEFAULTS)
    for section in SECTIONS:
        for key, value in data.get(section, {}).items():
            if section == "tools" and isinstance(value, dict) and key in merged["tools"]:
                merged["tools"][key].update(value)
            else:
                merged[section][key] = value
    validate_config(merged)
    return {section: merged[section] for section in SECTIONS}


def buildctx_text(buildctx: dict[str, Any]) -> str:
    """Canonical text of a build context: what is versioned and hashed."""
    clean = {section: {k: v for k, v in buildctx[section].items() if v is not None} for section in SECTIONS}
    clean["tools"] = {tool: {k: v for k, v in values.items() if v is not None}
                      for tool, values in clean["tools"].items()}
    return dumps(clean)


def buildctx_sha(buildctx: dict[str, Any]) -> str:
    return hashlib.sha256(buildctx_text(buildctx).encode("utf-8")).hexdigest()


def load_buildctx(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise UserError(f"cannot read build context {path}: {error}") from error
    return parse_buildctx(text, name=str(path))

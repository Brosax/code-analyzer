"""A deterministic TOML writer for the documents v3 versions: profiles and build contexts.

``tomllib`` reads TOML; nothing in the standard library writes it.  Output is
stable -- same data, same bytes -- because a profile's sha256 is recorded in
the ledger and on every exported list.  Supported: nested tables, arrays of
tables, inline tables inside them, strings, integers, floats, booleans and
arrays.  ``None`` values are omitted (TOML has no null).
"""
from __future__ import annotations

import math
import re
from typing import Any

_BARE_KEY = re.compile(r"^[A-Za-z0-9_-]+$")
_ESCAPES = {"\\": "\\\\", '"': '\\"', "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def dumps(data: dict[str, Any]) -> str:
    lines: list[str] = []
    _table(data, [], lines)
    return "\n".join(lines).strip("\n") + "\n"


def _table(data: dict[str, Any], path: list[str], lines: list[str]) -> None:
    scalars = [(k, v) for k, v in data.items() if v is not None and not _is_table(v) and not _is_table_array(v)]
    tables = [(k, v) for k, v in data.items() if _is_table(v)]
    arrays = [(k, v) for k, v in data.items() if _is_table_array(v)]
    if path and (scalars or not (tables or arrays)):
        lines.append(f"[{_path(path)}]")
    for key, value in scalars:
        lines.append(f"{_key(key)} = {value_text(value)}")
    if scalars or path:
        lines.append("")
    for key, value in tables:
        _table(value, [*path, key], lines)
    for key, items in arrays:
        for item in items:
            lines.append(f"[[{_path([*path, key])}]]")
            for inner_key, inner in item.items():
                if inner is not None:
                    lines.append(f"{_key(inner_key)} = {value_text(inner)}")
            lines.append("")


def value_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("TOML floats must be finite here")
        return repr(value)
    if isinstance(value, str):
        return '"' + "".join(_ESCAPES.get(c, f"\\u{ord(c):04x}" if ord(c) < 0x20 or ord(c) == 0x7F else c)
                             for c in value) + '"'
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(value_text(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{_key(k)} = {value_text(v)}" for k, v in value.items() if v is not None) + "}"
    raise TypeError(f"cannot write {type(value).__name__} as TOML")


def _is_table(value: Any) -> bool:
    return isinstance(value, dict)


def _is_table_array(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, dict) for item in value)


def _key(key: str) -> str:
    return key if _BARE_KEY.match(key) else value_text(key)


def _path(parts: list[str]) -> str:
    return ".".join(_key(part) for part in parts)

"""Scanner output schema and the lenient-parse / strict-validate boundary.

A structured-output request is a request, not a guarantee: a provider can end
with an error, wrap the object in a code fence, or bury it in prose.  So the
extraction step tolerates everything it safely can, while validation stays
strict and drops individual findings that do not hold up.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterator

from ..persist import json_bytes

SCHEMA_VERSION = 1
MAX_LINE = 1_000_000
RESPONSE_ERROR_PREFIX = "response: "

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# The category vocabulary the scanners are allowed to emit, grouped by the
# expert that owns it.  It is a closed set so that cross-engine correlation has
# a shared axis instead of free text.
FINDING_CATEGORIES: tuple[str, ...] = (
    "buffer",
    "out-of-bounds",
    "pointer-misuse",
    "unsafe-copy",
    "null-dereference",
    "uninitialized",
    "resource-leak",
    "integer-overflow",
    "undefined-behavior",
    "lifetime",
    "stack-usage",
    "format",
    "randomness",
    "input-validation",
    "protocol-parsing",
    "authentication",
    "hardcoded-secret",
    "info-leak",
    "crypto-misuse",
    "trust-boundary",
    "firmware-update",
    "debug-backdoor",
    "race",
    "isr-safety",
    "isr-race",
    "volatile-misuse",
    "atomicity",
    "rtos-sync",
    "watchdog",
    "mmio",
    "register-access",
    "dma",
    "timeout",
    "hardware-state",
    "reset-behavior",
    "other",
)

# British spellings of vocabulary entries.  The scanner prose is written in
# British English, so a model reaches for them even when told otherwise, and a
# spelling is not a reason to throw a finding away.
CATEGORY_SPELLINGS: dict[str, str] = {
    "undefined-behaviour": "undefined-behavior",
    "reset-behaviour": "reset-behavior",
    "uninitialised": "uninitialized",
    "information-leak": "info-leak",
}

FINDING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["file", "line_range", "category", "severity", "message"],
    "properties": {
        "file": {"type": "string", "minLength": 1, "description": "Repository-relative path of the affected file."},
        "line_range": {
            "type": "array",
            "items": {"type": "integer", "minimum": 1},
            "minItems": 2,
            "maxItems": 2,
            "description": "Inclusive 1-based [start, end] line span.",
        },
        "symbol": {"type": "string", "description": "Enclosing function or object name."},
        "category": {"type": "string", "enum": list(FINDING_CATEGORIES)},
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "cwe": {"type": "string", "pattern": "^CWE-[0-9]{1,5}$"},
        "message": {"type": "string", "minLength": 1, "description": "One-line statement of the defect."},
        "description": {"type": "string", "description": "Why the code is defective, in plain text."},
        "evidence": {"type": "string", "description": "The offending source text, copied verbatim."},
        "rule_id": {"type": "string"},
    },
}

SCANNER_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["findings"],
    "properties": {
        "unit_id": {"type": "string", "description": "The unit_id copied from the unit header."},
        "findings": {"type": "array", "items": FINDING_SCHEMA},
    },
}

_FENCE = re.compile(r"```[A-Za-z0-9_+-]*[ \t]*\r?\n(.*?)```", re.S)
_FENCE_OPENER = re.compile(r"^[A-Za-z0-9_+-]*[ \t]*\r?\n")
_CWE = re.compile(r"^cwe[-_ ]?(\d{1,5})$")
_OPENERS = {"{": "}", "[": "]"}


def schema_hash() -> str:
    """Stable identity of the schema recorded in request.json."""
    return hashlib.sha256(json_bytes(SCANNER_OUTPUT_SCHEMA)).hexdigest()


def parse_findings(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Extract findings from one scanner response.

    Returns the accepted findings and a problem report for everything dropped.
    Never raises: model output is untrusted input, and one bad finding must not
    cost the rest of the unit.
    """
    items, problem = _payload(text)
    if problem is not None:
        return [], [RESPONSE_ERROR_PREFIX + problem]
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, item in enumerate(items or []):
        finding, reason = _validate(item)
        if reason is not None:
            errors.append(f"finding[{index}]: {reason}")
            continue
        findings.append(finding)
    return findings, errors


def response_unparsed(errors: list[str]) -> bool:
    """True when nothing at all could be read out of a response."""
    return any(str(item).startswith(RESPONSE_ERROR_PREFIX) for item in errors)


def _payload(text: str) -> tuple[list[Any] | None, str | None]:
    if not isinstance(text, str) or not text.strip():
        return None, "empty response"
    fallback: str | None = None
    for candidate in _candidates(text):
        for attempt in (candidate, _drop_trailing_commas(candidate)):
            try:
                value = json.loads(attempt)
            except (json.JSONDecodeError, ValueError, RecursionError):
                continue
            items, problem = _findings_array(value)
            if problem is None:
                return items, None
            fallback = fallback or problem
            break
    return None, fallback or "no JSON object or array found in the response"


def _candidates(text: str) -> Iterator[str]:
    yield text.strip()
    for match in _FENCE.finditer(text):
        yield match.group(1).strip()
    if "```" in text:
        # A response cut off by the token limit leaves its fence unterminated.
        yield _FENCE_OPENER.sub("", text.rsplit("```", 1)[-1]).strip()
    yield from _spans(text)


def _spans(text: str) -> Iterator[str]:
    """Yield balanced brace/bracket substrings, ignoring delimiters in strings."""
    index = 0
    length = len(text)
    while index < length:
        closer = _OPENERS.get(text[index])
        if closer is None:
            index += 1
            continue
        end = _matching(text, index, closer)
        if end is None:
            index += 1
            continue
        yield text[index : end + 1]
        index = end + 1


def _matching(text: str, start: int, closer: str) -> int | None:
    opener = text[start]
    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(text)):
        character = text[index]
        if in_string:
            if escape:
                escape = False
            elif character == "\\":
                escape = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == opener:
            depth += 1
        elif character == closer:
            depth -= 1
            if depth == 0:
                return index
    return None


def _drop_trailing_commas(text: str) -> str:
    """Remove a ``,`` that directly precedes ``}`` or ``]`` outside a string."""
    out: list[str] = []
    in_string = False
    escape = False
    for character in text:
        if in_string:
            out.append(character)
            if escape:
                escape = False
            elif character == "\\":
                escape = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "}]":
            while out and out[-1].isspace():
                out.pop()
            if out and out[-1] == ",":
                out.pop()
        out.append(character)
    return "".join(out)


def _findings_array(value: Any, *, top: bool = True, depth: int = 0) -> tuple[list[Any] | None, str | None]:
    if top and isinstance(value, list):
        return value, None
    if not isinstance(value, dict):
        return None, "response is not a JSON object or array"
    items = value.get("findings")
    if isinstance(items, list):
        return items, None
    if depth < 3:
        for nested in value.values():
            if not isinstance(nested, dict):
                continue
            items, problem = _findings_array(nested, top=False, depth=depth + 1)
            if problem is None:
                return items, None
    if _looks_like_finding(value):
        return [value], None
    return None, "response has no findings array"


def _looks_like_finding(value: dict[str, Any]) -> bool:
    return "file" in value and "message" in value


def _validate(item: Any) -> tuple[dict[str, Any], str | None]:
    if not isinstance(item, dict):
        return {}, "not an object"
    path = _text(item.get("file"))
    if not path:
        return {}, "file must be a non-empty string"
    message = _text(item.get("message"))
    if not message:
        return {}, "message must be a non-empty string"
    category = _text(item.get("category")).lower()
    category = CATEGORY_SPELLINGS.get(category, category)
    if category not in FINDING_CATEGORIES:
        return {}, f"category {category or '<missing>'} is not a declared category"
    severity = _text(item.get("severity")).lower()
    if severity not in SEVERITIES:
        return {}, f"severity {severity or '<missing>'} is not one of {'/'.join(SEVERITIES)}"
    span, reason = _line_range(item)
    if span is None:
        return {}, reason
    finding: dict[str, Any] = {
        "file": path,
        "message": message,
        "category": category,
        "severity": severity,
        "line": span[0],
        "line_range": [span[0], span[1]],
    }
    for key in ("symbol", "description", "evidence", "rule_id"):
        value = _text(item.get(key))
        if value:
            finding[key] = value
    # An empty string is how a model says "no CWE applies"; that is an absent
    # optional field, not a malformed one, and must not cost the finding.
    declared_cwe = item.get("cwe")
    if isinstance(declared_cwe, str) and not declared_cwe.strip():
        declared_cwe = None
    if declared_cwe is not None:
        cwe = _cwe(declared_cwe)
        if cwe is None:
            return {}, "cwe is not in CWE-<number> form"
        finding["cwe"] = cwe
    if item.get("confidence") is not None:
        confidence = _confidence(item["confidence"])
        if confidence is None:
            return {}, "confidence is not a number in [0, 1]"
        finding["confidence"] = confidence
    return finding, None


def _line_range(item: dict[str, Any]) -> tuple[tuple[int, int] | None, str | None]:
    value = item.get("line_range")
    if value is None and item.get("line_start") is not None:
        value = [item["line_start"], item.get("line_end", item["line_start"])]
    if value is None and item.get("line") is not None:
        value = [item["line"], item["line"]]
    if isinstance(value, (list, tuple)) and len(value) == 1:
        value = [value[0], value[0]]
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        return None, "line_range must be a two-element array"
    numbers: list[int] = []
    for entry in value:
        if isinstance(entry, bool) or not isinstance(entry, int):
            return None, "line_range entries must be integers"
        numbers.append(entry)
    start, end = numbers
    if start < 1 or end < start or end > MAX_LINE:
        return None, f"line_range [{start}, {end}] is not an ordered 1-based range"
    return (start, end), None


def _cwe(value: Any) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return f"CWE-{value}" if 0 < value <= 99999 else None
    if not isinstance(value, str):
        return None
    match = _CWE.match(value.strip().lower())
    return f"CWE-{int(match.group(1))}" if match else None


def _confidence(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if 0.0 <= number <= 1.0 else None


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""

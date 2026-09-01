"""The validator's output contract: one verdict per candidate.

Lenient parse, strict validate, the same split as ``schema.py`` for scanner
findings: a fence, leading prose or a trailing comma must not cost the
verdict, while a verdict outside the declared set, a confidence outside
[0, 1] or a decisive line that is not a line is rejected and reported.  Model
output is untrusted input; nothing here raises on it.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..persist import json_bytes
from .schema import (
    MAX_LINE,
    RESPONSE_ERROR_PREFIX,
    _candidates,
    _drop_trailing_commas,
    _text,
    line_number,
)

VERDICT_SCHEMA_VERSION = 1
VERDICTS: tuple[str, ...] = ("CONFIRMED", "LIKELY", "UNCERTAIN", "FALSE_POSITIVE")
MAX_RATIONALE = 900
MAX_REMEDIATION = 200

VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["candidate_id", "verdict", "confidence", "decisive_line", "rationale"],
    "properties": {
        "candidate_id": {"type": "string"},
        "verdict": {"type": "string", "enum": list(VERDICTS)},
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "decisive_line": {
            "type": "object",
            "additionalProperties": False,
            "required": ["file", "line"],
            "properties": {"file": {"type": "string"}, "line": {"type": "integer", "minimum": 1}},
        },
        "rationale": {"type": "string", "maxLength": MAX_RATIONALE},
        "remediation": {"type": "string", "maxLength": MAX_REMEDIATION},
    },
}

_SPELLINGS = {
    "confirmed": "CONFIRMED", "likely": "LIKELY", "uncertain": "UNCERTAIN",
    "false_positive": "FALSE_POSITIVE", "false-positive": "FALSE_POSITIVE",
    "false positive": "FALSE_POSITIVE", "fp": "FALSE_POSITIVE",
}


def verdict_schema_hash() -> str:
    return hashlib.sha256(json_bytes(VERDICT_SCHEMA)).hexdigest()


def parse_verdict(text: str, *, candidate_id: str) -> tuple[dict[str, Any] | None, str | None]:
    """Extract the verdict for ``candidate_id`` from one validator response.

    Returns ``(verdict, None)`` or ``(None, reason)``.  A response naming a
    different candidate is rejected: a verdict must not be filed under the
    wrong group because the model echoed the wrong id.
    """
    if not isinstance(text, str) or not text.strip():
        return None, RESPONSE_ERROR_PREFIX + "empty response"
    fallback: str | None = None
    for candidate in _candidates(text):
        for attempt in (candidate, _drop_trailing_commas(candidate)):
            try:
                value = json.loads(attempt)
            except (json.JSONDecodeError, ValueError, RecursionError):
                continue
            if not isinstance(value, dict):
                fallback = fallback or "top-level value is not an object"
                break
            verdict, reason = _validate(value, candidate_id)
            if reason is None:
                return verdict, None
            fallback = fallback or reason
            break
    return None, fallback or RESPONSE_ERROR_PREFIX + "no JSON object found in the response"


def _validate(value: dict[str, Any], candidate_id: str) -> tuple[dict[str, Any] | None, str | None]:
    echoed = _text(value.get("candidate_id"))
    if echoed and echoed != candidate_id:
        return None, f"verdict names candidate {echoed!r}, expected {candidate_id!r}"
    label = _SPELLINGS.get(_text(value.get("verdict")).strip().lower())
    if label is None:
        return None, f"verdict must be one of {', '.join(VERDICTS)}"
    try:
        confidence = float(value.get("confidence"))
    except (TypeError, ValueError):
        return None, "confidence must be a number in [0, 1]"
    if not 0.0 <= confidence <= 1.0:
        return None, "confidence must be a number in [0, 1]"
    decisive = value.get("decisive_line")
    if not isinstance(decisive, dict):
        return None, "decisive_line must be an object with file and line"
    file = _text(decisive.get("file")).strip()
    line = line_number(decisive.get("line"))
    if not file or line is None or not 1 <= line <= MAX_LINE:
        return None, "decisive_line must name a file and a 1-based line"
    rationale = _text(value.get("rationale")).strip()
    if not rationale:
        return None, "rationale must be a non-empty string"
    verdict: dict[str, Any] = {
        "candidate_id": candidate_id,
        "verdict": label,
        "confidence": round(confidence, 3),
        "decisive_line": {"file": file, "line": line},
        "rationale": rationale[:MAX_RATIONALE],
    }
    remediation = _text(value.get("remediation")).strip()
    if remediation and label != "FALSE_POSITIVE":
        verdict["remediation"] = remediation[:MAX_REMEDIATION]
    return verdict, None

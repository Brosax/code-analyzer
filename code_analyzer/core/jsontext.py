"""Getting one JSON value out of a model's reply, and a line number out of a model's spelling of it.

A structured-output request is a request, not a guarantee: a reply may wrap the object in a fence, bury it in
prose, end mid-fence at the token limit, or leave a trailing comma.  Extraction tolerates what it safely can;
validation stays with the caller.  (Moved from harness/schema.py when the old scanner layer was retired.)
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

_FENCE = re.compile(r"```[A-Za-z0-9_+-]*[ \t]*\r?\n(.*?)```", re.S)
_FENCE_OPENER = re.compile(r"^[A-Za-z0-9_+-]*[ \t]*\r?\n")
_OPENERS = {"{": "}", "[": "]"}


def candidates(text: str) -> Iterator[str]:
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


def drop_trailing_commas(text: str) -> str:
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


def line_number(value: Any) -> int | None:
    """A 1-based line number, whether the model quoted it or not.

    ``"7"`` and ``7`` are one value in two spellings, and models quote
    numbers.  Rejecting the quoted form threw away whole verdicts: on
    2026-09-01 two different models each traced a real defect correctly and
    each lost the result to a pair of quote marks -- 56 seconds and five
    provider requests, for punctuation.  Telling the skill not to do it fixed
    one model and not the other, so the parser is where it has to be handled.

    This is the only spelling the parser forgives.  Floats, booleans and
    non-numeric strings stay rejected: those are not another spelling of a
    line number, they are a different value.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None

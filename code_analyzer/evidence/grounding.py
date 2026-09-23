"""Whether an AI claim is anchored in the code it was shown.

A lens answers about one unit of code it was shown with line numbers.  Its
claim is grounded only if every checkable part of it is true of that text:

* the path is the unit's path (inside the scanned tree);
* the line and the decisive line are inside the lines it was shown;
* the evidence quote, whitespace-normalised, appears verbatim in those lines;
* the function it names encloses the line (when it names one);
* the SFR, level and category it proposes are values the profile defines.

An ungrounded claim is kept -- deleting it would hide how often the model
invents things -- but it can never create or change a list entry, and the
coverage page reports each lens's grounding failure rate.  (Measured on the GPU
host: the model found a real off-by-one, then added a "timing side channel"
the code did not have; the quote check is what catches the second kind.)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

MIN_QUOTE_CHARS = 6


@dataclass(frozen=True)
class Shown:
    """What the model was shown: one file's lines, numbered."""
    path: str
    lines: dict[int, str]
    function: str = ""
    function_span: tuple[int, int] | None = None


@dataclass
class Verdict:
    grounded: bool
    problems: list[str] = field(default_factory=list)


def ground(claim: dict[str, Any], shown: Shown, *, sfr_ids: set[str], levels: set[str],
           categories: set[str]) -> Verdict:
    problems: list[str] = []
    path = str(claim.get("file") or claim.get("path") or shown.path)
    if path != shown.path:
        problems.append(f"path {path!r} is not the unit it was shown ({shown.path})")
    first, last = (min(shown.lines), max(shown.lines)) if shown.lines else (0, -1)
    for key in ("line", "decisive_line"):
        value = claim.get(key)
        if value is None:
            continue
        if not isinstance(value, int) or isinstance(value, bool) or not first <= value <= last:
            problems.append(f"{key} {value!r} is outside the lines shown ({first}-{last})")
    quote = str(claim.get("evidence_quote") or "")
    if len(_normalise(quote)) < MIN_QUOTE_CHARS:
        problems.append("the evidence quote is missing or too short to check")
    elif not _quoted(quote, shown.lines):
        problems.append("the evidence quote does not appear in the lines shown")
    symbol = str(claim.get("symbol") or claim.get("function") or "")
    if symbol and shown.function and symbol != shown.function and shown.function_span:
        line = claim.get("line")
        start, end = shown.function_span
        if isinstance(line, int) and start <= line <= end:
            problems.append(f"line {line} is in {shown.function}(), not {symbol}()")
    for key, allowed in (("sfr", sfr_ids), ("level", levels), ("category", categories)):
        value = claim.get(key)
        if value in (None, "", "none"):
            continue
        values = value if isinstance(value, list) else [value]
        unknown = [v for v in values if v not in allowed]
        if unknown:
            problems.append(f"{key} {unknown} is not defined in the profile")
    return Verdict(not problems, problems)


def _normalise(text: str) -> str:
    return " ".join(str(text).split())


def _quoted(quote: str, lines: dict[int, str]) -> bool:
    needle = _normalise(quote)
    # A quote may span consecutive lines; search the joined text, and each line alone.
    ordered = [lines[n] for n in sorted(lines)]
    return needle in _normalise(" ".join(ordered)) or any(needle in _normalise(line) for line in ordered)

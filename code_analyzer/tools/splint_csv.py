"""Splint's ``+csv`` report, read once and read tolerantly.

Splint 3.1.2 writes nine fixed columns -- ``Warning, Flag Code, Flag Name,
Priority, File, Line, Column, Warning Text, Additional Text`` -- and quotes
the two text columns without escaping the quotes *inside* them.  A
preprocessing error such as ``#error "No public key available"`` therefore
lands on disk as ``"#error "No public key available"","Preprocessing error."``
and a strict CSV reader rejects the whole file; on trusted-firmware-m that was
76 translation units discarded for a defect in Splint's writer, not in the
evidence.

The strict parse is still tried first, because it is the only one that can be
trusted blindly.  Only when it fails does the recovery below run, and it works
from what is known to be fixed: the first seven columns never contain a comma
(numbers, a flag name, a path) and the last two are quoted, so a record can be
split on the seven commas that precede the quoted text and the text columns on
their ``","`` separator.  Multi-line records -- Splint wraps long warning
texts with a raw newline inside the quotes -- are joined back first: a physical
line that does not start with ``<number>,<number>,<name>,<number>,`` continues
the record before it.

Both the adapter (``tools/splint.py``) and the review layer (``review.py``)
read through :func:`splint_rows`, so a report the adapter accepts is a report
the review can parse: one reader, one verdict.
"""
from __future__ import annotations

import csv
import io
import re

# The column count of a Splint 3.1.2 ``+csv`` report.
SPLINT_COLUMNS = 9
# A record starts with the warning number, the flag code, the flag name and
# the priority; nothing Splint writes into a text column looks like this at
# the start of a line.
_RECORD_START = re.compile(r"^\d+,\d+,[A-Za-z_][\w-]*,\d+,")
_HEADER_START = re.compile(r"^\s*warning\s*,\s*flag code\s*,", re.I)


def splint_rows(text: str) -> tuple[list[list[str]], int, str | None]:
    """Return ``(rows, recovered, error)`` for one ``report.csv``.

    ``rows`` are every non-blank record including the header; ``recovered`` is
    how many of them the strict reader rejected and the fixed-column recovery
    reassembled; ``error`` is the reason the report is unusable, in which case
    ``rows`` is empty.  Recovery only applies to Splint's own nine-column
    shape: a report with another header is either strictly valid or invalid.
    """
    if not text.strip():
        return [], 0, "invalid Splint CSV: report is empty"
    if "\x00" in text:
        return [], 0, "invalid Splint CSV: NUL byte"
    strict_error: str | None = None
    try:
        rows = [row for row in csv.reader(io.StringIO(text), strict=True) if any(cell.strip() for cell in row)]
    except csv.Error as exc:
        strict_error = str(exc)
        rows = []
    if strict_error is None:
        if not rows or len(rows[0]) < 2:
            return [], 0, "invalid Splint CSV: expected comma-separated columns"
        width = len(rows[0])
        if all(len(row) == width for row in rows):
            return rows, 0, None
        strict_error = "inconsistent or truncated rows"
    lines = text.splitlines()
    if not lines or not _HEADER_START.match(lines[0]):
        return [], 0, f"invalid Splint CSV: {strict_error}"
    header = next(csv.reader([lines[0]]))
    if len(header) != SPLINT_COLUMNS:
        return [], 0, f"invalid Splint CSV: {strict_error}"
    recovered = 0
    result = [header]
    for record in _records(lines[1:]):
        row = _strict_record(record)
        if row is None:
            row = _recover_record(record)
            if row is None:
                return [], 0, f"invalid Splint CSV: {strict_error}"
            recovered += 1
        result.append(row)
    return result, recovered, None


def _records(lines: list[str]) -> list[str]:
    """Join physical lines back into the records Splint wrote."""
    records: list[str] = []
    for line in lines:
        if _RECORD_START.match(line) or not records:
            if line.strip():
                records.append(line)
        else:
            records[-1] += "\n" + line
    return records


def _strict_record(record: str) -> list[str] | None:
    try:
        rows = [row for row in csv.reader(io.StringIO(record), strict=True) if row]
    except csv.Error:
        return None
    if len(rows) == 1 and len(rows[0]) == SPLINT_COLUMNS:
        return rows[0]
    return None


def _recover_record(record: str) -> list[str] | None:
    parts = record.split(",", SPLINT_COLUMNS - 2)
    if len(parts) != SPLINT_COLUMNS - 1:
        return None
    fixed, text = parts[:-1], parts[-1].strip()
    if len(text) < 2 or not text.startswith('"') or not text.endswith('"'):
        return None
    body = text[1:-1]
    # The additional text is Splint's fixed explanation of the flag and never
    # contains the separator, so the last one is the column boundary.  Splint
    # always quotes both text columns, so a body without the separator is a
    # record cut short (a killed process) or not Splint's at all: refusing it
    # is what keeps recovery from inventing a column.
    separator = body.rfind('","')
    if separator < 0:
        return None
    warning, additional = body[:separator], body[separator + 3:]
    return [*fixed, _unescape(warning), _unescape(additional)]


def _unescape(value: str) -> str:
    return value.replace('""', '"')

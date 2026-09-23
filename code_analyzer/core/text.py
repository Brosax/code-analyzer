"""Untrusted text made safe to print: analyzer output and scanned file names may carry control characters."""
from __future__ import annotations

import re

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def single_line(message: str) -> str:
    """Collapse a message to one line with no C0/DEL control characters, so a scanned file name holding an
    escape sequence cannot rewrite the operator's terminal or a log line."""
    return " ".join(_CONTROL_CHARS.sub(" ", str(message)).split())

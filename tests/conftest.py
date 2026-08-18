"""Shared pytest configuration.

Keeps the package importable under a bare ``pytest`` invocation (which does
not put the repository root on ``sys.path``) and the shared ``helpers``
module importable regardless of the invocation directory.
"""
from __future__ import annotations

import sys
from pathlib import Path

_TESTS_DIR = Path(__file__).parent
for _entry in (str(_TESTS_DIR.parent), str(_TESTS_DIR)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

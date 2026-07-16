#!/usr/bin/env python3
"""Compatibility facade for the modular Code Analyzer runtime."""

from __future__ import annotations

import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import code_analyzer_adapters as _adapters
import code_analyzer_ai as _ai
import code_analyzer_cli as _cli
import code_analyzer_reporting as _reporting
import code_analyzer_runtime as _runtime


# Preserve the original import surface for legacy forwarders and downstream users.
for _module in (_runtime, _ai, _adapters, _reporting, _cli):
    for _name, _value in vars(_module).items():
        if not _name.startswith("__"):
            globals()[_name] = _value

main = _cli.main

#!/usr/bin/env python3
"""Deprecated Splint-only forwarding entry point for Code Analyzer."""

import sys
from pathlib import Path


CORE = Path(__file__).resolve().parents[3] / "skills" / "code-analyzer" / "scripts"
sys.path.insert(0, str(CORE))
from code_analyzer_core import main  # noqa: E402


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if not any(value == "--out" or value.startswith("--out=") for value in arguments):
        arguments = ["--out", "splint-report"] + arguments
    raise SystemExit(main(["--tools", "splint"] + arguments))

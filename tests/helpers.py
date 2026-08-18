"""Helpers shared by the CLI-driving test modules."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).parents[1]


def run_cli(
    *args: object,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    runtime = {**os.environ, "PYTHONPATH": str(ROOT), **(env or {})}
    return subprocess.run(
        [sys.executable, "-m", "code_analyzer", *(str(item) for item in args)],
        cwd=cwd or ROOT, env=runtime, text=True, capture_output=True, timeout=timeout,
    )


def executable(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path

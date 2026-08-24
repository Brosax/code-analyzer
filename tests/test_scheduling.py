from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from code_analyzer.process import run_process

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize("jobs", (1, 4))
def test_splint_budget_accounts_unscheduled_tus(tmp_path: Path, jobs: int) -> None:
    """The total budget bounds the work on both scheduling paths.

    A worker checks the budget when it picks a unit up, not when the unit is
    submitted, so units behind an exhausted budget are unscheduled whether the
    pool has one worker or several.
    """
    source = tmp_path / "src"
    source.mkdir()
    for index in range(2 * jobs):
        (source / f"f{index}.c").write_text("int x;\n")
    fake = tmp_path / "slow-splint"
    fake.write_text("#!/usr/bin/env python3\nimport sys, time\nif '-help' in sys.argv: print('Splint 3.1.2'); raise SystemExit()\ntime.sleep(1)\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    config = tmp_path / "config.toml"
    config.write_text(textwrap.dedent(f"""
        config_schema_version = 1
        [run]
        shareable_export = false
        termination_grace_seconds = 0.01
        [tools.splint]
        executable = {json.dumps(str(fake))}
        tu_timeout_seconds = 0.05
        total_timeout_seconds = 0.02
        jobs = {jobs}
    """))
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    result = subprocess.run(
        [sys.executable, "-m", "code_analyzer", "analyze", str(source), "--config", str(config), "--output-root", str(tmp_path / "out"), "--tool", "splint", "--no-compile-db"],
        env=env, text=True, capture_output=True, timeout=30,
    )
    assert result.returncode == 20
    manifest = json.loads((Path(result.stdout.strip()) / "manifest.json").read_text())
    units = manifest["tools"]["splint"]["units"]
    assert len(units) == 2 * jobs
    assert sum(unit["status"] == "unscheduled" for unit in units) >= 1
    counts = manifest["tools"]["splint"]["unit_counts"]
    assert counts["planned"] == counts["started"] + counts["unscheduled"]


def test_process_timeout_drains_streams_and_kills_group(tmp_path: Path) -> None:
    script = tmp_path / "hang.py"
    script.write_text(textwrap.dedent("""
        import subprocess, sys, time
        print('started', flush=True)
        subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        print('diagnostic', file=sys.stderr, flush=True)
        time.sleep(30)
    """))
    result = run_process(
        [sys.executable, str(script)], tmp_path, tmp_path / "stdout.raw", tmp_path / "stderr.raw", 1.0, 0.1,
    )
    assert result.timed_out
    assert (tmp_path / "stdout.raw").read_text() == "started\n"
    assert (tmp_path / "stderr.raw").read_text() == "diagnostic\n"

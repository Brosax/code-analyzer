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



def test_header_attribution_resolves_each_path_once_and_never_inside_the_unit_loop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Header attribution must not be quadratic in (units x headers).

    Measured on trusted-firmware-m: 1588 units against 2335 headers with a
    filesystem resolve() in the innermost loop is 3.7 million syscalls. The run
    sat at 94% CPU for 42 minutes *after* every unit had been scanned, and
    projected to 255 minutes; the same work now takes about 39 seconds.
    """
    from code_analyzer.tools.splint import credit_headers, header_path_forms

    source = tmp_path / "src"
    (source / "inc").mkdir(parents=True)
    inventory = (
        [{"path": "inc/api.h", "is_header": True}]
        + [{"path": f"inc/other{n}.h", "is_header": True} for n in range(50)]
        + [{"path": "a.c", "is_header": False}]
    )

    resolved: list[str] = []
    real_resolve = Path.resolve
    monkeypatch.setattr(
        Path, "resolve",
        lambda self, *a, **k: (resolved.append(str(self)), real_resolve(self, *a, **k))[1],
    )

    forms = header_path_forms(inventory, source)
    assert len(forms) == 51, "only headers, both spellings, computed up front"
    after_setup = len(resolved)
    assert after_setup == 51, "each header path is resolved exactly once"

    headers: set[str] = set()
    absolute = forms[0][1]
    for cells in (
        ["Location: inc/api.h:1", "unrelated text"],   # relative spelling
        [f"included from {absolute}"],                 # absolute spelling
        ["nothing here"],                              # no match
        [],                                            # a unit with no report
        ["inc/api.h once more"],                       # already credited
    ):
        credit_headers(headers, forms, cells)

    assert headers == {"inc/api.h"}
    assert len(resolved) == after_setup, "no path may be resolved once the unit loop has started"


def test_header_attribution_agrees_with_the_straightforward_search(tmp_path: Path) -> None:
    """The fast form must credit exactly what scanning cell by cell would."""
    from code_analyzer.tools.splint import credit_headers, header_path_forms

    source = tmp_path / "src"
    (source / "inc").mkdir(parents=True)
    inventory = [{"path": f"inc/h{n}.h", "is_header": True} for n in range(12)]
    inventory.append({"path": "main.c", "is_header": False})
    forms = header_path_forms(inventory, source)
    units = [
        ["inc/h3.h:9: warning", "second cell"],
        [str((source / "inc/h7.h").resolve())],
        ["inc/h3.h again", "inc/h11.h"],
        ["no path at all"],
    ]

    fast: set[str] = set()
    for cells in units:
        credit_headers(fast, forms, cells)

    plain = {
        item["path"]
        for cells in units
        for item in inventory
        if item["is_header"]
        and any(item["path"] in cell or str((source / item["path"]).resolve()) in cell for cell in cells)
    }
    assert fast == plain == {"inc/h3.h", "inc/h7.h", "inc/h11.h"}

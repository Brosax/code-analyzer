from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


@pytest.mark.live_tools
@pytest.mark.skipif(os.environ.get("CODE_ANALYZER_LIVE_TOOLS") != "1", reason="set CODE_ANALYZER_LIVE_TOOLS=1 for native analyzer tests")
def test_live_tools_via_public_cli(tmp_path: Path) -> None:
    source = tmp_path / "fixture"
    source.mkdir()
    (source / "unsafe.c").write_text("#include <string.h>\nint main(int n, char **v) { char b[2]; if(n) strcpy(b,v[0]); return b[3]; }\n")
    (source / "clean.cpp").write_text("int add(int a, int b) { return a + b; }\n")
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    completed = subprocess.run(
        [sys.executable, "-m", "code_analyzer", "analyze", str(source), "--output-root", str(tmp_path / "reports"), "--no-compile-db"],
        env=env, text=True, capture_output=True, timeout=300,
    )
    assert completed.returncode in {0, 10}, completed.stderr
    manifest = json.loads((Path(completed.stdout.strip()) / "manifest.json").read_text())
    assert all(manifest["tools"][name]["status"] != "missing" for name in ("cppcheck", "flawfinder", "splint"))
    # Installed but under-capable versions are an expected, evidence-backed
    # live result (Ubuntu's Cppcheck 2.13 help omits --xml-version).
    assert all(manifest["tools"][name]["status"] in {"completed", "partial", "incompatible"} for name in manifest["tools"])
    assert any(manifest["tools"][name]["valid_reports"] for name in manifest["tools"])


@pytest.mark.live_tools
@pytest.mark.skipif(os.environ.get("CODE_ANALYZER_LIVE_TOOLS") != "1", reason="set CODE_ANALYZER_LIVE_TOOLS=1 for native analyzer tests")
def test_live_cppcheck_multiple_defines_are_one_project_pass(tmp_path: Path) -> None:
    real = shutil.which("cppcheck")
    if not real:
        pytest.skip("cppcheck is not installed")
    source = tmp_path / "source"
    source.mkdir()
    target = source / "branches.c"
    target.write_text("#ifdef FIRST\nint first(void) { int x; return x; }\n#endif\n#ifdef SECOND\nint second(void) { int y; return y; }\n#endif\n")
    (source / "compile_commands.json").write_text(json.dumps([
        {"directory": str(source), "file": str(target), "arguments": ["cc", "-DFIRST", "-c", str(target)]},
        {"directory": str(source), "file": str(target), "arguments": ["cc", "-DSECOND", "-c", str(target)]},
    ]))
    wrapper = tmp_path / "cppcheck-capability-wrapper"
    wrapper.write_text(
        "#!/usr/bin/env python3\nimport os, subprocess, sys\n"
        f"real={real!r}\n"
        "if sys.argv[1:] == ['--help']:\n"
        " r=subprocess.run([real, '--help']); print('  --xml-version=2'); raise SystemExit(r.returncode)\n"
        "os.execv(real, [real, *sys.argv[1:]])\n"
    )
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IXUSR)
    config = tmp_path / "config.toml"
    config.write_text(f'config_schema_version=1\n[run]\nshareable_export=false\n[tools.cppcheck]\nexecutable={json.dumps(str(wrapper))}\n')
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    completed = subprocess.run(
        [sys.executable, "-m", "code_analyzer", "analyze", str(source), "--config", str(config), "--output-root", str(tmp_path / "reports"), "--tool", "cppcheck"],
        env=env, text=True, capture_output=True, timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    run_dir = Path(completed.stdout.strip())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["compile_database"]["filtered_entries"] == 2
    assert [unit["id"] for unit in manifest["tools"]["cppcheck"]["units"]] == ["compile-db"]
    xml = (run_dir / "tools/cppcheck/compile-db/report.xml").read_text()
    assert 'line="2"' in xml and 'line="5"' in xml


@pytest.mark.tfm_full
@pytest.mark.skipif(os.environ.get("CODE_ANALYZER_TFM_FULL") != "1", reason="manual release acceptance only")
def test_tfm_full_degraded_accounting(tmp_path: Path) -> None:
    source = ROOT / "trusted-firmware-m"
    completed = subprocess.run(
        [sys.executable, "-m", "code_analyzer", "analyze", str(source), "--output-root", str(tmp_path / "reports"), "--no-compile-db"],
        cwd=ROOT, text=True, capture_output=True, timeout=8 * 60 * 60,
    )
    assert completed.returncode in {0, 10}
    run_dir = Path(completed.stdout.strip())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["analysis_context"] == "degraded"
    assert manifest["source_inventory"]["total"] > 0
    for item in manifest["tools"].values():
        counts = item["unit_counts"]
        assert counts["planned"] == counts["started"] + counts["unscheduled"]
    assert manifest["export"]["status"] == "completed"
    assert (run_dir / manifest["export"]["archive"]).is_file()

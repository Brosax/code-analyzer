"""M2: the evaluation workspace, the build context, and the headless `evaluate` end to end."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from helpers import ROOT, executable, run_cli

from code_analyzer.errors import UserError
from code_analyzer.evidence.buildctx_schema import (
    buildctx_sha,
    buildctx_text,
    default_buildctx,
    parse_buildctx,
    validate_buildctx,
)
from code_analyzer.evidence.store import Store
from code_analyzer.evidence.workspace import Ledger, Workspace

SOURCE = """\
#include <string.h>
int copy(char *dst, const char *src, int n) {
    char tmp[4];
    memcpy(tmp, src, n);
    strcpy(dst, tmp);
    return tmp[4];
}
"""


# -- ledger and workspace -------------------------------------------------------------

def test_ledger_survives_a_torn_last_line(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl")
    ledger.append("a", x=1)
    ledger.append("b", x=2)
    with open(ledger.path, "ab") as handle:
        handle.write(b'{"seq":3,"kind":"c","x":')  # killed mid-write
    records = Ledger(ledger.path).read()
    assert [r["kind"] for r in records] == ["a", "b"] and [r["seq"] for r in records] == [1, 2]


def test_workspace_refuses_to_live_inside_the_scanned_tree(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    with pytest.raises(UserError, match="inside the scanned tree"):
        Workspace.create_at(source / "eval", source)


def test_reconcile_closes_an_open_call_exactly_once(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    workspace = Workspace.create_at(tmp_path / "eval", source)
    workspace.ledger.append("call_started", call_id="C0001", call_kind="static")
    assert Workspace.open(workspace.root).ledger.of("call_finished")[0]["status"] == "interrupted"
    Workspace.open(workspace.root)
    assert len(Workspace.open(workspace.root).ledger.of("call_finished")) == 1
    assert workspace.next_call_id() == "C0002"


def test_versions_are_immutable_and_numbered(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    workspace = Workspace.create_at(tmp_path / "eval", source)
    assert workspace.save_version("buildctx", "a = 1\n")[0] == 1
    assert workspace.save_version("buildctx", "a = 2\n")[0] == 2
    assert workspace.version_text("buildctx", 1) == "a = 1\n"


# -- build context ----------------------------------------------------------------------

def test_default_build_context_round_trips_with_a_stable_hash() -> None:
    context = default_buildctx()
    again = parse_buildctx(buildctx_text(context))
    assert buildctx_sha(again) == buildctx_sha(context)


def test_a_build_context_cannot_reach_beyond_build_and_tools() -> None:
    with pytest.raises(UserError, match="only \\[build\\] and \\[tools\\]"):
        validate_buildctx({"llm": {"enabled": True}})
    with pytest.raises(UserError):
        validate_buildctx({"build": {"compile_database_mode": "sometimes"}})
    assert validate_buildctx({"build": {"define": ["TFM_ISOLATION_LEVEL=2"]}})["build"]["define"] == ["TFM_ISOLATION_LEVEL=2"]


# -- evaluate, end to end -----------------------------------------------------------------

def fake_tools(tmp_path: Path, source_file: Path, *, slow: bool = False) -> dict[str, Path]:
    tools = tmp_path / "fake tools"
    tools.mkdir(exist_ok=True)
    delay = "import time; time.sleep(30)" if slow else "pass"
    cppcheck = executable(tools / "cppcheck", f"""
        import pathlib, sys
        if '--version' in sys.argv: print('Cppcheck 2.13.0'); raise SystemExit()
        {delay}
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        checkers = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--checkers-report=')))
        def err(i, sev, msg, line, cwe):
            return (f'<error id="{{i}}" severity="{{sev}}" msg="{{msg}}" verbose="{{msg}}" cwe="{{cwe}}">'
                    f'<location file="{source_file}" line="{{line}}" column="5"/></error>')
        report.write_text('<?xml version="1.0"?><results version="2"><cppcheck version="2.13.0"/><errors>'
            + err('arrayIndexOutOfBounds', 'error', 'Array tmp[4] accessed at index 4', 6, '788')
            + err('bufferAccessOutOfBounds', 'error', 'Buffer is accessed out of bounds: tmp', 4, '788')
            + err('variableScope', 'style', 'The scope of the variable can be reduced', 3, '398')
            + err('checkLibraryFunction', 'information', 'no configuration for memcpy', 4, '0')
            + '</errors></results>')
        checkers.write_text('checked\\n')
    """)
    flawfinder = executable(tools / "flawfinder", """
        import json
        print(json.dumps({'version':'2.1.0','$schema':'x','runs':[{'tool':{'driver':{'name':'Flawfinder'}},'results':[]}]}))
    """)
    splint = executable(tools / "splint", """
        import pathlib, sys
        if '-help' in sys.argv: print('Splint 3.1.2'); raise SystemExit()
        report = pathlib.Path(sys.argv[sys.argv.index('+csv') + 1])
        report.write_text('Warning,Flag Code,Flag Name,Priority,File,Line,Column,Warning Text,Additional Text\\n')
        print('Finished checking --- no code warnings', file=sys.stderr)
    """)
    return {"cppcheck": cppcheck, "flawfinder": flawfinder, "splint": splint}


def buildctx_file(tmp_path: Path, tools: dict[str, Path]) -> Path:
    lines = []
    for name, path in tools.items():
        lines += [f"[tools.{name}]", f"executable = {json.dumps(str(path))}", ""]
    target = tmp_path / "buildctx.toml"
    target.write_text("\n".join(lines), encoding="utf-8")
    return target


def project(tmp_path: Path) -> Path:
    source = tmp_path / "project"
    source.mkdir()
    (source / "a.c").write_text(SOURCE, encoding="utf-8")
    return source


def test_analyze_records_the_call_and_numbers_the_list(tmp_path: Path) -> None:
    # The static path is the old runner's, minus its report phases; equivalence on Juliet (exit code, every unit's
    # status, every finding key) was checked against the old runner before it was removed (v3 M9).
    source = project(tmp_path)
    tools = fake_tools(tmp_path, source / "a.c")
    new = run_cli("analyze", source, "--eval-dir", tmp_path / "eval", "--buildctx", buildctx_file(tmp_path, tools),
                  "--no-compile-db")
    assert new.returncode == 0, new.stderr
    workspace = Workspace.open(Path(new.stdout.strip()))
    [call] = workspace.ledger.of("call_finished")
    run_dir = workspace.root / call["run_dir"]
    manifest = json.loads((run_dir / "manifest.json").read_text())
    units = {tool: [(u["id"], u["status"]) for u in item.get("units", [])] for tool, item in manifest["tools"].items()}
    assert units["cppcheck"] == [("fallback", "completed")] and manifest["status"] == "complete"
    assert set(manifest) >= {"tools", "source_inventory", "compile_database"} and "review" not in manifest

    store = Store(workspace.index_path)
    listing = store.list_pvs()
    # the two buffer errors (CWE-788) are one entry; the style finding is below the threshold
    assert listing["total"] == 1 and listing["rows"][0]["pv_id"] == "PV-0001"
    assert listing["rows"][0]["partition"] == "main" and listing["rows"][0]["level"] == "error"
    triage = store.triage_counts()
    assert triage["in_toe"] == triage["partition_main"] + triage["partition_unmapped"] + triage["partition_below"]
    assert store.list_findings({"view_class": "diagnostic"})["total"] == 1

    again = run_cli("analyze", source, "--eval-dir", workspace.root, "--buildctx", buildctx_file(tmp_path, tools),
                    "--no-compile-db")
    assert again.returncode == 0, again.stderr
    built = Workspace.open(workspace.root).ledger.of("index_built")
    assert built[-1]["kept"] == built[-1]["listed"] == 1 and built[-1]["new"] == 0
    assert len(Workspace.open(workspace.root).ledger.of("buildctx_version")) == 1  # unchanged context, one version


def test_fail_on_gates_only_native_findings(tmp_path: Path) -> None:
    source = project(tmp_path)
    tools = fake_tools(tmp_path, source / "a.c")
    completed = run_cli("analyze", source, "--eval-dir", tmp_path / "eval", "--buildctx",
                        buildctx_file(tmp_path, tools), "--no-compile-db", "--fail-on", "high")
    assert completed.returncode == 1, completed.stderr
    assert Workspace.open(tmp_path / "eval").ledger.of("gate_triggered")


def _start(tmp_path: Path, source: Path, tools: dict[str, Path]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-S", "-m", "code_analyzer", "analyze", str(source), "--eval-dir", str(tmp_path / "eval"),
         "--buildctx", str(buildctx_file(tmp_path, tools)), "--no-compile-db"],
        cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT)}, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _wait_for_call(tmp_path: Path) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        ledger = tmp_path / "eval" / "ledger.jsonl"
        if ledger.exists() and b"call_started" in ledger.read_bytes():
            time.sleep(1.0)
            return
        time.sleep(0.1)
    raise AssertionError("the call never started")


def test_sigterm_interrupts_with_130_and_an_honest_ledger(tmp_path: Path) -> None:
    source = project(tmp_path)
    process = _start(tmp_path, source, fake_tools(tmp_path, source / "a.c", slow=True))
    _wait_for_call(tmp_path)
    process.send_signal(signal.SIGTERM)
    _, stderr = process.communicate(timeout=60)
    assert process.returncode == 130, stderr
    finished = Workspace.open(tmp_path / "eval").ledger.of("call_finished")
    assert [(r["status"], r["exit_code"]) for r in finished] == [("interrupted", 130)]


def test_a_killed_evaluation_is_reconciled_when_reopened(tmp_path: Path) -> None:
    source = project(tmp_path)
    process = _start(tmp_path, source, fake_tools(tmp_path, source / "a.c", slow=True))
    _wait_for_call(tmp_path)
    process.kill()
    process.communicate(timeout=30)
    workspace = Workspace.open(tmp_path / "eval")
    [finished] = workspace.ledger.of("call_finished")
    assert finished["reconciled"] is True and finished["exit_code"] == 130

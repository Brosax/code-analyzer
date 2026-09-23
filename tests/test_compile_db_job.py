"""M6: a compilation database from CMake -- typed arguments, a card, and a jail the source tree cannot be written from."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
from helpers import executable
from test_evaluate import SOURCE, buildctx_file, fake_tools

from code_analyzer.core import sandbox
from code_analyzer.errors import UserError
from code_analyzer.evidence.analyze import current_buildctx, evaluate
from code_analyzer.evidence.buildctx_schema import load_buildctx
from code_analyzer.evidence.workspace import Workspace
from code_analyzer.jobs import compile_db_job
from code_analyzer.kernel import tools

needs_jail = pytest.mark.skipif(sandbox.available() is None or shutil.which("cmake") is None,
                                reason="bubblewrap and cmake are needed")


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Workspace:
    source = tmp_path / "project"
    source.mkdir()
    (source / "a.c").write_text(SOURCE, encoding="utf-8")
    (source / "CMakeLists.txt").write_text("project(demo C)\nadd_library(demo a.c)\n", encoding="utf-8")
    tools_ = fake_tools(tmp_path, source / "a.c")
    outcome = evaluate(source, eval_dir=tmp_path / "eval", profile="generic-sesip",
                       buildctx=load_buildctx(buildctx_file(tmp_path, tools_)), compile_db=False)
    # A cmake that tries to write into the source tree, then writes its database where it may.
    (tmp_path / "fakebin").mkdir()
    fake = executable(tmp_path / "fakebin" / "cmake", f"""
        import json, pathlib, sys
        if '--version' in sys.argv: print('cmake version 3.28.0'); raise SystemExit()
        build = pathlib.Path(sys.argv[sys.argv.index('-B') + 1])
        try:
            pathlib.Path({str(source)!r}, 'written-by-cmake').write_text('x')
            print('WROTE INTO THE SOURCE TREE')
        except OSError as error:
            print('source tree is read-only:', error.strerror, file=sys.stderr)
        build.mkdir(parents=True, exist_ok=True)
        (build / 'compile_commands.json').write_text(json.dumps([{{
            'directory': {str(source)!r}, 'file': {str(source / 'a.c')!r}, 'command': 'cc -DX=1 -c a.c'}}]))
    """)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}{os.environ['PATH']}")
    return outcome.workspace


@pytest.mark.parametrize(("kwargs", "match"), [
    ({"defines": {"X": "$(rm -rf ~)"}}, "plain words"),
    ({"defines": {"bad name": "1"}}, "C identifiers"),
    ({"generator": "Visual Studio 17"}, "generator"),
    ({"toolchain_file": "../../etc/passwd"}, "not a file in the source tree"),
    ({"preset": "nope"}, "unknown configure preset"),
])
def test_only_typed_arguments_reach_the_command(workspace: Workspace, kwargs: dict, match: str) -> None:
    with pytest.raises(UserError, match=match):
        compile_db_job.propose(workspace, **kwargs)


def test_the_model_gets_a_card_and_nothing_runs(workspace: Workspace) -> None:
    started: list[int] = []
    services = tools.Services(run_tools=lambda ws, t: None, jobs=lambda ws: [], export=lambda ws, v, f: {},
                              compile_db=lambda ws, n: started.append(n))
    result = tools.run(tools.ToolContext(workspace, services), "build_context",
                       {"op": "compile_db", "generator": "Unix Makefiles", "defines": ["TFM_PLATFORM=arm/mps2/an521"]})
    argv = result.approval["arguments"]["argv"]
    assert result.approval["tool"] == "compile_db" and argv[:2] == ["cmake", "-S"]
    assert "-DTFM_PLATFORM=arm/mps2/an521" in argv and "-G" in argv
    assert not started and not (workspace.root / "compile_db" / "B1").exists()


@needs_jail
def test_the_jail_keeps_the_source_read_only_and_the_database_becomes_build_context(workspace: Workspace) -> None:
    proposal = compile_db_job.propose(workspace, defines={"X": "1"})
    outcome = compile_db_job.run(workspace, proposal["number"])
    assert not (workspace.source / "written-by-cmake").exists()
    assert "read-only" in (workspace.root / "compile_db" / "B1.logs" / "stderr.log").read_text()
    assert outcome["usable"] and outcome["buildctx_version"] == 2
    context = current_buildctx(workspace)
    assert context["build"]["compile_database"].endswith("B1/compile_commands.json")
    assert workspace.ledger.of("compile_db_generated")[-1]["usable"] is True


def test_the_jail_argv_has_no_network_and_one_writable_directory(tmp_path: Path) -> None:
    if sandbox.available() is None:
        pytest.skip("bubblewrap is needed")
    argv = sandbox.jail(["cmake", "-S", "x"], writable=tmp_path, cwd=tmp_path)
    assert "--unshare-net" in argv and argv[argv.index("--ro-bind") + 1: argv.index("--ro-bind") + 3] == ["/", "/"]
    assert argv.index("--tmpfs") < argv.index("--bind")  # the build directory is bound after the private /tmp
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--bind"] == [str(tmp_path.resolve())]
    assert json.dumps(argv).count("--bind") == 1

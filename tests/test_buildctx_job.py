"""M6: build context from the conversation -- diagnose, propose and probe, apply on a click, re-run only failures."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from helpers import executable
from test_evaluate import buildctx_file, fake_tools

from code_analyzer.errors import UserError
from code_analyzer.evidence.analyze import current_buildctx, evaluate
from code_analyzer.evidence.buildctx_schema import load_buildctx
from code_analyzer.evidence.store import Store
from code_analyzer.evidence.workspace import Workspace
from code_analyzer.jobs import buildctx_job


def _splint_that_needs_an_include(tools: Path) -> Path:
    """Preprocesses only when -I points at the directory holding support.h."""
    return executable(tools / "splint", """
        import pathlib, sys
        if '-help' in sys.argv: print('Splint 3.1.2'); raise SystemExit()
        report = pathlib.Path(sys.argv[sys.argv.index('+csv') + 1])
        report.write_text('Warning,Flag Code,Flag Name,Priority,File,Line,Column,Warning Text,Additional Text\\n')
        if not any(a.startswith('-I') and a.rstrip('/').endswith('support') for a in sys.argv):
            print('main.c:1:10: Cannot find include file support.h on search path', file=sys.stderr)
            print('Preprocessing error. (Use -preproc to inhibit warning)', file=sys.stderr)
            print('Cannot continue.', file=sys.stderr)
            raise SystemExit(1)
        print('Finished checking --- no code warnings', file=sys.stderr)
    """)


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    source = tmp_path / "project"
    (source / "support").mkdir(parents=True)
    (source / "support" / "support.h").write_text("int helper(void);\n")
    for name in ("main.c", "other.c"):
        (source / name).write_text('#include "support.h"\nint main(void) { return helper(); }\n')
    tools = fake_tools(tmp_path, source / "main.c")
    tools["splint"] = _splint_that_needs_an_include(tmp_path / "fake tools")
    outcome = evaluate(source, eval_dir=tmp_path / "eval", profile="generic-sesip",
                       buildctx=load_buildctx(buildctx_file(tmp_path, tools)), compile_db=False)
    return outcome.workspace


def test_diagnose_reports_counts_from_the_evidence(workspace: Workspace) -> None:
    report = buildctx_job.diagnose(workspace)["splint"]
    assert (report["units_failed"], report["units_total"], report["units_analysis_reached"]) == (2, 2, 0)
    assert report["top_missing"][0] == {"header": "support.h", "units": 2, "kind": "unambiguous",
                                        "candidates": ["support"]}


def test_propose_stores_a_patch_and_applies_nothing(workspace: Workspace) -> None:
    before = current_buildctx(workspace)
    proposal = buildctx_job.propose(workspace, "splint")
    patch = proposal["patch"]
    assert patch["labels"] == ["-I support"] and patch["preselected"] == [0]
    assert patch["probe"]["reached_after"] == 2 and patch["probe"]["reached_before"] == 0
    assert current_buildctx(workspace) == before
    assert (workspace.root / "buildctx" / "patches" / "P-1.json").is_file()


def test_apply_reruns_only_failures_supersedes_and_keeps_numbers(workspace: Workspace) -> None:
    store = Store(workspace.index_path)
    numbers_before = {row["pv_id"] for row in store.all_pvs()}
    store.close()
    patch = buildctx_job.propose(workspace, "splint")["patch"]
    outcome = buildctx_job.apply(workspace, patch["patch_id"], patch["preselected"])
    assert (outcome["failed_before"], outcome["failed_after"], outcome["reached_after"]) == (2, 0, 2)
    assert outcome["rerun_files"] == 2 and outcome["buildctx_version"] == 2
    run_dir = workspace.root / workspace.ledger.of("call_finished")[-1]["run_dir"]
    record = json.loads((run_dir / "manifest.json").read_text())["tools"]["splint"]
    assert record["unit_counts"]["superseded"] == 2 and record["status"] == "completed"
    assert "support" in "".join(current_buildctx(workspace)["build"]["include"])
    store = Store(workspace.index_path)
    assert numbers_before <= {row["pv_id"] for row in store.all_pvs()}
    store.close()
    assert workspace.ledger.of("patch_applied")[-1]["failed_after"] == 0


def test_a_stale_patch_is_refused(workspace: Workspace) -> None:
    patch = buildctx_job.propose(workspace, "splint")["patch"]
    buildctx_job.apply(workspace, patch["patch_id"], patch["preselected"])
    with pytest.raises(UserError, match="older build context"):
        buildctx_job.apply(workspace, patch["patch_id"], patch["preselected"])

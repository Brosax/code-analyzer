"""tools-resume: a run whose patch was only recorded is completed later, review re-derived."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_reconfigure import _config, _tree

from code_analyzer.analysis import (
    AnalysisEvent,
    AnalysisRequest,
    CancellationToken,
    run_analysis,
)
from code_analyzer.cli import main
from code_analyzer.control import RunControl, auto_no, auto_yes
from code_analyzer.errors import UserError
from code_analyzer.reconfigure import run_tools_resume
from code_analyzer.tools.common import effective_units


def _recorded_run(tmp_path: Path):
    """A headless propose run: the patch is written, nothing applied."""
    source = _tree(tmp_path)
    config = _config(tmp_path, source, "propose")
    result = run_analysis(AnalysisRequest(source, config), events=lambda _e: None, control=RunControl(CancellationToken(), decider=auto_no))
    assert result.manifest["build_context"]["status"] == "rejected"
    assert result.manifest["tools"]["splint"]["coverage"]["analysis_reached"] == 1
    return source, result.report_directory


def test_resume_continues_at_the_next_round_and_rederives_the_review(tmp_path: Path) -> None:
    _source, run_dir = _recorded_run(tmp_path)
    review_before = (run_dir / "review/summary.json").read_bytes()
    events: list[AnalysisEvent] = []
    block = run_tools_resume(run_dir, decider=auto_yes, event_sink=events.append)
    assert block["outcome"] == "applied" and block["status"] == "applied"
    assert [item["round"] for item in block["rounds"]] == [1, 2]
    assert block["rounds"][0]["decision"] == "reject" and block["rounds"][1]["applied"] and block["rounds"][1]["attempt"] == 3
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    splint = manifest["tools"]["splint"]
    assert splint["coverage"]["analysis_reached"] == 4 and splint["unit_counts"]["superseded"] == 4
    assert {unit["attempt"] for unit in effective_units(splint["units"]) if unit["input_files"] != ["app/ok.c"]} == {3}
    assert manifest["resumed_at"]
    assert (run_dir / "inputs/build-context/r2/applied-config.toml").is_file()
    assert not (run_dir / "inputs/build-context/r1/applied-config.toml").exists()
    assert (run_dir / "suggested-config.toml").is_file()
    # The review was rebuilt from the merged evidence: superseded rows tagged, counts updated.
    summary = json.loads((run_dir / "review/summary.json").read_text(encoding="utf-8"))
    assert (run_dir / "review/summary.json").read_bytes() != review_before
    assert summary["report_integrity"]["superseded_units"] == 4
    assert any(row["evidence_context"].endswith("/superseded") for row in summary["findings"] if row["tool"] == "splint")
    statuses = [e.status for e in events if e.phase == "build_context"]
    assert statuses[0] == "started" and "continuing at round 2" in events[[e.phase for e in events].index("build_context")].message
    assert statuses[-2:] == ["applied", "finished"]
    assert [e.status for e in events if e.phase == "run"] == ["resumed"]


def test_resume_refuses_a_run_with_nothing_to_reconfigure_and_an_off_switch(tmp_path: Path) -> None:
    _source, run_dir = _recorded_run(tmp_path)
    with pytest.raises(UserError, match="assist is off"):
        run_tools_resume(run_dir, assist="off")
    with pytest.raises(UserError, match="no manifest"):
        run_tools_resume(tmp_path / "nowhere")
    # A tool the run never ran is not resumable.
    with pytest.raises(UserError, match="no reconfigurable tool"):
        run_tools_resume(run_dir, tool="cppcheck", decider=auto_yes)


def test_the_command_line_runs_it_headless_with_yes_and_records_only_without(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _source, run_dir = _recorded_run(tmp_path)
    assert main(["tools-resume", str(run_dir)]) == 10  # non-interactive: recorded, not applied
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert [item["round"] for item in manifest["build_context"]["rounds"]] == [1, 2] and not manifest["build_context"]["rounds"][1]["applied"]
    assert main(["tools-resume", str(run_dir), "--build-assist-yes", "--tool", "splint"]) == 0
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert [item["round"] for item in manifest["build_context"]["rounds"]] == [1, 2, 3] and manifest["build_context"]["rounds"][2]["applied"]
    assert manifest["tools"]["splint"]["coverage"]["analysis_reached"] == 4
    out, err = capsys.readouterr()
    assert str(run_dir) in out and "build-context applied" in err
    lines = [json.loads(line) for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [line["status"] for line in lines if line["phase"] == "run"][-2:] == ["resumed", "resumed"]

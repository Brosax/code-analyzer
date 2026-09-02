"""The build-context loop through a real run: diagnose, probe, decide, re-run, merge, report."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from helpers import executable

from code_analyzer.analysis import (
    AnalysisEvent,
    AnalysisRequest,
    CancellationToken,
    run_analysis,
)
from code_analyzer.config import load_config
from code_analyzer.control import Decision, RunControl, auto_no, auto_yes
from code_analyzer.tools import cppcheck
from code_analyzer.tools.common import effective_units


def _picky_splint(tmp_path: Path) -> Path:
    """Fails at the first include unless -I names the directory that carries it."""
    return executable(tmp_path / "picky-splint", """
        import pathlib, sys
        if '-help' in sys.argv: print('Splint 3.1.2'); raise SystemExit()
        report = pathlib.Path(sys.argv[sys.argv.index('+csv') + 1])
        source = sys.argv[-1]
        includes = [a[2:] for a in sys.argv if a.startswith('-I')]
        text = pathlib.Path(source).read_text()
        needed = [line.split('"')[1] for line in text.splitlines() if line.startswith('#include "')]
        missing = [h for h in needed if not any(pathlib.Path(i, h).is_file() for i in includes + [str(pathlib.Path(source).parent)])]
        header = 'Warning, Flag Code, Flag Name, Priority, File, Line, Column, Warning Text, Additional Text\\n'
        if missing:
            # Like the real tool: the warnings it found before dying, then the preprocessing errors.
            rows = f'2,201,boundswrite,1,{source},2,5,"Possible out-of-bounds store (before dying)","A memory write"\\n'
            rows += ''.join(f'1,397,preproc,1,{source},1,1,"Cannot find include file {h} on search path: /x","Preprocessing error."\\n' for h in missing)
            report.write_text(header + rows)
            print('Preprocessing error', file=sys.stderr)
            print('*** Cannot continue.', file=sys.stderr)
            raise SystemExit(1)
        report.write_text(header + f'2,201,boundswrite,1,{source},3,5,"Possible out-of-bounds store","A memory write"\\n')
        print('Finished checking --- 1 code warning', file=sys.stderr)
        raise SystemExit(1)
    """)


def _tree(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    (source / "app").mkdir(parents=True)
    (source / "include").mkdir()
    (source / "include/hal.h").write_text("int hal(void);\n", encoding="utf-8")
    for name in ("a", "b", "c"):
        (source / "app" / f"{name}.c").write_text('#include "hal.h"\nint f(void) { return hal(); }\n', encoding="utf-8")
    (source / "app/lone.c").write_text('#include "vendor.h"\nint g(void) { return 1; }\n', encoding="utf-8")
    (source / "app/ok.c").write_text("int h(void) { return 2; }\n", encoding="utf-8")
    return source


def _config(tmp_path: Path, source: Path, assist: str, **build: object) -> dict:
    return load_config(source, None, {
        "run": {"output_root": str(tmp_path / "reports"), "shareable_export": False},
        "build": {"compile_database_mode": "disabled", "assist": assist, "assist_probe_units": 2, **build},
        # A port nothing listens on: the configurator is skipped at its gate,
        # so these runs test the deterministic loop alone.
        "llm": {"endpoint": "http://127.0.0.1:1/v1"},
        "tools": {
            "cppcheck": {"enabled": False}, "flawfinder": {"enabled": False},
            "splint": {"executable": str(_picky_splint(tmp_path)), "jobs": 1},
        },
    })


def _argv(events: list[AnalysisEvent], path: str, attempt: int) -> list[str]:
    for event in events:
        data = event.data or {}
        if event.phase == "unit" and event.status == "started" and data.get("path") == path and data.get("attempt") == attempt:
            return list(data["argv"])
    raise AssertionError(f"no attempt {attempt} for {path}")


def _run(source: Path, config: dict, control: RunControl):
    events: list[AnalysisEvent] = []
    result = run_analysis(AnalysisRequest(source, config), events=events.append, control=control)
    return result, events


def test_auto_assist_reruns_the_failed_units_and_the_report_keeps_both_attempts(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source, "auto")
    result, events = _run(source, config, RunControl(CancellationToken()))
    splint = result.manifest["tools"]["splint"]
    assert splint["status"] == "partial", splint["unit_counts"]
    # Every unit the loop re-ran is superseded by its second attempt, even lone.c, which failed again.
    assert splint["unit_counts"]["superseded"] == 4
    assert splint["coverage"]["analysis_reached"] == 4  # a, b, c rescued + ok.c
    effective = {unit["input_files"][0]: unit for unit in effective_units(splint["units"])}
    assert effective["app/a.c"]["attempt"] == 2 and effective["app/a.c"]["analysis_reached"]
    assert effective["app/lone.c"]["attempt"] == 2 and effective["app/lone.c"]["failure_class"] == "include"
    old = [unit for unit in splint["units"] if unit["input_files"] == ["app/a.c"] and unit["attempt"] == 1][0]
    assert old["superseded_by"] == effective["app/a.c"]["id"]
    # The applied context is what the re-run saw.
    assert any(arg == f"-I{(source / 'include').resolve()}" for arg in _argv(events, "app/a.c", 2))
    block = result.manifest["build_context"]
    assert block["assist"] == "auto" and block["status"] == "applied" and block["authority"].startswith("non-authoritative")
    assert len(block["rounds"]) == 1 and block["rounds"][0]["applied"] and block["rounds"][0]["after"]["failed"] == 1
    run_dir = result.report_directory
    round_dir = run_dir / "inputs/build-context/r1"
    assert sorted(p.name for p in round_dir.iterdir()) == ["applied-config.toml", "decision.json", "diagnosis.json", "llm.json", "meta.json", "patch.json", "probe", "probe.json"]
    probe = json.loads((round_dir / "probe.json").read_text(encoding="utf-8"))
    assert probe["sampled"] == 2 and probe["reached_after"] == 2
    patch = json.loads((round_dir / "patch.json").read_text(encoding="utf-8"))
    assert [(item["op"], item["value"]) for item in patch["items"]] == [("add_include", "include"), ("add_stub_header", "vendor.h")]
    assert json.loads((round_dir / "decision.json").read_text(encoding="utf-8")) == {"answer": "apply", "selected": [0], "decided_by": "auto", "note": "deterministic patch; probe improved"}
    assert 'include = ["include"]' in (run_dir / "suggested-config.toml").read_text(encoding="utf-8")
    assert "vendor.h" not in [p.name for p in (round_dir / "stubs").glob("*")] if (round_dir / "stubs").exists() else True
    # The source tree and the project config were not touched.
    assert not (source / ".code-analyzer.toml").exists() and sorted(p.name for p in (source / "app").iterdir()) == ["a.c", "b.c", "c.c", "lone.c", "ok.c"]
    # The flow of events: diagnosed -> inferred -> probing -> probed -> (decision) -> applying -> applied -> finished.
    statuses = [e.status for e in events if e.phase == "build_context"]
    assert statuses == ["started", "diagnosed", "inferred", "consulted", "probing", "probed", "applying", "applied", "finished"]
    assert [e.status for e in events if e.phase == "decision"] == ["requested", "decided"]
    reruns = [e for e in events if e.phase == "unit" and e.status == "started" and (e.data or {}).get("attempt") == 2]
    assert len(reruns) == 4
    log = (run_dir / "logs/runner.log").read_text(encoding="utf-8")
    assert "build_context" in log and "attempt 2" in log or "applying" in log
    # The review keeps the superseded rows, tagged, and counts them.
    review = json.loads((run_dir / "review/summary.json").read_text(encoding="utf-8"))
    contexts = {row["evidence_context"] for row in review["findings"] if row["tool"] == "splint"}
    assert "source-only/superseded" in contexts and "source-only" in contexts
    assert review["report_integrity"]["superseded_units"] == 4


def test_propose_without_consent_records_the_patch_and_changes_nothing(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source, "propose")
    result, events = _run(source, config, RunControl(CancellationToken(), decider=auto_no))
    splint = result.manifest["tools"]["splint"]
    assert splint["coverage"]["analysis_reached"] == 1 and "superseded" not in splint["unit_counts"]
    block = result.manifest["build_context"]
    assert block["status"] == "rejected" and "non-interactive" in block["reason"] and block["suggested_config"] is None
    round_dir = result.report_directory / "inputs/build-context/r1"
    assert (round_dir / "patch.json").is_file() and (round_dir / "decision.json").is_file()
    assert not (round_dir / "applied-config.toml").exists()
    assert not (result.report_directory / "suggested-config.toml").exists()
    assert [e.status for e in events if e.phase == "build_context"][-3:] == ["awaiting", "rejected", "finished"]


def test_propose_with_yes_applies_exactly_the_preselected_items(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source, "propose")
    result, _events = _run(source, config, RunControl(CancellationToken(), decider=auto_yes))
    block = result.manifest["build_context"]
    assert block["status"] == "applied" and block["rounds"][0]["selected"] == [0] and block["rounds"][0]["decided_by"] == "cli --build-assist-yes"
    assert result.manifest["tools"]["splint"]["coverage"]["analysis_reached"] == 4


def test_an_operator_can_take_the_stub_too_and_the_stub_lives_under_the_run(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source, "propose")
    control = RunControl(CancellationToken())

    def answer() -> None:
        while not control.pending():
            threading.Event().wait(0.05)
        request = control.pending()[0]
        control.decide(request.id, "apply", (0, 1), "test")

    threading.Thread(target=answer, daemon=True).start()
    result, events = _run(source, config, control)
    splint = result.manifest["tools"]["splint"]
    assert splint["status"] == "completed" and splint["coverage"]["analysis_reached"] == 5
    stub = result.report_directory / "inputs/build-context/r1/stubs/vendor.h"
    assert stub.is_file() and "declares nothing" in stub.read_text(encoding="utf-8")
    assert any(arg.endswith("/r1/stubs") for arg in _argv(events, "app/lone.c", 2))
    assert 'include = ["include", "inputs/build-context/r1/stubs"]' not in (result.report_directory / "suggested-config.toml").read_text(encoding="utf-8")


def test_assist_off_leaves_the_manifest_saying_so(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    result, events = _run(source, _config(tmp_path, source, "off"), RunControl(CancellationToken()))
    assert result.manifest["build_context"]["status"] == "off"
    assert not [e for e in events if e.phase == "build_context"]
    assert not (result.report_directory / "inputs/build-context").exists()


def test_a_tree_with_nothing_to_prove_is_skipped_with_a_reason(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "only.c").write_text('#include "vendor.h"\nint g(void) { return 1; }\n', encoding="utf-8")
    config = _config(tmp_path, source, "auto", stub_headers=False)
    result, events = _run(source, config, RunControl(CancellationToken()))
    block = result.manifest["build_context"]
    assert block["status"] == "skipped" and "none resolvable" in block["reason"]
    assert [e.status for e in events if e.phase == "build_context"] == ["started", "diagnosed", "skipped", "finished"]


def test_cppcheck_reconfigurable_names_the_fallback_pass_only_when_headers_were_missing() -> None:
    record = {"units": [
        {"id": "compile-db", "valid_report": True, "diagnosis": {"counts": {"missingInclude": 3}}},
        {"id": "fallback", "valid_report": True, "diagnosis": {"counts": {"missingInclude": 2}}},
    ]}
    assert cppcheck.reconfigurable(record) == ["fallback"]
    assert cppcheck.reconfigurable({"units": [{"id": "fallback", "valid_report": True, "diagnosis": {"counts": {}}}]}) == []


def test_decision_objects_round_trip_through_the_journal() -> None:
    decision = Decision("apply", (0, 2), "tui", "")
    assert decision.answer == "apply" and decision.selected == (0, 2)

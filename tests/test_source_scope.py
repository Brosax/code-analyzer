"""Source discovery's own honesty: what it read, what it could not read, and
what that does to the run's verdict.

Every failure here is injected rather than provoked with ``chmod``: a suite
running as root reads a mode-000 file without blinking, and the test would go
green while testing nothing.
"""
from __future__ import annotations

import errno
import json
import os
import stat
import textwrap
from pathlib import Path
from typing import Any

import pytest

from code_analyzer.analysis import (
    AnalysisEvent,
    AnalysisRequest,
    CancellationToken,
    run_analysis,
)
from code_analyzer.config import load_config
from code_analyzer.inventory import Discovery, ScopeAnomaly, discover, scope_summary
from code_analyzer.runner import analyze
from code_analyzer.status import overall

# --- fault injection --------------------------------------------------------


def _denied(target: Path) -> PermissionError:
    return PermissionError(errno.EACCES, os.strerror(errno.EACCES), str(target))


def _real(target: Any) -> str:
    """Canonical path without ``Path.resolve``, which itself calls ``Path.stat``."""
    return os.path.realpath(os.fsdecode(target))


def deny_read(monkeypatch: pytest.MonkeyPatch, *targets: Path, exc: OSError | None = None) -> None:
    """Make ``read_bytes`` fail for exactly these paths."""
    blocked = {_real(target) for target in targets}
    original = Path.read_bytes

    def read_bytes(self: Path) -> bytes:
        if _real(self) in blocked:
            raise exc or _denied(self)
        return original(self)

    monkeypatch.setattr(Path, "read_bytes", read_bytes)


def deny_stat(monkeypatch: pytest.MonkeyPatch, *targets: Path) -> None:
    blocked = {_real(target) for target in targets}
    original = Path.stat

    def stat_(self: Path, *, follow_symlinks: bool = True) -> Any:
        if follow_symlinks and _real(self) in blocked:
            raise _denied(self)
        return original(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", stat_)


def deny_symlink_probe(monkeypatch: pytest.MonkeyPatch, *targets: Path) -> None:
    """Fail ``lstat`` -- what ``is_symlink`` runs -- for these paths."""
    blocked = {_real(target) for target in targets}
    original = Path.stat

    def stat_(self: Path, *, follow_symlinks: bool = True) -> Any:
        if not follow_symlinks and _real(self) in blocked:
            raise _denied(self)
        return original(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", stat_)


def deny_walk(monkeypatch: pytest.MonkeyPatch, *targets: Path) -> None:
    """Make ``os.scandir`` -- and so ``os.walk`` -- fail for these directories."""
    blocked = {_real(target) for target in targets}
    original = os.scandir

    def scandir(path: Any = None, *args: Any, **kwargs: Any) -> Any:
        # shutil.rmtree hands scandir an open descriptor; only a name can match.
        if isinstance(path, (str, bytes, os.PathLike)) and _real(path) in blocked:
            raise _denied(Path(os.fsdecode(path)))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", scandir)


# --- fixtures ---------------------------------------------------------------


def _cppcheck(tmp_path: Path, *, valid: bool = True) -> Path:
    body = (
        "report.write_text('<results><errors><error id=\"nullPointer\" severity=\"error\" cwe=\"476\" "
        "msg=\"Null\"><location file=\"main.c\" line=\"1\"/></error></errors></results>')"
        if valid else "report.write_text('not xml at all')"
    )
    fake = tmp_path / "cppcheck"
    fake.write_text(textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import pathlib, sys
        if '--version' in sys.argv:
            print('Cppcheck 2.fake'); raise SystemExit()
        if '--help' in sys.argv:
            print('usage --xml-version --output-file --project --file-list --check-level --check-library --checkers-report --cppcheck-build-dir')
            raise SystemExit()
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        checkers = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--checkers-report=')))
        {body}
        checkers.write_text('ok')
    """), encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    return fake


def _tree(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    (source / "vendor").mkdir(parents=True)
    (source / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    (source / "vendor" / "helper.c").write_text("int helper(void){return 1;}\n", encoding="utf-8")
    return source


def _config(tmp_path: Path, source: Path, *, export: bool = False, valid: bool = True) -> dict[str, Any]:
    return load_config(source, None, {
        "run": {"output_root": str(tmp_path / "reports"), "shareable_export": export},
        "tools": {
            "cppcheck": {"enabled": True, "executable": str(_cppcheck(tmp_path, valid=valid))},
            "flawfinder": {"enabled": False}, "splint": {"enabled": False},
        },
        "build": {"compile_database_mode": "disabled"},
    })


def _plain_config(source: Path, tmp_path: Path) -> dict[str, Any]:
    return load_config(source, None, {"run": {"output_root": str(tmp_path / "out")}})


# --- discovery records ------------------------------------------------------


def test_an_unreadable_file_is_recorded_instead_of_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    deny_read(monkeypatch, source / "vendor" / "helper.c")

    found = discover(source, _plain_config(source, tmp_path), tmp_path / "out")

    assert [item["path"] for item in found.files] == ["main.c"]
    assert [item.as_dict() for item in found.anomalies] == [{
        "path": "vendor/helper.c", "operation": "read",
        "error": "EACCES", "reason": os.strerror(errno.EACCES),
    }]
    assert not found.complete


def test_unreadable_attributes_are_their_own_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    deny_stat(monkeypatch, source / "main.c")

    found = discover(source, _plain_config(source, tmp_path), tmp_path / "out")

    assert [item["path"] for item in found.files] == ["vendor/helper.c"]
    assert [(item.path, item.operation) for item in found.anomalies] == [("main.c", "stat")]


def test_an_undecidable_symlink_probe_is_recorded_rather_than_taking_the_walk_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    deny_symlink_probe(monkeypatch, source / "main.c", source / "vendor")

    found = discover(source, _plain_config(source, tmp_path), tmp_path / "out")

    assert found.files == []
    assert [(item.path, item.operation) for item in found.anomalies] == [
        ("main.c", "stat"), ("vendor", "walk"),
    ]


def test_a_file_that_vanishes_between_the_walk_and_the_read_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    target = source / "main.c"
    deny_read(monkeypatch, target, exc=FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(target)))

    found = discover(source, _plain_config(source, tmp_path), tmp_path / "out")

    assert [item["path"] for item in found.files] == ["vendor/helper.c"]
    assert [(item.path, item.operation, item.error) for item in found.anomalies] == [
        ("main.c", "read", "ENOENT"),
    ]


def test_an_untraversable_directory_is_recorded_and_its_files_stay_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    deny_walk(monkeypatch, source / "vendor")

    found = discover(source, _plain_config(source, tmp_path), tmp_path / "out")

    assert [item["path"] for item in found.files] == ["main.c"]
    assert [(item.path, item.operation, item.error) for item in found.anomalies] == [
        ("vendor", "walk", "EACCES"),
    ]


def test_an_unreadable_ignore_file_leaves_the_scope_undecided(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    # A directory where .gitignore should be: an OS failure no test user escapes.
    (source / ".gitignore").mkdir()
    config = _plain_config(source, tmp_path)
    config["source"]["respect_gitignore"] = True

    found = discover(source, config, tmp_path / "out")

    assert [(item.path, item.operation) for item in found.anomalies] == [(".gitignore", "gitignore")]
    assert not found.complete
    # Rules that could not be read do not silently become "no rules kept out".
    assert scope_summary(found)["unreadable_ignore_files"] == 1


def test_scope_summary_folds_both_walks_without_double_counting() -> None:
    shared = ScopeAnomaly("a/lost.c", "read", "EACCES", "Permission denied")
    initial = Discovery([], (shared, ScopeAnomaly("a/sub", "walk", "EACCES", "Permission denied")))
    recheck = Discovery([], (shared,))

    assert scope_summary(initial, recheck) == {
        "complete": False, "discovery_complete": False, "recheck_complete": False,
        "unreadable_files": 1, "unreadable_directories": 1, "unreadable_ignore_files": 0,
        "anomalies": 2,
    }
    assert scope_summary(Discovery([]))["recheck_complete"] is None
    assert scope_summary(Discovery([]))["complete"] is True


# --- the stability recheck --------------------------------------------------


def test_a_file_the_recheck_cannot_read_is_unverified_not_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source)
    import code_analyzer.runner as runner_module

    real = runner_module.discover
    calls: list[int] = []

    def once_readable(*args: Any, **kwargs: Any) -> Discovery:
        calls.append(1)
        found = real(*args, **kwargs)
        if len(calls) == 1:
            return found
        return Discovery(
            [item for item in found.files if item["path"] != "vendor/helper.c"],
            (*found.anomalies, ScopeAnomaly("vendor/helper.c", "read", "EACCES", "Permission denied")),
        )

    monkeypatch.setattr(runner_module, "discover", once_readable)
    exit_code, run_dir = analyze(source, config)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    changes = manifest["source_inventory"]["changes"]
    assert changes["deleted"] == [] and changes["unverified"] == ["vendor/helper.c"]
    # Unknown, not "held still" and not "changed".
    assert manifest["source_inventory"]["stable"] is None
    assert manifest["source_inventory"]["scope"]["recheck_complete"] is False
    assert manifest["status"] == "partial" and exit_code == 10
    inventory = json.loads((run_dir / "inputs" / "source-inventory.json").read_text(encoding="utf-8"))
    assert inventory["discovery"] == {"complete": True, "anomalies": []}
    assert inventory["recheck"]["anomalies"] == [{
        "path": "vendor/helper.c", "operation": "read", "error": "EACCES", "reason": "Permission denied",
    }]


def test_the_same_missed_directory_in_both_walks_is_not_a_stable_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source)
    deny_walk(monkeypatch, source / "vendor")

    exit_code, run_dir = analyze(source, config)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    # Both walks agree, and both were blind in the same place.
    assert manifest["source_inventory"]["changes"] == {
        "added": [], "deleted": [], "changed": [], "unverified": [],
    }
    assert manifest["source_inventory"]["stable"] is None
    assert exit_code == 10


# --- the final verdict ------------------------------------------------------


def test_overall_lowers_a_finished_run_for_an_incomplete_scope() -> None:
    tools = {"x": {"requested": True, "status": "completed", "valid_reports": 1}}
    assert overall(tools, True, "completed", "completed") == ("complete", 0)
    assert overall(tools, True, "completed", "completed", scope_complete=False) == ("partial", 10)
    blind = {"x": {"requested": True, "status": "failed", "valid_reports": 0}}
    assert overall(blind, True, "completed", "completed", scope_complete=False) == ("failed", 20)


def test_an_incomplete_scope_survives_a_successful_tool_and_export(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source, export=True)
    deny_walk(monkeypatch, source / "vendor")

    exit_code, run_dir = analyze(source, config)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["tools"]["cppcheck"]["status"] == "completed"
    assert manifest["export"]["status"] == "completed"
    # A successful export must not launder an incomplete scan back to success.
    assert exit_code == 10 and manifest["status"] == "partial"
    assert manifest["source_inventory"]["scope"] == {
        "complete": False, "discovery_complete": False, "recheck_complete": False,
        "unreadable_files": 0, "unreadable_directories": 1, "unreadable_ignore_files": 0,
        "anomalies": 1,
    }


def test_an_incomplete_scope_without_a_valid_report_is_a_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source, valid=False)
    deny_walk(monkeypatch, source / "vendor")

    exit_code, run_dir = analyze(source, config)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    assert manifest["tools"]["cppcheck"]["valid_reports"] == 0
    assert exit_code == 20 and manifest["status"] == "failed"


def test_a_cancelled_run_with_an_incomplete_scope_still_exits_130(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source)
    deny_walk(monkeypatch, source / "vendor")
    token = CancellationToken()

    def sink(event: AnalysisEvent) -> None:
        if (event.phase, event.status) == ("discovery", "finished"):
            token.cancel()

    result = run_analysis(AnalysisRequest(source, config), events=sink, cancellation=token)

    assert result.exit_code == 130
    assert result.manifest is not None
    assert result.manifest["status"] == "interrupted"
    # What the run did learn about its scope is kept, not overwritten.
    assert result.manifest["source_inventory"]["scope"]["unreadable_directories"] == 1
    assert result.manifest["source_inventory"]["scope"]["recheck_complete"] is None


# --- what the four front ends say -------------------------------------------


def _incomplete_manifest() -> dict[str, Any]:
    return {
        "run_id": "scope-run", "tools": {}, "status": "partial", "exit_code": 10,
        "source_inventory": {
            "total": 120, "stable": None, "changes": {},
            "scope": {
                "complete": False, "discovery_complete": False, "recheck_complete": False,
                "unreadable_files": 2, "unreadable_directories": 1, "unreadable_ignore_files": 0,
                "anomalies": 3,
            },
        },
    }


def _embedded(rendered: str) -> dict[str, Any]:
    marker = '<script id="report-data" type="application/json">'
    return json.loads(rendered.split(marker, 1)[1].split("</script>", 1)[0])


def test_the_dashboard_carries_the_scope_and_labels_coverage_as_discovered_only() -> None:
    from code_analyzer.html_report import render

    rendered = render(_incomplete_manifest(), None)
    embedded = _embedded(rendered)

    assert embedded["source_manifest"]["scope"]["unreadable_directories"] == 1
    assert embedded["execution_manifest"]["source_inventory"]["scope"]["complete"] is False
    script = rendered.rsplit("<script>", 1)[1].rsplit("</script>", 1)[0]
    for literal in ("scope_notice_tail", "scope_dirs_unknown", "scope_basis", "scope_unrecorded"):
        assert literal in script
    # The two sentences the operator has to be able to read.
    assert "个目录无法遍历" in rendered and "这些目录里有多少源文件，本次运行不知道。" in rendered
    assert "基于已发现文件" in rendered


def test_a_report_written_before_scope_was_recorded_reads_as_unrecorded() -> None:
    from code_analyzer.html_report import render

    old = {"run_id": "old-run", "tools": {}, "status": "complete", "exit_code": 0,
           "source_inventory": {"total": 5, "stable": True}}

    embedded = _embedded(render(old, None))

    assert embedded["source_manifest"]["scope"] is None
    assert "未记录" in render(old, None)


def test_the_markdown_report_states_the_scope(tmp_path: Path) -> None:
    from code_analyzer.review import _scope_line, markdown_report

    summary = {"source_manifest": {"total_files": 120, "scope": _incomplete_manifest()["source_inventory"]["scope"]}}
    line = _scope_line(summary)

    assert "`incomplete`" in line and "`2` unreadable file(s)" in line
    assert "relative to the discovered files" in line
    assert _scope_line({"source_manifest": {"total_files": 1}}) == "`not recorded`"
    assert "Scan scope:" in markdown_report({**summary, "tools": {}, "findings": []})


def test_the_live_graph_draws_discovery_as_partial() -> None:
    from code_analyzer.serve import graph

    nodes = {item["id"]: item for item in graph(_incomplete_manifest())["nodes"]}

    assert nodes["discovery"]["state"] == "partial"
    assert nodes["discovery"]["note"] == "范围不完整：2 个文件无法读取，1 个目录无法遍历"
    complete = graph({"run_id": "x", "tools": {}, "source_inventory": {"total": 1, "scope": {"complete": True}}})
    assert {item["id"]: item for item in complete["nodes"]}["discovery"]["state"] == "success"


def test_the_tui_discovery_row_says_the_scope_is_incomplete() -> None:
    import copy

    from code_analyzer.config import DEFAULTS, validate_config
    from code_analyzer.flow import RunFlow

    flow = RunFlow(validate_config(copy.deepcopy(DEFAULTS)))
    flow.apply(AnalysisEvent(
        "discovery", "finished", "inventory ready: 120 files", timestamp=0.0, progress=0.1,
        data={"files": 120, "compile_db_entries": 0, "compile_db_path": None,
              "scope": _incomplete_manifest()["source_inventory"]["scope"]},
    ))

    node = flow.nodes["discovery"]
    assert node.state == "partial"
    assert node.detail == "120 文件 · 无 compile-db · 范围不完整（2 文件不可读，1 目录不可进）"


def test_preflight_warns_before_the_scan_rather_than_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from code_analyzer.preflight import run_preflight

    source = _tree(tmp_path)
    deny_walk(monkeypatch, source / "vendor")
    config = load_config(source, None, {"run": {"output_root": str(tmp_path / "reports")}})

    result = run_preflight(source, config, probe_tools=False)

    warnings = [item.message for item in result.issues if item.severity == "warning"]
    assert any("源码发现不完整" in message and "1 个目录无法遍历" in message for message in warnings)
    # A warning, not an error: the scan may still be worth running.
    assert result.ok and result.inventory_files == 1


def test_recovery_keeps_the_anomalies_and_does_not_rewrite_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import zipfile

    from code_analyzer.recovery import recover_report

    source = _tree(tmp_path)
    config = _config(tmp_path, source, export=True)
    deny_walk(monkeypatch, source / "vendor")
    exit_code, run_dir = analyze(source, config)
    before = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert exit_code == 10

    monkeypatch.undo()
    recover_report(run_dir)
    after = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    review = json.loads((run_dir / "review" / "summary.json").read_text(encoding="utf-8"))

    # A rebuild explains the old run; it does not re-judge it.
    assert (after["status"], after["exit_code"]) == (before["status"], before["exit_code"]) == ("partial", 10)
    assert after["source_inventory"]["scope"] == before["source_inventory"]["scope"]
    assert review["source_manifest"]["scope"]["unreadable_directories"] == 1
    archives = sorted((run_dir / "exports").glob("*-shareable.zip"))
    with zipfile.ZipFile(archives[-1]) as bundle:
        inventory = json.loads(bundle.read("inputs/source-inventory.json").decode("utf-8"))
    # The records survive redaction, and they never carried a host path.
    assert inventory["discovery"]["anomalies"] == [{
        "path": "vendor", "operation": "walk", "error": "EACCES", "reason": os.strerror(errno.EACCES),
    }]
    assert str(tmp_path) not in json.dumps(inventory)


def test_a_run_recorded_before_scope_existed_still_rebuilds(tmp_path: Path) -> None:
    """The upgrade must not strand the reports that were already on disk."""
    from code_analyzer.persist import json_bytes
    from code_analyzer.recovery import recover_report

    source = _tree(tmp_path)
    exit_code, run_dir = analyze(source, _config(tmp_path, source, export=True))
    assert exit_code == 0
    # Roll the artifacts back to the shape a pre-upgrade run left behind.
    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["source_inventory"].pop("scope")
    manifest["source_inventory"]["changes"].pop("unverified")
    manifest_path.write_bytes(json_bytes(manifest))
    inventory_path = run_dir / "inputs" / "source-inventory.json"
    old = json.loads(inventory_path.read_text(encoding="utf-8"))
    inventory_path.write_bytes(json_bytes({"source": old["source"], "files": old["files"]}))

    recover_report(run_dir)
    rebuilt = json.loads(manifest_path.read_text(encoding="utf-8"))
    review = json.loads((run_dir / "review" / "summary.json").read_text(encoding="utf-8"))

    # Readable, unchanged verdict, and honest about not knowing.
    assert (rebuilt["status"], rebuilt["exit_code"]) == ("complete", 0)
    assert "scope" not in rebuilt["source_inventory"]
    assert review["source_manifest"]["scope"] is None
    assert "未记录" in (run_dir / "index.html").read_text(encoding="utf-8")

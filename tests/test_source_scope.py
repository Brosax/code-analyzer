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
from helpers import load_config, run_static

from code_analyzer.core.cancel import CancellationToken
from code_analyzer.inventory import Discovery, ScopeAnomaly, discover, scope_summary
from code_analyzer.status import overall


def analyze(source: Path, config: dict[str, Any]) -> tuple[int, Path]:
    return run_static(source, config)

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


def _config(tmp_path: Path, source: Path, *, valid: bool = True) -> dict[str, Any]:
    return load_config(source, None, {
        "run": {"output_root": str(tmp_path / "reports")},
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


def test_one_file_that_failed_differently_in_each_walk_counts_once() -> None:
    """Two records, one unreadable file: the counts are of paths, not rows."""
    initial = Discovery([], (ScopeAnomaly("a/lost.c", "read", "EACCES", "Permission denied"),))
    recheck = Discovery([], (ScopeAnomaly("a/lost.c", "stat", "EACCES", "Permission denied"),))

    summary = scope_summary(initial, recheck)

    assert summary["unreadable_files"] == 1
    assert summary["anomalies"] == 2


# --- the stability recheck --------------------------------------------------


def test_a_file_the_recheck_cannot_read_is_unverified_not_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source)
    import code_analyzer.evidence.static_run as runner_module

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


def test_a_file_only_the_first_walk_could_not_read_is_unverified_not_added(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The file was there the whole time; the first walk just could not read
    it.  Calling that an addition invents a source change out of an errno."""
    source = _tree(tmp_path)
    config = _config(tmp_path, source)
    import code_analyzer.evidence.static_run as runner_module

    real = runner_module.discover
    calls: list[int] = []

    def blind_first(*args: Any, **kwargs: Any) -> Discovery:
        calls.append(1)
        found = real(*args, **kwargs)
        if len(calls) > 1:
            return found
        return Discovery(
            [item for item in found.files if item["path"] != "vendor/helper.c"],
            (*found.anomalies, ScopeAnomaly("vendor/helper.c", "read", "EACCES", "Permission denied")),
        )

    monkeypatch.setattr(runner_module, "discover", blind_first)
    exit_code, run_dir = analyze(source, config)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    changes = manifest["source_inventory"]["changes"]
    assert changes["added"] == [] and changes["unverified"] == ["vendor/helper.c"]
    assert manifest["source_inventory"]["stable"] is None
    assert manifest["source_inventory"]["scope"]["discovery_complete"] is False
    assert manifest["source_inventory"]["scope"]["recheck_complete"] is True
    assert exit_code == 10


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


def test_an_incomplete_scope_survives_a_successful_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source)
    deny_walk(monkeypatch, source / "vendor")

    exit_code, run_dir = analyze(source, config)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["tools"]["cppcheck"]["status"] == "completed"
    # A tool that finished must not launder an incomplete scan back to success.
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
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _tree(tmp_path)
    config = _config(tmp_path, source)
    deny_walk(monkeypatch, source / "vendor")
    token = CancellationToken()

    def cancel_after_discovery(line: str) -> None:
        if line.startswith("inventory ready"):
            token.cancel()

    from code_analyzer.evidence import static_run

    exit_code, run_dir = static_run.run(source, config, cancel_after_discovery, cancellation=token)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert exit_code == 130 and manifest["status"] == "interrupted"
    # What the run did learn about its scope is kept, not overwritten.
    assert manifest["source_inventory"]["scope"]["unreadable_directories"] == 1
    assert manifest["source_inventory"]["scope"]["recheck_complete"] is None


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

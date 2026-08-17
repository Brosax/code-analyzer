from __future__ import annotations

import hashlib
import json
import stat
import textwrap
import zipfile
from pathlib import Path

from code_analyzer.config import load_config
from code_analyzer.recovery import recover_report
from code_analyzer.review import build_review
from code_analyzer.sanitize import Redactor
from code_analyzer.tools import flawfinder


def test_redactor_distinguishes_unc_paths_from_json_escape_sequences() -> None:
    redactor = Redactor([])
    escaped_message = r'{"message":"line one\\n\", next"}'
    assert redactor.text(escaped_message) == escaped_message
    assert redactor.leaks(escaped_message) == []
    for value in (r"\\server\share\folder\file.c", r"\\\\server\\share\\folder\\file.c"):
        safe = redactor.text(value)
        assert "server" not in safe
        assert redactor.leaks(safe) == []


def test_flawfinder_streaming_utf8_exclusion_preserves_valid_inputs(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "good.c").write_text("int good;\n", encoding="utf-8")
    (source / "bad.c").write_bytes(b"int bad;\n\xff\n")
    executable = tmp_path / "flawfinder"
    executable.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        import json
        print(json.dumps({'version':'2.1.0','runs':[{'tool':{'driver':{'name':'Flawfinder'}},'results':[]}]}))
    """), encoding="utf-8")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    config = load_config(source, None, {"run": {"shareable_export": False}})

    result = flawfinder.run(
        str(executable), source, run_dir,
        [{"path": "good.c"}, {"path": "bad.c"}], config,
    )

    assert result["status"] == "partial"
    assert result["coverage"] == {
        "metric": "input_coverage", "total": 2, "attempted": 1,
        "analyzed": 1, "excluded": 1, "covered": 1,
        "ratio": 1.0, "effective_total": 1,
    }
    assert result["excluded_files"][0]["path"] == "bad.c"
    assert result["excluded_files"][0]["byte_offset"] == 9
    assert result["units"][0]["input_files"] == ["good.c"]
    assert result["units"][0]["evidence_context"] == "source-only"
    assert (run_dir / "tools/flawfinder/shard-0001/report.sarif").is_file()


def test_corrupt_declared_report_becomes_integrity_diagnostic(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    run_dir = tmp_path / "report"
    cpp = run_dir / "tools/cppcheck/compile-db"
    flaw = run_dir / "tools/flawfinder/shard-0001"
    flaw_two = run_dir / "tools/flawfinder/shard-0002"
    cpp.mkdir(parents=True)
    flaw.mkdir(parents=True)
    flaw_two.mkdir(parents=True)
    (cpp / "report.xml").write_text(
        '<results><errors><error id="x" severity="warning" msg="valid">'
        '<location file="main.c" line="1"/></error></errors></results>', encoding="utf-8",
    )
    (flaw / "report.sarif").write_text("{broken", encoding="utf-8")
    (flaw_two / "report.sarif").write_text("{broken", encoding="utf-8")
    manifest = {
        "manifest_schema_version": 2, "run_id": "r", "status": "partial",
        "source_options": {"include": ["**/*"], "exclude": []},
        "tools": {
            "cppcheck": {"requested": True, "status": "completed", "valid_reports": 1,
                         "units": [{"id": "compile-db", "valid_report": True, "input_files": ["main.c"]}]},
            "flawfinder": {"requested": True, "status": "partial", "valid_reports": 1,
                           "units": [
                               {"id": "shard-0001", "valid_report": True, "input_files": ["main.c"]},
                               {"id": "shard-0002", "valid_report": True, "input_files": ["other.c"]},
                           ]},
            "splint": {"requested": False, "status": "not_requested", "valid_reports": 0, "units": []},
        },
    }

    review = build_review(source, run_dir, manifest, [{"path": "main.c"}])

    assert review["total_findings"] == 1
    assert review["finding_counts"] == {"total": 1, "build-aware": 1, "source-only": 0}
    integrity = [item for item in review["diagnostics"] if item["category"] == "report-integrity"]
    assert len(integrity) == 2 and {item["unit_id"] for item in integrity} == {"shard-0001", "shard-0002"}
    assert review["report_integrity"]["status"] == "partial"
    assert [item["input_files"] for item in review["report_integrity"]["omitted_units"]] == [["main.c"], ["other.c"]]


def test_recover_report_is_offline_preserves_native_state_and_never_overwrites_zip(tmp_path: Path) -> None:
    report = tmp_path / "report"
    native = report / "tools/cppcheck/compile-db/report.xml"
    broken = report / "tools/flawfinder/shard-0001/report.sarif"
    native.parent.mkdir(parents=True)
    broken.parent.mkdir(parents=True)
    native.write_text(
        '<results><errors><error id="x" severity="error" msg="valid">'
        '<location file="main.c" line="2"/></error></errors></results>', encoding="utf-8",
    )
    broken.write_text("not SARIF", encoding="utf-8")
    (report / "inputs").mkdir()
    (report / "inputs/source-inventory.json").write_text(json.dumps({
        "source": "/private/project", "files": [{"path": "main.c", "is_header": False}],
    }), encoding="utf-8")
    (report / "inputs/effective-config.toml").write_text(
        "config_schema_version=2\n[run]\nshareable_export=true\n", encoding="utf-8",
    )
    manifest = {
        "manifest_schema_version": 2, "run_id": "original", "status": "partial", "exit_code": 10,
        "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:01:00Z",
        "source": "/private/project", "output_root": "/private/reports",
        "source_options": {"include": ["**/*"], "exclude": []},
        "source_inventory": {"total": 1, "stable": True},
        "tools": {
            "cppcheck": {"requested": True, "status": "completed", "valid_reports": 1,
                         "coverage": {"total": 1, "covered": 1}, "unit_counts": {},
                         "units": [{"id": "compile-db", "status": "completed", "valid_report": True,
                                    "input_files": ["main.c"], "artifacts": []}]},
            "flawfinder": {"requested": True, "status": "partial", "valid_reports": 0,
                           "coverage": {"total": 1, "covered": 0}, "unit_counts": {},
                           "units": [{"id": "shard-0001", "status": "failed", "valid_report": False,
                                      "input_files": ["main.c"], "reason": "invalid SARIF", "artifacts": []}]},
            "splint": {"requested": False, "status": "not_requested", "valid_reports": 0,
                       "coverage": {}, "unit_counts": {}, "units": []},
        },
        "review": {"enabled": True, "status": "failed", "schema_version": 1},
        "export": {"enabled": True, "status": "failed", "archive": None, "error": "old failure"},
        "artifacts": [],
    }
    (report / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    native_before = native.read_bytes()
    broken_before = broken.read_bytes()

    first = recover_report(report)
    first_review = (report / "review/summary.json").read_bytes()
    second = recover_report(report)

    after = json.loads((report / "manifest.json").read_text(encoding="utf-8"))
    assert first == second == report / "index.html"
    assert native.read_bytes() == native_before and broken.read_bytes() == broken_before
    assert after["status"] == "partial" and after["exit_code"] == 10
    assert after["started_at"] == manifest["started_at"] and after["finished_at"] == manifest["finished_at"]
    assert after["tools"] == manifest["tools"]
    assert after["recovery"]["analyzers_invoked"] is False
    assert (report / "review/summary.json").read_bytes() == first_review
    archives = sorted((report / "exports").glob("*.zip"))
    assert len(archives) == 2 and archives[0].name != archives[1].name
    with zipfile.ZipFile(archives[-1]) as bundle:
        assert broken.relative_to(report).as_posix() not in bundle.namelist()
        payload = b"\n".join(bundle.read(name) for name in bundle.namelist())
        assert b"/private/project" not in payload and b"/private/reports" not in payload
    for relative in ("review/summary.json", "review/summary.md", "index.html"):
        path = report / relative
        indexed = next(item for item in after["artifacts"] if item["path"] == relative)
        assert indexed["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()

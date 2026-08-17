from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
import time
from pathlib import Path

from code_analyzer.compile_db import splint_flags
from code_analyzer.config import load_config
from code_analyzer.html_report import render
from code_analyzer.process import run_process
from code_analyzer.review import build_review, markdown_report, should_fail
from code_analyzer.runner import analyze
from code_analyzer.tools import splint


def test_v1_config_is_upgraded_with_v2_defaults(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    config_file = tmp_path / "old.toml"
    config_file.write_text("config_schema_version=1\n[run]\nshareable_export=false\n", encoding="utf-8")
    config = load_config(source, config_file)
    assert config["config_schema_version"] == 2
    assert config["review"] == {"enabled": True, "fail_on": "none", "max_markdown_findings": 200}
    assert config["tools"]["splint"]["scope"] == "auto"
    assert config["tools"]["splint"]["jobs"] == 1


def test_splint_flags_resolve_each_entry_directory_and_drop_gcc_only_options(tmp_path: Path) -> None:
    build = tmp_path / "build"
    build.mkdir()
    entry = {
        "directory": str(build), "file": str(tmp_path / "main.c"),
        "arguments": [
            "cc", "-I", "../include", "-isystemvendor", "-iquote", "quotes", "-D", "A=1",
            "-UB", "-include", "forced.h", "@response.rsp", "-Wall", "-c", "main.c",
        ],
    }
    assert splint_flags(entry) == [
        "-I" + str((tmp_path / "include").resolve()),
        "-I" + str((build / "vendor").resolve()),
        "-I" + str((build / "quotes").resolve()),
        "-DA=1", "-UB",
    ]


def test_splint_csv_validation_rejects_empty_wrong_delimiter_and_truncation(tmp_path: Path) -> None:
    report = tmp_path / "report.csv"
    report.write_text("", encoding="utf-8")
    assert not splint._validate_csv(report)[0]
    report.write_text("file;line;message\na.c;1;bad\n", encoding="utf-8")
    assert not splint._validate_csv(report)[0]
    report.write_text('file,line,message\na.c,1,"unterminated\n', encoding="utf-8")
    assert not splint._validate_csv(report)[0]
    report.write_text("file,line,message\na.c,1,bad\n", encoding="utf-8")
    assert splint._validate_csv(report)[0]


def test_splint_auto_build_scope_records_inventory_files_not_in_database(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "built.c").write_text("int built;\n", encoding="utf-8")
    (source / "extra.c").write_text("int extra;\n", encoding="utf-8")
    fake = tmp_path / "splint"
    fake.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        import pathlib, sys
        report = pathlib.Path(sys.argv[sys.argv.index('+csv') + 1])
        report.write_text('file,line,message\\nbuilt.c,1,warning\\n')
        print('Finished checking --- 1 code warning', file=sys.stderr)
        raise SystemExit(1)
    """), encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    run_dir = tmp_path / "run"
    (run_dir / "inputs").mkdir(parents=True)
    config = load_config(source, None, {"run": {"shareable_export": False}})
    inventory = [
        {"path": "built.c", "is_header": False}, {"path": "extra.c", "is_header": False},
    ]
    entry = {"directory": str(source), "file": str(source / "built.c"), "arguments": ["cc", "-DBUILT", "built.c"]}
    result = splint.run(str(fake), source, run_dir, inventory, [entry], config, compile_db_present=True)
    assert result["scope"] == "build"
    assert result["coverage"]["total"] == 2
    assert result["coverage"]["effective_total"] == 1
    assert result["coverage"]["excluded"] == 1
    assert result["status"] == "partial"
    assert result["not_in_build"] == 1
    assert len(result["units"]) == 1
    assert (run_dir / "inputs/splint-not-in-build.txt").read_text() == "extra.c\n"


def test_review_parses_native_reports_separates_diagnostics_and_groups_overlap(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    cpp = run_dir / "tools/cppcheck/one"
    flaw = run_dir / "tools/flawfinder/one"
    spl = run_dir / "tools/splint/one"
    for path in (cpp, flaw, spl):
        path.mkdir(parents=True)
    (cpp / "report.xml").write_text(
        '<results><errors><error id="nullPointer" severity="error" cwe="476" msg="Null pointer">'
        '<location file="main.c" line="10" column="2"/></error>'
        '<error id="missingInclude" severity="information" msg="Missing include file">'
        '<location file="main.c" line="1"/></error></errors></results>', encoding="utf-8",
    )
    (flaw / "report.sarif").write_text(json.dumps({
        "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Flawfinder", "rules": [{"id": "null", "properties": {"security-severity": "4"}}]}},
        "results": [{"ruleId": "null", "level": "warning", "message": {"text": "Null pointer CWE-476"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.c"}, "region": {"startLine": 12}}}]}]}],
    }), encoding="utf-8")
    (spl / "report.csv").write_text("file,line,message\nmain.c,20,Variable used before definition\n", encoding="utf-8")
    (spl / "stderr.raw").write_text("main.c:3: Cannot find include file <missing.h>\nFinished checking\n", encoding="utf-8")
    manifest = {
        "run_id": "run", "started_at": "now", "finished_at": "later", "status": "complete",
        "source_options": {"include": ["**/*"], "exclude": []},
        "tools": {
            name: {"requested": True, "status": "completed", "units": [{"id": "one"}], "valid_reports": 1}
            for name in ("cppcheck", "flawfinder", "splint")
        },
    }
    summary = build_review(source, run_dir, manifest, [{"path": "main.c"}])
    assert summary["review_schema_version"] == 2
    assert summary["total_findings"] == 3
    assert {item["severity"] for item in summary["findings"] if item["tool"] == "splint"} == {"unknown"}
    assert {item["review_level"] for item in summary["findings"] if item["tool"] == "cppcheck"} == {"error"}
    assert {item["review_level"] for item in summary["findings"] if item["tool"] != "cppcheck"} == {"unmapped"}
    assert summary["review_level_counts"] == {"error": 1, "unmapped": 2}
    assert summary["grading_reference"]["document"]["file_name"] == "NXP_iMXRT700-AVA_TP_v1.1 (1).pdf"
    assert summary["grading_reference"]["section"]["grading_subsections"][0]["number"] == "7.4.1"
    assert "Manual verification is required" in markdown_report(summary)
    assert {item["category"] for item in summary["diagnostics"]} == {"include"}
    assert len(summary["overlap_groups"]) == 1
    assert should_fail(summary, "medium")
    assert not should_fail(summary, "critical")


def test_dashboard_embeds_all_data_safely_and_uses_text_content() -> None:
    malicious = "bad </script><script>alert(1)</script> & value\u2028next"
    review = {
        "review_schema_version": 1, "project": "/tmp/project", "run": {}, "tools": {},
        "source_manifest": {}, "total_findings": 1, "total_diagnostics": 0,
        "severity_counts": {"high": 1}, "top_cwes": [], "top_files": [], "overlap_groups": [],
        "diagnostics": [], "findings": [{
            "tool": "cppcheck", "severity": "high", "rank": 4, "rule_id": "x", "cwe": "",
            "canonical_path": "main.c", "file": "main.c", "line": "1", "column": "", "message": malicious,
            "fingerprint": "f", "source_artifact": "tools/cppcheck/one/report.xml",
        }],
    }
    rendered = render({"run_id": "x", "tools": {}}, review)
    marker = '<script id="report-data" type="application/json">'
    embedded = json.loads(rendered.split(marker, 1)[1].split("</script>", 1)[0])
    assert embedded["findings"][0]["message"] == malicious
    assert "\\u003c/script\\u003e" in rendered
    assert "</script><script>alert(1)</script>" not in rendered
    assert "textContent" in rendered
    assert "Code review grading reference" in rendered
    assert "review-level" in rendered
    assert "http://" not in rendered and "https://" not in rendered


def test_dashboard_without_review_still_declares_default_grading_reference() -> None:
    rendered = render({"run_id": "no-review", "tools": {}})
    marker = '<script id="report-data" type="application/json">'
    embedded = json.loads(rendered.split(marker, 1)[1].split("</script>", 1)[0])
    assert embedded["grading_reference"]["document"]["file_name"] == "NXP_iMXRT700-AVA_TP_v1.1 (1).pdf"
    assert embedded["grading_reference"]["section"]["number"] == "7"


def test_explicit_gate_only_changes_complete_exit_and_latest_is_atomic_record(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    fake = tmp_path / "cppcheck"
    fake.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        import pathlib, sys
        if '--version' in sys.argv:
            print('Cppcheck 2.fake'); raise SystemExit()
        if '--help' in sys.argv:
            print('usage --xml-version --output-file --project --file-list --check-level --check-library --checkers-report --cppcheck-build-dir')
            raise SystemExit()
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        checkers = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--checkers-report=')))
        report.write_text('<results><errors><error id="nullPointer" severity="error" cwe="476" msg="Null"><location file="main.c" line="1"/></error></errors></results>')
        checkers.write_text('ok')
    """), encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    output = tmp_path / "reports"
    config = load_config(source, None, {
        "run": {"output_root": str(output), "shareable_export": False},
        "review": {"fail_on": "high"},
        "tools": {
            "cppcheck": {"enabled": True, "executable": str(fake)},
            "flawfinder": {"enabled": False}, "splint": {"enabled": False},
        },
        "build": {"compile_database_mode": "disabled"},
    })
    exit_code, run_dir = analyze(source, config)
    manifest = json.loads((run_dir / "manifest.json").read_text())
    latest = json.loads((run_dir.parent / "latest.json").read_text())
    assert exit_code == 1
    assert manifest["status"] == "complete" and manifest["gate"]["triggered"]
    assert latest["run_id"] == manifest["run_id"] and latest["exit_code"] == 1


def test_normal_parent_exit_with_inherited_pipe_is_bounded_and_cleans_process_group(tmp_path: Path) -> None:
    script = tmp_path / "fork.py"
    child_pid = tmp_path / "child.pid"
    script.write_text(textwrap.dedent(f"""
        import subprocess, sys
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])
        open({str(child_pid)!r}, 'w').write(str(child.pid))
        print('parent done', flush=True)
    """), encoding="utf-8")
    started = time.monotonic()
    result = run_process([sys.executable, str(script)], tmp_path, tmp_path / "out", tmp_path / "err", 5, 0.1)
    assert result.exit_code == 0
    assert time.monotonic() - started < 2
    assert (tmp_path / "out").read_text() == "parent done\n"

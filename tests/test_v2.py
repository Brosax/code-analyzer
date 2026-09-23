from __future__ import annotations

import json
import stat
import sys
import textwrap
import time
from pathlib import Path

import pytest
from helpers import load_config

from code_analyzer.compile_db import splint_flags
from code_analyzer.evidence.findings import parse_run
from code_analyzer.evidence.parsing import should_fail
from code_analyzer.process import run_process
from code_analyzer.tools import splint


def build_review(source: Path, run_dir: Path, manifest: dict, _inventory: list) -> dict:
    """What the old review summarised, read back through the v3 parser (evidence/findings.parse_run)."""
    (run_dir / "manifest.json").write_text(json.dumps({**manifest, "source": str(source)}), encoding="utf-8")
    parsed = parse_run(run_dir, source=source)
    return {"findings": parsed.findings, "diagnostics": parsed.diagnostics}


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


# Splint 3.1.2's own header and its own stdout for the same two warnings.  The
# earlier fixtures wrote a hand-made ``file,line,message`` CSV, which is why the
# parser read the ordinal column as the message for years without a red test.
_SPLINT_CSV = (
    "Warning, Flag Code, Flag Name, Priority, File, Line, Column, Warning Text, Additional Text\n"
    '1,63,usereleased,1,bad.c,9,8,"Dead storage p passed as out parameter to free: p",'
    '"Memory is used after it has been released."\n'
    '2,201,boundswrite,1,bad.c,5,3,"Possible out-of-bounds store: strcpy(buf, in)\n'
    'Unable to resolve constraint:\n'
    'requires maxRead(in @ bad.c:5:15) <= 7","A memory write may write beyond the buffer."\n'
)
_SPLINT_STDOUT = (
    "bad.c: (in function copy)\n"
    "bad.c:9:8: Dead storage p passed as out parameter to free: p\n"
    "  Memory is used after it has been released. (Use -usereleased to inhibit warning)\n"
    "bad.c:5:3: Possible out-of-bounds store: strcpy(buf, in)\n"
    "    Unable to resolve constraint:\n"
    "    requires maxRead(in @ bad.c:5:15) <= 7\n"
)


def _splint_only_manifest() -> dict[str, object]:
    return {
        "run_id": "run", "started_at": "now", "finished_at": "later", "status": "complete",
        "source_options": {"include": ["**/*"], "exclude": []},
        "tools": {"splint": {
            "requested": True, "status": "completed",
            "units": [{"id": "one"}], "valid_reports": 1,
        }},
    }


def _splint_review(tmp_path: Path, *, csv_text: str, stdout_text: str) -> dict:
    source = tmp_path / "source"
    source.mkdir()
    (source / "bad.c").write_text("int bad;\n", encoding="utf-8")
    unit = tmp_path / "run" / "tools" / "splint" / "one"
    unit.mkdir(parents=True)
    (unit / "report.csv").write_text(csv_text, encoding="utf-8")
    (unit / "stdout.raw").write_text(stdout_text, encoding="utf-8")
    (unit / "stderr.raw").write_text("Finished checking --- 2 code warnings\n", encoding="utf-8")
    return build_review(source, tmp_path / "run", _splint_only_manifest(), [{"path": "bad.c"}])


def _splint_findings(summary: dict) -> list[dict]:
    return [item for item in summary["findings"] if item["tool"] == "splint"]


def test_splint_csv_findings_carry_the_warning_text_and_the_flag_name(tmp_path: Path) -> None:
    findings = _splint_findings(_splint_review(tmp_path, csv_text=_SPLINT_CSV, stdout_text=_SPLINT_STDOUT))

    # Two warnings, reported once: the CSV and stdout describe the same two.
    assert len(findings) == 2, [item["message"] for item in findings]
    by_rule = {item["rule_id"]: item for item in findings}
    assert set(by_rule) == {"usereleased", "boundswrite"}
    released = by_rule["usereleased"]
    assert released["message"] == (
        "Dead storage p passed as out parameter to free: p "
        "Memory is used after it has been released."
    )
    assert (released["file"], released["line"], released["column"]) == ("bad.c", "9", "8")
    assert released["source_artifact"] == "tools/splint/one/report.csv"
    # A constraint warning wraps over several CSV lines and must still read as
    # one message, the way the text parser renders it.
    assert "\n" not in by_rule["boundswrite"]["message"]
    assert by_rule["boundswrite"]["message"].startswith("Possible out-of-bounds store")


def test_splint_falls_back_to_the_logs_when_the_csv_holds_no_warning(tmp_path: Path) -> None:
    header = _SPLINT_CSV.splitlines()[0] + "\n"

    summary = _splint_review(
        tmp_path, csv_text=header,
        stdout_text=_SPLINT_STDOUT + "bad.c:1: Cannot find include file <missing.h>\n",
    )

    findings = _splint_findings(summary)
    assert len(findings) == 2, [item["message"] for item in findings]
    # The warnings are on stdout; attributing them to stderr.raw -- which holds
    # only the summary table -- points an auditor at a file without them.
    assert {item["source_artifact"] for item in findings} == {"tools/splint/one/stdout.raw"}
    include = [item for item in summary["diagnostics"] if item["tool"] == "splint"]
    assert [item["source_artifact"] for item in include] == ["tools/splint/one/stdout.raw"]


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


def test_native_reports_are_parsed_and_diagnostics_kept_apart(tmp_path: Path) -> None:
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
    assert len(summary["findings"]) == 3
    assert {item["severity"] for item in summary["findings"] if item["tool"] == "splint"} == {"unknown"}
    assert {item["severity"] for item in summary["findings"] if item["tool"] == "flawfinder"} == {"medium"}
    assert {item["review_level"] for item in summary["findings"] if item["tool"] == "cppcheck"} == {"error"}
    assert {item["review_level"] for item in summary["findings"] if item["tool"] != "cppcheck"} == {"unmapped"}
    assert {item["category"] for item in summary["diagnostics"]} == {"include"}
    assert should_fail(summary, "medium")
    assert not should_fail(summary, "critical")


def test_flawfinder_severity_scales_are_not_conflated() -> None:
    from code_analyzer.evidence.parsing import _normalize_severity

    assert _normalize_severity("flawfinder", "4", "security-severity") == "medium"
    assert _normalize_severity("flawfinder", "4", "level") == "high"
    assert _normalize_severity("flawfinder", "5", "level") == "critical"
    assert _normalize_severity("flawfinder", "9.1", "security-severity") == "critical"
    assert _normalize_severity("flawfinder", "0", "level") == "info"
    assert _normalize_severity("flawfinder", "error", None) == "high"


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


def test_setup_failure_after_spawn_reaps_the_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from code_analyzer import process as process_module

    children: list[object] = []
    real_terminate = process_module._terminate

    def spying_terminate(proc: object, grace: float) -> str:
        children.append(proc)
        return real_terminate(proc, grace)

    def failing_set_blocking(fd: int, blocking: bool) -> None:
        raise RuntimeError("setup failure after spawn")

    monkeypatch.setattr(process_module, "_terminate", spying_terminate)
    monkeypatch.setattr(process_module.os, "set_blocking", failing_set_blocking)
    with pytest.raises(RuntimeError, match="setup failure after spawn"):
        run_process(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            tmp_path, tmp_path / "out", tmp_path / "err", 5, 0.1,
        )
    assert children and children[0].poll() is not None

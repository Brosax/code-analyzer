from __future__ import annotations

import hashlib
import json
import textwrap
import zipfile
from pathlib import Path

import pytest
from helpers import executable, run_cli

from code_analyzer.config import load_config
from code_analyzer.inventory import discover, source_slug
from code_analyzer.status import aggregate_units, overall
from code_analyzer.tools.common import artifact_index


def fake_tools(tmp_path: Path, bad_stdout: bool = False) -> dict[str, Path]:
    tools = tmp_path / "fake tools"
    tools.mkdir()
    stdout_line = "sys.stdout.buffer.write(b'\\xff\\xfe')" if bad_stdout else "print('ordinary output')"
    cppcheck = executable(tools / "cppcheck", f"""
        import pathlib, sys
        if '--version' in sys.argv: print('Cppcheck 2.fake'); raise SystemExit()
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        checkers = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--checkers-report=')))
        report.write_text('<?xml version="1.0"?><results version="2"><errors><error file="/mnt/c/Users/Test User/project/a.c"/></errors></results>')
        checkers.write_text('checked /home/tester/project\\n')
        {stdout_line}
        print('diagnostic only', file=sys.stderr)
    """)
    flawfinder = executable(tools / "flawfinder", """
        import json
        print(json.dumps({'version':'2.1.0','$schema':'x','runs':[{'tool':{'driver':{'name':'Flawfinder'}},'artifacts':[{'location':{'uri':'C:\\\\Users\\\\tester\\\\a.c'}}]}]}))
    """)
    splint = executable(tools / "splint", """
        import pathlib, sys
        if '-help' in sys.argv: print('Splint 3.1.2'); raise SystemExit()
        report = pathlib.Path(sys.argv[sys.argv.index('+csv') + 1])
        report.write_text('file,line,message\\n/home/tester/a.c,1,warning\\n')
        print('Finished checking --- 1 code warning', file=sys.stderr)
        raise SystemExit(1)
    """)
    return {"cppcheck": cppcheck, "flawfinder": flawfinder, "splint": splint}


def write_config(path: Path, tools: dict[str, Path], export: bool = True) -> Path:
    path.write_text(textwrap.dedent(f"""
        config_schema_version = 1
        [run]
        shareable_export = {str(export).lower()}
        [tools.cppcheck]
        executable = {json.dumps(str(tools['cppcheck']))}
        [tools.flawfinder]
        executable = {json.dumps(str(tools['flawfinder']))}
        [tools.splint]
        executable = {json.dumps(str(tools['splint']))}
    """), encoding="utf-8")
    return path


def test_config_precedence_and_path_bases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / ".code-analyzer.toml").write_text('config_schema_version=1\n[run]\noutput_root="implicit"\n[build]\ndefine=["A"]\n')
    explicit_dir = tmp_path / "settings"
    explicit_dir.mkdir()
    explicit = explicit_dir / "config.toml"
    explicit.write_text('config_schema_version=1\n[run]\noutput_root="reports"\n[build]\ndefine=["B"]\ninclude=["inc"]\n')
    monkeypatch.chdir(tmp_path)
    config = load_config(source, explicit, {"build": {"define": ["CLI"]}})
    assert config["run"]["output_root"] == str((explicit_dir / "reports").resolve())
    assert config["build"]["include"] == [str((explicit_dir / "inc").resolve())]
    assert config["build"]["define"] == ["CLI"]


def test_inventory_exclusions_hashes_and_slug_collisions(tmp_path: Path) -> None:
    source = tmp_path / "a b"
    source.mkdir()
    (source / "good.c").write_text("int x;")
    (source / "vendor").mkdir()
    (source / "vendor" / "kept.cpp").write_text("int y;")
    (source / "build").mkdir()
    (source / "build" / "ignored.c").write_text("int z;")
    output = source / "reports"
    output.mkdir()
    (output / "old.c").write_text("bad")
    config = load_config(source, None)
    records = discover(source, config, output)
    assert [item["path"] for item in records] == ["good.c", "vendor/kept.cpp"]
    assert all(len(item["sha256"]) == 64 for item in records)
    other = tmp_path / "a?b"
    assert source_slug(source) != source_slug(other)


def test_gitignore_is_opt_in(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "kept.c").write_text("int kept;")
    (source / "ignored.c").write_text("int ignored;")
    (source / ".gitignore").write_text("ignored.c\n")
    config = load_config(source, None)
    assert {item["path"] for item in discover(source, config, tmp_path / "out")} == {"kept.c", "ignored.c"}
    config["source"]["respect_gitignore"] = True
    assert {item["path"] for item in discover(source, config, tmp_path / "out")} == {"kept.c"}


def test_status_semantics() -> None:
    assert aggregate_units([{"status": "completed", "valid_report": True}]) == "completed"
    assert aggregate_units([{"status": "timed_out", "valid_report": False}, {"status": "unscheduled", "valid_report": False}]) == "timed_out"
    assert aggregate_units([{"status": "failed", "valid_report": True}]) == "partial"
    tools = {"x": {"requested": True, "status": "completed", "valid_reports": 1}}
    assert overall(tools, True, "completed") == ("complete", 0)
    assert overall(tools, False, "completed") == ("partial", 10)
    assert overall(tools, None, "completed") == ("partial", 10)
    assert overall(tools, True, "completed", "partial") == ("partial", 10)
    assert overall(tools, True, "completed", "failed") == ("partial", 10)
    assert overall(tools, True, "completed", "completed") == ("complete", 0)


def test_artifact_index_skips_caches_and_reuses_unchanged_hashes(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    for relative in (
        "manifest.json", ".manifest.json.tmp", ".recover-abc.tmp",
        "tools/cppcheck/compile-db/build/cache.a1", "tools/splint/u1/tmp/scratch",
        "tools/cppcheck/compile-db/report.xml", "logs/runner.log",
    ):
        target = run_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("data", encoding="utf-8")
    indexed = artifact_index(run_dir)
    # runner.log is written to the run's last breath, so it cannot be hashed
    # into a manifest that is saved before that breath; like events.jsonl it
    # is a log, not evidence.
    assert {item["path"] for item in indexed} == {"tools/cppcheck/compile-db/report.xml"}
    cache: dict[str, tuple[int, int, dict]] = {}
    artifact_index(run_dir, cache)
    for _size, _mtime_ns, item in cache.values():
        item["sha256"] = "from-cache"
    assert {item["sha256"] for item in artifact_index(run_dir, cache)} == {"from-cache"}


def test_cli_dirty_c_exit_semantics_and_private_export(tmp_path: Path) -> None:
    source = tmp_path / "project with spaces"
    source.mkdir()
    (source / "unsafe.c").write_text("int main(void) { char x[1]; return x[2]; }\n")
    tools = fake_tools(tmp_path)
    config = write_config(tmp_path / "config.toml", tools)
    output = tmp_path / "reports"
    completed = run_cli("analyze", source, "--config", config, "--output-root", output, "--no-compile-db")
    assert completed.returncode == 0, completed.stderr
    assert "[code-analyzer] inventory ready: 1 files" in completed.stderr
    assert "tool 1/3 cppcheck: unit 1/1 fallback: scanning 1 files" in completed.stderr
    assert "shareable export completed" in completed.stderr
    assert "run finished: status complete, exit code 0" in completed.stderr
    run_dir = Path(completed.stdout.strip())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["status"] == "complete"
    assert {name: item["status"] for name, item in manifest["tools"].items()} == {"cppcheck": "completed", "flawfinder": "completed", "splint": "completed"}
    cpp_unit = manifest["tools"]["cppcheck"]["units"][0]
    assert cpp_unit["process"]["exit_code"] == 0
    assert "<?xml" not in (run_dir / "tools/cppcheck/fallback/stderr.raw").read_text()
    assert manifest["tools"]["splint"]["units"][0]["process"]["exit_code"] == 1
    for item in manifest["artifacts"]:
        assert hashlib.sha256((run_dir / item["path"]).read_bytes()).hexdigest() == item["sha256"]
    archive = run_dir / manifest["export"]["archive"]
    assert archive.is_file()
    with zipfile.ZipFile(archive) as bundle:
        payload = b"\n".join(bundle.read(name) for name in bundle.namelist())
        assert str(source).encode() not in payload
        assert b"/home/tester" not in payload
        assert b"C:\\Users\\tester" not in payload
        assert "inputs/sanitizer-map.private.json" not in bundle.namelist()


def test_unsanitizable_artifact_is_omitted_from_partial_export_and_kept_private(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "a.c").write_text("int a;")
    tools = fake_tools(tmp_path, bad_stdout=True)
    config = write_config(tmp_path / "config.toml", tools)
    completed = run_cli("analyze", source, "--config", config, "--output-root", tmp_path / "out", "--tool", "cppcheck")
    assert completed.returncode == 10
    run_dir = Path(completed.stdout.strip())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["tools"]["cppcheck"]["status"] == "completed"
    assert manifest["export"]["status"] == "partial"
    assert (run_dir / "tools/cppcheck/fallback/stdout.raw").read_bytes() == b"\xff\xfe"
    archive = run_dir / manifest["export"]["archive"]
    assert archive.is_file()
    assert any(item["entry"].endswith("stdout.raw") for item in manifest["export"]["omitted_artifacts"])
    with zipfile.ZipFile(archive) as bundle:
        assert "tools/cppcheck/fallback/stdout.raw" not in bundle.namelist()
        report = json.loads(bundle.read("redaction-report.json"))
        assert report["status"] == "partial" and report["omitted_artifacts"]


def test_invalid_compile_database_exits_two_before_tools(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.c").write_text("int a;")
    database = source / "compile_commands.json"
    database.write_text("not json")
    completed = run_cli("analyze", source, "--output-root", tmp_path / "out")
    assert completed.returncode == 2
    assert "invalid compile database" in completed.stderr
    assert not (tmp_path / "out").exists()


def test_not_selected_tools_are_manifested(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "a.c").write_text("int a;")
    tools = fake_tools(tmp_path)
    config = write_config(tmp_path / "config.toml", tools, export=False)
    completed = run_cli("analyze", source, "--config", config, "--output-root", tmp_path / "out", "--tool", "flawfinder", "--no-compile-db")
    assert completed.returncode == 0
    manifest = json.loads((Path(completed.stdout.strip()) / "manifest.json").read_text())
    assert manifest["tools"]["cppcheck"]["status"] == "not_requested"
    assert manifest["tools"]["splint"]["status"] == "not_requested"


def test_cppcheck_compile_database_preserves_multiple_configs(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    target = source / "branch.c"
    target.write_text("#ifdef FIRST\nint first;\n#else\nint second;\n#endif\n")
    database = source / "compile_commands.json"
    database.write_text(json.dumps([
        {"directory": str(source), "file": str(target), "arguments": ["cc", "-DFIRST", "-c", str(target)]},
        {"directory": str(source), "file": str(target), "arguments": ["cc", "-DSECOND", "-c", str(target)]},
    ]))
    fake = executable(tmp_path / "cppcheck", """
        import json, pathlib, sys
        if '--version' in sys.argv: print('Cppcheck 2.13.0'); raise SystemExit()
        project = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--project=')))
        entries = json.loads(project.read_text())
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        checkers = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--checkers-report=')))
        errors = ''.join(f'<error id="config-{i}"/>' for i, _ in enumerate(entries))
        report.write_text(f'<results version="2"><errors>{errors}</errors></results>')
        checkers.write_text('ok')
    """)
    config = tmp_path / "config.toml"
    config.write_text(f'config_schema_version=1\n[run]\nshareable_export=false\n[tools.cppcheck]\nexecutable={json.dumps(str(fake))}\n')
    completed = run_cli("analyze", source, "--config", config, "--output-root", tmp_path / "out", "--tool", "cppcheck")
    assert completed.returncode == 0, completed.stderr
    run_dir = Path(completed.stdout.strip())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    assert manifest["compile_database"]["filtered_entries"] == 2
    assert [unit["id"] for unit in manifest["tools"]["cppcheck"]["units"]] == ["compile-db"]
    assert len(json.loads((run_dir / "inputs/compile_commands.filtered.json").read_text())) == 2
    assert (run_dir / "tools/cppcheck/compile-db/report.xml").read_text().count("<error ") == 2


def test_cppcheck_fallback_uses_file_list_for_dash_prefixed_name(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "--option.c").write_text("int safe;\n")
    tools = fake_tools(tmp_path)
    config = write_config(tmp_path / "config.toml", tools, export=False)
    completed = run_cli("analyze", source, "--config", config, "--output-root", tmp_path / "out", "--tool", "cppcheck", "--no-compile-db")
    assert completed.returncode == 0
    run_dir = Path(completed.stdout.strip())
    manifest = json.loads((run_dir / "manifest.json").read_text())
    argv = manifest["tools"]["cppcheck"]["units"][0]["process"]["argv"]
    assert "--option.c" not in argv
    file_list_arg = next(item for item in argv if item.startswith("--file-list="))
    assert Path(file_list_arg.split("=", 1)[1]).read_text() == "--option.c\n"

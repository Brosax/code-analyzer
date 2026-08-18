from __future__ import annotations

import json
import os
import sys
import textwrap
from pathlib import Path

from helpers import executable, run_cli

from code_analyzer.compile_db import discover_candidate_paths, resolve_compile_db
from code_analyzer.config import load_config


def write_db(path: Path, source: Path, names: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([
        {"directory": str(path.parent), "file": str(source / name), "arguments": ["cc", "-c", str(source / name)]}
        for name in names
    ]), encoding="utf-8")


def test_auto_discovery_scores_adjacent_tfm_style_database_by_coverage(tmp_path: Path) -> None:
    source = tmp_path / "project"
    source.mkdir()
    for name in ("one.c", "two.cpp"):
        (source / name).write_text("int value;\n", encoding="utf-8")
    write_db(source / "build-small" / "compile_commands.json", source, ["one.c"])
    best = tmp_path / "build" / "board" / "compile_commands.json"
    write_db(best, source, ["one.c", "two.cpp"])

    config = load_config(source, None)
    selected, entries, reasons, discovery = resolve_compile_db(source, config)

    assert selected == best.resolve()
    assert len(entries) == 2 and reasons == []
    assert discovery["selected"] == str(best.resolve())
    winner = next(item for item in discovery["candidates"] if item["path"] == str(best.resolve()))
    assert winner["source_coverage_ratio"] == 1.0


def test_discovery_is_bounded_and_does_not_follow_symlinks(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    shallow = source / "build" / "a" / "b" / "c" / "compile_commands.json"
    shallow.parent.mkdir(parents=True)
    shallow.write_text("[]", encoding="utf-8")
    too_deep = source / "build" / "a" / "b" / "c" / "d" / "compile_commands.json"
    too_deep.parent.mkdir()
    too_deep.write_text("[]", encoding="utf-8")
    link = source / "out"
    link.symlink_to(too_deep.parent, target_is_directory=True)
    paths = discover_candidate_paths(source)
    assert shallow in paths
    assert too_deep not in paths


def test_json_mode_is_read_only_and_reports_components_and_suggestion(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void) {}\n", encoding="utf-8")
    (source / "CMakeLists.txt").write_text("project(example C)\n", encoding="utf-8")
    completed = run_cli("compile-db", source, "--json", cwd=tmp_path)
    payload = json.loads(completed.stdout)
    assert completed.returncode == 10
    assert payload["selected"] is None
    assert set(payload["components"]) == {"bear", "cmake", "make", "ninja"}
    assert "--method cmake" in payload["suggested_commands"][0]
    assert not (source / "build").exists()


def test_cmake_generation_uses_argv_and_validates_product(tmp_path: Path) -> None:
    source = tmp_path / "source with spaces"
    source.mkdir()
    (source / "main.c").write_text("int main(void) {}\n", encoding="utf-8")
    (source / "CMakeLists.txt").write_text("project(example C)\n", encoding="utf-8")
    tools = tmp_path / "tools"
    tools.mkdir()
    argv_log = tmp_path / "argv.json"
    executable(tools / "ninja", "raise SystemExit(0)\n")
    executable(tools / "cmake", f"""
        import json, pathlib, sys
        pathlib.Path({str(argv_log)!r}).write_text(json.dumps(sys.argv[1:]))
        build = pathlib.Path(sys.argv[sys.argv.index('-B') + 1])
        build.mkdir(parents=True, exist_ok=True)
        source = pathlib.Path(sys.argv[sys.argv.index('-S') + 1])
        (build / 'compile_commands.json').write_text(json.dumps([{{
            'directory': str(build), 'file': str(source / 'main.c'),
            'arguments': ['cc', '-DNAME=hello world', '-c', str(source / 'main.c')]
        }}]))
    """)
    env = {"PATH": str(tools) + os.pathsep + os.environ.get("PATH", "")}
    completed = run_cli(
        "compile-db", source, "--method", "cmake", "--cmake-arg=-DNAME=hello world", "--yes",
        cwd=tmp_path, env=env,
    )
    assert completed.returncode == 0, completed.stderr
    invoked = json.loads(argv_log.read_text())
    assert invoked[-1] == "-DNAME=hello world"
    assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in invoked
    assert "code-analyzer analyze" in completed.stdout
    assert 'compile_database_mode = "explicit"' in completed.stdout
    logs = list((tmp_path / "code-analyzer-reports" / "compile-db").rglob("preparation.json"))
    assert len(logs) == 1
    assert json.loads(logs[0].read_text())["status"] == "completed"


def test_custom_generation_never_uses_a_shell_and_requires_yes_when_redirected(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void) {}\n", encoding="utf-8")
    expected = source / "compile_commands.json"
    marker = tmp_path / "should-not-exist"
    script = tmp_path / "generate.py"
    received = tmp_path / "received.json"
    script.write_text(textwrap.dedent(f"""
        import json, pathlib, sys
        pathlib.Path({str(received)!r}).write_text(json.dumps(sys.argv[1:]))
        source = pathlib.Path({str(source)!r})
        pathlib.Path({str(expected)!r}).write_text(json.dumps([{{
            'directory': str(source), 'file': str(source / 'main.c'),
            'arguments': ['cc', '-c', 'main.c']
        }}]))
    """), encoding="utf-8")
    common = ("compile-db", source, "--method", "command", "--expected-db", expected, "--", sys.executable, script, f"$(touch {marker})")
    refused = run_cli(*common, cwd=tmp_path)
    assert refused.returncode == 10 and not expected.exists()
    completed = run_cli(*common[:6], "--yes", *common[6:], cwd=tmp_path)
    assert completed.returncode == 0, completed.stderr
    assert json.loads(received.read_text()) == [f"$(touch {marker})"]
    assert not marker.exists()


def test_cmake_preset_inherits_binary_dir_and_omits_manual_generator_options(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void) {}\n", encoding="utf-8")
    (source / "CMakeLists.txt").write_text("project(example C)\n", encoding="utf-8")
    (source / "CMakePresets.json").write_text(json.dumps({
        "version": 4,
        "configurePresets": [
            {"name": "base", "hidden": True, "binaryDir": "${sourceDir}/build/${presetName}"},
            {"name": "debug", "inherits": "base"},
        ],
    }), encoding="utf-8")
    tools = tmp_path / "tools"
    tools.mkdir()
    invoked_path = tmp_path / "preset-argv.json"
    executable(tools / "cmake", f"""
        import json, pathlib, sys
        pathlib.Path({str(invoked_path)!r}).write_text(json.dumps(sys.argv[1:]))
        source = pathlib.Path(sys.argv[sys.argv.index('-S') + 1])
        build = source / 'build' / 'debug'
        build.mkdir(parents=True, exist_ok=True)
        (build / 'compile_commands.json').write_text(json.dumps([{{
            'directory': str(build), 'file': str(source / 'main.c'),
            'command': 'cc -c main.c'
        }}]))
    """)
    env = {"PATH": str(tools) + os.pathsep + os.environ.get("PATH", "")}
    completed = run_cli(
        "compile-db", source, "--method", "cmake", "--preset", "debug", "--yes",
        cwd=tmp_path, env=env,
    )
    assert completed.returncode == 0, completed.stderr
    invoked = json.loads(invoked_path.read_text())
    assert invoked[:2] == ["--preset", "debug"]
    assert "-B" not in invoked and "-G" not in invoked

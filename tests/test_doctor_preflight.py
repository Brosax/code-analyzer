from __future__ import annotations

import json
from pathlib import Path

from helpers import executable, run_cli

from code_analyzer.config import load_config
from code_analyzer.doctor import probe_all, probe_tool
from code_analyzer.grading import UNMAPPED_REVIEW_LEVEL, reference_review_level
from code_analyzer.preflight import _field_from_error, run_preflight

CPPCHECK_HELP = (
    "--xml-version --output-file --project --file-list --check-level "
    "--check-library --checkers-report --cppcheck-build-dir"
)


def compatible_cppcheck(tmp_path: Path) -> Path:
    return executable(tmp_path / "cppcheck", f"""
        import pathlib, sys
        if '--version' in sys.argv: print('Cppcheck 2.fake'); raise SystemExit()
        if '--help' in sys.argv: print('{CPPCHECK_HELP}'); raise SystemExit()
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        report.write_text('<results version="2"/>')
    """)


def test_probe_tool_reports_missing_executable_with_guidance() -> None:
    result = probe_tool("cppcheck", "definitely-not-installed-anywhere")
    assert result["status"] == "missing"
    assert result["version"] is None
    assert "apt install cppcheck" in result["guidance"]


def test_probe_tool_accepts_a_tool_that_passes_the_canary(tmp_path: Path) -> None:
    result = probe_tool("cppcheck", str(compatible_cppcheck(tmp_path)))
    assert result["status"] == "compatible"
    assert result["version"] == "Cppcheck 2.fake"
    assert result["verification"] == "canary"
    assert result["canary"] == {"ok": True, "reason": None}
    assert result["missing_capabilities"] == []
    assert result["guidance"] is None


def test_probe_tool_rejects_a_tool_whose_canary_produces_no_report(tmp_path: Path) -> None:
    broken = executable(tmp_path / "cppcheck", f"""
        import sys
        if '--version' in sys.argv: print('Cppcheck 2.broken'); raise SystemExit()
        if '--help' in sys.argv: print('{CPPCHECK_HELP}'); raise SystemExit()
    """)
    result = probe_tool("cppcheck", str(broken))
    assert result["status"] == "incompatible"
    assert result["canary"]["ok"] is False
    assert result["missing_capabilities"]
    assert result["guidance"] is not None


def test_probe_all_ignores_disabled_tools_for_the_overall_verdict(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    config = load_config(source, None, {"tools": {
        "cppcheck": {"enabled": True, "executable": str(compatible_cppcheck(tmp_path))},
        "flawfinder": {"enabled": False, "executable": "missing-flawfinder"},
        "splint": {"enabled": False, "executable": "missing-splint"},
    }})
    result = probe_all(config)
    assert result["ok"] is True
    assert result["tools"]["cppcheck"]["status"] == "compatible"
    assert result["tools"]["flawfinder"]["status"] == "missing"
    assert result["python"]["ok"] is True


def test_doctor_cli_json_output_and_exit_codes(tmp_path: Path) -> None:
    config = tmp_path / "config.toml"
    config.write_text(f"""
config_schema_version = 2
[tools.cppcheck]
executable = {json.dumps(str(compatible_cppcheck(tmp_path)))}
[tools.flawfinder]
enabled = false
[tools.splint]
enabled = false
""", encoding="utf-8")
    healthy = run_cli("doctor", "--json", "--config", config)
    assert healthy.returncode == 0, healthy.stderr
    report = json.loads(healthy.stdout)
    assert report["ok"] is True
    assert report["tools"]["cppcheck"]["status"] == "compatible"

    config.write_text("""
config_schema_version = 2
[tools.cppcheck]
executable = "definitely-not-installed-anywhere"
[tools.flawfinder]
enabled = false
[tools.splint]
enabled = false
""", encoding="utf-8")
    broken = run_cli("doctor", "--json", "--config", config)
    assert broken.returncode == 20
    assert json.loads(broken.stdout)["ok"] is False


def test_preflight_reports_tool_selection_and_output_root_errors(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    config = load_config(source, None, {
        "run": {"output_root": str(source)},
        "tools": {name: {"enabled": False} for name in ("cppcheck", "flawfinder", "splint")},
        "build": {"compile_database_mode": "disabled"},
    })
    result = run_preflight(source, config, probe_tools=False)
    assert result.ok is False
    fields = {issue.field for issue in result.issues if issue.severity == "error"}
    assert fields == {"tools", "run.output_root"}


def test_preflight_passes_a_valid_configuration(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
    config = load_config(source, None, {
        "run": {"output_root": str(tmp_path / "reports")},
        "tools": {
            "cppcheck": {"enabled": True},
            "flawfinder": {"enabled": False}, "splint": {"enabled": False},
        },
        "build": {"compile_database_mode": "disabled"},
    })
    result = run_preflight(source, config, probe_tools=False)
    assert result.ok is True
    assert result.inventory_files == 1
    assert result.compile_database == {
        "path": None, "entries": 0, "degraded": ["compile database disabled"],
        "discovery": result.compile_database["discovery"],
    }
    assert not any(issue.severity == "error" for issue in result.issues)


def test_preflight_field_extraction_from_validation_errors() -> None:
    assert _field_from_error("run.output_root: must be a string") == "run.output_root"
    assert _field_from_error("tools.splint.jobs must be positive") == "tools.splint.jobs"
    assert _field_from_error("something unrelated") is None


def test_reference_review_level_is_an_exact_match_mapping() -> None:
    assert reference_review_level("Error") == "error"
    assert reference_review_level(" style ") == "style"
    assert reference_review_level("warning") == "warning"
    assert reference_review_level("information") == "information"
    for unmapped in ("4", "performance", "", None, "critical"):
        assert reference_review_level(unmapped) == UNMAPPED_REVIEW_LEVEL

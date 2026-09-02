"""Splint evidence honesty: the tolerant CSV reader, failure classes, typed options, overrides."""
from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

import pytest
from helpers import executable

from code_analyzer.cli import _overrides, parser
from code_analyzer.config import (
    effective_toml,
    load_config,
    save_config_snapshot,
    validate_config,
)
from code_analyzer.errors import UserError
from code_analyzer.review import _validate_splint_report
from code_analyzer.tools import splint
from code_analyzer.tools.splint_csv import splint_rows

HEADER = "Warning, Flag Code, Flag Name, Priority, File, Line, Column, Warning Text, Additional Text\n"
# Verbatim from a real trusted-firmware-m run: Splint does not escape the
# quotes inside its own quoted text column.
NESTED_QUOTE_ROW = (
    '5,397,preproc,1,bl2/ext/mcuboot/keys.c,302,62,'
    '"#error "No public key available for given signing algorithm."","Preprocessing error."\n'
)
MULTILINE_ROW = (
    '63,201,boundswrite,1,drv.c,145,5,"Possible out-of-bounds store: *byte\n'
    'Unable to resolve constraint:\n'
    'requires maxSet(byte @ drv.c:145:6) >= 0","A memory write may write to an address beyond the allocated buffer."\n'
)
PREPROC_ROW = (
    '1,397,preproc,1,bl1/lib/image_flash.c,8,19,"Cannot find include file image.h on search path: '
    '/src/bl1/lib;/usr/include","Preprocessing error."\n'
)


# --- the reader ---------------------------------------------------------------


def test_splint_rows_recovers_the_unescaped_quote_row() -> None:
    rows, recovered, error = splint_rows(HEADER + PREPROC_ROW + NESTED_QUOTE_ROW)
    assert error is None and recovered == 1
    assert [len(row) for row in rows] == [9, 9, 9]
    assert rows[2][7] == '#error "No public key available for given signing algorithm."'
    assert rows[2][8] == "Preprocessing error."


def test_splint_rows_keeps_multiline_records_whole() -> None:
    rows, recovered, error = splint_rows(HEADER + MULTILINE_ROW + PREPROC_ROW)
    assert error is None and recovered == 0
    assert len(rows) == 3
    assert rows[1][7].startswith("Possible out-of-bounds store: *byte\nUnable to resolve constraint:")
    assert rows[2][2] == "preproc"


def test_splint_rows_rejects_what_it_cannot_recover() -> None:
    assert splint_rows("")[2] == "invalid Splint CSV: report is empty"
    assert splint_rows("a,b\x00")[2] == "invalid Splint CSV: NUL byte"
    # Not Splint's shape and not strictly valid: no recovery is attempted.
    _rows, _recovered, error = splint_rows('file,line,message\nx.c,1,"unterminated\n')
    assert error is not None and error.startswith("invalid Splint CSV")
    # Strict three-column fixtures used across the suite stay valid, untouched.
    rows, recovered, error = splint_rows("file,line,message\nmain.c,20,Variable used before definition\n")
    assert error is None and recovered == 0 and rows[1] == ["main.c", "20", "Variable used before definition"]


def test_the_review_layer_accepts_what_the_adapter_recovered(tmp_path: Path) -> None:
    report = tmp_path / "report.csv"
    report.write_text(HEADER + NESTED_QUOTE_ROW, encoding="utf-8")
    assert _validate_splint_report(report) == (True, None)


# --- the adapter ----------------------------------------------------------------


def _fake_splint(tmp_path: Path, *, csv_text: str, stdout_text: str = "", stderr_text: str = "", exit_code: int = 1) -> Path:
    return executable(tmp_path / "fake-splint", f"""
        import json, pathlib, sys
        if '-help' in sys.argv:
            print('Splint 3.1.2'); raise SystemExit()
        report = pathlib.Path(sys.argv[sys.argv.index('+csv') + 1])
        report.write_text({csv_text!r})
        (report.parent / 'argv.json').write_text(json.dumps(sys.argv[1:]))
        sys.stdout.write({stdout_text!r})
        sys.stderr.write({stderr_text!r})
        raise SystemExit({exit_code})
    """)


def _run(tmp_path: Path, fake: Path, files: tuple[str, ...] = ("a.c",), session: dict | None = None) -> dict:
    source = tmp_path / "source"
    for name in files:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("int x;\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    (run_dir / "inputs").mkdir(parents=True)
    config = load_config(source, None, {"run": {"shareable_export": False}, **(session or {})})
    inventory = [{"path": name, "is_header": False} for name in files]
    return splint.run(str(fake), source, run_dir, inventory, [], config)


def _argv(tmp_path: Path, unit: dict) -> list[str]:
    return json.loads((tmp_path / "run" / "tools" / "splint" / unit["id"] / "argv.json").read_text())


def test_a_preprocessing_failure_names_the_missing_headers(tmp_path: Path) -> None:
    stdout = (
        "a.c:8:19: Cannot find include file image.h on search\n"
        "    path: /src;/usr/include\n"
        "  Preprocessing error. (Use -preproc to inhibit warning)\n"
        "a.c:10:26: Cannot find include file Driver_Flash.h on\n"
        "    search path: /src;/usr/include\n"
    )
    stderr = "Splint 3.1.2 --- 20 Feb 2018\n\nPreprocessing error for file: /src/a.c\n*** Cannot continue.\n"
    csv_text = HEADER + PREPROC_ROW + PREPROC_ROW.replace("image.h", "Driver_Flash.h").replace("1,397", "2,397")
    result = _run(tmp_path, _fake_splint(tmp_path, csv_text=csv_text, stdout_text=stdout, stderr_text=stderr))
    unit = result["units"][0]
    assert unit["status"] == "partial" and unit["valid_report"] is True
    assert unit["failure_class"] == "include"
    assert unit["missing_includes"] == ["image.h", "Driver_Flash.h"]
    assert unit["analysis_reached"] is False
    assert unit["reason"] == "preprocessing failed: 2 missing include(s): image.h, Driver_Flash.h"
    assert unit["diagnosis"]["preproc_only"] is True
    assert unit["diagnosis"]["category"] == "include"
    assert unit["attempt"] == 1
    coverage = result["coverage"]
    # `ratio` keeps its old meaning (a valid report exists); the new pair says
    # nothing was actually analysed.
    assert coverage["ratio"] == 1.0 and coverage["analysis_reached"] == 0 and coverage["analysis_ratio"] == 0.0


def test_an_error_directive_is_a_configuration_failure_and_the_row_is_recovered(tmp_path: Path) -> None:
    csv_text = HEADER + NESTED_QUOTE_ROW
    stderr = "Preprocessing error for file: /src/a.c\n*** Cannot continue.\n"
    result = _run(tmp_path, _fake_splint(tmp_path, csv_text=csv_text, stderr_text=stderr))
    unit = result["units"][0]
    assert unit["valid_report"] is True and unit["csv_recovered_rows"] == 1
    assert unit["failure_class"] == "configuration"
    assert unit["reason"].startswith('preprocessing failed: #error "No public key available')
    assert unit["missing_includes"] == []


def test_a_completed_unit_reaches_analysis(tmp_path: Path) -> None:
    csv_text = HEADER + '1,300,fcnuse,1,a.c,1,5,"Function f declared but not used","A function is declared but not used."\n'
    result = _run(tmp_path, _fake_splint(tmp_path, csv_text=csv_text, stderr_text="Finished checking --- 1 code warning\n"))
    unit = result["units"][0]
    assert unit["status"] == "completed" and unit["failure_class"] is None
    assert unit["analysis_reached"] is True and unit["reason"] is None
    assert result["coverage"]["analysis_reached"] == 1 and result["coverage"]["analysis_ratio"] == 1.0


def test_a_unit_that_says_nothing_useful_is_a_tool_failure(tmp_path: Path) -> None:
    result = _run(tmp_path, _fake_splint(tmp_path, csv_text="", stderr_text="segmentation fault\n", exit_code=139))
    unit = result["units"][0]
    assert unit["status"] == "failed" and unit["failure_class"] == "csv"
    assert unit["reason"] == "invalid Splint CSV: report is empty"


def test_typed_options_reach_the_argv(tmp_path: Path) -> None:
    system = tmp_path / "sys"
    system.mkdir()
    session = {"tools": {"splint": {
        "mode": "weak", "report_reserved_names": False, "try_to_recover": True,
        "skip_system_headers": True, "system_dirs": [str(system)],
    }}}
    result = _run(
        tmp_path, _fake_splint(tmp_path, csv_text=HEADER, stderr_text="Finished checking\n"), session=session,
    )
    argv = _argv(tmp_path, result["units"][0])
    assert "-weak" in argv and "-strict" not in argv
    for flag in ("-isoreserved", "+trytorecover", "-skipsysheaders"):
        assert flag in argv
    assert argv[argv.index("-systemdirs") + 1] == str(system)


def test_overrides_apply_only_to_matching_paths(tmp_path: Path) -> None:
    board = tmp_path / "board-include"
    board.mkdir()
    shared = tmp_path / "shared-include"
    shared.mkdir()
    session = {"build": {
        "include": [str(shared)],
        "overrides": [{"match": "boards/alpha/**", "include": [str(board)], "define": ["BOARD_ALPHA=1"]}],
    }}
    fake = _fake_splint(tmp_path, csv_text=HEADER, stderr_text="Finished checking\n")
    result = _run(tmp_path, fake, files=("boards/alpha/main.c", "common/util.c"), session=session)
    by_file = {unit["input_files"][0]: unit for unit in result["units"]}
    alpha = _argv(tmp_path, by_file["boards/alpha/main.c"])
    common = _argv(tmp_path, by_file["common/util.c"])
    assert f"-I{shared}" in alpha and f"-I{board}" in alpha and "-DBOARD_ALPHA=1" in alpha
    assert f"-I{shared}" in common and f"-I{board}" not in common and "-DBOARD_ALPHA=1" not in common
    # The global list comes first so a specific directory can shadow a general one.
    assert alpha.index(f"-I{shared}") < alpha.index(f"-I{board}")


# --- the configuration ------------------------------------------------------------


def test_overrides_round_trip_through_toml(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "inc").mkdir()
    config_path = tmp_path / "review.toml"
    config_path.write_text(textwrap.dedent("""
        config_schema_version = 2
        [build]
        include = ["source/inc"]
        [[build.overrides]]
        match = "platform/ext/target/arm/corstone1000/**"
        include = ["source/inc"]
        define = ["CORSTONE=1"]
        [tools.splint]
        mode = "checks"
        report_reserved_names = false
    """), encoding="utf-8")
    config = load_config(source, config_path)
    override = config["build"]["overrides"][0]
    assert override["include"] == [str((source / "inc").resolve())]
    assert config["tools"]["splint"]["mode"] == "checks"
    text = effective_toml(config)
    assert "[[build.overrides]]" in text and 'match = "platform/ext/target/arm/corstone1000/**"' in text
    # The array of tables follows the section's scalars, so a reload files
    # `assist` under [build] and not under the last override.
    assert text.index("assist = ") < text.index("[[build.overrides]]") < text.index("[review]")
    saved = save_config_snapshot(source, config, tmp_path / "snapshot.toml")
    reloaded = load_config(source, saved)
    assert reloaded["build"]["overrides"] == config["build"]["overrides"]
    assert reloaded["tools"]["splint"]["report_reserved_names"] is False


@pytest.mark.parametrize(
    ("patch", "message"),
    (
        ({"build": {"overrides": [{"match": "a/**", "flags": ["-x"]}]}}, "unknown configuration key(s) in build.overrides[0]"),
        ({"build": {"overrides": [{"include": ["x"]}]}}, "build.overrides[0].match must be a non-empty glob"),
        ({"build": {"assist": "always"}}, "build.assist must be off, propose, or auto"),
        ({"build": {"assist_rounds": 3}}, "build.assist_rounds must be at most 2"),
        ({"tools": {"splint": {"mode": "paranoid"}}}, "tools.splint.mode must be"),
        ({"run": {"log_level": "trace"}}, "run.log_level must be"),
        ({"llm": {"consecutive_failure_limit": -1}}, "llm.consecutive_failure_limit must be"),
    ),
)
def test_invalid_new_keys_are_rejected(tmp_path: Path, patch: dict, message: str) -> None:
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(UserError, match=re.escape(message)):
        load_config(source, None, patch)


def test_the_defaults_leave_the_argv_contract_unchanged(tmp_path: Path) -> None:
    result = _run(tmp_path, _fake_splint(tmp_path, csv_text=HEADER, stderr_text="Finished checking\n"))
    argv = _argv(tmp_path, result["units"][0])
    assert argv[:4] == ["+nof", "-strict", "+unixlib", "+showsummary"]
    assert not any(flag in argv for flag in ("-isoreserved", "+trytorecover", "-skipsysheaders", "-systemdirs"))


def test_cli_flags_map_onto_the_typed_keys(tmp_path: Path) -> None:
    args = parser().parse_args([
        "analyze", str(tmp_path), "--splint-mode", "weak", "--build-assist", "auto", "--log-level", "debug",
    ])
    overrides = _overrides(args)
    assert overrides["tools"]["splint"]["mode"] == "weak"
    assert overrides["build"]["assist"] == "auto"
    assert overrides["run"]["log_level"] == "debug"
    validate_config(load_config(tmp_path, None, overrides))


# --- what the review of M1 established -------------------------------------------


def test_recovery_never_invents_a_column() -> None:
    # An eight-field record (no additional column), a record cut after an
    # inner quote, and a record cut right after the separator are truncated
    # reports, not recoverable ones.
    for tail in (
        '1,397,preproc,1,a.c,1,1,"Cannot find include file x.h"\n',
        '1,397,preproc,1,a.c,1,1,"#error "\n',
        '1,397,preproc,1,a.c,1,1,"x.h","\n',
    ):
        _rows, _recovered, error = splint_rows(HEADER + tail)
        assert error is not None and error.startswith("invalid Splint CSV"), tail
    # An empty additional column is a legitimate Splint record.
    rows, recovered, error = splint_rows(HEADER + '1,397,preproc,1,a.c,1,1,"W",""\n')
    assert error is None and rows[1][7:] == ["W", ""]
    # A warning text containing '", ' parses cleanly to ten fields and is
    # re-joined on the last separator, not rejected.
    rows, recovered, error = splint_rows(HEADER + '1,397,preproc,1,a.c,1,1,"foo", bar","Preprocessing error."\n')
    assert error is None and rows[1][7:] == ['foo", bar', "Preprocessing error."]


def test_finished_checking_wins_over_a_preproc_only_report(tmp_path: Path) -> None:
    csv_text = HEADER + '1,397,preproc,1,a.c,1,30,"#warning "board not selected"","Preprocessing error."\n'
    result = _run(tmp_path, _fake_splint(tmp_path, csv_text=csv_text, stderr_text="Finished checking --- 1 code warning\n"))
    unit = result["units"][0]
    assert unit["status"] == "completed" and unit["failure_class"] is None
    assert unit["diagnosis"]["preproc_only"] is True and unit["csv_recovered_rows"] == 1
    assert unit["analysis_reached"] is True
    assert result["coverage"]["analysis_reached"] == 1 and result["coverage"]["analysis_ratio"] == 1.0


def test_a_killed_unit_carries_no_failure_class(tmp_path: Path) -> None:
    fake = executable(tmp_path / "hanging-splint", f"""
        import pathlib, sys, time
        if '-help' in sys.argv: print('Splint 3.1.2'); raise SystemExit()
        report = pathlib.Path(sys.argv[sys.argv.index('+csv') + 1])
        report.write_text({HEADER!r})
        time.sleep(30)
    """)
    session = {"tools": {"splint": {"tu_timeout_seconds": 0.3}}, "run": {"termination_grace_seconds": 0.2}}
    result = _run(tmp_path, fake, session=session)
    unit = result["units"][0]
    assert unit["process"]["timed_out"] is True
    assert unit["status"] == "partial" and unit["valid_report"] is True
    assert unit["failure_class"] is None and unit["diagnosis"]["category"] is None
    assert unit["analysis_reached"] is False


def test_parse_errors_and_reserved_names_are_counted_once() -> None:
    stderr = (
        "a.c:161:35:\n    Parse Error. (For help on parse errors, see splint -help parseerrors.)\n*** Cannot continue.\n"
    )
    diagnosis = splint.diagnose(stderr, [])
    assert diagnosis["parse_errors"] == 1
    rows = [
        ["Warning", "Flag Code", "Flag Name", "Priority", "File", "Line", "Column", "Warning Text", "Additional Text"],
        ["1", "280", "isoreserved", "1", "a.c", "1", "1", "Name _x is in the implementation name space", "External name is reserved for system use by ISO C99 standard."],
        ["2", "280", "isoreserved", "1", "a.c", "2", "1", "Name EFOO is reserved for future library extensions.", "External name is reserved for system use by ISO C99 standard."],
    ]
    assert splint.diagnose("", rows)["reserved_name_warnings"] == 2
    prose = (
        "a.c:3:5: Name EFOO is reserved for the standard\n    library.\n"
        "  External name is reserved for system use by ISO C99 standard. (Use -isoreserved to inhibit warning)\n"
    )
    assert splint.diagnose(prose, [])["reserved_name_warnings"] == 1


def test_the_log_fallback_survives_a_wrap_after_include_file(tmp_path: Path) -> None:
    stdout = "a.c:11:31: Cannot find include file\n    tfm_psa_call_pack.h on search path: /src;/usr/include\n"
    stderr = "Preprocessing error for file: /src/a.c\n*** Cannot continue.\n"
    result = _run(tmp_path, _fake_splint(tmp_path, csv_text=HEADER, stdout_text=stdout, stderr_text=stderr))
    unit = result["units"][0]
    assert unit["missing_includes"] == ["tfm_psa_call_pack.h"] and unit["failure_class"] == "include"


def test_an_empty_overrides_list_is_written_so_a_snapshot_cancels_lower_layers(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / ".code-analyzer.toml").write_text(textwrap.dedent("""
        config_schema_version = 2
        [[build.overrides]]
        match = "hal/**"
        define = ["HAL=1"]
    """), encoding="utf-8")
    explicit = tmp_path / "explicit.toml"
    explicit.write_text("config_schema_version = 2\n[build]\noverrides = []\n", encoding="utf-8")
    config = load_config(source, explicit)
    assert config["build"]["overrides"] == []
    text = effective_toml(config)
    assert "overrides = []" in text and "[[build.overrides]]" not in text
    saved = save_config_snapshot(source, config, tmp_path / "snapshot.toml")
    assert load_config(source, saved)["build"]["overrides"] == []


def test_a_non_string_override_path_is_a_user_error(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    explicit = tmp_path / "explicit.toml"
    explicit.write_text('config_schema_version = 2\n[[build.overrides]]\nmatch = "a"\ninclude = [1]\n', encoding="utf-8")
    with pytest.raises(UserError, match=re.escape("build.overrides[0].include must be an array of strings")):
        load_config(source, explicit)
    explicit.write_text("config_schema_version = 2\n[tools.splint]\nsystem_dirs = [1]\n", encoding="utf-8")
    with pytest.raises(UserError, match=re.escape("tools.splint.system_dirs must be an array of strings")):
        load_config(source, explicit)


def test_the_shareable_export_keeps_a_recovered_splint_report(tmp_path: Path) -> None:
    """Run the CLI with a fake Splint that writes Splint's unescaped quote; the report must be exported."""
    import json as _json
    import zipfile

    from helpers import run_cli

    source = tmp_path / "source"
    source.mkdir()
    (source / "a.c").write_text("int x;\n", encoding="utf-8")
    fake = _fake_splint(tmp_path, csv_text=HEADER + NESTED_QUOTE_ROW, stderr_text="Finished checking --- 1 code warning\n")
    config = tmp_path / "config.toml"
    config.write_text(textwrap.dedent(f"""
        config_schema_version = 2
        [tools.cppcheck]
        enabled = false
        [tools.flawfinder]
        enabled = false
        [tools.splint]
        executable = {_json.dumps(str(fake))}
    """), encoding="utf-8")
    completed = run_cli("analyze", source, "--config", config, "--output-root", tmp_path / "out", "--no-compile-db")
    assert completed.returncode == 0, completed.stderr
    run_dir = Path(completed.stdout.strip())
    manifest = _json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["export"]["status"] == "completed"
    unit = manifest["tools"]["splint"]["units"][0]
    assert unit["csv_recovered_rows"] == 1
    with zipfile.ZipFile(run_dir / manifest["export"]["archive"]) as bundle:
        names = set(bundle.namelist())
        assert f"tools/splint/{unit['id']}/report.csv" in names
        exported = bundle.read(f"tools/splint/{unit['id']}/report.csv").decode("utf-8")
    rows, recovered, error = splint_rows(exported)
    assert error is None and recovered == 0 and rows[1][7].startswith("#error ")

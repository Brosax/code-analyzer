"""Provider profiles, endpoint credential hygiene and skill packaging.

These three concerns share one property: they are decided before a single
model token is spent, and every one of them can leak or break silently.
"""
from __future__ import annotations

import contextlib
import copy
import json
import shutil
import zipfile
from pathlib import Path

import pytest

from code_analyzer.cli import _overrides, main, parser
from code_analyzer.config import (
    DEFAULTS,
    effective_toml,
    load_config,
    load_config_with_sources,
    validate_config,
)
from code_analyzer.errors import UserError
from code_analyzer.llm.profiles import PROFILES, third_party_warning
from code_analyzer.llm.skills import SKILL_FILENAME

REPOSITORY = Path(__file__).resolve().parent.parent
OPENROUTER = PROFILES["openrouter"]
GPU_HOST = PROFILES["gpu-host"]

# A credential shaped like the real thing: no test may let it reach an
# artifact, a snapshot or a terminal.
SECRET = "sk-live-SUPERSECRET"
USERINFO_ENDPOINT = f"https://svc:{SECRET}@gpu-host.internal:8000/v1"


def _write(path: Path, body: str) -> Path:
    path.write_text("config_schema_version = 2\n" + body, encoding="utf-8")
    return path


# --- provider profiles ------------------------------------------------------


def test_the_default_profile_is_the_operator_gpu_host(tmp_path: Path) -> None:
    loaded = load_config_with_sources(tmp_path, None)
    llm = loaded.config["llm"]

    assert llm["profile"] == "gpu-host"
    assert {key: llm[key] for key in GPU_HOST} == GPU_HOST
    assert third_party_warning(llm) is None


def test_a_profile_supplies_the_defaults_it_owns(tmp_path: Path) -> None:
    path = _write(tmp_path / "openrouter.toml", '[llm]\nprofile = "openrouter"\n')

    loaded = load_config_with_sources(tmp_path, path)
    llm = loaded.config["llm"]

    assert {key: llm[key] for key in OPENROUTER} == OPENROUTER
    assert loaded.sources["llm.endpoint"] == "profile:openrouter"
    assert loaded.sources["llm.model"] == "profile:openrouter"
    assert loaded.sources["llm.api_key_env"] == "profile:openrouter"
    # Nothing else in the section moves with the profile.
    assert llm["context_window"] == DEFAULTS["llm"]["context_window"]


def test_explicitly_set_values_win_over_the_profile(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "mixed.toml",
        '[llm]\nprofile = "openrouter"\nmodel = "house-model"\n',
    )

    from_file = load_config_with_sources(tmp_path, path)
    assert from_file.config["llm"]["model"] == "house-model"
    assert from_file.sources["llm.model"] == str(path)
    assert from_file.config["llm"]["endpoint"] == OPENROUTER["endpoint"]

    from_cli = load_config_with_sources(
        tmp_path, path, {"llm": {"endpoint": "http://127.0.0.1:1/v1"}}
    )
    assert from_cli.config["llm"]["endpoint"] == "http://127.0.0.1:1/v1"
    assert from_cli.sources["llm.endpoint"] == "session"
    assert from_cli.config["llm"]["api_key_env"] == OPENROUTER["api_key_env"]


def test_the_resolved_profile_round_trips_through_effective_toml(tmp_path: Path) -> None:
    path = _write(tmp_path / "openrouter.toml", '[llm]\nprofile = "openrouter"\n')
    resolved = load_config(tmp_path, path)

    text = effective_toml(resolved)
    assert 'profile = "openrouter"' in text
    assert f'endpoint = "{OPENROUTER["endpoint"]}"' in text

    snapshot = _write(tmp_path / "snapshot.toml", "")
    snapshot.write_text(text, encoding="utf-8")
    assert load_config(tmp_path, snapshot)["llm"] == resolved["llm"]


def test_an_unknown_profile_name_is_rejected(tmp_path: Path) -> None:
    broken = copy.deepcopy(DEFAULTS)
    broken["llm"]["profile"] = "my-friends-gpu"
    with pytest.raises(UserError, match="llm.profile must be"):
        validate_config(broken)


def test_the_cli_flag_selects_a_profile(tmp_path: Path) -> None:
    args = parser().parse_args(["analyze", str(tmp_path), "--llm", "--llm-profile", "openrouter"])
    assert _overrides(args)["llm"] == {"enabled": True, "profile": "openrouter"}

    with pytest.raises(SystemExit):
        parser().parse_args(["analyze", str(tmp_path), "--llm-profile", "my-friends-gpu"])


def test_a_third_party_profile_warns_that_source_leaves_the_machine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(OPENROUTER["api_key_env"], SECRET)
    path = _write(tmp_path / "openrouter.toml", '[llm]\nprofile = "openrouter"\n')

    assert main(["doctor", "--json", "--config", str(path)]) in {0, 20}
    captured = capsys.readouterr()
    json.loads(captured.out)  # The warning never pollutes machine-readable output.
    assert "openrouter" in captured.err and "leaves this machine" in captured.err
    assert "openrouter.ai" in captured.err
    assert SECRET not in captured.err

    assert main(["doctor", "--json"]) in {0, 20}
    assert "leaves this machine" not in capsys.readouterr().err


# --- endpoint credential hygiene --------------------------------------------


def test_an_endpoint_carrying_userinfo_is_rejected(tmp_path: Path) -> None:
    broken = copy.deepcopy(DEFAULTS)
    broken["llm"]["endpoint"] = USERINFO_ENDPOINT
    with pytest.raises(UserError, match="api_key_env"):
        validate_config(broken)

    empty_userinfo = copy.deepcopy(DEFAULTS)
    empty_userinfo["llm"]["endpoint"] = "https://@gpu-host.internal:8000/v1"
    with pytest.raises(UserError, match="api_key_env"):
        validate_config(empty_userinfo)


def test_no_endpoint_credential_can_reach_an_artifact(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    reports = tmp_path / "reports"

    exit_code = main([
        "analyze", str(source), "--llm", "--llm-endpoint", USERINFO_ENDPOINT,
        "--output-root", str(reports),
    ])

    leaked = [
        str(item.relative_to(tmp_path)) for item in tmp_path.rglob("*")
        if item.is_file() and SECRET in item.read_text(encoding="utf-8", errors="replace")
    ]
    assert leaked == []
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "api_key_env" in captured.err
    assert SECRET not in captured.err + captured.out


def test_a_config_file_cannot_smuggle_a_credential_into_the_snapshot(tmp_path: Path) -> None:
    path = _write(tmp_path / "userinfo.toml", f'[llm]\nendpoint = "{USERINFO_ENDPOINT}"\n')
    with pytest.raises(UserError, match="api_key_env"):
        load_config(tmp_path, path)


# --- packaging --------------------------------------------------------------


def test_the_packaged_skills_are_present_in_a_built_wheel(tmp_path: Path) -> None:
    """The skills live in hyphenated, non-package directories.

    ``packages.find`` picks up ``code_analyzer.skills`` for its ``__init__.py``
    and stops there, so without explicit package-data the SKILL.md files exist
    only in an editable checkout and every real install fails to load a skill.
    """
    build_root = tmp_path / "tree"
    build_root.mkdir()
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy2(REPOSITORY / name, build_root / name)
    shutil.copytree(
        REPOSITORY / "code_analyzer",
        build_root / "code_analyzer",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    expected = {
        f"code_analyzer/skills/{item.parent.name}/{SKILL_FILENAME}"
        for item in (REPOSITORY / "code_analyzer" / "skills").glob(f"*/{SKILL_FILENAME}")
    }
    assert expected, "the repository must ship at least one scanner skill"

    wheel = _build_wheel(build_root, tmp_path / "dist")

    with zipfile.ZipFile(wheel) as archive:
        assert expected <= set(archive.namelist())


def _build_wheel(source: Path, destination: Path) -> Path:
    """Build a wheel with the project's real build backend, out of tree."""
    # Imported here so a missing build backend cannot take the rest of this
    # module down with it; it is declared in the dev extra.
    from setuptools import build_meta

    destination.mkdir(parents=True, exist_ok=True)
    with contextlib.chdir(source):
        name = build_meta.build_wheel(str(destination))
    return destination / name


def test_the_token_budgets_scale_with_the_scanner_roster_but_never_over_a_choice(tmp_path: Path) -> None:
    from code_analyzer.config import SCANNER_SCALED_KEYS
    from code_analyzer.tools import LLM_PRODUCERS

    source = tmp_path / "src"
    source.mkdir()
    loaded = load_config_with_sources(source, None)
    # The default roster is every scanner, and each of them reads every unit.
    for key in SCANNER_SCALED_KEYS:
        assert loaded.config["llm"][key] == DEFAULTS["llm"][key] * len(LLM_PRODUCERS)
        assert loaded.sources[f"llm.{key}"] == f"default:{len(LLM_PRODUCERS)}-scanners"

    # One scanner: the base, unscaled, and still recorded as a plain default.
    one = load_config_with_sources(source, None, {"llm": {"scanners": ["llm-memory-safety"]}})
    for key in SCANNER_SCALED_KEYS:
        assert one.config["llm"][key] == DEFAULTS["llm"][key]
        assert one.sources[f"llm.{key}"] == "default"

    # A number the user wrote is the number the user gets, whatever the roster.
    chosen = load_config_with_sources(source, None, {"llm": {"total_prompt_tokens": 5000}})
    assert chosen.config["llm"]["total_prompt_tokens"] == 5000
    assert chosen.sources["llm.total_prompt_tokens"] == "session"
    # ... and the other budget still scales: the rule is per key, not per section.
    assert chosen.config["llm"]["total_completion_tokens"] == DEFAULTS["llm"]["total_completion_tokens"] * len(LLM_PRODUCERS)

    # Reloading a run's own effective config reproduces it: the file states the
    # resolved product explicitly, so nothing is scaled a second time.
    written = tmp_path / "effective.toml"
    written.write_text(effective_toml(loaded.config), encoding="utf-8")
    reloaded = load_config_with_sources(source, written)
    for key in SCANNER_SCALED_KEYS:
        assert reloaded.config["llm"][key] == loaded.config["llm"][key]

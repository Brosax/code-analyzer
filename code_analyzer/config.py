"""The analysis configuration a static call runs with: where output goes, what is scanned, the build context
(include paths, defines, compile database, per-path overrides) and each analyzer's settings.

It is never edited by an operator any more: ``evidence/buildctx_schema.py`` versions the [build] and [tools]
parts per evaluation, ``evidence/analyze.static_config`` fills in the rest, and ``validate_config`` holds every
value -- a patch the conversation proposes included -- to the same closed rules.  The model, review and export
settings of the old configuration are gone: settings.toml has the nine that remain (v3 M9).
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .errors import UserError
from .tools import TOOL_NAMES

DEFAULTS: dict[str, Any] = {
    "config_schema_version": 2,
    "run": {
        # Where a static call writes its run directory; the evaluation sets it to calls/Cnnnn-static/.
        "output_root": "./code-analyzer-runs",
        "termination_grace_seconds": 5.0,
    },
    "source": {
        "include": ["**/*"],
        "exclude": [],
        "follow_symlinks": False,
        "respect_gitignore": False,
        "hash_algorithm": "sha256",
    },
    "build": {
        "compile_database_mode": "auto",
        "compile_database": None,
        "c_standard": None,
        "cpp_standard": None,
        "cppcheck_platform": None,
        "include": [],
        "system_include": [],
        "define": [],
        "undefine": [],
        # Build-context assistance: when Splint or Cppcheck's fallback pass
        # fail to preprocess, diagnose the missing headers, infer a patch and
        # re-run the failed units with it.  "propose" always asks; "auto"
        # applies only a patch inferred by code and proven on a probe; "off"
        # keeps the analyzer exactly as it was.
        "assist": "propose",
        "assist_rounds": 1,
        "assist_probe_units": 12,
        # Empty include-guarded headers for names that exist nowhere in the
        # tree, offered per item and never checked by default.
        "stub_headers": True,
        # How long a proposal waits for the operator; 0 waits indefinitely.
        "approval_timeout_seconds": 0.0,
        # Per-path build context: [[build.overrides]] tables of
        # {match, include, system_include, define, undefine}, matched by glob
        # against the source-relative path of each translation unit.
        "overrides": [],
    },
    "tools": {
        "cppcheck": {"enabled": True, "executable": "cppcheck", "timeout_seconds": 7200.0, "heartbeat_seconds": 10.0},
        "flawfinder": {"enabled": True, "executable": "flawfinder", "timeout_seconds": 1800.0, "heartbeat_seconds": 10.0},
        "splint": {
            "enabled": True,
            "executable": "splint",
            "tu_timeout_seconds": 60.0,
            "total_timeout_seconds": 14400.0,
            "scope": "auto",
            # splint is per-translation-unit and CPU-bound, and its units are
            # independent: raising its own parallelism is the cheap half of
            # "run the analyzers concurrently" without a shared-cancel rewrite.
            # A fixed number, not a CPU count: the resolved value is recorded in
            # inputs/effective-config.toml and must reload the same on any host.
            "jobs": 4,
            "heartbeat_seconds": 10.0,
            # Typed Splint options, each verified against `splint -help`; the
            # set is closed on purpose (README: arbitrary arguments are
            # unavailable) and doubles as the allow-list a build-context
            # proposal may pick from.
            "mode": "strict",
            "report_reserved_names": True,
            "try_to_recover": False,
            "skip_system_headers": False,
            "system_dirs": [],
        },
    },
}

ASSIST_MODES: tuple[str, ...] = ("off", "propose", "auto")
SPLINT_MODES: tuple[str, ...] = ("strict", "checks", "standard", "weak")
OVERRIDE_KEYS: tuple[str, ...] = ("match", "include", "system_include", "define", "undefine")

_ALLOWED = {
    "": {"config_schema_version", "run", "source", "build", "tools"},
    "run": set(DEFAULTS["run"]),
    "source": set(DEFAULTS["source"]),
    "build": set(DEFAULTS["build"]),
    "tools": set(TOOL_NAMES),
    "tools.cppcheck": set(DEFAULTS["tools"]["cppcheck"]),
    "tools.flawfinder": set(DEFAULTS["tools"]["flawfinder"]),
    "tools.splint": set(DEFAULTS["tools"]["splint"]),
}


def _validate_keys(value: dict[str, Any], prefix: str = "") -> None:
    unknown = set(value) - _ALLOWED[prefix]
    if unknown:
        raise UserError(f"unknown configuration key(s) in {prefix or 'root'}: {', '.join(sorted(unknown))}")
    for key, child in value.items():
        path = f"{prefix}.{key}" if prefix else key
        if path in _ALLOWED:
            if not isinstance(child, dict):
                raise UserError(f"configuration section {path} must be a table")
            _validate_keys(child, path)


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a schema-v2 configuration in place."""
    _validate_keys({key: value for key, value in config.items() if not key.startswith("_")})
    if config["config_schema_version"] != 2:
        raise UserError("config_schema_version must be 2")
    run, src, build, tools = config["run"], config["source"], config["build"], config["tools"]
    _expect(run["output_root"], str, "run.output_root")
    _number(run["termination_grace_seconds"], "run.termination_grace_seconds")
    for key in ("include", "exclude"):
        _string_list(src[key], f"source.{key}")
    _expect(src["follow_symlinks"], bool, "source.follow_symlinks")
    _expect(src["respect_gitignore"], bool, "source.respect_gitignore")
    _expect(src["hash_algorithm"], str, "source.hash_algorithm")
    _expect(build["compile_database_mode"], str, "build.compile_database_mode")
    if build["compile_database"] is not None:
        _expect(build["compile_database"], str, "build.compile_database")
    for key in ("c_standard", "cpp_standard", "cppcheck_platform"):
        if build[key] is not None:
            _expect(build[key], str, f"build.{key}")
    for key in ("include", "system_include", "define", "undefine"):
        _string_list(build[key], f"build.{key}")
    _expect(build["assist"], str, "build.assist")
    if build["assist"] not in ASSIST_MODES:
        raise UserError("build.assist must be off, propose, or auto")
    _non_negative_int(build["assist_rounds"], "build.assist_rounds")
    if build["assist_rounds"] > 2:
        raise UserError("build.assist_rounds must be at most 2")
    _positive_int(build["assist_probe_units"], "build.assist_probe_units")
    _expect(build["stub_headers"], bool, "build.stub_headers")
    _non_negative_number(build["approval_timeout_seconds"], "build.approval_timeout_seconds")
    _validate_overrides(build["overrides"])
    if src["hash_algorithm"] != "sha256":
        raise UserError("only source.hash_algorithm='sha256' is supported")
    if build["compile_database_mode"] not in {"auto", "explicit", "disabled"}:
        raise UserError("build.compile_database_mode must be auto, explicit, or disabled")
    if build["compile_database_mode"] == "explicit" and not build.get("compile_database"):
        raise UserError("explicit compile database mode requires build.compile_database")
    for name, section in tools.items():
        if not isinstance(section["enabled"], bool) or not isinstance(section["executable"], str):
            raise UserError("tool enabled and executable values have invalid types")
        for key, value in section.items():
            if key.endswith(("timeout_seconds", "heartbeat_seconds")):
                _number(value, f"tools.{name}.{key}")
    splint = tools["splint"]
    if splint["scope"] not in {"auto", "build", "inventory"}:
        raise UserError("tools.splint.scope must be auto, build, or inventory")
    _positive_int(splint["jobs"], "tools.splint.jobs")
    _expect(splint["mode"], str, "tools.splint.mode")
    if splint["mode"] not in SPLINT_MODES:
        raise UserError("tools.splint.mode must be strict, checks, standard, or weak")
    for key in ("report_reserved_names", "try_to_recover", "skip_system_headers"):
        _expect(splint[key], bool, f"tools.splint.{key}")
    _string_list(splint["system_dirs"], "tools.splint.system_dirs")
    run["output_root"] = str(_absolute(run["output_root"], Path.cwd()))
    if build.get("compile_database"):
        build["compile_database"] = str(_absolute(build["compile_database"], Path.cwd()))
    build["include"] = [str(_absolute(p, Path.cwd())) for p in build["include"]]
    build["system_include"] = [str(_absolute(p, Path.cwd())) for p in build["system_include"]]
    for override in build["overrides"]:
        for key in ("include", "system_include"):
            if key in override:
                override[key] = [str(_absolute(p, Path.cwd())) for p in override[key]]
    splint["system_dirs"] = [str(_absolute(p, Path.cwd())) for p in splint["system_dirs"]]
    return config


def _validate_overrides(value: Any) -> None:
    if not isinstance(value, list):
        raise UserError("build.overrides must be an array of tables")
    for index, override in enumerate(value):
        name = f"build.overrides[{index}]"
        if not isinstance(override, dict):
            raise UserError(f"{name} must be a table")
        unknown = set(override) - set(OVERRIDE_KEYS)
        if unknown:
            raise UserError(f"unknown configuration key(s) in {name}: {', '.join(sorted(unknown))}")
        match = override.get("match")
        if not isinstance(match, str) or not match.strip():
            raise UserError(f"{name}.match must be a non-empty glob")
        for key in OVERRIDE_KEYS[1:]:
            if key in override:
                _string_list(override[key], f"{name}.{key}")


def _absolute(value: os.PathLike[str] | str, base: Path) -> Path:
    path = Path(value).expanduser()
    return (path if path.is_absolute() else base / path).resolve()



def _expect(value: Any, expected: type, name: str) -> None:
    if not isinstance(value, expected):
        raise UserError(f"{name} has invalid type; expected {expected.__name__}")


def _number(value: Any, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise UserError(f"{name} must be a number greater than zero")


def _string_list(value: Any, name: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise UserError(f"{name} must be an array of strings")


def _positive_int(value: Any, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise UserError(f"{name} must be an integer greater than zero")


def _non_negative_int(value: Any, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise UserError(f"{name} must be an integer of zero or more")


def _non_negative_number(value: Any, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise UserError(f"{name} must be a number of zero or more")


def effective_toml(config: dict[str, Any]) -> str:
    """Serialize the supported config model deterministically."""
    lines = ["config_schema_version = 2", ""]
    for section in ("run", "source", "build"):
        lines.append(f"[{section}]")
        for key in DEFAULTS[section]:
            value = config[section][key]
            if value is None:
                continue
            if (section, key) == ("build", "overrides"):
                if value:
                    continue  # emitted below as [[build.overrides]] tables
                # Explicit, so a snapshot cancels a lower layer's tables.
                lines.append("overrides = []")
                continue
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
        if section == "build":
            # Arrays of tables must follow the section's own keys, or TOML
            # would file those keys under the last table instead.
            for override in config["build"]["overrides"]:
                lines.append("[[build.overrides]]")
                for key in OVERRIDE_KEYS:
                    if key in override:
                        lines.append(f"{key} = {_toml_value(override[key])}")
                lines.append("")
    for tool in TOOL_NAMES:
        lines.append(f"[tools.{tool}]")
        for key in DEFAULTS["tools"][tool]:
            value = config["tools"][tool][key]
            if value is None:
                continue
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    return "\n".join(lines)


def _toml_value(value: Any) -> str:
    if value is None:
        raise ValueError("TOML has no null value; omit None fields")
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    text = str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{text}"'

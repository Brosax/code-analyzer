from __future__ import annotations

import copy
import os
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import UserError


DEFAULTS: dict[str, Any] = {
    "config_schema_version": 2,
    "run": {
        "output_root": "./code-analyzer-reports",
        "profile": "exhaustive",
        "shareable_export": True,
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
    },
    "review": {
        "enabled": True,
        "fail_on": "none",
        "max_markdown_findings": 200,
    },
    "tools": {
        "cppcheck": {"enabled": True, "executable": "cppcheck", "timeout_seconds": 7200.0},
        "flawfinder": {"enabled": True, "executable": "flawfinder", "timeout_seconds": 1800.0},
        "splint": {
            "enabled": True,
            "executable": "splint",
            "tu_timeout_seconds": 60.0,
            "total_timeout_seconds": 14400.0,
            "scope": "auto",
            "jobs": 1,
            "heartbeat_seconds": 10.0,
        },
    },
}


@dataclass(frozen=True)
class FieldSpec:
    """Presentation metadata for one schema-v2 leaf.

    Validation deliberately remains in :func:`validate_config`; this registry
    is shared by front ends so labels, choices and defaults cannot drift.
    """

    path: str
    kind: str
    label: str
    help: str
    choices: tuple[str, ...] = ()
    minimum: float | None = None
    advanced: bool = False
    readonly: bool = False


FIELD_REGISTRY: tuple[FieldSpec, ...] = (
    FieldSpec("run.output_root", "path", "输出目录", "分析报告根目录。", advanced=False),
    FieldSpec("run.profile", "string", "运行配置", "固定为 exhaustive。", choices=("exhaustive",), readonly=True),
    FieldSpec("run.shareable_export", "bool", "生成可分享导出", "创建脱敏 ZIP 导出。"),
    FieldSpec("run.termination_grace_seconds", "float", "终止宽限（秒）", "发送 TERM 后等待 KILL 的时间。", minimum=0.001, advanced=True),
    FieldSpec("source.include", "list", "包含规则", "源码相对路径 glob 列表。"),
    FieldSpec("source.exclude", "list", "排除规则", "源码相对路径 glob 列表。"),
    FieldSpec("source.follow_symlinks", "bool", "跟随符号链接", "扫描符号链接指向的文件。", advanced=True),
    FieldSpec("source.respect_gitignore", "bool", "遵循 .gitignore", "从源码范围中排除 Git 忽略项。"),
    FieldSpec("source.hash_algorithm", "string", "哈希算法", "固定为 sha256。", choices=("sha256",), readonly=True),
    FieldSpec("build.compile_database_mode", "choice", "Compile DB 模式", "自动发现、显式路径或禁用。", choices=("auto", "explicit", "disabled")),
    FieldSpec("build.compile_database", "optional_path", "Compile DB 路径", "compile_commands.json 的显式路径。"),
    FieldSpec("build.c_standard", "optional_string", "C 标准", "例如 c11、c17；允许自定义。"),
    FieldSpec("build.cpp_standard", "optional_string", "C++ 标准", "例如 c++17、c++20；允许自定义。"),
    FieldSpec("build.cppcheck_platform", "optional_string", "Cppcheck 平台", "例如 unix64；允许自定义。"),
    FieldSpec("build.include", "path_list", "Include 目录", "项目 include 搜索路径。"),
    FieldSpec("build.system_include", "path_list", "System include 目录", "系统 include 搜索路径。", advanced=True),
    FieldSpec("build.define", "list", "宏定义", "传给分析器的 NAME 或 NAME=VALUE。"),
    FieldSpec("build.undefine", "list", "取消宏定义", "传给分析器的宏名称。", advanced=True),
    FieldSpec("review.enabled", "bool", "生成 Review", "派生非权威统一 findings。"),
    FieldSpec("review.fail_on", "choice", "失败阈值", "达到该严重性时退出 1。", choices=("none", "medium", "high", "critical")),
    FieldSpec("review.max_markdown_findings", "int", "Markdown 最大 findings", "限制 Markdown 报告长度。", minimum=1, advanced=True),
    FieldSpec("tools.cppcheck.enabled", "bool", "启用 Cppcheck", "运行 Cppcheck。"),
    FieldSpec("tools.cppcheck.executable", "string", "Cppcheck 可执行文件", "命令名或绝对路径。", advanced=True),
    FieldSpec("tools.cppcheck.timeout_seconds", "float", "Cppcheck 超时", "总超时秒数。", minimum=0.001, advanced=True),
    FieldSpec("tools.flawfinder.enabled", "bool", "启用 Flawfinder", "运行 Flawfinder。"),
    FieldSpec("tools.flawfinder.executable", "string", "Flawfinder 可执行文件", "命令名或绝对路径。", advanced=True),
    FieldSpec("tools.flawfinder.timeout_seconds", "float", "Flawfinder 超时", "总超时秒数。", minimum=0.001, advanced=True),
    FieldSpec("tools.splint.enabled", "bool", "启用 Splint", "运行 Splint。"),
    FieldSpec("tools.splint.executable", "string", "Splint 可执行文件", "命令名或绝对路径。", advanced=True),
    FieldSpec("tools.splint.tu_timeout_seconds", "float", "Splint 单元超时", "每个翻译单元的超时秒数。", minimum=0.001, advanced=True),
    FieldSpec("tools.splint.total_timeout_seconds", "float", "Splint 总超时", "全部翻译单元共享的总预算。", minimum=0.001, advanced=True),
    FieldSpec("tools.splint.scope", "choice", "Splint 范围", "自动、build 覆盖范围或完整 inventory。", choices=("auto", "build", "inventory")),
    FieldSpec("tools.splint.jobs", "int", "Splint 并发数", "并发翻译单元数量。", minimum=1),
    FieldSpec("tools.splint.heartbeat_seconds", "float", "Splint 心跳", "长任务状态刷新间隔。", minimum=0.001, advanced=True),
)

FIELD_BY_PATH = {field.path: field for field in FIELD_REGISTRY}


@dataclass(frozen=True)
class LoadedConfig:
    config: dict[str, Any]
    sources: dict[str, str]
    paths: tuple[Path, ...]

_ALLOWED = {
    "": {"config_schema_version", "run", "source", "build", "review", "tools"},
    "run": set(DEFAULTS["run"]),
    "source": set(DEFAULTS["source"]),
    "build": set(DEFAULTS["build"]),
    "review": set(DEFAULTS["review"]),
    "tools": {"cppcheck", "flawfinder", "splint"},
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


def _merge(base: dict[str, Any], update: dict[str, Any]) -> None:
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = copy.deepcopy(value)


def _merge_with_sources(
    base: dict[str, Any], update: dict[str, Any], sources: dict[str, str], label: str, prefix: str = ""
) -> None:
    for key, value in update.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge_with_sources(base[key], value, sources, label, path)
        else:
            base[key] = copy.deepcopy(value)
            if path in FIELD_BY_PATH:
                sources[path] = label


def _read(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise UserError(f"cannot read configuration {path}: {exc}") from exc
    _validate_keys(data)
    version = data.get("config_schema_version")
    if version not in {1, 2}:
        raise UserError(f"{path}: config_schema_version must be 1 or 2")
    # v1 files are accepted as input and upgraded to the in-memory v2 model.
    data["config_schema_version"] = 2
    _resolve_file_paths(data, path.parent.resolve())
    return data


def _resolve_file_paths(data: dict[str, Any], base: Path) -> None:
    run = data.get("run", {})
    if "output_root" in run:
        run["output_root"] = str(_absolute(run["output_root"], base))
    build = data.get("build", {})
    if build.get("compile_database"):
        build["compile_database"] = str(_absolute(build["compile_database"], base))
    for name in ("include", "system_include"):
        if name in build:
            build[name] = [str(_absolute(item, base)) for item in build[name]]


def _absolute(value: os.PathLike[str] | str, base: Path) -> Path:
    path = Path(value).expanduser()
    return (path if path.is_absolute() else base / path).resolve()


def load_config_with_sources(
    source: Path, explicit: Path | None, session: dict[str, Any] | None = None
) -> LoadedConfig:
    source = source.expanduser().resolve()
    config = copy.deepcopy(DEFAULTS)
    config_paths: list[str] = []
    sources = {field.path: "default" for field in FIELD_REGISTRY}
    implicit = source / ".code-analyzer.toml"
    if implicit.is_file():
        _merge_with_sources(config, _read(implicit), sources, str(implicit.resolve()))
        config_paths.append(str(implicit.resolve()))
    if explicit is not None:
        explicit = explicit.expanduser().resolve()
        if not explicit.is_file():
            raise UserError(f"configuration file does not exist: {explicit}")
        if explicit != implicit.resolve():
            _merge_with_sources(config, _read(explicit), sources, str(explicit))
            config_paths.append(str(explicit))
    if session:
        _validate_keys(session)
        _merge_with_sources(config, session, sources, "session")
    validate_config(config)
    # Runtime metadata is deliberately not part of the versioned TOML model.
    config["_config_paths"] = config_paths
    config["_config_sources"] = sources
    return LoadedConfig(config, sources, tuple(Path(value) for value in config_paths))


def load_config(source: Path, explicit: Path | None, cli: dict[str, Any] | None = None) -> dict[str, Any]:
    """Load the four configuration layers while preserving the historical API."""
    return load_config_with_sources(source, explicit, cli).config


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a schema-v2 configuration in place."""
    _validate_keys({key: value for key, value in config.items() if not key.startswith("_")})
    if config["config_schema_version"] != 2:
        raise UserError("config_schema_version must be 1 or 2")
    run, src, build, review, tools = config["run"], config["source"], config["build"], config["review"], config["tools"]
    _expect(run["output_root"], str, "run.output_root")
    _expect(run["profile"], str, "run.profile")
    _expect(run["shareable_export"], bool, "run.shareable_export")
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
    _expect(review["enabled"], bool, "review.enabled")
    _expect(review["fail_on"], str, "review.fail_on")
    if review["fail_on"] not in {"none", "medium", "high", "critical"}:
        raise UserError("review.fail_on must be none, medium, high, or critical")
    _positive_int(review["max_markdown_findings"], "review.max_markdown_findings")
    if run["profile"] != "exhaustive":
        raise UserError("only run.profile='exhaustive' is supported in v1")
    if src["hash_algorithm"] != "sha256":
        raise UserError("only source.hash_algorithm='sha256' is supported")
    if build["compile_database_mode"] not in {"auto", "explicit", "disabled"}:
        raise UserError("build.compile_database_mode must be auto, explicit, or disabled")
    if build["compile_database_mode"] == "explicit" and not build.get("compile_database"):
        raise UserError("explicit compile database mode requires build.compile_database")
    for section in tools.values():
        if not isinstance(section["enabled"], bool) or not isinstance(section["executable"], str):
            raise UserError("tool enabled and executable values have invalid types")
        for key, value in section.items():
            if key.endswith("timeout_seconds"):
                _number(value, key)
    splint = tools["splint"]
    if splint["scope"] not in {"auto", "build", "inventory"}:
        raise UserError("tools.splint.scope must be auto, build, or inventory")
    _positive_int(splint["jobs"], "tools.splint.jobs")
    run["output_root"] = str(_absolute(run["output_root"], Path.cwd()))
    if build.get("compile_database"):
        build["compile_database"] = str(_absolute(build["compile_database"], Path.cwd()))
    build["include"] = [str(_absolute(p, Path.cwd())) for p in build["include"]]
    build["system_include"] = [str(_absolute(p, Path.cwd())) for p in build["system_include"]]
    return config


# Kept private alias for downstream code which imported it during v2 previews.
_normalize_and_validate = validate_config


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


def effective_toml(config: dict[str, Any]) -> str:
    """Serialize the supported config model deterministically."""
    lines = ["config_schema_version = 2", ""]
    for section in ("run", "source", "build", "review"):
        lines.append(f"[{section}]")
        for key in DEFAULTS[section]:
            value = config[section][key]
            if value is None:
                continue
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    for tool in ("cppcheck", "flawfinder", "splint"):
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


def config_value(config: dict[str, Any], path: str) -> Any:
    value: Any = config
    for part in path.split("."):
        value = value[part]
    return value


def set_config_value(config: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    target = config
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value


def persistent_config(config: dict[str, Any], base: Path | None = None) -> dict[str, Any]:
    """Return the versioned model only, optionally making contained paths relative."""
    result = copy.deepcopy({key: config[key] for key in DEFAULTS})
    if base is None:
        return result
    base = base.expanduser().resolve()
    path_fields = (
        "run.output_root",
        "build.compile_database",
    )
    list_fields = ("build.include", "build.system_include")
    for name in path_fields:
        value = config_value(result, name)
        if value:
            set_config_value(result, name, _portable_path(value, base))
    for name in list_fields:
        set_config_value(result, name, [_portable_path(value, base) for value in config_value(result, name)])
    return result


def _portable_path(value: str, base: Path) -> str:
    path = Path(value).expanduser()
    absolute = (path if path.is_absolute() else Path.cwd() / path).resolve()
    try:
        relative = absolute.relative_to(base)
    except ValueError:
        return str(absolute)
    text = relative.as_posix()
    return text if text != "." else "."


def save_config_snapshot(
    source: Path,
    config: dict[str, Any],
    destination: Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Atomically save and reload-check a complete reproducible v2 snapshot."""
    source = source.expanduser().resolve()
    destination = destination.expanduser().resolve()
    if destination.exists() and not overwrite:
        raise UserError(f"configuration file already exists: {destination}")
    if not destination.parent.is_dir():
        raise UserError(f"configuration directory does not exist: {destination.parent}")
    model = persistent_config(config, destination.parent)
    validate_config(copy.deepcopy(model))
    text = effective_toml(model)
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        temporary = Path(name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = -1
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        reloaded = load_config(source, temporary)
        expected = persistent_config(config)
        validate_config(expected)
        if persistent_config(reloaded) != persistent_config(expected):
            raise UserError("saved configuration did not reload to the same effective values")
        os.replace(temporary, destination)
        temporary = None
    except OSError as exc:
        raise UserError(f"cannot save configuration {destination}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination

from __future__ import annotations

import copy
import os
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import UserError
from .llm.profiles import DEFAULT_PROFILE, PROFILE_NAMES, PROFILES, apply_profile
from .llm.replan import REPLAN_DECIDERS
from .llm.risk import RISK_PROFILES, RISK_TIERS, parse_overrides
from .tools import LLM_PRODUCERS, TOOL_NAMES

DEFAULTS: dict[str, Any] = {
    "config_schema_version": 2,
    "run": {
        "output_root": "./code-analyzer-reports",
        "profile": "exhaustive",
        "shareable_export": True,
        "termination_grace_seconds": 5.0,
        "events_file": "",
        # What logs/runner.log records.  "debug" adds every heartbeat and LLM
        # step; the default keeps the log a narrative, not a trace.
        "log_level": "info",
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
    "review": {
        "enabled": True,
        "fail_on": "none",
        "max_markdown_findings": 200,
        # Off by default, and that default is the charter: generated findings
        # never fail a build unless a team says so for its own repository.
        "gate_includes_llm": False,
    },
    "llm": {
        "enabled": False,
        # Supplies endpoint/api_key_env/model unless a layer sets them itself.
        "profile": DEFAULT_PROFILE,
        "endpoint": PROFILES[DEFAULT_PROFILE]["endpoint"],
        # A variable name, never a secret: the value would reach
        # inputs/effective-config.toml and from there every shared export.
        "api_key_env": PROFILES[DEFAULT_PROFILE]["api_key_env"],
        "model": PROFILES[DEFAULT_PROFILE]["model"],
        "context_window": 32768,
        "scanners": list(LLM_PRODUCERS),
        "temperature": 0.0,
        "seed": 0,
        "max_completion_tokens": 2000,
        "max_steps": 4,
        "max_turns": 8,
        "request_timeout_seconds": 600.0,
        "total_timeout_seconds": 14400.0,
        # Per-scanner budgets: see scale_scanner_budgets.
        "total_prompt_tokens": 700000,
        "total_completion_tokens": 140000,
        "jobs": 2,
        "heartbeat_seconds": 15.0,
        "cache": True,
        "cache_directory": "",
        "risk_profile": "auto",
        "risk_overrides": [],
        "min_tier": "low",
        "export_sessions": False,
        "lsp": False,
        # Bounded re-planning.  0 means round 0 only -- the deterministic plan,
        # exactly as it has always been -- and is the default: an adaptive scan
        # is an operator's explicit choice, never a surprise.
        "max_replan_rounds": 0,
        "replan_decider": "deterministic",
        # Consecutive transport failures that open the circuit breaker and
        # unschedule the rest of the phase; 0 disables the breaker.
        "consecutive_failure_limit": 5,
    },
    "audit": {
        "enabled": False,
        "validation_model": "",
        "validation_max_candidates": 200,
        # The validator traces values through callers with the file tool, so
        # it gets its own step ceiling instead of the scanner's.
        "validation_max_steps": 12,
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

LOG_LEVELS: tuple[str, ...] = ("debug", "info", "warning")
ASSIST_MODES: tuple[str, ...] = ("off", "propose", "auto")
SPLINT_MODES: tuple[str, ...] = ("strict", "checks", "standard", "weak")
OVERRIDE_KEYS: tuple[str, ...] = ("match", "include", "system_include", "define", "undefine")


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
    FieldSpec("run.events_file", "path", "事件日志文件", "运行级 events.jsonl 的位置；留空则写入 <运行目录>/events.jsonl。", advanced=True),
    FieldSpec("run.log_level", "choice", "日志级别", "logs/runner.log 的详细程度；debug 额外记录每次心跳与 LLM 分步事件。", choices=LOG_LEVELS, advanced=True),
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
    FieldSpec("build.assist", "choice", "构建上下文辅助", "Splint/Cppcheck 预处理失败时推断缺失的 include/宏并重跑失败单元：off 关闭；propose 先询问再应用；auto 自动应用仅由代码推断且经探针验证的补丁。", choices=ASSIST_MODES),
    FieldSpec("build.assist_rounds", "int", "辅助轮数", "最多进行几轮诊断→补丁→重跑；0 表示只诊断不重跑。", minimum=0, advanced=True),
    FieldSpec("build.assist_probe_units", "int", "探针样本数", "应用补丁前先在多少个失败单元上试跑。", minimum=1, advanced=True),
    FieldSpec("build.stub_headers", "bool", "允许桩头文件", "为源码树中不存在的头文件生成空的桩文件（写在报告目录内，逐项确认）。", advanced=True),
    FieldSpec("build.approval_timeout_seconds", "float", "审批超时（秒）", "补丁等待操作者决定的时间；0 表示一直等待。", minimum=0.0, advanced=True),
    FieldSpec("build.overrides", "table_list", "按路径覆盖", "[[build.overrides]] 表：match 为源码相对路径 glob，其余为该路径专用的 include/system_include/define/undefine。仅通过 TOML 编辑。", advanced=True),
    FieldSpec("review.enabled", "bool", "生成 Review", "派生非权威统一 findings。"),
    FieldSpec("review.fail_on", "choice", "失败阈值", "达到该严重性时退出 1。", choices=("none", "medium", "high", "critical")),
    FieldSpec("review.max_markdown_findings", "int", "Markdown 最大 findings", "限制 Markdown 报告长度。", minimum=1, advanced=True),
    FieldSpec("llm.enabled", "bool", "启用 LLM 扫描", "以 LLM 专家 scanner 作为第二条独立检测路径；默认关闭。"),
    FieldSpec("llm.profile", "choice", "Provider Profile", "内置 provider 预设，提供端点/模型/密钥变量名默认值；显式设置的同名键优先。", choices=PROFILE_NAMES, advanced=True),
    FieldSpec("llm.endpoint", "string", "LLM 端点", "OpenAI 兼容 /v1 基地址，必须以 http:// 或 https:// 开头。", advanced=True),
    FieldSpec("llm.api_key_env", "string", "API Key 环境变量名", "只写变量名；密钥本身永不进入配置或导出。", advanced=True),
    FieldSpec("llm.model", "string", "模型", "端点上的模型 id。", advanced=True),
    FieldSpec("llm.context_window", "int", "上下文窗口", "模型上下文 token 上限。", minimum=1, advanced=True),
    FieldSpec("llm.scanners", "list", "启用的 Scanner", "LLM 专家 scanner 名称列表。", advanced=True),
    FieldSpec("llm.temperature", "float", "采样温度", "0 表示尽可能确定的输出。", minimum=0.0, advanced=True),
    FieldSpec("llm.seed", "int", "随机种子", "端点支持时用于复现采样。", minimum=0, advanced=True),
    FieldSpec("llm.max_completion_tokens", "int", "单次生成上限", "单个单元的最大生成 token 数。", minimum=1, advanced=True),
    FieldSpec("llm.max_steps", "int", "Agent 步数上限", "单个单元内 agent 的最大步数。", minimum=1, advanced=True),
    FieldSpec("llm.max_turns", "int", "模型往返上限", "单个单元内的最大模型往返次数。", minimum=1, advanced=True),
    FieldSpec("llm.request_timeout_seconds", "float", "单元请求超时", "单个单元的壁钟超时秒数。", minimum=0.001, advanced=True),
    FieldSpec("llm.total_timeout_seconds", "float", "LLM 总超时", "整个 LLM 阶段共享的壁钟预算。", minimum=0.001, advanced=True),
    FieldSpec("llm.total_prompt_tokens", "int", "Prompt token 预算", "单个 scanner 的预算，未显式设置时按启用 scanner 数线性放大；预算耗尽的单元记为 unscheduled，绝不截断上下文。", minimum=1, advanced=True),
    FieldSpec("llm.total_completion_tokens", "int", "生成 token 预算", "单个 scanner 的生成 token 上限，未显式设置时按启用 scanner 数线性放大。", minimum=1, advanced=True),
    FieldSpec("llm.jobs", "int", "LLM 并发数", "并发扫描单元数量。", minimum=1, advanced=True),
    FieldSpec("llm.heartbeat_seconds", "float", "LLM 心跳", "长任务状态刷新间隔。", minimum=0.001, advanced=True),
    FieldSpec("llm.cache", "bool", "跨运行缓存", "命中缓存的单元不再调用模型。", advanced=True),
    FieldSpec("llm.cache_directory", "path", "缓存目录", "留空则使用 <输出目录>/.llm-cache。", advanced=True),
    FieldSpec("llm.risk_profile", "choice", "风险档位", "auto 自动分档，或强制为某一档。", choices=RISK_PROFILES, advanced=True),
    FieldSpec("llm.risk_overrides", "list", "风险覆盖", '形如 "src/led.c=low" 的 glob=tier 列表。', advanced=True),
    FieldSpec("llm.min_tier", "choice", "最低档位", "档位下限，保证没有代码被排除在计划外。", choices=RISK_TIERS, advanced=True),
    FieldSpec("llm.export_sessions", "bool", "导出 Session 证据", "含源码片段的会话日志默认不进入可分享导出。", advanced=True),
    FieldSpec("llm.lsp", "bool", "启用 LSP 导航", "为 agent 提供编译器级符号导航。", advanced=True),
    FieldSpec("llm.max_replan_rounds", "int", "重规划轮数上限", "0 表示只跑确定性的第 0 轮；每多一轮都在同一预算内。", minimum=0, advanced=True),
    FieldSpec("llm.replan_decider", "choice", "重规划决策者", "deterministic 为规则表；model 显式启用模型决策。", choices=("deterministic", "model"), advanced=True),
    FieldSpec("llm.consecutive_failure_limit", "int", "断路器阈值", "连续多少个单元因传输错误失败后停止本阶段并释放预算；0 关闭断路器。", minimum=0, advanced=True),
    FieldSpec("review.gate_includes_llm", "bool", "门禁纳入 LLM 发现", "默认关闭：LLM 发现不影响退出码。开启后 LLM 发现与静态发现一同参与 fail_on 判定。", advanced=True),
    FieldSpec("audit.enabled", "bool", "启用 Audit 层", "关联与验证，产出非权威的 audit/assessment.json。"),
    FieldSpec("audit.validation_model", "string", "验证模型", "留空则沿用 [llm] model。", advanced=True),
    FieldSpec("audit.validation_max_candidates", "int", "最大验证 candidate 数", "按风险排序优先验证。", minimum=1, advanced=True),
    FieldSpec("audit.validation_max_steps", "int", "验证 agent 步数上限", "validator 每个 candidate 可执行的工具步数（读文件、追调用者）。", minimum=1, advanced=True),
    FieldSpec("tools.cppcheck.enabled", "bool", "启用 Cppcheck", "运行 Cppcheck。"),
    FieldSpec("tools.cppcheck.executable", "string", "Cppcheck 可执行文件", "命令名或绝对路径。", advanced=True),
    FieldSpec("tools.cppcheck.timeout_seconds", "float", "Cppcheck 超时", "总超时秒数。", minimum=0.001, advanced=True),
    FieldSpec("tools.cppcheck.heartbeat_seconds", "float", "Cppcheck 心跳", "长任务状态刷新间隔。", minimum=0.001, advanced=True),
    FieldSpec("tools.flawfinder.enabled", "bool", "启用 Flawfinder", "运行 Flawfinder。"),
    FieldSpec("tools.flawfinder.executable", "string", "Flawfinder 可执行文件", "命令名或绝对路径。", advanced=True),
    FieldSpec("tools.flawfinder.timeout_seconds", "float", "Flawfinder 超时", "总超时秒数。", minimum=0.001, advanced=True),
    FieldSpec("tools.flawfinder.heartbeat_seconds", "float", "Flawfinder 心跳", "长任务状态刷新间隔。", minimum=0.001, advanced=True),
    FieldSpec("tools.splint.enabled", "bool", "启用 Splint", "运行 Splint。"),
    FieldSpec("tools.splint.executable", "string", "Splint 可执行文件", "命令名或绝对路径。", advanced=True),
    FieldSpec("tools.splint.tu_timeout_seconds", "float", "Splint 单元超时", "每个翻译单元的超时秒数。", minimum=0.001, advanced=True),
    FieldSpec("tools.splint.total_timeout_seconds", "float", "Splint 总超时", "全部翻译单元共享的总预算。", minimum=0.001, advanced=True),
    FieldSpec("tools.splint.scope", "choice", "Splint 范围", "自动、build 覆盖范围或完整 inventory。", choices=("auto", "build", "inventory")),
    FieldSpec("tools.splint.jobs", "int", "Splint 并发数", "并发翻译单元数量。", minimum=1),
    FieldSpec("tools.splint.heartbeat_seconds", "float", "Splint 心跳", "长任务状态刷新间隔。", minimum=0.001, advanced=True),
    FieldSpec("tools.splint.mode", "choice", "Splint 检查模式", "Splint 预定义模式：strict 最严格，weak 最宽松。", choices=SPLINT_MODES, advanced=True),
    FieldSpec("tools.splint.report_reserved_names", "bool", "报告保留名冲突", "关闭后传 -isoreserved，不再报告以下划线开头等实现保留名。", advanced=True),
    FieldSpec("tools.splint.try_to_recover", "bool", "解析错误后尝试恢复", "开启后传 +trytorecover。", advanced=True),
    FieldSpec("tools.splint.skip_system_headers", "bool", "跳过系统头文件", "开启后传 -skipsysheaders。", advanced=True),
    FieldSpec("tools.splint.system_dirs", "path_list", "系统目录", "传给 -systemdirs 的目录列表；留空沿用 Splint 默认 /usr/include。", advanced=True),
)

FIELD_BY_PATH = {field.path: field for field in FIELD_REGISTRY}


@dataclass(frozen=True)
class LoadedConfig:
    config: dict[str, Any]
    sources: dict[str, str]
    paths: tuple[Path, ...]

_ALLOWED = {
    "": {"config_schema_version", "run", "source", "build", "review", "llm", "audit", "tools"},
    "run": set(DEFAULTS["run"]),
    "source": set(DEFAULTS["source"]),
    "build": set(DEFAULTS["build"]),
    "review": set(DEFAULTS["review"]),
    "llm": set(DEFAULTS["llm"]),
    "audit": set(DEFAULTS["audit"]),
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
    if run.get("events_file"):
        run["events_file"] = str(_absolute(run["events_file"], base))
    build = data.get("build", {})
    if build.get("compile_database"):
        build["compile_database"] = str(_absolute(build["compile_database"], base))
    for name in ("include", "system_include"):
        if isinstance(build.get(name), list):
            build[name] = _absolute_items(build[name], base)
    for override in build.get("overrides") or []:
        if isinstance(override, dict):
            for name in ("include", "system_include"):
                if isinstance(override.get(name), list):
                    override[name] = _absolute_items(override[name], base)
    splint = data.get("tools", {}).get("splint", {})
    if isinstance(splint.get("system_dirs"), list):
        splint["system_dirs"] = _absolute_items(splint["system_dirs"], base)


def _absolute_items(items: list[Any], base: Path) -> list[Any]:
    """Absolutise the string items; anything else is left for validate_config to name."""
    return [str(_absolute(item, base)) if isinstance(item, str) else item for item in items]


def _absolute(value: os.PathLike[str] | str, base: Path) -> Path:
    path = Path(value).expanduser()
    return (path if path.is_absolute() else base / path).resolve()


# Every enabled scanner reads every unit, so a per-run token budget has to grow
# with the roster: leaving it fixed would silently halve each scanner's reach
# when the roster doubles, and the units it could not afford would be reported
# as unscheduled rather than as a budget the user chose.  The two DEFAULTS above
# are therefore the budget for ONE scanner, multiplied here by the number of
# enabled scanners -- but only while the value is still that default.  A number
# the user wrote is the number the user gets, and inputs/effective-config.toml
# records the resolved product, so reloading a run's own config reproduces it.
SCANNER_SCALED_KEYS: tuple[str, ...] = ("total_prompt_tokens", "total_completion_tokens")


def scale_scanner_budgets(llm: dict[str, Any], sources: dict[str, str]) -> None:
    """Scale the still-default token budgets by the number of enabled scanners."""
    scanners = llm.get("scanners")
    # The roster that spends the budget is the one the scan phase resolves:
    # duplicates run once, so a list naming one scanner three times must not
    # buy three scanners' worth of tokens.
    count = len({name for name in scanners if name in LLM_PRODUCERS}) if isinstance(scanners, list) else 0
    if count <= 1:
        return
    for key in SCANNER_SCALED_KEYS:
        path = f"llm.{key}"
        base = DEFAULTS["llm"][key]
        if sources.get(path, "default") != "default" or llm.get(key) != base:
            continue
        llm[key] = int(base) * count
        sources[path] = f"default:{count}-scanners"


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
    apply_profile(config["llm"], sources)
    scale_scanner_budgets(config["llm"], sources)
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
    _validate_llm(config["llm"], config["audit"])
    _expect(run["output_root"], str, "run.output_root")
    _expect(run["profile"], str, "run.profile")
    _expect(run["shareable_export"], bool, "run.shareable_export")
    _number(run["termination_grace_seconds"], "run.termination_grace_seconds")
    _expect(run["events_file"], str, "run.events_file")
    _expect(run["log_level"], str, "run.log_level")
    if run["log_level"] not in LOG_LEVELS:
        raise UserError("run.log_level must be debug, info, or warning")
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
    _expect(review["enabled"], bool, "review.enabled")
    _expect(review["gate_includes_llm"], bool, "review.gate_includes_llm")
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
    if run["events_file"]:
        run["events_file"] = str(_absolute(run["events_file"], Path.cwd()))
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


def _validate_llm(llm: dict[str, Any], audit: dict[str, Any]) -> None:
    """Validate the [llm] and [audit] sections of a schema-v2 configuration."""
    for key in ("enabled", "cache", "export_sessions", "lsp"):
        _expect(llm[key], bool, f"llm.{key}")
    for key in ("profile", "endpoint", "api_key_env", "model", "cache_directory"):
        _expect(llm[key], str, f"llm.{key}")
    if llm["profile"] not in PROFILES:
        raise UserError("llm.profile must be " + ", ".join(PROFILE_NAMES))
    _validate_endpoint(llm["endpoint"])
    for key in ("scanners", "risk_overrides"):
        _string_list(llm[key], f"llm.{key}")
    unknown = [name for name in llm["scanners"] if name not in LLM_PRODUCERS]
    if unknown:
        raise UserError(
            f"unknown llm.scanners entry: {', '.join(sorted(unknown))}; expected {', '.join(LLM_PRODUCERS)}"
        )
    parse_overrides(llm["risk_overrides"])
    if llm["risk_profile"] not in RISK_PROFILES:
        raise UserError("llm.risk_profile must be " + ", ".join(RISK_PROFILES))
    if llm["min_tier"] not in RISK_TIERS:
        raise UserError("llm.min_tier must be " + ", ".join(RISK_TIERS))
    for key in (
        "context_window", "max_completion_tokens", "max_steps", "max_turns",
        "total_prompt_tokens", "total_completion_tokens", "jobs",
    ):
        _positive_int(llm[key], f"llm.{key}")
    for key in ("request_timeout_seconds", "total_timeout_seconds", "heartbeat_seconds"):
        _number(llm[key], f"llm.{key}")
    # Temperature 0 and seed 0 are the deliberate defaults, so these two are
    # the only numbers in the section that may be zero.
    if isinstance(llm["temperature"], bool) or not isinstance(llm["temperature"], (int, float)) or llm["temperature"] < 0:
        raise UserError("llm.temperature must be a number greater than or equal to zero")
    if isinstance(llm["seed"], bool) or not isinstance(llm["seed"], int) or llm["seed"] < 0:
        raise UserError("llm.seed must be an integer greater than or equal to zero")
    if isinstance(llm["max_replan_rounds"], bool) or not isinstance(llm["max_replan_rounds"], int) or llm["max_replan_rounds"] < 0:
        raise UserError("llm.max_replan_rounds must be an integer greater than or equal to zero")
    if llm["replan_decider"] not in REPLAN_DECIDERS:
        raise UserError("llm.replan_decider must be " + " or ".join(REPLAN_DECIDERS))
    _expect(audit["enabled"], bool, "audit.enabled")
    _expect(audit["validation_model"], str, "audit.validation_model")
    _positive_int(audit["validation_max_candidates"], "audit.validation_max_candidates")
    _positive_int(audit["validation_max_steps"], "audit.validation_max_steps")
    _non_negative_int(llm["consecutive_failure_limit"], "llm.consecutive_failure_limit")


def _validate_endpoint(endpoint: str) -> None:
    if not endpoint.startswith(("http://", "https://")):
        raise UserError("llm.endpoint must start with http:// or https://")
    try:
        split = urlsplit(endpoint)
    except ValueError as exc:
        raise UserError(f"llm.endpoint is not a valid URL: {exc}") from exc
    # An endpoint is persisted verbatim into inputs/effective-config.toml and
    # from there into every shared export, so it may never carry a credential.
    if split.username or split.password or "@" in split.netloc:
        raise UserError(
            "llm.endpoint must not embed userinfo credentials; put the credential in the "
            "environment variable named by llm.api_key_env instead"
        )


# Kept private alias for downstream code which imported it during v2 previews.


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
    for section in ("run", "source", "build", "review", "llm", "audit"):
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
        "run.events_file",
        "build.compile_database",
    )
    list_fields = ("build.include", "build.system_include", "tools.splint.system_dirs")
    for name in path_fields:
        value = config_value(result, name)
        if value:
            set_config_value(result, name, _portable_path(value, base))
    for name in list_fields:
        set_config_value(result, name, [_portable_path(value, base) for value in config_value(result, name)])
    for override in result["build"]["overrides"]:
        for name in ("include", "system_include"):
            if name in override:
                override[name] = [_portable_path(value, base) for value in override[name]]
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

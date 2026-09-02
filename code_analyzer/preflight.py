from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .compile_db import resolve_compile_db
from .config import validate_config
from .doctor import probe_tool
from .errors import UserError
from .inventory import discover
from .llm.doctor import endpoint_reachable
from .tools import TOOL_NAMES

LLM_PROBE_SECONDS = 15.0


@dataclass(frozen=True)
class PreflightIssue:
    severity: str
    field: str | None
    message: str


@dataclass(frozen=True)
class PreflightResult:
    ok: bool
    issues: tuple[PreflightIssue, ...]
    compile_database: dict[str, Any] | None
    inventory_files: int | None
    tools: dict[str, dict[str, Any]]
    # The LLM endpoint's answer to "are you there and serving the model",
    # when the LLM lane is enabled; None otherwise.
    llm: dict[str, Any] | None = None


def run_preflight(source: Path, config: dict[str, Any], *, probe_tools: bool = True) -> PreflightResult:
    """Read-only validation used by the TUI before confirmation."""
    issues: list[PreflightIssue] = []
    source = source.expanduser().resolve()
    checked = copy.deepcopy(config)
    try:
        validate_config(checked)
    except UserError as exc:
        issues.append(PreflightIssue("error", _field_from_error(str(exc)), str(exc)))
        return PreflightResult(False, tuple(issues), None, None, {})
    if not source.is_dir():
        issues.append(PreflightIssue("error", "SOURCE", f"source is not a directory: {source}"))
        return PreflightResult(False, tuple(issues), None, None, {})
    selected = [name for name in TOOL_NAMES if checked["tools"][name]["enabled"]]
    if not selected:
        issues.append(PreflightIssue("error", "tools", "至少选择一个分析工具"))

    compile_info = None
    try:
        compile_path, entries, degraded, discovery = resolve_compile_db(source, checked)
        compile_info = {
            "path": str(compile_path) if compile_path else None,
            "entries": len(entries),
            "degraded": degraded,
            "discovery": discovery,
        }
        for message in degraded:
            issues.append(PreflightIssue("warning", "build.compile_database", message))
    except UserError as exc:
        issues.append(PreflightIssue("error", "build.compile_database", str(exc)))

    inventory_files: int | None = None
    try:
        output_root = Path(checked["run"]["output_root"])
        if output_root.resolve() == source:
            raise UserError("output root must not be identical to source")
        inventory_files = len(discover(source, checked, output_root))
    except (OSError, UserError) as exc:
        issues.append(PreflightIssue("error", "run.output_root", str(exc)))

    tool_results: dict[str, dict[str, Any]] = {}
    if probe_tools:
        for name in selected:
            result = probe_tool(name, checked["tools"][name]["executable"])
            tool_results[name] = result
            if result["status"] != "compatible":
                issues.append(PreflightIssue("warning", f"tools.{name}.executable", f"{name}: {result['status']}"))
    llm_info: dict[str, Any] | None = None
    if probe_tools and checked["llm"]["enabled"]:
        # A scan that may run for hours must not find out one unit at a time
        # that the tunnel is down.
        reachable, reason = endpoint_reachable(checked["llm"], timeout=LLM_PROBE_SECONDS)
        llm_info = {
            "reachable": reachable, "reason": reason,
            "endpoint": checked["llm"].get("endpoint"), "model": checked["llm"].get("model"),
        }
        if not reachable:
            issues.append(PreflightIssue("warning", "llm.endpoint", f"LLM 端点不可达：{reason}"))
    return PreflightResult(
        not any(item.severity == "error" for item in issues), tuple(issues), compile_info, inventory_files,
        tool_results, llm_info,
    )


def _field_from_error(message: str) -> str | None:
    prefixes = ("run.", "source.", "build.", "review.", "tools.")
    words = message.replace(":", " ").split()
    return next((word.rstrip(",") for word in words if word.startswith(prefixes)), None)

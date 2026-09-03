"""Isolation layer for the deepseek-harness agent runtime.

Every ``deepseek_harness`` touch point lives in this package, and the import
itself is deferred to call time: ``code-analyzer analyze`` must keep working
when the optional extra, or its bundled runtime binary, is not installed.
Upstream is a release candidate that promises compatibility-breaking changes,
so when it breaks, the blast radius is these four modules.
"""
from __future__ import annotations

from .cordis import (
    FORBIDDEN_TOOLS,
    PROJECT_SKILL_ROOTS,
    SCANNER_TOOL_ALLOWLIST,
    cordis_document,
    skill_directory,
    tool_allowlist,
    write_cordis_config,
)
from .runtime import (
    HarnessRunFailed,
    HarnessRuntime,
    HarnessUnavailable,
    RunOutcome,
    harness_available,
    sdk_version,
)
from .schema import (
    FINDING_CATEGORIES,
    SCANNER_OUTPUT_SCHEMA,
    SCHEMA_VERSION,
    SEVERITIES,
    parse_findings,
    response_unparsed,
    schema_hash,
)
from .session import run_summary, run_unit, unit_directory

__all__ = [
    "FINDING_CATEGORIES",
    "FORBIDDEN_TOOLS",
    "HarnessRunFailed",
    "HarnessRuntime",
    "HarnessUnavailable",
    "PROJECT_SKILL_ROOTS",
    "RunOutcome",
    "SCANNER_OUTPUT_SCHEMA",
    "SCANNER_TOOL_ALLOWLIST",
    "tool_allowlist",
    "SCHEMA_VERSION",
    "SEVERITIES",
    "cordis_document",
    "harness_available",
    "parse_findings",
    "response_unparsed",
    "run_summary",
    "run_unit",
    "schema_hash",
    "sdk_version",
    "skill_directory",
    "unit_directory",
    "write_cordis_config",
]

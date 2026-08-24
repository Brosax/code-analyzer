"""The adapter registry: one seam, one lookup, no per-tool branches above it.

Adding a native analyzer used to mean editing about twenty places, four of
which raised ``KeyError`` on an unknown name and one of which silently handed
it to splint.  These tests pin the replacement: the registry is exactly
``TOOL_NAMES``, every former crash point now fails by name, and an adapter
substituted at the registry is the one the runner actually calls.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from code_analyzer import doctor, review, runner
from code_analyzer import tools as tools_package
from code_analyzer.analysis import AnalysisRequest, run_analysis
from code_analyzer.config import DEFAULTS, validate_config
from code_analyzer.errors import UserError
from code_analyzer.tools import (
    TOOL_NAMES,
    Adapter,
    CompileDatabase,
    RunContext,
    adapter,
    adapters,
)

UNKNOWN = "shellcheck"


def test_the_registry_is_exactly_the_declared_tool_names() -> None:
    assert tuple(adapters()) == TOOL_NAMES
    for name in TOOL_NAMES:
        declared = adapter(name)
        assert declared.name == name
        assert declared.apt_package, name
        assert declared.version_argv("/bin/tool")[0] == "/bin/tool"
        # Every adapter declares one capability check or the other, never both
        # and never neither: help flags for the GNU-style tools, help topics
        # for splint, which answers `-help <topic>` instead.
        assert bool(declared.required_capabilities) != bool(declared.help_topics), name


@pytest.mark.parametrize(
    "call",
    (
        pytest.param(lambda: adapter(UNKNOWN), id="lookup"),
        pytest.param(lambda: runner._version(UNKNOWN, "/bin/true"), id="runner-version"),
        pytest.param(lambda: runner._incompatibility(UNKNOWN, "/bin/true"), id="runner-incompatibility"),
        pytest.param(lambda: doctor._guidance(UNKNOWN), id="doctor-guidance"),
        pytest.param(lambda: doctor.probe_tool(UNKNOWN, "sh"), id="doctor-probe"),
    ),
)
def test_an_unknown_analyzer_fails_by_name_at_every_former_crash_point(call) -> None:
    with pytest.raises(UserError) as error:
        call()
    assert UNKNOWN in str(error.value) and "supported analyzers" in str(error.value)


def test_an_unknown_analyzer_never_stops_a_review_from_being_written() -> None:
    """Severity normalisation stays total.

    A manifest naming a tool this build does not have is bad input, but the
    findings beside it are still evidence: they normalise to "unknown" rather
    than aborting the review.  This is the same stance ``_producer_rank`` takes.
    """
    assert review._normalize_severity(UNKNOWN, "error") == "unknown"
    assert review._normalize_severity(UNKNOWN, "") == "unknown"
    # ... while the tools that do exist keep their own vocabulary.
    assert review._normalize_severity("cppcheck", "error") == "high"
    assert review._normalize_severity("flawfinder", "5") == "critical"
    assert review._normalize_severity("flawfinder", "9", "security-severity") == "critical"
    assert review._normalize_severity("splint", "error") == "unknown"


def _fake_adapter(seen: list[RunContext]) -> Adapter:
    def run(executable: str, ctx: RunContext) -> dict[str, Any]:
        seen.append(ctx)
        record = runner._not_requested(ctx.inventory, "cppcheck")
        record.update({
            "requested": True, "status": "completed", "executable": executable,
            "units": [], "valid_reports": 0,
        })
        return record

    return Adapter(
        name="cppcheck",
        run=run,
        parse=lambda _source, _run_dir, _execution: ([], []),
        severity=lambda _raw, _scale=None: "unknown",
        version_argv=lambda executable: [executable, "--version"],
        required_capabilities=("--only-a-fake-would-have-this",),
        canary=lambda _executable, _root: (True, None),
        apt_package="fake",
    )


def test_a_substituted_adapter_is_the_one_the_runner_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The registry is the dispatch: nothing above it names a tool.

    Registering a different implementation under a known name is enough to
    change what the run executes, what the manifest records and what the
    review parses -- which is the property that makes a fourth analyzer one
    module and one registry entry.
    """
    source = tmp_path / "src"
    source.mkdir()
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    seen: list[RunContext] = []
    monkeypatch.setattr(tools_package, "_ADAPTERS", {**adapters(), "cppcheck": _fake_adapter(seen)})

    config = validate_config(json.loads(json.dumps(DEFAULTS)))
    config["run"]["output_root"] = str(tmp_path / "reports")
    config["run"]["shareable_export"] = False
    config["build"]["compile_database_mode"] = "disabled"
    for name in TOOL_NAMES:
        config["tools"][name]["enabled"] = name == "cppcheck"
    config["tools"]["cppcheck"]["executable"] = "/bin/true"

    result = run_analysis(AnalysisRequest(source, config))

    assert result.report_directory is not None
    [context] = seen
    assert isinstance(context, RunContext)
    assert context.source == source.resolve() and context.run_dir == result.report_directory
    assert isinstance(context.compile_db, CompileDatabase)
    # The compile database travels as one object now, not as two positional
    # arguments one adapter took and another did not.
    assert context.compile_db.entries == [] and context.compile_db.present is False
    assert [item["path"] for item in context.inventory] == ["main.c"]
    assert context.cancelled() is False
    manifest = json.loads((result.report_directory / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["tools"]["cppcheck"]["status"] == "completed"
    assert manifest["tools"]["cppcheck"]["executable"] == "/bin/true"


def test_the_canary_isolates_every_adapter_the_same_way(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolation is shared; the argv and the report check belong to the tool."""
    seen: dict[str, Path] = {}

    def canary(_executable: str, root: Path) -> tuple[bool, str | None]:
        seen["root"] = root
        seen["source"] = (root / "canary.c").read_text(encoding="utf-8")
        return False, None

    fake = _fake_adapter([])
    monkeypatch.setattr(
        tools_package, "_ADAPTERS",
        {**adapters(), "cppcheck": Adapter(**{**vars(fake), "canary": canary})},
    )

    ok, reason = doctor.verify_canary("cppcheck", "/bin/true")

    assert ok is False and reason == "minimal cppcheck canary did not produce a valid native report"
    assert "int main(void)" in seen["source"]
    # The temporary tree is gone: no adapter can leave a canary behind.
    assert not seen["root"].exists()

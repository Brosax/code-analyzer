"""Shared pytest configuration.

Keeps the package importable under a bare ``pytest`` invocation (which does
not put the repository root on ``sys.path``) and the shared ``helpers``
module importable regardless of the invocation directory.

It also keeps the suite honest about the provider.  Free text now routes to a
model by default, so without a seam "691 tests green" would quietly mean
"green on a machine whose GPU host happened to be up" -- and on a machine
where it is down, a blackholed endpoint costs 30 seconds per call.  The
autouse fixture below switches the model lane off and stubs the one function
that would reach it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).parent
for _entry in (str(_TESTS_DIR.parent), str(_TESTS_DIR)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)


@pytest.fixture(autouse=True)
def no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test opens a socket to a model unless it says so.

    Two mechanisms, because either alone leaves a hole.  ``CODE_ANALYZER_NO_MODEL``
    makes ``propose.gate`` refuse before anything connects, which covers code
    that calls the gate directly.  The stub on ``propose.propose`` covers the
    TUI, whose ``_propose_worker`` imports it inside the function -- so a
    module-attribute patch really is what it resolves.

    Deliberately NOT patched: ``propose.gate``.  ``propose()`` resolves it as a
    module global, so patching it would hijack the very tests that check the
    gate's own behaviour.
    """
    monkeypatch.setenv("CODE_ANALYZER_NO_MODEL", "1")

    from code_analyzer.llm import propose as propose_module

    def refused(utterance: str, config: object, **_kwargs: object) -> object:
        return propose_module.Proposal(
            "skipped", "CODE_ANALYZER_NO_MODEL=1 已关闭模型通道（测试）",
            model=str((config or {}).get("llm", {}).get("model") or None) if isinstance(config, dict) else None,
        )

    monkeypatch.setattr(propose_module, "propose", refused)


@pytest.fixture
def provider_lane_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Opt back in: for the tests that exercise the gate's own refusals.

    They still never reach a live provider -- they point at an unconfigured or
    a closed endpoint -- but they need ``gate`` to get past the env switch.
    """
    monkeypatch.delenv("CODE_ANALYZER_NO_MODEL", raising=False)

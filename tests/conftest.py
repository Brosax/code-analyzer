"""Shared pytest configuration.

Keeps the package importable under a bare ``pytest`` invocation and the shared ``helpers`` module importable
regardless of the invocation directory, and keeps the suite honest about the model: no test opens a socket to a
model unless it removes ``CODE_ANALYZER_NO_MODEL`` itself (and then it talks to a FakeTransport).
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
    """The model lane is off unless a test turns it on (``client.chat`` refuses before any socket)."""
    monkeypatch.setenv("CODE_ANALYZER_NO_MODEL", "1")


@pytest.fixture(autouse=True)
def private_home(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Nothing a test does lands in the operator's ~/.code-analyzer."""
    home = tmp_path_factory.mktemp("code-analyzer-home")
    monkeypatch.setenv("CODE_ANALYZER_HOME", str(home))
    return home

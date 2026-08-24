"""The one seam every native analyzer is reached through.

Three adapters grew three different ``run()`` signatures, and the layers above
them grew a hardcoded ``if name == …`` dispatch plus four per-tool dictionaries
indexed outside any ``try`` -- so a fourth tool meant editing about twenty
places, four of which would raise ``KeyError`` and one of which (the ``else:``
in the runner's dispatch) would silently hand the unknown tool to splint.

This module replaces all of that with one declaration per tool.  An
:class:`Adapter` is a frozen record of the per-tool behaviour the analysis,
review and doctor layers need; :data:`~code_analyzer.tools.ADAPTERS` is the
registry, keyed by ``TOOL_NAMES``, and :func:`~code_analyzer.tools.adapter`
is the only lookup -- it raises a named error instead of ``KeyError``.

The adapters stay *functions*, not classes: the tool modules are modules of
functions, and wrapping them in objects would add ceremony without adding a
seam.  ``Adapter`` binds those functions; it does not reimplement them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

Progress = Callable[[str], None]
UnitEvent = Callable[..., None]


@dataclass(frozen=True)
class CompileDatabase:
    """The compile database as the adapters see it.

    ``filtered`` and ``covered`` used to travel as two positional arguments to
    two of the three adapters and not at all to the third; ``present`` was a
    keyword argument computed from a path the adapter never saw.  One object
    keeps them consistent and lets a new adapter use whichever part it needs.
    """

    entries: list[dict[str, Any]] = field(default_factory=list)
    covered: frozenset[str] = frozenset()
    present: bool = False

    @property
    def covered_set(self) -> set[str]:
        """A mutable copy, for adapters whose helpers expect ``set``."""
        return set(self.covered)


@dataclass(frozen=True)
class RunContext:
    """Everything one analysis run hands an adapter, read-only.

    The callbacks are part of the context rather than the signature because
    every adapter takes the same four, and an adapter that ignores one must
    not have to declare it.
    """

    source: Path
    run_dir: Path
    inventory: list[dict[str, Any]]
    compile_db: CompileDatabase
    config: dict[str, Any]
    progress: Progress
    cancelled: Callable[[], bool]
    unit_event: UnitEvent
    output_event: UnitEvent | None = None


@dataclass(frozen=True)
class Adapter:
    """One native analyzer, declared once.

    Every field is behaviour some layer used to reach through a per-tool
    branch: ``run`` the runner's dispatch, ``parse`` the review layer's
    ``parsers[tool]``, ``severity`` its normalisation chain, and the probe
    fields the runner's ``_incompatibility``/``_version`` and doctor's
    ``REQUIRED`` / ``_guidance`` / ``verify_canary``.
    """

    name: str
    # The analysis: run the tool over the context and return its execution record.
    run: Callable[[str, RunContext], dict[str, Any]]
    # The review: native report -> (findings, diagnostics).  Late-bound by the
    # tool module, because parsing produces review rows and belongs to that
    # layer; see the tool modules' ``_parse``.
    parse: Callable[[Path, Path, dict[str, Any]], tuple[list[dict[str, Any]], list[dict[str, Any]]]]
    # The review: this tool's native severity vocabulary -> the shared ladder.
    severity: Callable[[str, str | None], str]
    # Capability probing.  ``version_argv`` is how the tool is asked its
    # version; ``required_capabilities`` are flags that must appear in its help
    # text; ``help_topics`` are ``-help <topic>`` subjects that must answer.
    version_argv: Callable[[str], list[str]]
    # The version *number* doctor reports, parsed out of that command's output.
    # The runner records the whole first line in the manifest instead: one is a
    # human-facing field, the other is evidence of exactly what answered.
    reported_version: Callable[[str], str | None] = lambda text: (
        text.strip().splitlines()[0] if text.strip() else None
    )
    required_capabilities: tuple[str, ...] = ()
    help_topics: tuple[str, ...] = ()
    # The isolated canary: run the tool over a minimal source file in ``root``
    # and report whether it produced a valid native report.
    canary: Callable[[str, Path], tuple[bool, str | None]] = lambda _executable, _root: (True, None)
    # Named in doctor's guidance; never installed automatically (README:9).
    apt_package: str = ""

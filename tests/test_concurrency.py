"""The static adapters and the LLM scan phase running at the same time.

Four properties, in the order they matter.  Progress must never walk
backwards, because the bar is the only thing an operator watches for minutes
at a stretch.  The evidence must not move a byte, because a run directory is
the product and concurrency is an implementation detail of how it was filled.
Cancellation must reach both sides, or Ctrl-C stops half a run.  And the event
log must stay parseable, because two threads now write it.

Everything here drives ``tests/fake_harness.py`` and a fake analyzer
executable: what is under test is the scheduling, not cppcheck and not a model.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from fake_harness import FakeHarness, response
from helpers import executable
from test_llm_pipeline import (  # noqa: F401  (fixtures)
    _analyze,
    _config,
    _finding,
    _report,
    _tree,
    closed_endpoint,
    fake,
)

from code_analyzer import runner
from code_analyzer.analysis import (
    AnalysisEvent,
    AnalysisRequest,
    CancellationToken,
    run_analysis,
)
from code_analyzer.events import JsonlEventSink, fan_out
from code_analyzer.persist import json_bytes
from code_analyzer.tools import TOOL_NAMES

SCANNER = "llm-memory-safety"


def _slow_cppcheck(tmp_path: Path, seconds: float) -> Path:
    """``_cppcheck`` from test_llm_pipeline, plus a measurable running time."""
    return executable(tmp_path / "slow-cppcheck", f"""
        import pathlib, sys, time
        if '--version' in sys.argv: print('Cppcheck 2.fake'); raise SystemExit()
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        checkers = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--checkers-report=')))
        time.sleep({seconds})
        report.write_text('<?xml version="1.0"?><results version="2"><errors>'
            '<error id="nullPointer" severity="error" msg="Null pointer dereference" cwe="476">'
            '<location file="parser.c" line="8" column="9"/></error></errors></results>')
        checkers.write_text('checked\\n')
    """)


def _span(events: list[AnalysisEvent], phase: str, tool: str | None = None) -> tuple[float, float]:
    """The wall-clock interval one side of the window occupied."""
    marks = [
        event.timestamp for event in events
        if event.phase == phase and (tool is None or event.tool == tool)
    ]
    assert marks, f"no {phase} events to bound"
    return min(marks), max(marks)


def _values(events: list[AnalysisEvent]) -> list[float]:
    return [event.progress for event in events if event.progress is not None]


# --- progress ---------------------------------------------------------------


def test_progress_is_non_decreasing_with_both_sides_reporting(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811  (pytest fixtures by name)
) -> None:
    """The work-proportion model, exercised where the fixed ladder broke.

    Both sides emit into one window from two threads, so the interleaving is
    real, and the values still only ever grow.  The window is genuinely shared
    rather than one side idling through it: with equal weights neither side
    alone can carry the bar past the window's midpoint.
    """
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding()), delay=0.15))
    config = _config(tmp_path, closed_endpoint, cppcheck=_slow_cppcheck(tmp_path, 0.3))

    exit_code, _run_dir, manifest = _analyze(source, config)

    assert exit_code == 0, manifest
    events = list(config["_events"])
    values = _values(events)
    assert values == sorted(values)
    assert values[0] == 0.0 and values[-1] == 1.0
    window = [
        event for event in events
        if event.progress is not None and event.phase in {"tool", "unit", "llm"}
    ]
    assert {"tool", "llm"} <= {event.phase for event in window}
    assert min(event.progress for event in window) >= runner.WINDOW_START
    assert max(event.progress for event in window) == runner.WINDOW_END
    assert sum(runner.WEIGHTS_WITH_LLM) == 1.0
    midpoint = runner.WINDOW_START + (runner.WINDOW_END - runner.WINDOW_START) * runner.WEIGHTS_WITH_LLM[0]
    assert [event for event in window if event.progress > midpoint]


def test_a_static_only_run_keeps_the_whole_window_for_the_static_side(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811  (pytest fixtures by name)
) -> None:
    """With the LLM phase off the weights collapse to (1, 0).

    The last tool then lands on the window's end instead of stranding a share
    of the bar that nothing will ever fill, which is the pre-concurrency shape.
    """
    source = _tree(tmp_path)
    config = _config(tmp_path, closed_endpoint, cppcheck=_slow_cppcheck(tmp_path, 0))
    config["llm"]["enabled"] = False

    exit_code, _run_dir, manifest = _analyze(source, config)

    assert exit_code == 0, manifest
    values = _values(config["_events"])
    assert values == sorted(values)
    finished = next(
        event for event in config["_events"] if event.phase == "tool" and event.status == "completed"
    )
    assert finished.progress == runner.WINDOW_END
    assert fake.calls == []


# --- overlap ----------------------------------------------------------------


def test_the_static_and_llm_sides_really_run_at_the_same_time(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811  (pytest fixtures by name)
) -> None:
    """The point of the change: the window costs the longer side, not the sum.

    Both intervals come out of the event stream -- what the TUI and the event
    log see -- rather than out of a timer the runner keeps to itself.
    """
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding()), delay=0.25))
    config = _config(tmp_path, closed_endpoint, cppcheck=_slow_cppcheck(tmp_path, 0.5))

    exit_code, _run_dir, manifest = _analyze(source, config)

    assert exit_code == 0, manifest
    events = list(config["_events"])
    static_start, static_end = _span(events, "tool", "cppcheck")
    llm_start, llm_end = _span(events, "llm")
    assert min(static_end, llm_end) - max(static_start, llm_start) > 0.2
    elapsed = max(static_end, llm_end) - min(static_start, llm_start)
    assert elapsed < (static_end - static_start) + (llm_end - llm_start) - 0.2


# --- evidence ---------------------------------------------------------------

# The only files whose bytes embed the run's identity or a wall clock, so the
# only files whose digest may move between two runs of one tree.  Naming them
# is the point: a new entry here has to be argued for, not discovered.
_PER_RUN_FILES = (
    "index.html", "inputs/sanitizer-map.private.json", "audit/assessment.json",
    "llm/cordis.json", "llm/cordis.meta.json", "review/summary.json",
    "review/summary.md", "review/summary.sarif", "logs/runner.log", "meta.json",
)


def _by_path(value: Any) -> Any:
    """Re-key every ``[{"path": ...}, ...]`` index by path.

    Comparing two runs leaf by leaf is only readable if a digest is identified
    by the file it belongs to instead of by its position in a list.  Ordering
    is asserted separately, so nothing is lost by dropping it here -- but a
    list with a repeated path is left alone, because collapsing it would hide
    entries from the comparison rather than re-key them.
    """
    if isinstance(value, list):
        paths = [item["path"] for item in value if isinstance(item, dict) and "path" in item]
        if value and len(paths) == len(value) == len(set(paths)):
            return {str(item["path"]): _by_path(item) for item in value}
        return [_by_path(item) for item in value]
    if isinstance(value, dict):
        return {key: _by_path(child) for key, child in value.items()}
    return value


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    """Every leaf of a JSON document, keyed by its path through the document."""
    if isinstance(value, dict):
        flat: dict[str, Any] = {}
        for key, child in value.items():
            flat |= _flatten(child, f"{prefix}.{key}")
        return flat
    if isinstance(value, list):
        flat = {}
        for index, child in enumerate(value):
            flat |= _flatten(child, f"{prefix}[{index}]")
        return flat
    return {prefix: value}


def _differing(left: Any, right: Any) -> set[str]:
    missing = object()
    flat_left, flat_right = _flatten(_by_path(left)), _flatten(_by_path(right))
    return {
        path for path in set(flat_left) | set(flat_right)
        if flat_left.get(path, missing) != flat_right.get(path, missing)
    }


def _per_run(path: str) -> bool:
    """May this leaf differ between two runs of the same tree?

    Three reasons and no fourth: the run's own identity, a wall clock, and the
    size or digest of one of the named files that embed either.  A status, a
    coverage ratio, a finding, an ordering -- none of them qualifies, so a
    concurrency bug in any of those fails the caller's assertion rather than
    being absorbed into "runs differ".
    """
    if path in {".run_id", ".run_directory", ".run.id"}:
        return True
    if path.endswith(("_at", ".duration_seconds")):  # a moment, or a span of them
        return True
    if ".process.argv[" in path:  # the run directory, on a command line
        return True
    return path.endswith((".sha256", ".size")) and any(
        f"{name}." in path for name in _PER_RUN_FILES
    )


def _blank(value: Any, paths: set[str], prefix: str = "") -> Any:
    if isinstance(value, dict):
        return {key: _blank(child, paths, f"{prefix}.{key}") for key, child in value.items()}
    if isinstance(value, list):
        return [_blank(child, paths, f"{prefix}[{index}]") for index, child in enumerate(value)]
    return "<per-run>" if prefix in paths else value


def _identical(documents: list[Any], volatile: set[str]) -> bool:
    blanked = {json_bytes(_blank(_by_path(item), volatile)) for item in documents}
    return len(blanked) == 1


def test_concurrency_changes_no_byte_of_the_evidence(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    """Two serial runs and one concurrent run of the same tree, compared.

    The two serial runs are the control: whatever they disagree about is what
    *any* rerun costs, and every such place has to pass ``_per_run`` before it
    is allowed to be blanked.  With exactly those leaves blanked, all three
    manifests -- and all three review summaries -- are the same bytes.
    """
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding())))
    tool = _slow_cppcheck(tmp_path, 0)
    runs = []
    for concurrent in (False, False, True):
        monkeypatch.setattr(runner, "CONCURRENT_PHASES", concurrent)
        # One output root throughout, so the run directory is the only path
        # that moves.  The cache is off: a hit would replay the first run's
        # evidence into the later ones and prove nothing.
        config = _config(tmp_path, closed_endpoint, cppcheck=tool, cache=False)
        exit_code, run_dir, manifest = _analyze(source, config)
        assert exit_code == 0, manifest
        runs.append((run_dir, manifest))
    first, second, third = (manifest for _dir, manifest in runs)

    volatile = _differing(first, second) | _differing(first, third)
    assert not {path for path in volatile if not _per_run(path)}, sorted(volatile)
    assert _identical([first, second, third], volatile)

    # Ordering, which _by_path deliberately dropped, and the manifest key order
    # as it was actually persisted (these manifests are read back off disk).
    assert list(third["tools"]) == list(TOOL_NAMES)
    assert [item["path"] for item in first["artifacts"]] == [item["path"] for item in third["artifacts"]]

    summaries = [
        json.loads((run_dir / "review" / "summary.json").read_text(encoding="utf-8"))
        for run_dir, _manifest in runs
    ]
    review_volatile = _differing(summaries[0], summaries[1]) | _differing(summaries[0], summaries[2])
    assert not {path for path in review_volatile if not _per_run(path)}, sorted(review_volatile)
    assert _identical(summaries, review_volatile)
    # tests/test_producers.py pins what overlap_groups contains; this pins that
    # running two producers at once does not reorder or reshape it.
    assert json_bytes(summaries[0]["overlap_groups"]) == json_bytes(summaries[2]["overlap_groups"])
    assert summaries[2]["run"]["tool_order"] == list(TOOL_NAMES)


def test_a_failing_llm_phase_still_lands_the_static_results(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    """A crash on one side costs the run one producer, never both.

    This is the LLM phase's own ``except Exception``, which concurrency must
    not have moved; the next test is the other direction, where the failure
    escapes a side entirely and _run_together has to hold it.
    """
    def explode(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("the scan phase fell over")

    monkeypatch.setattr(runner.llm_scan, "run", explode)
    source = _tree(tmp_path)
    config = _config(tmp_path, closed_endpoint, cppcheck=_slow_cppcheck(tmp_path, 0.2))

    exit_code, _run_dir, manifest = _analyze(source, config)

    assert manifest["tools"]["cppcheck"]["status"] == "completed"
    assert manifest["tools"]["cppcheck"]["valid_reports"] == 1
    assert manifest["llm"]["status"] == "failed"
    assert "the scan phase fell over" in manifest["llm"]["reason"]
    # A model failure still never reaches status.overall.
    assert exit_code == 0 and manifest["status"] == "complete"


def test_a_crashing_static_side_still_lands_the_llm_results(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    """The other direction, where nothing inside the side catches it.

    A failure that escapes the static thread altogether is held until the LLM
    thread has written its half of the manifest, and only then re-raised.
    """
    def explode(_name: str, _executable: str) -> str:
        raise RuntimeError("the version probe fell over")

    monkeypatch.setattr(runner, "_version", explode)
    fake.script_default(response(_report(_finding())))
    source = _tree(tmp_path)
    config = _config(tmp_path, closed_endpoint, cppcheck=_slow_cppcheck(tmp_path, 0))
    created: list[Path] = []

    def sink(event: AnalysisEvent) -> None:
        if (event.phase, event.status) == ("run", "created"):
            created.append(Path(event.message))

    with pytest.raises(RuntimeError, match="the version probe fell over"):
        run_analysis(AnalysisRequest(source, config), events=sink)

    manifest = json.loads((created[0] / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["llm"]["status"] == "completed"
    assert manifest["llm"]["unit_counts"]["completed"] == manifest["llm"]["planned_units"] > 0
    assert (created[0] / "llm" / "index.json").is_file()


# --- cancellation -----------------------------------------------------------


def test_a_raised_interrupt_still_finalises_the_manifest(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    """A SIGTERM from a supervisor reaches the CLI as a raised KeyboardInterrupt,
    not a flipped token.  _run_together re-raises it from the static thread, so
    the cooperative `if interrupted or cancelled` check never runs.  The manifest
    must still be finalised: status interrupted, exit 130, no stale `running` --
    the TF-M review and the first Juliet run both ended with the status a lie
    because this raised path skipped the finalise."""
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding()), delay=0.2))
    config = _config(tmp_path, closed_endpoint)

    def stop(*_args: Any, **_kwargs: Any) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(runner.llm_scan, "run", stop)
    exit_code, _run_dir, manifest = _analyze(source, config)

    assert exit_code == 130
    assert manifest["status"] == "interrupted" and manifest["exit_code"] == 130
    assert manifest["llm"]["status"] == "interrupted"
    assert "running" not in json.dumps(manifest)


def test_cancellation_stops_both_sides(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811  (pytest fixtures by name)
) -> None:
    """Ctrl-C during the window has to reach the thread it did not land on.

    The token is set once the LLM side is demonstrably in flight, by which
    time cppcheck is inside a five-second sleep.  The run still finishes fast,
    through _finish_interrupted, with a manifest that says interrupted on both
    sides and a progress column that never went backwards on the way there.
    """
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding()), delay=0.2))
    config = _config(tmp_path, closed_endpoint, cppcheck=_slow_cppcheck(tmp_path, 5.0))
    config["run"]["termination_grace_seconds"] = 0.2
    token = CancellationToken()
    seen: list[AnalysisEvent] = []

    def sink(event: AnalysisEvent) -> None:
        seen.append(event)
        if (event.phase, event.status, event.tool) == ("unit", "started", SCANNER):
            token.cancel()

    started = time.monotonic()
    result = run_analysis(AnalysisRequest(source, config), events=sink, cancellation=token)
    elapsed = time.monotonic() - started

    assert result.exit_code == 130 and result.manifest is not None
    # cppcheck's five-second sleep was cut short rather than waited out.
    assert elapsed < 4.0
    manifest = result.manifest
    assert manifest["status"] == "interrupted" and manifest["exit_code"] == 130
    assert manifest["tools"]["cppcheck"]["status"] == "interrupted"
    assert manifest["llm"]["status"] == "interrupted"
    assert manifest["source_inventory"]["stable"] is None
    assert manifest["review"]["status"] == "interrupted"
    assert "running" not in json.dumps(manifest)
    values = _values(seen)
    assert values == sorted(values) and values[-1] == 1.0


# --- the event log ----------------------------------------------------------


def test_the_event_log_survives_two_writers(tmp_path: Path) -> None:
    """Two threads through one fan-out, as the runner now drives it.

    Both properties matter: no line is torn, so every one parses; and the file
    and the caller's own sink agree on the order, so a TUI replaying the log
    cannot disagree with the TUI that watched the run live.
    """
    target = tmp_path / "events.jsonl"
    mirror: list[AnalysisEvent] = []
    writers, per_writer = 2, 400
    with JsonlEventSink(target) as log:
        sink = fan_out(log, mirror.append)

        def emit(worker: int) -> None:
            for index in range(per_writer):
                sink(AnalysisEvent(
                    "unit", "heartbeat", f"worker {worker} event {index} " + "y" * 800,
                    tool=f"worker-{worker}", unit=f"u{index}",
                ))

        threads = [threading.Thread(target=emit, args=(worker,)) for worker in range(writers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    text = target.read_text(encoding="utf-8")
    assert text.endswith("\n")
    records = [json.loads(line) for line in text.splitlines()]
    assert len(records) == writers * per_writer == len(mirror)
    assert [item["message"] for item in records] == [event.message for event in mirror]
    for worker in range(writers):
        own = [item["message"] for item in records if item["tool"] == f"worker-{worker}"]
        assert own == [
            f"worker {worker} event {index} " + "y" * 800 for index in range(per_writer)
        ]

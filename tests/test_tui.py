from __future__ import annotations

import asyncio
import copy
from pathlib import Path

import pytest

from code_analyzer.analysis import (
    AnalysisEvent,
    AnalysisRequest,
    CancellationToken,
    run_analysis,
)
from code_analyzer.cli import main
from code_analyzer.config import (
    DEFAULTS,
    FIELD_REGISTRY,
    effective_toml,
    load_config,
    load_config_with_sources,
    save_config_snapshot,
)
from code_analyzer.progress import BRAILLE_FRAMES
from code_analyzer.tui import AnalyzerApp, TuiOutcome


def test_config_sources_and_atomic_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "源 代码"
    source.mkdir()
    (source / ".code-analyzer.toml").write_text(
        'config_schema_version=2\n[run]\noutput_root="项目 报告"\n[source]\nexclude=["生成/**"]\n',
        encoding="utf-8",
    )
    explicit = tmp_path / "显式 config.toml"
    explicit.write_text('config_schema_version=2\n[review]\nfail_on="high"\n', encoding="utf-8")
    loaded = load_config_with_sources(source, explicit, {"review": {"enabled": False}})
    assert loaded.sources["run.output_root"] == str((source / ".code-analyzer.toml").resolve())
    assert loaded.sources["review.fail_on"] == str(explicit.resolve())
    assert loaded.sources["review.enabled"] == "session"
    assert loaded.sources["tools.cppcheck.enabled"] == "default"

    destination = source / "配置 快照.toml"
    save_config_snapshot(source, loaded.config, destination)
    text = destination.read_text(encoding="utf-8")
    assert "compile_database =" not in text  # None is omitted, never serialized as an empty string.
    assert 'output_root = "项目 报告"' in text
    reloaded = load_config(source, destination)
    assert reloaded["run"]["output_root"] == loaded.config["run"]["output_root"]
    assert reloaded["review"]["enabled"] is False
    with pytest.raises(Exception, match="already exists"):
        save_config_snapshot(source, loaded.config, destination)


def test_registry_covers_every_schema_leaf() -> None:
    def leaves(value: object, prefix: str = "") -> set[str]:
        result: set[str] = set()
        assert isinstance(value, dict)
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(child, dict):
                result |= leaves(child, path)
            elif path != "config_schema_version":
                result.add(path)
        return result

    assert {field.path for field in FIELD_REGISTRY} == leaves(DEFAULTS)


def test_effective_toml_omits_optional_none() -> None:
    text = effective_toml(copy.deepcopy(DEFAULTS))
    assert "compile_database =" not in text
    assert "c_standard =" not in text


def test_headless_tui_has_single_basic_form_and_preserves_hidden_config(tmp_path: Path) -> None:
    async def exercise() -> None:
        explicit = tmp_path / "advanced.toml"
        explicit.write_text(
            'config_schema_version=2\n[tools.cppcheck]\ntimeout_seconds=123\n[source]\nexclude=["vendor/**"]\n',
            encoding="utf-8",
        )
        app = AnalyzerApp(tmp_path, explicit)
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause()
            assert not app.small
            assert not app.has_class("wide")
            assert len(app.query("#nav")) == 0
            assert len(app.query(".page")) == 0
            assert len(app.query("#field-source-include")) == 0
            assert len(app.query("#field-tools-cppcheck-timeout-seconds")) == 0
            assert app.query_one("#field-build-compile-database-mode")
            assert app.query_one("#field-tools-cppcheck-enabled")
            assert app.query_one("#basic-actions")
            left = app.query_one("#column-left").virtual_region
            right = app.query_one("#column-right").virtual_region
            assert right.y >= left.y + left.height  # 窄终端：两栏纵向堆叠
            source, config = app._collect()
            assert source == tmp_path.resolve()
            assert config["build"]["compile_database_mode"] == "auto"
            assert config["tools"]["cppcheck"]["timeout_seconds"] == 123
            assert config["source"]["exclude"] == ["vendor/**"]
        minimum = AnalyzerApp(tmp_path)
        async with minimum.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            assert not minimum.small
            assert not minimum.has_class("wide")
            run_button = minimum.query_one("#run").region
            assert run_button.height > 0 and run_button.y < 24  # 操作按钮免滚动可见
        wide = AnalyzerApp(tmp_path)
        async with wide.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert not wide.small
            assert wide.has_class("wide")
            left = wide.query_one("#column-left").region
            right = wide.query_one("#column-right").region
            assert right.x >= left.x + left.width  # 宽终端：两栏并排
        small = AnalyzerApp(tmp_path)
        async with small.run_test(size=(79, 23)) as pilot:
            await pilot.pause()
            assert small.small and small.has_class("too-small")

    asyncio.run(exercise())


def _running(app: AnalyzerApp) -> None:
    """Put the app into the running state the way a confirmed run does."""
    app.running = True
    app._reset_run_display()
    app.add_class("running")


def _panel(app: AnalyzerApp) -> str:
    """What the flow panel is handed, as plain text.

    The assertion boundary is the Text this app builds, not Textual's private
    render state: markup in a scanned path must survive as characters, which
    is a property of building the Text segment by segment.
    """
    frame = app._flow_frame if app._flow_animated else -1
    return app._flow_text(app.flow.rows(capacity=app._flow_capacity, now=0.0, frame=frame)).plain


def _feed(app: AnalyzerApp, *events: AnalysisEvent) -> None:
    for event in events:
        app._analysis_event(event)
    app._repaint_flow()


def test_the_flow_panel_and_the_log_share_the_minimum_terminal(tmp_path: Path) -> None:
    """80x24 is the floor, and both halves have to survive it."""

    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            _running(app)
            await pilot.pause()
            _feed(
                app,
                AnalysisEvent("discovery", "finished", "inventory ready: 8 files", progress=0.1),
                AnalysisEvent("tool", "started", "cppcheck starting", tool="cppcheck"),
            )
            await pilot.pause()
            flow = app.query_one("#run-flow")
            log = app.query_one("#run-log")
            assert flow.display and log.display
            assert flow.region.y + flow.region.height <= 24
            assert log.region.height > 0
            assert log.region.y >= flow.region.y + flow.region.height  # 窄终端：上下堆叠
            assert app._flow_capacity == 7

    asyncio.run(exercise())


def test_a_wide_terminal_puts_the_flow_beside_the_log(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        async with app.run_test(size=(140, 40)) as pilot:
            _running(app)
            await pilot.pause()
            flow = app.query_one("#run-flow").region
            log = app.query_one("#run-log").region
            assert log.x >= flow.x + flow.width  # 宽终端：左右并排
            assert app._flow_capacity == 16

    asyncio.run(exercise())


def test_f2_gives_the_log_its_rows_back(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            _running(app)
            await pilot.pause()
            before = app.query_one("#run-log").region.height
            await pilot.press("f2")
            await pilot.pause()
            assert not app.query_one("#run-flow").display
            assert app.query_one("#run-log").region.height > before

    asyncio.run(exercise())


def test_the_animation_honours_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The switch the CLI has always honoured and the TUI used to ignore.

    Frozen is not blank: the panel still repaints on every event, it just
    stops moving between them.
    """
    monkeypatch.setenv("CODE_ANALYZER_NO_ANIMATION", "1")

    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            assert app._flow_animated is False
            _running(app)
            await pilot.pause()
            first = _panel(app)
            assert "○" in first
            assert not set(first) & set(BRAILLE_FRAMES)
            _feed(app, AnalysisEvent("tool", "started", "cppcheck starting", tool="cppcheck"))
            await pilot.pause()
            second = _panel(app)
            assert second != first and "●" in second
            # Ticking must not animate it either: only events may change it.
            app._tick_flow()
            assert _panel(app) == second

    asyncio.run(exercise())


def test_an_untrusted_path_reaches_the_panel_as_text(tmp_path: Path) -> None:
    """Rich markup in a scanned file name must render, not style."""

    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        async with app.run_test(size=(140, 40)) as pilot:
            _running(app)
            await pilot.pause()
            _feed(app, AnalysisEvent(
                "unit", "started", "scanning [bold red]evil[/].c (high)",
                tool="cppcheck", unit="[bold red]evil[/].c",
            ))
            await pilot.pause()
            plain = _panel(app)
            assert "[bold red]evil[/].c" in plain
            assert "\x1b" not in plain

    asyncio.run(exercise())


def test_cli_tui_routing_and_non_tty(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    monkeypatch.setattr("code_analyzer.cli._has_tty", lambda: False)
    assert main([]) == 2
    assert "hint:" in capsys.readouterr().err
    assert main(["tui", str(tmp_path)]) == 2
    assert "requires an interactive terminal" in capsys.readouterr().err

    monkeypatch.setattr("code_analyzer.cli._has_tty", lambda: True)
    monkeypatch.setattr("code_analyzer.tui.run_tui", lambda source, config=None: TuiOutcome(10, tmp_path / "report"))
    assert main(["tui", str(tmp_path)]) == 10
    assert capsys.readouterr().out.strip() == str(tmp_path / "report")
    assert main([]) == 10
    assert capsys.readouterr().out.strip() == str(tmp_path / "report")


def test_pre_cancelled_headless_request_has_no_report(tmp_path: Path) -> None:
    token = CancellationToken()
    token.cancel()
    config = load_config(tmp_path, None, {"run": {"output_root": str(tmp_path / "reports")}})
    events = []
    result = run_analysis(AnalysisRequest(tmp_path, config), events=events.append, cancellation=token)
    assert result.exit_code == 130 and result.report_directory is None and result.manifest is None
    assert [event.status for event in events] == ["started", "interrupted"]


# --- the operator's hand (milestone 4) --------------------------------------------


def test_run_keys_pause_skip_and_jobs_reach_the_control(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            _running(app)
            await pilot.pause()
            assert app.control is not None and not app.control.paused("llm")
            await pilot.press("p")
            await pilot.pause()
            assert app.control.paused("llm")
            await pilot.press("p")
            await pilot.pause()
            assert not app.control.paused("llm")
            jobs = app.control.jobs("llm")
            await pilot.press("plus")
            await pilot.pause()
            assert app.control.jobs("llm") == jobs + 1
            await pilot.press("minus")
            await pilot.pause()
            assert app.control.jobs("llm") == jobs
            # The cursor walks the producers and the marker follows it.
            before = app._selected_node()
            await pilot.press("down")
            await pilot.pause()
            selected = app._selected_node()
            assert selected in app.flow.producer_ids() and selected != before
            marked = app._flow_text(app.flow.rows(capacity=20, now=0.0, frame=-1, selected=selected)).plain
            assert "▶" in marked and marked.count("▶") == 1
            _feed(app, AnalysisEvent("tool", "started", "cppcheck starting", tool="cppcheck"))
            app._cursor = "flawfinder"
            await pilot.press("s")
            await pilot.pause()
            await pilot.click("#yes")  # confirm the skip dialog
            await pilot.pause()
            assert app.control.skipped("flawfinder")
            _feed(app, AnalysisEvent("control", "skipped", "flawfinder skipped by operator", data={"name": "flawfinder"}))
            assert "已跳过" in _panel(app)

    asyncio.run(exercise())


def test_f3_cycles_one_side_pane_at_a_time_and_f4_filters_the_log(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            _running(app)
            await pilot.pause()
            log, problems, llm = app.query_one("#run-log"), app.query_one("#run-problems"), app.query_one("#run-llm")
            assert log.display and not problems.display and not llm.display
            await pilot.press("f3")
            await pilot.pause()
            # The LLM lane is off in this config, so the next pane is 问题.
            assert problems.display and not log.display and app.query_one("#run-flow").display
            assert problems.region.y + problems.region.height <= 24
            await pilot.press("f3")
            await pilot.pause()
            assert log.display and not problems.display
            await pilot.press("f4")
            await pilot.pause()
            assert app._log_filter == "warn"
            app._queue_log_event(AnalysisEvent("tool", "started", "cppcheck starting", tool="cppcheck"))
            app._queue_log_event(AnalysisEvent("unit", "partial", "partial in 0.02s", tool="splint", unit="u1"))
            assert len(app._pending_log_lines) == 1 and "partial" in app._pending_log_lines[0]

    asyncio.run(exercise())


def test_events_queue_on_the_worker_and_fold_on_the_tick(tmp_path: Path) -> None:
    """No call_from_thread per event: the worker queues, the 5 Hz tick folds."""

    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        async with app.run_test(size=(100, 30)) as pilot:
            _running(app)
            await pilot.pause()
            for _index in range(3000):
                app._event_from_worker(AnalysisEvent(
                    "unit", "heartbeat", "heartbeat; elapsed 1.0s", tool="cppcheck", unit="fallback",
                    data={"index": 1, "total": 1},
                ))
            app._event_from_worker(AnalysisEvent("tool", "started", "cppcheck starting", tool="cppcheck"))
            app._event_from_worker(AnalysisEvent(
                "unit", "started", "scanning 8 files", tool="cppcheck", unit="fallback", data={"index": 1, "total": 4, "label": "fallback"},
            ))
            assert app.flow.nodes["cppcheck"].state == "pending", "nothing folds until the tick"
            app._tick_flow()
            assert app.flow.nodes["cppcheck"].state == "running" and app.flow.nodes["cppcheck"].total == 4
            assert not app._pending_events and not app._liveness_events
            # A control event raised on the app thread takes the same path.
            app.control.pause("llm", "tui")
            app._event_from_worker(AnalysisEvent("control", "paused", "llm lane paused", data={"lane": "llm"}))
            app._tick_flow()
            assert app.flow.paused["llm"]

    asyncio.run(exercise())

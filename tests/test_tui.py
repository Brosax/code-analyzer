from __future__ import annotations

import asyncio
import copy
import threading
from pathlib import Path

import pytest
from rich.cells import cell_len

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


def test_a_pending_patch_opens_the_dialog_and_the_choice_reaches_the_runner(tmp_path: Path) -> None:
    from code_analyzer.control import DecisionRequest
    from code_analyzer.tui import PatchScreen

    request = DecisionRequest(
        id="bc1", kind="build_context_patch", summary="splint: round 1: 2 item(s); probe 2/2 now preprocess",
        items=(
            {"op": "add_include", "value": "include", "label": "-I include", "evidence": "satisfies 3 unit(s): hal.h", "origin": "deterministic", "preselected": True},
            {"op": "add_stub_header", "value": "vendor.h", "label": "stub vendor.h", "evidence": "1 unit(s); the tree carries no vendor.h", "origin": "deterministic", "preselected": False},
        ),
        round=1, probe={"sampled": 2, "reached_before": 0, "reached_after": 2}, evidence_path="inputs/build-context/r1", preselected=(0,),
    )

    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            _running(app)
            await pilot.pause()
            answers: list = []
            threading.Thread(target=lambda: answers.append(app.control.request_decision(request, timeout=15)), daemon=True).start()
            for _ in range(30):
                await pilot.pause(0.1)
                if isinstance(app.screen, PatchScreen):
                    break
            assert isinstance(app.screen, PatchScreen), "the runner's request did not open the dialog"
            items = app.screen.query_one("#patch-items")
            assert list(items.selected) == [0]
            # Defer: the dialog closes, the runner keeps waiting, `d` brings it back.
            await pilot.press("l")
            await pilot.pause(0.3)
            assert not isinstance(app.screen, PatchScreen) and not answers
            await pilot.press("d")
            await pilot.pause(0.3)
            assert isinstance(app.screen, PatchScreen)
            await pilot.click("#apply")
            for _ in range(30):
                await pilot.pause(0.1)
                if answers:
                    break
            assert answers and answers[0].answer == "apply" and answers[0].selected == (0,) and answers[0].decided_by == "tui"
            assert not app.control.pending()

    asyncio.run(exercise())


def test_r_opens_the_retry_dialog_while_the_llm_lane_runs_and_asks_the_control(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        app.config["llm"]["enabled"] = True
        app.config["llm"]["scanners"] = ["llm-security"]
        async with app.run_test(size=(120, 40)) as pilot:
            _running(app)
            await pilot.pause()
            _feed(app, AnalysisEvent("llm", "started", "llm starting"))
            _feed(app, AnalysisEvent("unit", "started", "scanning", tool="llm-security", unit="a.c:f", data={"index": 1, "total": 3, "path": "a.c"}))
            _feed(app, AnalysisEvent("unit", "failed", "failed; provider TRANSPORT", tool="llm-security", unit="a.c:f", data={"index": 1, "total": 3, "failure_class": "transport"}))
            _feed(app, AnalysisEvent("unit", "started", "scanning", tool="llm-security", unit="b.c:g", data={"index": 2, "total": 3, "path": "b.c"}))
            _feed(app, AnalysisEvent("unit", "failed", "failed; scanner produced no parsable report", tool="llm-security", unit="b.c:g", data={"index": 2, "total": 3, "failure_class": "parse"}))
            assert app.flow is not None and app.flow.retryable_units(transport_only=True) == ["a.c:f"]
            await pilot.press("r")
            await pilot.pause()
            await pilot.click("#retry")
            await pilot.pause()
            assert app.control is not None and app.control.drain_retries("llm") == ["a.c:f"]
            # Untick the filter: every unit that never got an answer.
            await pilot.press("r")
            await pilot.pause()
            await pilot.click("#transport-only")
            await pilot.click("#retry")
            await pilot.pause()
            assert app.control.drain_retries("llm") is None

    asyncio.run(exercise())


def _llm_app(tmp_path: Path) -> AnalyzerApp:
    app = AnalyzerApp(tmp_path)
    app.config["llm"]["enabled"] = True
    app.config["llm"]["scanners"] = ["llm-security"]
    return app


def test_a_run_with_a_model_opens_on_the_conversation_and_a_static_run_does_not(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _llm_app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            _running(app)
            await pilot.pause()
            assert app._pane == "chat" and app.query_one("#run-chat").display
            assert not app.query_one("#run-log").display
            # F3 walks every pane and comes back; 对话 is one of them.
            seen = [app._pane]
            for _step in range(len(app._pane_order())):
                await pilot.press("f3")
                await pilot.pause()
                seen.append(app._pane)
            assert seen == ["chat", "log", "llm", "problems", "chat"]

        static = AnalyzerApp(tmp_path)
        async with static.run_test(size=(120, 40)) as pilot:
            _running(static)
            await pilot.pause()
            # Nothing answers in a static-only run, so the log opens as before.
            assert static._pane == "log" and static.query_one("#run-log").display
            assert static._pane_order() == ["log", "problems"]

    asyncio.run(exercise())


def test_the_answer_streams_into_the_conversation_pane_and_the_prompt_waits_for_f6(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _llm_app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            _running(app)
            await pilot.pause()
            _feed(app, AnalysisEvent("llm", "started", "llm starting", data={"model": "qwen3.8:27b"}))
            _feed(app, AnalysisEvent(
                "unit", "started", "scanning (high)", tool="llm-security", unit="a.c:f",
                data={"index": 1, "total": 3, "path": "a.c", "tier": "high"},
            ))
            _feed(app, AnalysisEvent(
                "output", "running", "# Scan unit\n\nfile: a.c", tool="llm-security", unit="a.c:f",
                stream="prompt", data={"chars": 8000},
            ))
            _feed(app, AnalysisEvent(
                "output", "running", '{"findings": []}', tool="llm-security", unit="a.c:f", stream="answer",
            ))
            await pilot.pause()
            panel = app.query_one("#run-chat")
            assert '{"findings": []}' in panel.render().plain
            assert "file: a.c" not in panel.render().plain
            assert "显示提示词" in str(panel.border_title)
            # A prompt preview is thousands of characters of source: the log
            # pane must not repeat it one row at a time.
            assert not any("Scan unit" in line for line in app._pending_log_lines)

            await pilot.press("f6")
            await pilot.pause()
            assert app._show_prompts and "file: a.c" in app.query_one("#run-chat").render().plain
            assert "隐藏提示词" in str(app.query_one("#run-chat").border_title)

    asyncio.run(exercise())


def test_a_long_answer_is_wrapped_to_the_pane_and_the_tail_still_fits(tmp_path: Path) -> None:
    """An answer is one JSON document on one line; the pane has to break it."""

    async def exercise() -> None:
        app = _llm_app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            _running(app)
            await pilot.pause()
            _feed(app, AnalysisEvent(
                "unit", "started", "scanning", tool="llm-security", unit="a.c:f",
                data={"index": 1, "total": 1, "path": "a.c"},
            ))
            _feed(app, AnalysisEvent(
                "output", "running", '{"findings": [' + "x" * 4000 + "]}", tool="llm-security",
                unit="a.c:f", stream="answer",
            ))
            await pilot.pause()
            panel = app.query_one("#run-chat")
            rendered = panel.render().plain.splitlines()
            # Every row fits the pane, and there are no more rows than rows.
            assert len(rendered) <= max(3, panel.size.height)
            assert all(cell_len(row) <= panel.size.width for row in rendered)
            # The tail is what is kept: the end of the answer, not its start.
            assert rendered[-1].endswith("]}") or "tok" in rendered[-1]
            assert "x" * 40 in panel.render().plain

    asyncio.run(exercise())


def test_the_lane_bars_and_the_speed_strip_report_what_was_measured(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = _llm_app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            _running(app)
            await pilot.pause()
            _feed(app, AnalysisEvent("llm", "started", "llm starting", data={"model": "qwen3.8:27b"}))
            _feed(app, AnalysisEvent("llm", "planned", "planned", data={"units": 4, "tasks": 4, "scanners": 1}))
            _feed(app, AnalysisEvent(
                "tool", "completed", "cppcheck finished with status completed", tool="cppcheck", progress=0.3,
            ))
            _feed(app, AnalysisEvent(
                "unit", "completed", "completed; 1 finding(s)", tool="llm-security", unit="a.c:f", progress=0.4,
                data={"index": 1, "total": 4, "path": "a.c", "finding_count": 1, "duration_seconds": 2.0,
                      "usage": {"prompt_tokens": 3000, "completion_tokens": 300, "requests": 1}},
            ))
            _feed(app, AnalysisEvent("unit", "heartbeat", "heartbeat", tool="llm-security", unit="b.c:g", data={
                "measured": {"prompt_tokens": 3000, "completion_tokens": 300, "requests": 1},
                "tok_s": 88.0, "eta_seconds": 90.0, "in_flight": 2,
            }))
            await pilot.pause()
            bars = app.query_one("#run-bars").render().plain
            # One bar per lane the overall percentage is a weighted sum of.
            assert "静态分析" in bars and "1/3 工具" in bars
            # The label column is padded by display width, so a CJK label and
            # an ASCII one start their bars in the same terminal column --
            # which is a count of cells, not of characters.
            starts = {cell_len(line[: min(line.index("█") if "█" in line else 999, line.index("░"))])
                      for line in bars.splitlines()}
            assert starts == {12}
            assert "LLM 扫描" in bars and "1/4 单元" in bars
            assert "█" in bars and "░" in bars
            speed = app.query_one("#run-speed").render().plain
            assert "88.0 tok/s（会话均值）" in speed and "输出 300 tok（测量）" in speed
            assert "在途 2" in speed and "ETA 01:30" in speed
            # 300 output tokens over a 2.0s session: the peak is a measurement.
            assert speed.startswith("⚡ qwen3.8:27b") and "峰值 150.0" in speed
            assert speed.count("⚡") == 1

    asyncio.run(exercise())


def test_answer_chunks_queue_as_liveness_and_never_displace_a_state_event(tmp_path: Path) -> None:
    """An overloaded display drops answer text, not the counters."""

    async def exercise() -> None:
        app = _llm_app(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            _running(app)
            await pilot.pause()
            for _index in range(6000):
                app._event_from_worker(AnalysisEvent(
                    "output", "running", "chunk", tool="llm-security", unit="a.c:f", stream="answer",
                ))
            app._event_from_worker(AnalysisEvent(
                "unit", "completed", "completed", tool="llm-security", unit="a.c:f",
                data={"index": 1, "total": 1, "finding_count": 3},
            ))
            assert len(app._liveness_events) == 5000 and len(app._pending_events) == 1
            app._tick_flow()
            await pilot.pause()
            assert app.chat is not None and app.chat.turns()[0].findings == 3

    asyncio.run(exercise())

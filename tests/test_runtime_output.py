from __future__ import annotations

import asyncio
import json
import stat
import sys
import textwrap
import time
from pathlib import Path

from textual.widgets import RichLog

from code_analyzer.analysis import AnalysisEvent, AnalysisRequest, run_analysis
from code_analyzer.config import load_config
from code_analyzer.process import MAX_LIVE_LINE_CHARS, run_process
from code_analyzer.tools import cppcheck, flawfinder, splint
from code_analyzer.tui import AnalyzerApp


def _executable(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_process_forwards_incremental_lines_without_changing_raw_evidence(tmp_path: Path) -> None:
    script = tmp_path / "streams.py"
    script.write_text(textwrap.dedent("""\
        import os, time
        os.write(1, b'first\\r\\ncaf\\xc3')
        time.sleep(0.15)
        os.write(1, b'\\xa9\\nbad:\\xff')
        os.write(2, b'err')
        time.sleep(0.15)
        os.write(2, b'or\\nlast')
    """), encoding="utf-8")
    stdout = tmp_path / "stdout.raw"
    stderr = tmp_path / "stderr.raw"
    seen: list[tuple[str, str]] = []

    result = run_process(
        [sys.executable, str(script)], tmp_path, stdout, stderr, 5, 0.1, output=lambda stream, line: seen.append((stream, line))
    )

    assert result.exit_code == 0
    assert stdout.read_bytes() == b"first\r\ncaf\xc3\xa9\nbad:\xff"
    assert stderr.read_bytes() == b"error\nlast"
    assert [line for line in seen if line[0] == "stdout"] == [
        ("stdout", "first"), ("stdout", "caf\N{LATIN SMALL LETTER E WITH ACUTE}"), ("stdout", "bad:\ufffd"),
    ]
    assert [line for line in seen if line[0] == "stderr"] == [("stderr", "error"), ("stderr", "last")]


def test_process_ignores_output_callback_failures(tmp_path: Path) -> None:
    def broken(_stream: str, _line: str) -> None:
        raise RuntimeError("display is gone")

    result = run_process(
        [sys.executable, "-c", "import sys; print('kept'); print('also kept', file=sys.stderr)"],
        tmp_path,
        tmp_path / "stdout.raw",
        tmp_path / "stderr.raw",
        5,
        0.1,
        output=broken,
    )

    assert result.exit_code == 0
    assert (tmp_path / "stdout.raw").read_bytes() == b"kept\n"
    assert (tmp_path / "stderr.raw").read_bytes() == b"also kept\n"


def test_process_flushes_unterminated_live_lines_on_timeout_and_cancel(tmp_path: Path) -> None:
    script = tmp_path / "wait.py"
    script.write_text("import os, time; os.write(2, b'unterminated'); time.sleep(30)\n", encoding="utf-8")

    timed_lines: list[tuple[str, str]] = []
    timed = run_process(
        [sys.executable, str(script)], tmp_path, tmp_path / "timed.out", tmp_path / "timed.err", 0.2, 0.05,
        output=lambda stream, line: timed_lines.append((stream, line)),
    )
    assert timed.timed_out
    assert timed_lines == [("stderr", "unterminated")]
    assert (tmp_path / "timed.err").read_bytes() == b"unterminated"

    cancel_started = time.monotonic()
    cancelled_lines: list[tuple[str, str]] = []
    cancelled = run_process(
        [sys.executable, str(script)], tmp_path, tmp_path / "cancelled.out", tmp_path / "cancelled.err", 5, 0.05,
        cancelled=lambda: time.monotonic() - cancel_started >= 0.2,
        output=lambda stream, line: cancelled_lines.append((stream, line)),
    )
    assert cancelled.interrupted
    assert cancelled_lines == [("stderr", "unterminated")]
    assert (tmp_path / "cancelled.err").read_bytes() == b"unterminated"


def test_adapters_apply_fixed_live_output_filters(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    config = load_config(source, None, {
        "run": {"shareable_export": False},
        "build": {"compile_database_mode": "disabled"},
        "tools": {"splint": {"scope": "inventory"}},
    })
    inventory = [{"path": "main.c", "is_header": False}]

    cpp = _executable(tmp_path / "cppcheck", """
        import pathlib, sys
        report = pathlib.Path(next(value.split('=', 1)[1] for value in sys.argv if value.startswith('--output-file=')))
        report.write_text('<results><errors/></results>')
        print('cpp out')
        print('cpp err', file=sys.stderr)
    """)
    cpp_run = tmp_path / "cpp-run"
    (cpp_run / "inputs").mkdir(parents=True)
    cpp_output: list[tuple[str, str, str]] = []
    cppcheck.run(
        str(cpp), source, cpp_run, inventory, [], set(), config,
        output_event=lambda unit, stream, line: cpp_output.append((unit, stream, line)),
    )
    assert {(stream, line) for _, stream, line in cpp_output} == {("stdout", "cpp out"), ("stderr", "cpp err")}

    flaw = _executable(tmp_path / "flawfinder", """
        import json, sys
        print(json.dumps({'version': '2.1.0', 'runs': []}))
        print('flaw diagnostic', file=sys.stderr)
    """)
    flaw_run = tmp_path / "flaw-run"
    (flaw_run / "inputs").mkdir(parents=True)
    flaw_output: list[tuple[str, str, str]] = []
    flaw_events: list[tuple[str, str]] = []
    flawfinder.run(
        str(flaw), source, flaw_run, inventory, config,
        unit_event=lambda _unit, status, message, _value: flaw_events.append((status, message)),
        output_event=lambda unit, stream, line: flaw_output.append((unit, stream, line)),
    )
    assert [(stream, line) for _, stream, line in flaw_output] == [("stderr", "flaw diagnostic")]
    assert any("report.sarif" in message for _, message in flaw_events)
    assert json.loads((flaw_run / "tools/flawfinder/shard-0001/report.sarif").read_text())["version"] == "2.1.0"

    spl = _executable(tmp_path / "splint", """
        import pathlib, sys
        report = pathlib.Path(sys.argv[sys.argv.index('+csv') + 1])
        report.write_text('file,line,message\\nmain.c,1,warning\\n')
        print('splint out')
        print('Finished checking', file=sys.stderr)
    """)
    spl_run = tmp_path / "splint-run"
    (spl_run / "inputs").mkdir(parents=True)
    splint_output: list[tuple[str, str, str]] = []
    splint.run(
        str(spl), source, spl_run, inventory, [], config,
        output_event=lambda unit, stream, line: splint_output.append((unit, stream, line)),
    )
    assert {(stream, line) for _, stream, line in splint_output} == {
        ("stdout", "splint out"), ("stderr", "Finished checking"),
    }


def test_headless_service_emits_output_metadata_without_using_logs_as_status(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    fake = _executable(tmp_path / "cppcheck", """
        import pathlib, sys
        if '--version' in sys.argv:
            print('Cppcheck test'); raise SystemExit()
        if '--help' in sys.argv:
            print('usage --xml-version --output-file --project --file-list --check-level --check-library --checkers-report --cppcheck-build-dir')
            raise SystemExit()
        report = pathlib.Path(next(value.split('=', 1)[1] for value in sys.argv if value.startswith('--output-file=')))
        report.write_text('<results><errors/></results>')
        print('failed is only analyzer text')
        print('readable diagnostic', file=sys.stderr)
    """)
    config = load_config(source, None, {
        "run": {"output_root": str(tmp_path / "reports"), "shareable_export": False},
        "review": {"enabled": False},
        "build": {"compile_database_mode": "disabled"},
        "tools": {
            "cppcheck": {"enabled": True, "executable": str(fake)},
            "flawfinder": {"enabled": False},
            "splint": {"enabled": False},
        },
    })
    events: list[AnalysisEvent] = []

    result = run_analysis(AnalysisRequest(source, config), events=events.append)

    assert result.exit_code == 0
    output = [event for event in events if event.phase == "output"]
    assert {(event.tool, event.unit, event.stream, event.message) for event in output} == {
        ("cppcheck", "fallback", "stdout", "failed is only analyzer text"),
        ("cppcheck", "fallback", "stderr", "readable diagnostic"),
    }
    assert next(event for event in events if event.phase == "tool" and event.status == "completed").message.startswith("cppcheck finished")
    progress_values = [event.progress for event in events if event.progress is not None]
    assert progress_values == sorted(progress_values)


def test_running_page_batches_and_bounds_log_lines(tmp_path: Path) -> None:
    async def exercise() -> None:
        app = AnalyzerApp(tmp_path)
        async with app.run_test(size=(120, 40)) as pilot:
            app.running = True
            app._reset_run_display()
            app.add_class("running")
            await pilot.pause()
            assert app.query_one("#running").display
            assert not app.query_one("#workspace").display
            log = app.query_one("#run-log", RichLog)
            assert log.max_lines == 2000 and log.auto_scroll and log.wrap

            for index in range(2100):
                app._queue_log_event(AnalysisEvent(
                    "output", "running", f"line {index}", tool="cppcheck", unit="fallback", stream="stderr"
                ))
            assert len(app._pending_log_lines) == 2000
            assert sum("界面日志过载" in line for line in app._pending_log_lines) == 1

            before = len(app._pending_log_lines)
            app._flush_log_queue()
            assert before - len(app._pending_log_lines) == 200

            app._reset_run_display()
            assert not app._pending_log_lines
            assert not log.lines

    asyncio.run(exercise())


def test_a_runaway_tool_is_capped_without_being_blocked(tmp_path: Path) -> None:
    """The ceiling bounds the disk, never the child.

    The project refuses Docker (README:9) and cannot use ``preexec_fn`` under
    the adapters' thread pools, so this cap is the whole resource limit.  It
    has to keep draining the pipe after it stops storing: a pipe left unread
    blocks the writer, which would turn a limit on disk use into a hang.
    """
    script = tmp_path / "runaway.py"
    script.write_text(textwrap.dedent("""\
        import os, sys
        payload = b'x' * 4096
        for _ in range(256):          # 1 MiB, far past the ceiling below
            os.write(1, payload)
        os.write(2, b'e' * 5000)
        sys.exit(3)
    """), encoding="utf-8")
    stdout, stderr = tmp_path / "stdout.raw", tmp_path / "stderr.raw"

    result = run_process(
        [sys.executable, str(script)], tmp_path, stdout, stderr,
        timeout=30.0, grace=1.0, max_output_bytes=4096,
    )

    # The child ran to completion and was reaped: capped, not killed.
    assert result.exit_code == 3 and result.timed_out is False and result.interrupted is False
    assert stdout.stat().st_size == 4096 and stderr.stat().st_size == 4096
    assert result.truncated_bytes["stdout"] == 1024 * 1024 - 4096
    assert result.truncated_bytes["stderr"] == 5000 - 4096
    # Truncation is evidence: it travels in the unit record like any other
    # process fact, so a report that fails to parse can be explained.
    assert result.as_dict()["truncated_bytes"] == result.truncated_bytes


def test_output_below_the_ceiling_is_stored_whole_and_reports_no_truncation(tmp_path: Path) -> None:
    script = tmp_path / "small.py"
    script.write_text("import os\nos.write(1, b'ok\\n')\n", encoding="utf-8")
    stdout, stderr = tmp_path / "stdout.raw", tmp_path / "stderr.raw"

    result = run_process([sys.executable, str(script)], tmp_path, stdout, stderr, timeout=30.0, grace=1.0)

    assert stdout.read_bytes() == b"ok\n"
    assert result.truncated_bytes == {"stdout": 0, "stderr": 0}


def test_a_stream_without_line_breaks_does_not_stall_the_reader(tmp_path: Path) -> None:
    """Live forwarding must stay linear, or it invents a timeout.

    The forwarder used to re-scan its whole pending buffer on every 64 KiB
    read, so a tool that wrote megabytes without a newline made the reader
    quadratic: reads stopped, the child blocked on a full pipe, and the run
    recorded a timeout the tool never caused — losing its native report.
    """
    script = tmp_path / "flood.py"
    script.write_text("import os\nos.write(1, b'x' * (8 * 1024 * 1024))\n", encoding="utf-8")
    stdout, stderr = tmp_path / "stdout.raw", tmp_path / "stderr.raw"
    forwarded: list[int] = []

    started = time.monotonic()
    result = run_process(
        [sys.executable, str(script)], tmp_path, stdout, stderr, timeout=30.0, grace=1.0,
        output=lambda _stream, line: forwarded.append(len(line)),
    )
    elapsed = time.monotonic() - started

    assert result.exit_code == 0 and result.timed_out is False
    # The evidence on disk is whole whatever the display did with it.
    assert stdout.stat().st_size == 8 * 1024 * 1024
    # Generous: the old implementation took ~25s for this input, the new one
    # ~0.1s.  The assertion is about the complexity class, not the machine.
    assert elapsed < 5.0, f"forwarding 8 MiB took {elapsed:.1f}s"
    # Forwarded in bounded pieces rather than one unbounded line.
    assert forwarded and max(forwarded) <= MAX_LIVE_LINE_CHARS


def test_a_bounded_line_still_reaches_the_display_whole(tmp_path: Path) -> None:
    script = tmp_path / "lines.py"
    script.write_text("import os\nos.write(1, b'alpha\\r\\nbeta\\rgamma\\n')\n", encoding="utf-8")
    seen: list[str] = []

    run_process(
        [sys.executable, str(script)], tmp_path, tmp_path / "o.raw", tmp_path / "e.raw",
        timeout=30.0, grace=1.0, output=lambda _stream, line: seen.append(line),
    )

    assert seen == ["alpha", "beta", "gamma"]

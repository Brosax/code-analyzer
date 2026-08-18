from __future__ import annotations

import io
import threading
import time

from code_analyzer.progress import ProgressDisplay, single_line


class TtyBuffer(io.StringIO):
    def isatty(self) -> bool:
        return True


class AsciiTtyBuffer(TtyBuffer):
    @property
    def encoding(self) -> str:
        return "ascii"


def test_spinner_animates_on_tty_and_keeps_durable_messages(monkeypatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_ANIMATION", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    stream = TtyBuffer()

    with ProgressDisplay(stream, interval_seconds=0.02) as display:
        display.emit("tool 1/1 cppcheck: scanning 3 files")
        time.sleep(0.07)

    output = stream.getvalue()
    assert "[code-analyzer] tool 1/1 cppcheck: scanning 3 files\n" in output
    assert "\r\x1b[2K[code-analyzer]" in output
    assert "active 00:00" in output
    assert "cppcheck: scanning 3 files" in output


def test_redirected_stderr_has_plain_stable_lines_only(monkeypatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_ANIMATION", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    stream = io.StringIO()

    with ProgressDisplay(stream, interval_seconds=0.02) as display:
        display.emit("scanning")
        time.sleep(0.03)

    assert stream.getvalue() == "[code-analyzer] scanning\n"


def test_animation_can_be_disabled_for_a_tty(monkeypatch) -> None:
    monkeypatch.setenv("CODE_ANALYZER_NO_ANIMATION", "1")
    monkeypatch.setenv("TERM", "xterm-256color")
    stream = TtyBuffer()

    with ProgressDisplay(stream, interval_seconds=0.02) as display:
        assert not display.enabled
        display.emit("scanning")

    assert stream.getvalue() == "[code-analyzer] scanning\n"


def test_progress_output_is_thread_safe_for_parallel_splint_units(monkeypatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_ANIMATION", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    stream = TtyBuffer()

    with ProgressDisplay(stream, interval_seconds=0.02) as display:
        threads = [
            threading.Thread(target=display.emit, args=(f"unit {index}: completed",))
            for index in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    output = stream.getvalue()
    for index in range(8):
        assert output.count(f"[code-analyzer] unit {index}: completed\n") == 1


def test_exception_stops_spinner_and_close_is_idempotent(monkeypatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_ANIMATION", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    stream = TtyBuffer()
    display = ProgressDisplay(stream, interval_seconds=0.02)
    thread = None

    try:
        with display:
            thread = display._thread
            raise RuntimeError("simulated adapter failure")
    except RuntimeError:
        pass

    assert thread is not None and not thread.is_alive()
    display.close()


def test_ascii_terminal_uses_ascii_frames_and_separators(monkeypatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_ANIMATION", raising=False)
    monkeypatch.setenv("TERM", "xterm")
    stream = AsciiTtyBuffer()

    with ProgressDisplay(stream, interval_seconds=0.02) as display:
        display.emit("scanning")
        time.sleep(0.03)

    output = stream.getvalue()
    assert any(f"[code-analyzer] {frame} active" in output for frame in "|/-\\")
    assert " · " not in output and "…" not in output


def test_untrusted_text_cannot_inject_terminal_control_sequences() -> None:
    assert single_line("unit 1/2 a\x1b[2Jb.c: scanning") == "unit 1/2 a [2Jb.c: scanning"
    assert single_line("first\r\nsecond\tthird\x00") == "first second third"
    stream = io.StringIO()
    with ProgressDisplay(stream) as display:
        display.emit("evil\x1b]0;owned\x07name.c")
    assert "\x1b" not in stream.getvalue() and "\x07" not in stream.getvalue()

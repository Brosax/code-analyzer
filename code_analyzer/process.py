from __future__ import annotations

import codecs
import os
import selectors
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Collection


OutputSink = Callable[[str, str], None]


class _LineForwarder:
    """Incrementally decode one byte stream and forward complete text lines."""

    def __init__(self, stream: str, sink: OutputSink | None) -> None:
        self.stream = stream
        self.sink = sink
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.pending = ""

    def feed(self, chunk: bytes) -> None:
        if self.sink is None:
            return
        self.pending += self.decoder.decode(chunk, final=False)
        self._drain(final=False)

    def finish(self) -> None:
        if self.sink is None:
            return
        self.pending += self.decoder.decode(b"", final=True)
        self._drain(final=True)

    def _drain(self, *, final: bool) -> None:
        start = 0
        index = 0
        length = len(self.pending)
        while index < length:
            character = self.pending[index]
            if character not in "\r\n":
                index += 1
                continue
            if character == "\r" and index + 1 == length and not final:
                break
            self._emit(self.pending[start:index])
            index += 2 if character == "\r" and index + 1 < length and self.pending[index + 1] == "\n" else 1
            start = index
        self.pending = self.pending[start:]
        if final and self.pending:
            self._emit(self.pending)
            self.pending = ""

    def _emit(self, line: str) -> None:
        try:
            assert self.sink is not None
            self.sink(self.stream, line)
        except Exception:
            # Live display is best-effort. Native evidence and process control
            # must never depend on a UI/event callback behaving correctly.
            pass


@dataclass
class ProcessResult:
    argv: list[str]
    cwd: str
    started_at: str
    duration_seconds: float
    exit_code: int | None
    signal: int | None
    timed_out: bool
    interrupted: bool
    termination: str | None

    def as_dict(self) -> dict:
        return asdict(self)


def run_process(
    argv: list[str],
    cwd: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout: float,
    grace: float,
    *,
    heartbeat: Callable[[float], None] | None = None,
    heartbeat_seconds: float = 10.0,
    cancelled: Callable[[], bool] | None = None,
    output: OutputSink | None = None,
    output_streams: Collection[str] = ("stdout", "stderr"),
) -> ProcessResult:
    """Run an argv and drain output without trusting descendants to close pipes.

    A child may fork, exit, and leave a grandchild holding stdout/stderr open.  A
    traditional pair of reader threads then blocks forever in ``read()``.  The
    selector loop below uses non-blocking descriptors and stops a bounded time
    after the direct child has been reaped.
    """
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}
    started_wall = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    started = time.monotonic()
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=True,
    )

    assert proc.stdout is not None and proc.stderr is not None
    selector = selectors.DefaultSelector()
    selected_streams = frozenset(output_streams)
    outputs = {
        proc.stdout: (
            stdout_path.open("wb"),
            _LineForwarder("stdout", output if "stdout" in selected_streams else None),
        ),
        proc.stderr: (
            stderr_path.open("wb"),
            _LineForwarder("stderr", output if "stderr" in selected_streams else None),
        ),
    }
    for pipe in outputs:
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
    timed_out = interrupted = False
    termination = None
    deadline = started + timeout
    next_heartbeat = started + max(0.1, heartbeat_seconds)
    child_exited_at: float | None = None
    try:
        while proc.poll() is None or selector.get_map():
            now = time.monotonic()
            if proc.poll() is None and cancelled is not None and cancelled():
                interrupted = True
                termination = _terminate(proc, grace)
            elif proc.poll() is None and now >= deadline:
                timed_out = True
                termination = _terminate(proc, grace)
            if proc.poll() is not None and child_exited_at is None:
                child_exited_at = time.monotonic()
            if heartbeat is not None and proc.poll() is None and now >= next_heartbeat:
                heartbeat(now - started)
                next_heartbeat = now + max(0.1, heartbeat_seconds)
            # After the direct child exits, allow already-buffered data to
            # arrive briefly, then close inherited pipes even if an escaped
            # descendant still owns them.
            if child_exited_at is not None and now - child_exited_at >= 0.5:
                if selector.get_map():
                    _signal_group(proc, signal.SIGTERM)
                    selector.select(min(0.1, max(0.0, grace)))
                    _signal_group(proc, signal.SIGKILL)
                    termination = termination or "kill"
                break
            wait_for = 0.1
            if proc.poll() is None:
                wait_for = min(wait_for, max(0.0, deadline - now))
                if heartbeat is not None:
                    wait_for = min(wait_for, max(0.0, next_heartbeat - now))
            events = selector.select(wait_for) if selector.get_map() else []
            for key, _ in events:
                pipe = key.fileobj
                try:
                    chunk = os.read(pipe.fileno(), 65536)
                except BlockingIOError:
                    continue
                if chunk:
                    destination, forwarder = outputs[pipe]
                    destination.write(chunk)
                    forwarder.feed(chunk)
                else:
                    selector.unregister(pipe)
        # One last non-blocking sweep captures bytes already in either pipe.
        for pipe in list(outputs):
            while True:
                try:
                    chunk = os.read(pipe.fileno(), 65536)
                except (BlockingIOError, OSError):
                    break
                if not chunk:
                    break
                destination, forwarder = outputs[pipe]
                destination.write(chunk)
                forwarder.feed(chunk)
    except KeyboardInterrupt:
        interrupted = True
        termination = _terminate(proc, grace)
    finally:
        if proc.poll() is None:
            termination = _terminate(proc, grace)
        else:
            proc.wait()
        selector.close()
        for pipe, (destination, forwarder) in outputs.items():
            try:
                forwarder.finish()
            finally:
                try:
                    pipe.close()
                finally:
                    destination.close()
    code = proc.returncode
    return ProcessResult(
        argv=argv,
        cwd=str(cwd.resolve()),
        started_at=started_wall,
        duration_seconds=round(time.monotonic() - started, 6),
        exit_code=code if code is not None and code >= 0 else None,
        signal=-code if code is not None and code < 0 else None,
        timed_out=timed_out,
        interrupted=interrupted,
        termination=termination,
    )


def _signal_group(proc: subprocess.Popen, sig: signal.Signals) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass


def _terminate(proc: subprocess.Popen, grace: float) -> str:
    """Terminate, kill if necessary, and always reap the direct child."""
    if proc.poll() is not None:
        proc.wait()
        return "term"
    _signal_group(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=grace)
        return "term"
    except subprocess.TimeoutExpired:
        _signal_group(proc, signal.SIGKILL)
        proc.wait()
        return "kill"

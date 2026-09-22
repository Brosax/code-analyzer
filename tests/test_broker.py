from __future__ import annotations

import threading
import time

import pytest
from fake_transport import FakeTransport, delta, sse

from code_analyzer.model.broker import BACKGROUND, INTERACTIVE, Broker, Preempted
from code_analyzer.model.client import Cancelled, CancelToken, Endpoint, ModelClient
from code_analyzer.model.egress import open_target

EP = Endpoint("http://127.0.0.1:11434/v1", "m")


@pytest.fixture(autouse=True)
def model_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CODE_ANALYZER_NO_MODEL", raising=False)


def client(transport: FakeTransport) -> ModelClient:
    return ModelClient(EP, transport=transport, egress=lambda ep: open_target(ep, resolver=lambda h, p: ("127.0.0.1",)))


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_an_interactive_request_preempts_background_work() -> None:
    broker = Broker(resume_after=0.0)
    background = client(FakeTransport(block=True))
    errors: list[BaseException] = []

    def run() -> None:
        try:
            broker.chat(background, BACKGROUND, messages=[], max_tokens=5)
        except BaseException as error:  # noqa: BLE001
            errors.append(error)

    worker = threading.Thread(target=run)
    worker.start()
    deadline = time.monotonic() + 2
    while not broker._background and time.monotonic() < deadline:  # noqa: SLF001
        time.sleep(0.01)
    reply = broker.chat(client(FakeTransport(sse(delta(content="hi")))), INTERACTIVE, messages=[], max_tokens=5)
    worker.join(2)
    assert reply.text == "hi"
    assert len(errors) == 1 and isinstance(errors[0], Preempted)
    assert broker.preemptions == 1


def test_background_waits_for_quiet_and_resumes_after_the_grace_period() -> None:
    clock = Clock()
    broker = Broker(resume_after=30.0, clock=clock)
    with broker.interactive():
        assert not broker.background_ready()
    clock.now += 29.0
    assert not broker.background_ready()
    broker.note_activity()  # typing
    clock.now += 29.0
    assert not broker.background_ready()
    clock.now += 2.0
    assert broker.background_ready()


def test_a_stopped_job_stops_waiting_for_the_gpu() -> None:
    clock = Clock()
    broker = Broker(resume_after=30.0, clock=clock)
    broker.note_activity()
    stop = CancelToken()
    threading.Timer(0.05, lambda: stop.cancel("operator stop")).start()
    with pytest.raises(Cancelled, match="operator stop"):
        with broker.background(CancelToken(), stop=stop, poll=0.01):
            pass


def test_a_job_stop_cancels_its_in_flight_request_as_a_stop_not_a_preemption() -> None:
    broker = Broker(resume_after=0.0)
    stop = CancelToken()
    threading.Timer(0.05, lambda: stop.cancel("operator stop")).start()
    with pytest.raises(Cancelled) as caught:
        broker.chat(client(FakeTransport(block=True)), BACKGROUND, stop=stop, messages=[], max_tokens=5)
    assert not isinstance(caught.value, Preempted) and caught.value.reason == "operator stop"


def test_an_interactive_request_honours_its_stop_token() -> None:
    broker = Broker(resume_after=0.0)
    stop = CancelToken()
    threading.Timer(0.05, lambda: stop.cancel("operator")).start()
    with pytest.raises(Cancelled, match="operator"):
        broker.chat(client(FakeTransport(block=True)), INTERACTIVE, stop=stop, messages=[], max_tokens=5)

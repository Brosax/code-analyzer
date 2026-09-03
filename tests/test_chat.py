"""The run as a conversation: the transcript model the TUI's chat pane draws.

Pure -- no Textual, no asyncio, no screen -- for the same reason test_flow.py
is: the rendering contract is asserted on the lines the model produces, so a
regression in what the operator reads shows up here and not only on a terminal
nobody is watching.
"""
from __future__ import annotations

import copy

from code_analyzer.analysis import AnalysisEvent, AnalysisRequest, run_analysis
from code_analyzer.chat import (
    CHARS_PER_TOKEN,
    MAX_ANSWER_CHARS,
    MAX_ANSWER_LINES,
    Transcript,
)
from code_analyzer.config import DEFAULTS, validate_config


def _event(phase: str, status: str, message: str = "", **kwargs: object) -> AnalysisEvent:
    return AnalysisEvent(phase, status, message, timestamp=kwargs.pop("timestamp", 0.0), **kwargs)


def _answer(text: str, *, at: float, producer: str = "llm-security", unit: str = "u1") -> AnalysisEvent:
    return _event("output", "running", text, tool=producer, unit=unit, stream="answer", timestamp=at)


def _plain(transcript: Transcript, **kwargs: object) -> list[str]:
    kwargs.setdefault("capacity", 200)
    kwargs.setdefault("now", 10.0)
    return [line.text for line in transcript.lines(**kwargs)]


def _started(**data: object) -> AnalysisEvent:
    facts = {"index": 1, "total": 4, "path": "src/parse.c", "tier": "high", **data}
    return _event("unit", "started", "scanning (high)", tool="llm-security", unit="u1", data=facts)


def _settled(status: str = "completed", **data: object) -> AnalysisEvent:
    facts = {
        "index": 1, "total": 4, "path": "src/parse.c", "tier": "high", "finding_count": 2,
        "duration_seconds": 4.0, "usage": {"prompt_tokens": 2100, "completion_tokens": 400, "requests": 1},
        **data,
    }
    return _event("unit", status, f"{status}; 2 finding(s)", tool="llm-security", unit="u1", data=facts, timestamp=9.0)


# --- one exchange -----------------------------------------------------------


def test_an_exchange_is_the_prompt_the_answer_and_what_it_cost() -> None:
    transcript = Transcript()
    transcript.apply(_event("llm", "started", "starting", data={"model": "qwen3.8:27b"}))
    transcript.apply(_started())
    transcript.apply(_event(
        "output", "running", "# Scanner\n\nskill: llm-security", tool="llm-security", unit="u1",
        stream="prompt", data={"chars": 12000, "omitted_lines": 340, "estimated_tokens": 3000},
    ))
    transcript.apply(_answer('{"findings": [', at=2.0))
    transcript.apply(_answer('{"cwe": "CWE-787"}]}', at=3.0))
    transcript.apply(_settled())

    turn = transcript.turns()[0]
    assert turn.producer == "llm-security" and turn.subject() == "src/parse.c"
    # A chunk boundary is not a line boundary: an answer streamed in pieces is
    # one JSON document, not one line per piece.
    assert Transcript.answer_lines(turn) == (['{"findings": [{"cwe": "CWE-787"}]}'], 0)
    assert turn.state == "completed" and turn.findings == 2
    # Measured beats estimated once the provider has reported its own counts.
    assert turn.speed() == (100.0, "测量")
    assert turn.ttft_seconds() == 2.0
    assert transcript.model == "qwen3.8:27b"

    lines = _plain(transcript)
    assert any(line.startswith("✓ llm-security · src/parse.c · 1/4 · high · 完成") for line in lines)
    assert any('{"findings": [{"cwe": "CWE-787"}]}' in line for line in lines)
    footer = next(line for line in lines if "tok/s" in line)
    assert "100.0 tok/s（测量）" in footer and "首字 2.0s" in footer
    assert "输出 400 tok" in footer and "输入 2100 tok" in footer and "发现 2" in footer


def test_the_prompt_is_shown_only_when_it_is_asked_for() -> None:
    transcript = Transcript()
    transcript.apply(_started())
    transcript.apply(_event(
        "output", "running", "# Scan unit\n\nfile: src/parse.c", tool="llm-security", unit="u1",
        stream="prompt", data={"chars": 12000, "omitted_lines": 340},
    ))

    assert not any("Scan unit" in line for line in _plain(transcript))
    shown = _plain(transcript, show_prompts=True)
    assert any("▸ 发送的提示词 · 12000 字符 · 约 3000 tok" in line for line in shown)
    assert any("file: src/parse.c" in line for line in shown)
    # The pane only ever had a preview, and it says where the whole thing is
    # without re-counting what the sender already marked block by block.
    assert any(line.endswith("…（完整提示词见报告目录 llm/units/）") for line in shown)
    assert not any("340" in line for line in shown)


def test_a_speed_is_estimated_while_the_answer_streams_and_says_so() -> None:
    transcript = Transcript()
    transcript.apply(_started())
    for index in range(4):
        transcript.apply(_answer("x" * 40, at=1.0 + index))

    turn = transcript.turns()[0]
    assert turn.state == "streaming"
    # 160 characters over 3 seconds, at the divisor the budget already uses.
    assert turn.speed() == (round(160 / CHARS_PER_TOKEN / 3, 1), "估算")
    assert "（估算）" in transcript.summary(now=4.0)
    assert transcript.live_tok_s(now=4.0) == round(160 / CHARS_PER_TOKEN / 3, 1)
    # A window that has gone quiet reports no current speed rather than the
    # last one it saw: a stalled provider must not read as a fast one.
    assert transcript.live_tok_s(now=400.0) is None


def test_the_peak_survives_the_window_the_live_rate_does_not() -> None:
    transcript = Transcript()
    transcript.apply(_started())
    for index in range(4):
        transcript.apply(_answer("x" * 400, at=1.0 + index))

    live = transcript.stats(now=4.0).live_tok_s
    assert live is not None and transcript.stats(now=500.0).peak_tok_s == live


def test_tools_and_retries_are_part_of_the_exchange() -> None:
    transcript = Transcript()
    transcript.apply(_started())
    transcript.apply(_event("output", "running", "read", tool="llm-security", unit="u1", stream="tool"))
    transcript.apply(_event(
        "output", "running", "retry 1/5: TRANSPORT connection reset", tool="llm-security", unit="u1", stream="note",
    ))

    lines = _plain(transcript)
    assert any(line.strip() == "⚒ 工具调用 read" for line in lines)
    assert any("retry 1/5: TRANSPORT" in line for line in lines)
    assert transcript.turns()[0].state == "reading"


def test_a_failed_exchange_carries_the_reason_not_a_throughput() -> None:
    transcript = Transcript()
    transcript.apply(_started())
    transcript.apply(_settled("failed", reason="provider TRANSPORT: connection reset", finding_count=0, usage=None))

    turn = transcript.turns()[0]
    assert turn.failed and turn.speed() == (None, "")
    lines = _plain(transcript)
    assert any(line.startswith("✕ llm-security") and "失败" in line for line in lines)
    assert any("provider TRANSPORT: connection reset" in line for line in lines)


def test_a_cached_exchange_says_so() -> None:
    transcript = Transcript()
    transcript.apply(_started(cached=True))
    transcript.apply(_settled(cache_hit=True))

    assert transcript.stats().cached == 1
    assert any("缓存" in line for line in _plain(transcript))


# --- the run's totals -------------------------------------------------------


def test_the_totals_come_from_the_provider_and_the_scheduler() -> None:
    transcript = Transcript()
    transcript.apply(_event("unit", "heartbeat", "heartbeat", tool="llm-security", unit="u1", data={
        "measured": {"prompt_tokens": 120_000, "completion_tokens": 8_400, "requests": 42},
        "tok_s": 91.5, "eta_seconds": 754.0, "in_flight": 3,
    }))

    stats = transcript.stats(now=1.0)
    assert (stats.prompt_tokens, stats.completion_tokens, stats.requests) == (120_000, 8_400, 42)
    assert stats.in_flight == 3 and stats.eta_seconds == 754.0
    summary = transcript.summary(now=1.0)
    # No answer is streaming, so the session mean is what can honestly be shown.
    assert "91.5 tok/s（会话均值）" in summary
    assert "输入 120,000 · 输出 8,400 tok（测量）" in summary
    assert "请求 42" in summary and "ETA 12:34" in summary and "在途 3" in summary


def test_a_counter_never_walks_backwards() -> None:
    """Heartbeats from several sessions arrive interleaved; totals only grow."""
    transcript = Transcript()
    for measured in ({"prompt_tokens": 900}, {"prompt_tokens": 10}, {"prompt_tokens": 1_500}):
        transcript.apply(_event("unit", "heartbeat", "", tool="llm-security", unit="u1", data={"measured": measured}))
    assert transcript.stats().prompt_tokens == 1_500


# --- bounds -----------------------------------------------------------------


def test_the_transcript_is_bounded_and_keeps_the_newest_exchange() -> None:
    transcript = Transcript(max_turns=3)
    for index in range(8):
        unit = f"u{index}"
        transcript.apply(_event("unit", "started", "", tool="llm-security", unit=unit, data={"path": f"f{index}.c"}))
        transcript.apply(_event("unit", "completed", "", tool="llm-security", unit=unit, data={"finding_count": 0}))

    units = [turn.unit for turn in transcript.turns()]
    assert units == ["u5", "u6", "u7"] and transcript.dropped() == 5
    assert transcript.stats().turns == 8


def test_an_unsettled_exchange_is_never_evicted() -> None:
    """A turn still streaming is the one the operator is watching."""
    transcript = Transcript(max_turns=2)
    transcript.apply(_event("unit", "started", "", tool="llm-security", unit="live", data={"path": "live.c"}))
    for index in range(6):
        unit = f"u{index}"
        transcript.apply(_event("unit", "started", "", tool="llm-security", unit=unit))
        transcript.apply(_event("unit", "completed", "", tool="llm-security", unit=unit))

    assert "live" in [turn.unit for turn in transcript.turns()]


def test_a_long_answer_keeps_its_tail_and_says_what_it_dropped() -> None:
    transcript = Transcript()
    transcript.apply(_started())
    transcript.apply(_answer("\n".join(f"line {index}" for index in range(MAX_ANSWER_LINES + 40)), at=1.0))

    lines, omitted = Transcript.answer_lines(transcript.turns()[0])
    assert len(lines) == MAX_ANSWER_LINES and omitted == 40
    assert lines[-1] == f"line {MAX_ANSWER_LINES + 39}"
    assert any("已折叠 40 行回复" in line for line in _plain(transcript, capacity=MAX_ANSWER_LINES + 10))


def test_a_newline_that_ends_a_chunk_ends_a_line() -> None:
    """The real runtime sends one JSON answer as hundreds of text deltas."""
    transcript = Transcript()
    transcript.apply(_started())
    for piece in ('{', '\n', '  "unit_id":', ' "u1",\n', '  "findings": []', '\n}'):
        transcript.apply(_answer(piece, at=1.0))

    lines, omitted = Transcript.answer_lines(transcript.turns()[0])
    assert omitted == 0
    assert lines == ["{", '  "unit_id": "u1",', '  "findings": []', "}"]


def test_an_answer_that_outgrows_its_bound_keeps_the_end_of_it() -> None:
    transcript = Transcript()
    transcript.apply(_started())
    transcript.apply(_answer("a" * (MAX_ANSWER_CHARS + 500) + "TAIL", at=1.0))

    turn = transcript.turns()[0]
    assert turn.answer_truncated and len(turn.answer) == MAX_ANSWER_CHARS
    assert turn.answer.endswith("TAIL")
    # The characters are still counted in full: they are what the rate is from.
    assert turn.answer_chars == MAX_ANSWER_CHARS + 504
    assert any("完整回复见报告目录 llm/sessions/" in line for line in _plain(transcript, capacity=60))


def test_the_tail_fits_the_terminal_and_the_newest_exchange_wins() -> None:
    transcript = Transcript()
    for index in range(4):
        unit = f"u{index}"
        transcript.apply(_event("unit", "started", "", tool="llm-security", unit=unit, data={"path": f"f{index}.c"}))
        transcript.apply(_answer(f"answer {index}", at=1.0 + index, unit=unit))

    lines = _plain(transcript, capacity=4)
    # Oldest omission at the top, then the newest exchange in full: header,
    # answer, footer.  A four-row terminal shows four rows of what is
    # happening now, not four rows of the first unit scanned an hour ago.
    assert len(lines) == 4
    assert "未显示" in lines[0] and lines[0].startswith("… 以上 3 个单元")
    assert "f3.c" in lines[1] and "answer 3" in lines[2] and "tok" in lines[3]


def test_an_untrusted_answer_cannot_rewrite_the_terminal() -> None:
    """Model output and scanned paths are untrusted; escapes never reach a pane."""
    transcript = Transcript()
    transcript.apply(_started(path="src/\x1b[2Jevil.c"))
    transcript.apply(_answer("clean\x1b[31m\x07 text", at=1.0))

    lines = _plain(transcript)
    assert not any("\x1b" in line or "\x07" in line for line in lines)
    assert any("evil.c" in line for line in lines)
    assert any("clean" in line and "text" in line for line in lines)


def test_a_static_analyzer_line_is_not_part_of_the_conversation() -> None:
    transcript = Transcript()
    assert not transcript.apply(_event(
        "output", "running", "src/parse.c:12: warning", tool="cppcheck", unit="fallback", stream="stdout",
    ))
    assert not transcript.turns()


# --- against a real run -----------------------------------------------------


def test_a_real_run_produces_a_transcript(tmp_path) -> None:
    """The end-to-end shape: a static-only run says nothing, and says it once."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    config = validate_config(copy.deepcopy(DEFAULTS))
    config["run"]["output_root"] = str(tmp_path / "out")
    for name in ("cppcheck", "flawfinder", "splint"):
        config["tools"][name]["enabled"] = False
    config["run"]["shareable_export"] = False

    transcript = Transcript()
    run_analysis(AnalysisRequest(tmp_path, config), events=transcript.apply)

    assert not transcript.turns() and transcript.summary() == ""


# --- who is actually in the conversation ------------------------------------


def test_a_native_analyzer_unit_is_not_an_exchange_with_a_model() -> None:
    """cppcheck and splint emit unit events of exactly the same shape."""
    transcript = Transcript()
    for tool in ("cppcheck", "flawfinder", "splint"):
        assert not transcript.apply(_event(
            "unit", "completed", "completed", tool=tool, unit="shard-0001",
            data={"index": 1, "total": 1, "duration_seconds": 0.1},
        ))
    assert not transcript.turns() and transcript.stats().turns == 0

    # The build-context configurator does talk to a model, so it does count.
    assert transcript.apply(_event(
        "unit", "completed", "completed", tool="build-context-configurator", unit="r1",
        data={"index": 1, "total": 1},
    ))
    assert [turn.producer for turn in transcript.turns()] == ["build-context-configurator"]


def test_a_producer_that_has_answered_stays_in_the_conversation() -> None:
    """A scanner added to the registry needs no edit here to be shown."""
    transcript = Transcript()
    assert not transcript.apply(_event(
        "unit", "started", "", tool="llm-brand-new", unit="u1", data={"path": "a.c"},
    ))
    assert transcript.apply(_event(
        "output", "running", "hello", tool="llm-security", unit="u1", stream="answer",
    ))


def test_a_settled_phase_has_nothing_in_flight() -> None:
    transcript = Transcript()
    transcript.apply(_event("unit", "heartbeat", "", tool="llm-security", unit="u1", data={"in_flight": 3}))
    assert transcript.stats().in_flight == 3
    transcript.apply(_event("llm", "completed", "LLM scan finished with status completed"))
    assert transcript.stats().in_flight == 0


def test_the_totals_include_the_session_that_settled_after_the_last_heartbeat() -> None:
    """The phase publishes its ledger on a heartbeat; the last one has none after it."""
    transcript = Transcript()
    transcript.apply(_event("unit", "heartbeat", "", tool="llm-security", unit="u1", data={
        "measured": {"prompt_tokens": 2000, "completion_tokens": 100, "requests": 1},
    }))
    transcript.apply(_started())
    transcript.apply(_settled(usage={"prompt_tokens": 2100, "completion_tokens": 400, "requests": 1}))

    stats = transcript.stats()
    # The ledger stopped at one session; the settled turn is the second.
    assert (stats.prompt_tokens, stats.completion_tokens, stats.requests) == (2100, 400, 1)
    # A ledger that has seen more still wins: it counts sessions whose unit
    # events were dropped under load, and replans and the validator too.
    transcript.apply(_event("unit", "heartbeat", "", tool="llm-security", unit="u2", data={
        "measured": {"prompt_tokens": 90_000, "completion_tokens": 5_000, "requests": 30},
    }))
    stats = transcript.stats()
    assert (stats.prompt_tokens, stats.requests) == (90_000, 30)

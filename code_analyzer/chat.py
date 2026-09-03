"""The run as a conversation: what was asked, what the model answered, how fast.

The TUI's transcript pane is a view over this model, the way the flow panel is
a view over :mod:`code_analyzer.flow`.  Nothing here touches a terminal: the
pane asks for rendered lines and the tests ask for the same lines.

One ``Turn`` is one exchange with the model over one scan unit -- the prompt we
sent, the answer as it streams in, the tools the agent reached for, and the
speed both were measured at.  Two speeds are reported and never conflated: an
estimate while the answer is still arriving (characters over wall clock, the
``CHARS_PER_TOKEN`` divisor the budget already uses), and the provider's own
count once the session settles.  A pane that showed one as the other would be
inventing throughput the provider never reported.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .analysis import AnalysisEvent
from .progress import multi_line, single_line
from .tools import LLM_PRODUCERS

# The prompt-estimate divisor of the LLM budget (llm/scan.py); repeated here
# rather than imported so the pane does not drag the scan phase into the TUI.
CHARS_PER_TOKEN = 4

# Bounds. A run scans thousands of units and each answer is a JSON document;
# the transcript is a live view, not evidence, and the run directory keeps
# every prompt and response in full.
MAX_TURNS = 240
MAX_ANSWER_LINES = 400
MAX_ANSWER_CHARS = 40_000
MAX_PROMPT_LINES = 400
MAX_LINE_CHARS = 2000
# The window the header's "current speed" is measured over: long enough that
# one slow chunk does not read as a stall, short enough to still be "now".
RATE_WINDOW_SECONDS = 10.0

# Who holds a conversation.  A native analyzer emits unit events of exactly the
# same shape, and a run that showed "✓ flawfinder · shard-0001" among the
# model's answers would be counting a subprocess as an exchange; the build
# context configurator does talk to the model, so it belongs here.
CONVERSANTS = frozenset(LLM_PRODUCERS) | {"build-context-configurator"}

# Streams the LLM lane sends through ``output_event``; anything else is a
# static analyzer's stdout and belongs in the log pane, not here.
STREAM_PROMPT = "prompt"
STREAM_ANSWER = "answer"
STREAM_TOOL = "tool"
STREAM_NOTE = "note"
CHAT_STREAMS = frozenset({STREAM_PROMPT, STREAM_ANSWER, STREAM_TOOL, STREAM_NOTE})

# Turn state -> what the header of the turn says.
STATE_LABELS = {
    "waiting": "等待模型",
    "streaming": "接收中",
    "reading": "读取工具",
    "parsing": "解析响应",
    "completed": "完成",
    "partial": "截断",
    "failed": "失败",
    "timed_out": "超时",
    "interrupted": "已中断",
    "unscheduled": "未调度",
    "cached": "缓存命中",
}
_SETTLED = frozenset({"completed", "partial", "failed", "timed_out", "interrupted", "unscheduled"})
_BAD = frozenset({"failed", "timed_out", "interrupted", "unscheduled"})


def _lines(text: str, limit: int = MAX_LINE_CHARS) -> list[str]:
    """Split model or prompt text into display lines, control characters gone.

    Split on ``"\n"`` rather than with ``splitlines()``: the latter drops the
    information that the text ended on a newline, and the runtime streams one
    answer as hundreds of text deltas that have to be rejoined in the right
    places.
    """
    out = []
    for raw in str(text).split("\n"):
        cleaned = multi_line(raw)
        while len(cleaned) > limit:
            out.append(cleaned[:limit])
            cleaned = cleaned[limit:]
        out.append(cleaned)
    return out


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


@dataclass
class Line:
    """One rendered line: the pane resolves ``role`` to a colour."""

    role: str
    text: str
    turn: str = ""


@dataclass
class Turn:
    """One exchange with the model over one scan unit."""

    turn_id: str
    producer: str
    unit: str
    path: str = ""
    tier: str = ""
    index: int | None = None
    total: int | None = None
    state: str = "waiting"
    reason: str = ""
    started_at: float | None = None
    settled_at: float | None = None
    cached: bool = False
    # What we sent.
    prompt_lines: list[str] = field(default_factory=list)
    prompt_chars: int = 0
    prompt_omitted: int = 0
    # What came back, chunk by chunk: the text as received, bounded, with the
    # lines derived at render time.  A chunk boundary is not a line boundary --
    # a model streams one JSON document as hundreds of text deltas -- so
    # splitting per chunk would shred every finding across the pane.
    answer: str = ""
    answer_chars: int = 0
    answer_truncated: bool = False
    first_chunk_at: float | None = None
    last_chunk_at: float | None = None
    tools: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # What the provider and the parser reported once it settled.
    duration_seconds: float | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    requests: int | None = None
    findings: int | None = None
    malformed: int | None = None
    finish_reason: str = ""

    @property
    def settled(self) -> bool:
        return self.state in _SETTLED

    @property
    def failed(self) -> bool:
        return self.state in _BAD

    @property
    def prompt_tokens_estimated(self) -> int:
        return max(1, -(-self.prompt_chars // CHARS_PER_TOKEN)) if self.prompt_chars else 0

    def ttft_seconds(self) -> float | None:
        """Time to the first token of the answer: what the operator feels as lag."""
        if self.first_chunk_at is None or self.started_at is None:
            return None
        return max(0.0, self.first_chunk_at - self.started_at)

    def speed(self) -> tuple[float | None, str]:
        """Output tokens per second, and the basis it was derived from.

        Measured wins: once the provider has reported ``outputTokens`` and the
        session has a duration, that is the throughput.  Before then the answer
        is still arriving and only its characters are known.
        """
        if self.completion_tokens and self.duration_seconds:
            return round(self.completion_tokens / self.duration_seconds, 1), "测量"
        if self.first_chunk_at is not None and self.last_chunk_at is not None and self.answer_chars:
            span = self.last_chunk_at - self.first_chunk_at
            if span >= 0.05:
                return round(self.answer_chars / CHARS_PER_TOKEN / span, 1), "估算"
        return None, ""

    def subject(self) -> str:
        """The unit as the operator names it: path, symbol or unit id."""
        return self.path or self.unit


@dataclass
class Stats:
    """The run's conversation totals, for the header strip."""

    turns: int = 0
    answered: int = 0
    failed: int = 0
    cached: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    requests: int = 0
    live_tok_s: float | None = None
    peak_tok_s: float | None = None
    session_tok_s: float | None = None
    eta_seconds: float | None = None
    in_flight: int = 0
    findings: int = 0
    model: str = ""


class Transcript:
    """Every exchange of one run, folded from the event stream.

    ``apply`` returns whether the view changed, so a 5 Hz repaint can skip a
    tick that folded nothing -- the same contract ``RunFlow.apply`` has.
    """

    def __init__(self, *, max_turns: int = MAX_TURNS) -> None:
        self._max_turns = max_turns
        self._turns: dict[str, Turn] = {}
        self._order: deque[str] = deque()
        self.model = ""
        self.planned: int | None = None
        self.measured: dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "requests": 0}
        # The same quantity, counted the other way: what the settled sessions
        # themselves reported.  The phase publishes its ledger on a heartbeat,
        # so the last session's usage lands after the last heartbeat and the
        # ledger alone under-reports the end of every run.  Neither counter can
        # exceed the truth, so the totals take whichever has seen more -- the
        # ledger includes sessions whose unit events were dropped under load,
        # and this one includes the sessions that settled after it last spoke.
        self._from_turns: dict[str, int] = {"prompt_tokens": 0, "completion_tokens": 0, "requests": 0}
        self.eta_seconds: float | None = None
        self.session_tok_s: float | None = None
        self.in_flight = 0
        self.peak_tok_s: float | None = None
        # (arrival, characters) of recent answer chunks: the live rate.
        self._recent: deque[tuple[float, int]] = deque()
        self._dropped = 0

    # --- folding ------------------------------------------------------------

    def apply(self, event: AnalysisEvent) -> bool:
        if event.phase == "output":
            return self._on_output(event)
        if event.phase == "llm":
            return self._on_phase(event)
        if event.phase == "unit" and self._conversant(event.tool):
            return self._on_unit(event)
        return False

    def _conversant(self, producer: str | None) -> bool:
        """Is this producer one that talks to a model?

        A producer this transcript has already seen answer counts too: a scan
        that adds a scanner should show up here without this module having to
        be edited, and a producer that has streamed an answer has proved what
        it is.
        """
        return bool(producer) and (producer in CONVERSANTS or any(
            turn.producer == producer for turn in self._turns.values()
        ))

    def _on_phase(self, event: AnalysisEvent) -> bool:
        data = event.data or {}
        changed = False
        if event.status in _SETTLED and self.in_flight:
            # The last heartbeat is not the last word: a phase that has ended
            # has nothing in flight, and a strip that still said "在途 1"
            # would be reporting a session that is over.
            self.in_flight, changed = 0, True
        model = str(data.get("model") or "")
        if model and model != self.model:
            self.model, changed = model, True
        planned = _int(data.get("planned_units")) or _int(data.get("units"))
        if planned is not None and planned != self.planned:
            self.planned, changed = planned, True
        return changed

    def _on_output(self, event: AnalysisEvent) -> bool:
        stream = event.stream or ""
        if stream not in CHAT_STREAMS or not event.tool or not event.unit:
            return False
        if not self._conversant(event.tool):
            return False
        turn = self._turn(event.tool, event.unit, event.timestamp)
        if stream == STREAM_PROMPT:
            return self._absorb_prompt(turn, event)
        if stream == STREAM_ANSWER:
            return self._absorb_answer(turn, event)
        if stream == STREAM_TOOL:
            name = single_line(event.message)[:120]
            if name:
                turn.tools.append(name)
                if turn.state in {"waiting", "streaming"}:
                    turn.state = "reading"
                return True
            return False
        note = single_line(event.message)[:200]
        if note:
            turn.notes.append(note)
            return True
        return False

    def _absorb_prompt(self, turn: Turn, event: AnalysisEvent) -> bool:
        """Keep the preview, and how much of the real prompt it stands for.

        The preview already carries a marker per block for what the sender left
        out; ``prompt_omitted`` is only what this pane dropped on top of that,
        so the two counts are never added up into a number that is neither.
        """
        data = event.data or {}
        chars = _int(data.get("chars"))
        turn.prompt_chars = chars if chars is not None else len(event.message)
        lines = _lines(event.message)
        turn.prompt_omitted = max(0, len(lines) - MAX_PROMPT_LINES)
        turn.prompt_lines = lines[:MAX_PROMPT_LINES]
        return True

    def _absorb_answer(self, turn: Turn, event: AnalysisEvent) -> bool:
        text = str(event.message)
        if not text:
            return False
        now = event.timestamp
        if turn.first_chunk_at is None:
            turn.first_chunk_at = now
        turn.last_chunk_at = now
        turn.answer_chars += len(text)
        if turn.state in {"waiting", "reading"}:
            turn.state = "streaming"
        joined = turn.answer + text
        if len(joined) > MAX_ANSWER_CHARS:
            joined = joined[-MAX_ANSWER_CHARS:]
            turn.answer_truncated = True
        turn.answer = joined
        self._sample(now, len(text))
        return True

    @staticmethod
    def answer_lines(turn: Turn) -> tuple[list[str], int]:
        """The answer as display lines, newest kept, and how many were dropped."""
        if not turn.answer:
            return [], 0
        lines = _lines(turn.answer)
        if len(lines) <= MAX_ANSWER_LINES:
            return lines, 0
        return lines[-MAX_ANSWER_LINES:], len(lines) - MAX_ANSWER_LINES

    def _on_unit(self, event: AnalysisEvent) -> bool:
        data = event.data or {}
        if event.status in {"heartbeat", "info"}:
            return self._absorb_totals(data)
        if not event.unit:
            return self._absorb_totals(data)
        turn = self._turn(str(event.tool), event.unit, event.timestamp)
        changed = self._absorb_totals(data)
        for attribute, key in (("path", "path"), ("tier", "tier")):
            value = data.get(key)
            if value and getattr(turn, attribute) != str(value):
                setattr(turn, attribute, single_line(str(value))[:200])
                changed = True
        for attribute, key in (("index", "index"), ("total", "total")):
            value = _int(data.get(key))
            if value is not None and getattr(turn, attribute) != value:
                setattr(turn, attribute, value)
                changed = True
        if event.status == "started":
            turn.started_at = event.timestamp
            turn.cached = bool(data.get("cached"))
            turn.state = "cached" if turn.cached else "waiting"
            return True
        if event.status == "step":
            step = str(data.get("step") or "")
            if step in {"waiting", "streaming", "reading", "parsing"} and not turn.settled:
                turn.state = step
                return True
            return changed
        if event.status in _SETTLED:
            return self._settle(turn, event, data)
        return changed

    def _settle(self, turn: Turn, event: AnalysisEvent, data: dict[str, Any]) -> bool:
        turn.state = event.status
        turn.settled_at = event.timestamp
        turn.reason = single_line(str(data.get("reason") or ""))[:300]
        turn.finish_reason = single_line(str(data.get("finish_reason") or ""))[:60]
        turn.duration_seconds = _float(data.get("duration_seconds"))
        turn.findings = _int(data.get("finding_count"))
        turn.malformed = _int(data.get("malformed_count"))
        if data.get("cache_hit"):
            turn.cached = True
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        turn.prompt_tokens = _int(usage.get("prompt_tokens"))
        turn.completion_tokens = _int(usage.get("completion_tokens"))
        turn.requests = _int(usage.get("requests"))
        for key in self._from_turns:
            value = _int(usage.get(key))
            if value is not None and value > 0:
                self._from_turns[key] += value
        speed, basis = turn.speed()
        if speed is not None and basis == "测量":
            self.peak_tok_s = speed if self.peak_tok_s is None else max(self.peak_tok_s, speed)
        return True

    def _absorb_totals(self, data: dict[str, Any]) -> bool:
        changed = False
        measured = data.get("measured")
        if isinstance(measured, dict):
            for key in self.measured:
                value = _int(measured.get(key))
                if value is not None and value > self.measured[key]:
                    self.measured[key], changed = value, True
        eta = _float(data.get("eta_seconds"))
        if eta is not None and eta != self.eta_seconds:
            self.eta_seconds, changed = eta, True
        rate = _float(data.get("tok_s"))
        if rate is not None and rate != self.session_tok_s:
            self.session_tok_s, changed = rate, True
        in_flight = _int(data.get("in_flight"))
        if in_flight is not None and in_flight != self.in_flight:
            self.in_flight, changed = in_flight, True
        return changed

    def _turn(self, producer: str, unit: str, when: float) -> Turn:
        turn_id = f"{producer}/{unit}"
        turn = self._turns.get(turn_id)
        if turn is None:
            turn = Turn(turn_id=turn_id, producer=producer, unit=unit, started_at=when)
            self._turns[turn_id] = turn
            self._order.append(turn_id)
            self._evict()
        return turn

    def _evict(self) -> None:
        """Forget the oldest settled turns; an unsettled turn is still live."""
        while len(self._order) > self._max_turns:
            for position, turn_id in enumerate(self._order):
                if self._turns[turn_id].settled:
                    del self._turns[turn_id]
                    del self._order[position]
                    self._dropped += 1
                    break
            else:
                return

    def _sample(self, when: float, characters: int) -> None:
        self._recent.append((when, characters))
        cutoff = when - RATE_WINDOW_SECONDS
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    # --- what the pane asks for ---------------------------------------------

    def turns(self) -> list[Turn]:
        return [self._turns[turn_id] for turn_id in self._order]

    def dropped(self) -> int:
        return self._dropped

    def live_tok_s(self, now: float | None = None) -> float | None:
        """Output tokens per second across every answer arriving right now.

        An estimate by construction (characters / 4): the provider reports its
        counts when a session ends, and this is what the pane can honestly show
        while one is still streaming.
        """
        now = time.time() if now is None else now
        cutoff = now - RATE_WINDOW_SECONDS
        samples = [(when, chars) for when, chars in self._recent if when >= cutoff]
        if len(samples) < 2:
            return None
        span = samples[-1][0] - samples[0][0]
        if span < 0.05:
            return None
        return round(sum(chars for _when, chars in samples) / CHARS_PER_TOKEN / span, 1)

    def totals(self) -> dict[str, int]:
        """The provider's own counts, from whichever ledger has seen more."""
        return {key: max(self.measured[key], self._from_turns[key]) for key in self.measured}

    def stats(self, now: float | None = None) -> Stats:
        turns = self.turns()
        live = self.live_tok_s(now)
        if live is not None:
            self.peak_tok_s = live if self.peak_tok_s is None else max(self.peak_tok_s, live)
        totals = self.totals()
        return Stats(
            turns=len(turns) + self._dropped,
            answered=sum(1 for turn in turns if turn.state in {"completed", "partial"}),
            failed=sum(1 for turn in turns if turn.failed),
            cached=sum(1 for turn in turns if turn.cached),
            prompt_tokens=totals["prompt_tokens"],
            completion_tokens=totals["completion_tokens"],
            requests=totals["requests"],
            live_tok_s=live,
            peak_tok_s=self.peak_tok_s,
            session_tok_s=self.session_tok_s,
            eta_seconds=self.eta_seconds,
            in_flight=self.in_flight,
            findings=sum(turn.findings or 0 for turn in turns),
            model=self.model,
        )

    def lines(self, *, capacity: int, show_prompts: bool = False, now: float | None = None) -> list[Line]:
        """The transcript's tail, newest last, at most ``capacity`` lines.

        Rendered youngest-first and reversed at the end: the pane always shows
        the exchange happening now, and a terminal that can hold three lines
        shows three lines of it rather than three lines of the first unit
        scanned an hour ago.
        """
        now = time.time() if now is None else now
        out: list[Line] = []
        for turn in reversed(self.turns()):
            block = self._block(turn, show_prompts, now)
            if len(out) + len(block) > capacity and out:
                out.append(Line("omitted", f"… 以上 {len(self.turns()) - self._counted(out)} 个单元未显示"))
                break
            out.extend(reversed(block))
            if len(out) >= capacity:
                break
        return list(reversed(out[:capacity]))

    @staticmethod
    def _counted(lines: list[Line]) -> int:
        return len({line.turn for line in lines if line.turn})

    def _block(self, turn: Turn, show_prompts: bool, now: float) -> list[Line]:
        block = [Line("header", self.header(turn, now), turn.turn_id)]
        if show_prompts and turn.prompt_lines:
            block.append(Line("prompt-title", f"  ▸ 发送的提示词 · {turn.prompt_chars} 字符 · 约 {turn.prompt_tokens_estimated} tok", turn.turn_id))
            block.extend(Line("prompt", f"  │ {line}", turn.turn_id) for line in turn.prompt_lines)
            tail = f"本页另折叠 {turn.prompt_omitted} 行；" if turn.prompt_omitted else ""
            block.append(Line("prompt", f"  │ …（{tail}完整提示词见报告目录 llm/units/）", turn.turn_id))
        for name in turn.tools[-4:]:
            block.append(Line("tool", f"  ⚒ 工具调用 {name}", turn.turn_id))
        for note in turn.notes[-3:]:
            block.append(Line("note", f"  ! {note}", turn.turn_id))
        lines, omitted = self.answer_lines(turn)
        if omitted or turn.answer_truncated:
            block.append(Line("omitted", f"  …（已折叠 {omitted} 行回复；完整回复见报告目录 llm/sessions/）", turn.turn_id))
        block.extend(Line("answer", f"  {line}", turn.turn_id) for line in lines)
        footer = self.footer(turn)
        if footer:
            block.append(Line("footer", f"  {footer}", turn.turn_id))
        return block

    def header(self, turn: Turn, now: float) -> str:
        marker = "✕" if turn.failed else ("✓" if turn.settled else "●")
        parts = [f"{marker} {turn.producer}", turn.subject() or turn.unit]
        if turn.index and turn.total:
            parts.append(f"{turn.index}/{turn.total}")
        if turn.tier:
            parts.append(turn.tier)
        label = STATE_LABELS.get(turn.state, turn.state)
        if turn.cached and turn.settled:
            label = f"{label} · 缓存"
        parts.append(label)
        if not turn.settled:
            elapsed = 0.0 if turn.started_at is None else max(0.0, now - turn.started_at)
            parts.append(f"{elapsed:.0f}s")
        return single_line(" · ".join(part for part in parts if part))

    def footer(self, turn: Turn) -> str:
        parts = []
        speed, basis = turn.speed()
        if speed is not None:
            parts.append(f"{speed} tok/s（{basis}）")
        ttft = turn.ttft_seconds()
        if ttft is not None:
            parts.append(f"首字 {ttft:.1f}s")
        if turn.completion_tokens:
            parts.append(f"输出 {turn.completion_tokens} tok")
        elif turn.answer_chars:
            parts.append(f"输出 ~{turn.answer_chars // CHARS_PER_TOKEN} tok")
        if turn.prompt_tokens:
            parts.append(f"输入 {turn.prompt_tokens} tok")
        if turn.duration_seconds is not None:
            parts.append(f"耗时 {turn.duration_seconds:.1f}s")
        if turn.findings is not None and turn.settled:
            parts.append(f"发现 {turn.findings}")
        if turn.malformed:
            parts.append(f"格式错误 {turn.malformed}")
        if turn.reason and turn.failed:
            parts.append(turn.reason)
        elif turn.finish_reason and turn.state == "partial":
            parts.append(turn.finish_reason)
        return single_line(" · ".join(parts))

    def summary(self, now: float | None = None) -> str:
        """The header strip: model, speed, tokens, ETA."""
        stats = self.stats(now)
        parts = []
        if stats.model:
            parts.append(stats.model)
        # The marker belongs to whoever draws the strip, not to the number.
        if stats.live_tok_s is not None:
            parts.append(f"{stats.live_tok_s} tok/s（估算）")
        elif stats.session_tok_s is not None:
            parts.append(f"{stats.session_tok_s} tok/s（会话均值）")
        if stats.peak_tok_s is not None:
            parts.append(f"峰值 {stats.peak_tok_s}")
        if stats.in_flight:
            parts.append(f"在途 {stats.in_flight}")
        if stats.prompt_tokens or stats.completion_tokens:
            parts.append(f"输入 {_thousands(stats.prompt_tokens)} · 输出 {_thousands(stats.completion_tokens)} tok（测量）")
        if stats.requests:
            parts.append(f"请求 {_thousands(stats.requests)}")
        if stats.findings:
            parts.append(f"发现 {stats.findings}")
        if stats.eta_seconds is not None:
            parts.append(f"ETA {_duration(stats.eta_seconds)}")
        return single_line(" · ".join(parts))


def _thousands(value: int) -> str:
    return f"{value:,}"


def _duration(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}" if hours else f"{minutes:02d}:{secs:02d}"

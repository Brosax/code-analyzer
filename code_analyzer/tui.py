"""The interface is a conversation: one transcript, one input box.

What replaced what.  A form asked the operator to know which of thirteen
fields mattered before anything could start, and a three-region state machine
(form -> running -> result) meant the run and its result were different
screens from the thing that asked for them.  Now every exchange is a block in
one scrolling record: what you typed, what the tool answered, the scan itself,
the questions it stopped to ask, and the line it collapsed to when it was
done.  You can scroll back to any of it.

What did not change, and must not.  The event pipeline is the part that was
paid for with a run that emitted 520 000 events in an hour: events are queued
on the worker thread under a lock, folded by a 5 Hz tick, and never delivered
one ``call_from_thread`` at a time.  Blocks are mounted once each -- one widget
per turn, never one per event.  Every line is built as ``rich.Text`` segment by
segment and never from markup, because scanned file names and model output
reach these rows.

The models this draws are unchanged: ``RunFlow``, ``chat.Transcript``,
``RunControl``, and now ``dialogue.Dialogue``.  This file is a view.
"""
from __future__ import annotations

import copy
import shlex
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.cells import cell_len, chop_cells
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.widgets import Collapsible, Footer, Header, Input, RichLog, Static

from .actions import (
    CONFIRM_ALWAYS,
    SUBJECT_NONE,
    SUBJECT_REPORT,
    SUBJECT_SOURCE,
    ActionContext,
    ActionRequest,
    by_name,
    invoke,
    render_writes,
)
from .analysis import AnalysisEvent, CancellationToken
from .argv import analyze_overrides, assess_overrides
from .ask import CONFIRM, Answer, Asker, Question
from .config import (
    apply_overrides,
    config_value,
    load_config_with_sources,
    save_config_snapshot,
    set_config_value,
    validate_config,
)
from .control import RunControl
from .dialogue import Block, Dialogue, RunBlock, spin
from .errors import UserError
from .flow import WIDE_BREAKPOINT, Lane, RunFlow, capacity
from .intent import (
    ACTION,
    AMBIGUOUS,
    ASK,
    CONFIG_SET,
    CONFIG_SHOW,
    EMPTY,
    META,
    coerce,
    help_lines,
    offline_hint,
    parse,
)
from .journal import Journal, disabled_by_env
from .progress import animation_disabled_by_env, single_line
from .runlog import LEVELS, format_line, level_of

# Keys that only mean something while something is running; check_action frees
# them for the input box otherwise.
RUN_ONLY_ACTIONS = frozenset({"cycle_filter", "toggle_prompts", "toggle_log"})

# Whether a model-resolved read-only step runs without a second human beat.
# One boolean, so the whole of that decision reverts by flipping it.
AUTO_RUN_READ_ONLY = True

# How many queued events one 5 Hz tick folds at most, and how many liveness
# events may pile up before the oldest are dropped.  Unchanged.
DRAIN_PER_TICK = 5000
LIVENESS_QUEUE = 5000
LOG_FILTERS = ("all", "warn", "error")
FILTER_LABELS = {"all": "全部", "warn": "警告+", "error": "仅错误"}

# Node state -> colour, and the three-step ramp the spine cell walks.
_STATE_STYLES = {"success": "green", "partial": "yellow", "failed": "red", "running": "bold cyan", "pending": "dim"}
_SPINE_STYLES = ("bold cyan", "cyan", "dim cyan")
_LABEL_WIDTH = 24
# Transcript line role -> colour.  The answer itself is left unstyled: it is
# the content, and everything around it is furniture.
_CHAT_STYLES = {
    "header": "bold cyan", "prompt-title": "bold yellow", "prompt": "yellow", "answer": "",
    # The chain of thought is dim on purpose: it is the loudest thing on the
    # pane by volume and the least load-bearing by content.
    "thinking-title": "bold blue", "thinking": "dim blue",
    "tool": "magenta", "note": "bold red", "footer": "dim", "omitted": "dim italic",
}
_BLOCK_STYLES = {"user": "bold", "say": "", "error": "bold red", "question": "bold yellow",
                 "config": "cyan", "proposal": "bold yellow"}
_LANE_LABEL_CELLS = 12
# How often a streaming chain of thought repaints the wait block.  Fast enough
# to read as live, slow enough that a 30-second reasoning burst is a few dozen
# repaints rather than a few hundred.
THINKING_REPAINT_SECONDS = 0.25
_BAR_WIDTH = 22
_BAR_FULL = "█"
_BAR_EMPTY = "░"

GREETING = (
    "输入一个目录开始扫描，或者用 / 开头的命令。",
    "  /help 列出全部 · /config 看配置 · /doctor 体检 · Ctrl+C 退出",
)


@dataclass(frozen=True)
class TuiOutcome:
    exit_code: int = 0
    report_directory: Path | None = None


class RunBlockWidget(Collapsible):
    """One run, collapsed to a live line and expanded to the whole diagram.

    Collapsed it is the title, refreshed at 5 Hz.  Expanded it is what the old
    run view drew -- the fan-out, the lane bars, the speed strip, the per
    scanner panel and the model's transcript -- from the same two models, which
    is why every painter moved across unchanged.
    """

    def __init__(self, block: RunBlock, **kwargs: Any) -> None:
        self.body = Static("", classes="run-body")
        super().__init__(self.body, title=block.headline(), collapsed=True, **kwargs)
        self.block = block


class AnalyzerApp(App[TuiOutcome]):
    TITLE = "Code Analyzer"
    SUB_TITLE = "对话"
    BINDINGS = [
        Binding("ctrl+c", "cancel_or_exit", "取消/退出", priority=True),
        Binding("ctrl+s", "save", "保存配置", priority=True),
        Binding("escape", "focus_prompt", "回到输入框", priority=True),
        Binding("f1", "help", "帮助"),
        Binding("f2", "toggle_last_run", "展开/折叠运行"),
        Binding("f4", "cycle_filter", "日志过滤", show=False),
        Binding("f5", "toggle_log", "日志"),
        Binding("f6", "toggle_prompts", "提示词", show=False),
    ]
    CSS = """
    Screen { background: $surface; }
    #too-small { display: none; dock: top; height: 3; background: $error; color: $text; content-align: center middle; }
    .too-small #too-small { display: block; }
    #transcript { height: 1fr; padding: 0 1; background: $surface; }
    .block { height: auto; margin: 0 0 1 0; }
    .block-user { color: $text; text-style: bold; }
    .block-error { color: $error; }
    .block-question { color: $warning; }
    .block-config { color: $accent; }
    Collapsible { margin: 0 0 1 0; border: none; background: $surface-darken-1; }
    Collapsible > CollapsibleTitle { color: $accent; }
    .run-body { height: auto; padding: 0 1; }
    #log { display: none; dock: bottom; height: 12; border-top: solid $primary;
           background: $surface-darken-1; }
    .show-log #log { display: block; }
    #bottom { dock: bottom; height: auto; }
    #status { height: 1; padding: 0 1; background: $boost; color: $text-muted; }
    #prompt { border: none; background: $surface-darken-1; }
    #prompt:focus { border: none; }
    """

    def __init__(self, source: Path, explicit_config: Path | None = None) -> None:
        super().__init__()
        self.source = source.expanduser().resolve()
        self.explicit_config = explicit_config.expanduser().resolve() if explicit_config else None
        loaded = load_config_with_sources(self.source, self.explicit_config)
        self.dialogue = Dialogue(source=self.source, config=loaded.config)
        self.sources = dict(loaded.sources)
        self.dirty = False
        self.small = False
        self.last_outcome: TuiOutcome | None = None
        self.control: RunControl | None = None
        self.cancel_token: CancellationToken | None = None
        self.journal = None if disabled_by_env() else Journal()
        # The two queues, unchanged: state events are never dropped, liveness
        # events may be.  Entries carry the block they belong to, because more
        # than one action can emit now.
        self._pending_events: deque[tuple[str, AnalysisEvent]] = deque()
        self._liveness_events: deque[tuple[str, AnalysisEvent]] = deque(maxlen=LIVENESS_QUEUE)
        self._events_lock = threading.Lock()
        self._pending_log_lines: deque[str] = deque()
        self._log_lock = threading.Lock()
        self._log_overflowed = False
        self._log_filter = "all"
        self._show_prompts = False
        self._flow_frame = 0
        self._flow_animated = not animation_disabled_by_env()
        self._flow_capacity = 7
        self._history: list[str] = []
        self._history_at = 0
        # Questions a worker is blocked on, by block id.
        self._waiting: dict[str, tuple[threading.Event, dict[str, Answer]]] = {}
        self._busy = False
        self._busy_since = 0.0
        # Speeds this session actually measured.  Never a default, never an
        # estimate dressed as one: absent means nothing has measured it yet.
        self._last_benchmark: dict[str, Any] | None = None
        self._last_benchmark_at = 0.0
        self._last_ask_rate: float | None = None
        # What a model proposed and the operator has not yet ticked, and the
        # commands a ticked proposal turned into.
        self._pending_steps: list[Any] = []
        self._queued: list[str] = []
        self._pending_save: Path | None = None
        # One outstanding provider request per session.  `_ask_generation` is
        # bumped on abandon so a late answer can be identified and dropped;
        # `_ask_inflight` stays true until the worker thread actually returns,
        # because abandoning detaches rather than kills (the SDK exposes no
        # cancel handle and the runtime only polls between notifications).
        self._ask_generation = 0
        self._ask_inflight = False
        self._last_ask_seconds: float | None = None
        # Said once per reason, not once per sentence.
        self._gate_reason: str = ""
        self._stop_event: threading.Event | None = None

    # --- the screen ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("终端至少需要 80×24；当前尺寸不足。", id="too-small")
        yield VerticalScroll(id="transcript")
        yield RichLog(max_lines=2000, auto_scroll=True, wrap=True, markup=False, id="log")
        # Both docked bottom inside one container, because `Footer` keeps the
        # last row to itself: a sibling with `dock: bottom` lands *under* it and
        # is painted over, which is where the status line has been living.
        with Vertical(id="bottom"):
            yield Static("", id="status")
            yield Input(placeholder="说点什么，或输入 / 开头的命令…", id="prompt")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#log", RichLog).border_title = "日志 · 全部"
        self.query_one("#transcript", VerticalScroll).anchor()
        self.set_interval(0.1, self._flush_log_queue)
        self.set_interval(0.2, self._tick)
        self.set_interval(1.0, self._tick_clock)
        for line in GREETING:
            self._mount(self.dialogue.say(line))
        self._mount(self.dialogue.say(f"当前目录：{self.source}"))
        self._update_status()
        self.query_one("#prompt", Input).focus()

    def on_resize(self, event: Any) -> None:
        width, height = event.size.width, event.size.height
        self.small = width < 80 or height < 24
        self.set_class(self.small, "too-small")
        self.set_class(width >= WIDE_BREAKPOINT, "wide")
        self._flow_capacity = capacity(width, height)

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action in RUN_ONLY_ACTIONS:
            return self.dialogue.live_run() is not None
        return True

    # --- what the operator typed --------------------------------------------

    @on(Input.Submitted, "#prompt")
    def prompt_submitted(self, event: Input.Submitted) -> None:
        text = event.value
        event.input.value = ""
        self.submit(text)

    def submit(self, text: str) -> None:
        """One line in.  Never raises: every refusal is a block."""
        line = (text or "").strip()
        if not line:
            return
        self._history.append(line)
        self._history_at = len(self._history)
        if self.journal is not None:
            self.journal.said(line)

        pending = self.dialogue.pending_question()
        if pending is not None:
            self._answer_pending(pending.block_id, line)
            return

        intent = parse(line, self.dialogue.state())
        by = "model" if intent.kind == ASK else "parser"
        # A slash command answers in 0 ms and never waits behind a model, so
        # /cancel and /help stay reachable while one is thinking.  Anything
        # that would occupy the one busy slot queues instead of being refused.
        if intent.kind not in {META, CONFIG_SET, CONFIG_SHOW, EMPTY} and self._occupied():
            self._queued.append(line)
            self._mount(self.dialogue.said(line, queued=len(self._queued)))
            if self.journal is not None:
                self.journal.read_as("queued", intent.action, intent.argv)
            return
        if self.journal is not None:
            self.journal.read_as(intent.kind, intent.action, intent.argv, by=by)
        reading = "" if intent.confidence == "exact" else (intent.action or "")
        self._mount(self.dialogue.said(line, reading=reading, by=by))
        self._route(intent)

    def _occupied(self) -> bool:
        """Is the one slot that runs things taken?"""
        return self._busy or self._ask_inflight

    def _route(self, intent: Any) -> None:
        if intent.kind == EMPTY:
            return
        if intent.kind == META:
            self._meta(intent)
            return
        if intent.kind == CONFIG_SHOW:
            self._show_config(all_fields=bool(intent.values.get("all")))
            return
        if intent.kind == CONFIG_SET:
            self._set_config(intent.values["path"], intent.values["raw"])
            return
        if intent.kind == ASK:
            self._ask_model(intent.values.get("utterance") or intent.text)
            return
        if intent.kind == AMBIGUOUS:
            lines = [f"  /{name} {' '.join(intent.argv) or ''}".rstrip() for name in intent.candidates]
            self._mount(self.dialogue.say(intent.problem, lines))
            return
        if intent.kind == ACTION:
            self._start(intent)
            return
        self._mount(self.dialogue.failed(intent.problem or "没看懂这一行"))

    # --- the conversation's own commands ------------------------------------

    def _meta(self, intent: Any) -> None:
        name, argv = intent.action, list(intent.argv)
        control, run = self.control, self.dialogue.live_run()
        if name == "help":
            self._mount(self.dialogue.say("", help_lines()))
        elif name in {"quit", "exit"}:
            self._exit_with_last()
        elif name == "clear":
            for widget in self.query(RunBlockWidget):
                widget.collapsed = True
            self._mount(self.dialogue.say("已折叠全部运行块"))
        elif name == "cancel":
            self.action_cancel_or_exit()
        elif name in {"pause", "resume"} and control is not None:
            lane = (argv[0] if argv else "llm").strip()
            if lane not in {"llm", "static"}:
                self._mount(self.dialogue.failed(f"没有 {lane} 这条泳道；只有 llm 和 static"))
                return
            control.pause(lane, "tui") if name == "pause" else control.resume(lane, "tui")
            self._mount(self.dialogue.say(f"{lane} 泳道已{'暂停' if name == 'pause' else '恢复'}"))
        elif name == "jobs" and control is not None:
            try:
                value = int(argv[0])
            except (IndexError, ValueError):
                self._mount(self.dialogue.failed("用法：/jobs <并发数>"))
                return
            control.set_jobs("llm", value, "tui")
            self._mount(self.dialogue.say(f"LLM 并发 → {control.jobs('llm')}"))
        elif name == "skip" and control is not None:
            if not argv:
                self._mount(self.dialogue.failed("用法：/skip <producer>"))
                return
            control.skip(argv[0], "tui")
            self._mount(self.dialogue.say(f"已请求跳过 {argv[0]} 余下的单元"))
        elif name == "retry" and control is not None and run is not None:
            ids = run.flow.retryable_units(transport_only=True) if run.flow else []
            control.request_retry("llm", ids or None, "tui")
            self._mount(self.dialogue.say(
                f"已请求重试 {len(ids) if ids else '全部未得到回答的'} 个 LLM 单元；本轮结束后执行"))
        elif name == "decide" and control is not None:
            pending = control.pending()
            self._mount(self.dialogue.say(
                f"待决策 {len(pending)} 项" if pending else "当前没有待决策项"))
        elif name == "save":
            self.action_save(Path(argv[0]) if argv else None)
        else:
            self._mount(self.dialogue.failed(f"/{name} 现在没有意义：没有正在运行的扫描"))

    def _show_config(self, *, all_fields: bool) -> None:
        outcome = invoke(by_name("config"), ActionContext(
            request=ActionRequest("config", config=self.dialogue.config,
                                  values={"all": all_fields, "filter": ""}),
        ))
        from .dialogue import ConfigBlock

        head = f"配置 · {outcome.summary}" + ("" if all_fields else " · /config --all 看全部")
        self._mount(self.dialogue.add(ConfigBlock(text=head, lines=list(outcome.lines))))

    def _set_config(self, path: str, raw: str) -> None:
        from .dialogue import ConfigBlock

        try:
            value = coerce(path, raw)
            before = config_value(self.dialogue.config, path)
            draft = validate_config({**self.dialogue.config})
            set_config_value(draft, path, value)
            validate_config(draft)
        except (UserError, ValueError, KeyError) as exc:
            self._mount(self.dialogue.failed(single_line(str(exc))))
            return
        set_config_value(self.dialogue.config, path, value)
        self.sources[path] = "session"
        self.dirty = True
        self._mount(self.dialogue.add(ConfigBlock(
            text="", changes=[(path, before, value)],
            lines=["  （未保存，Ctrl+S 写入 TOML 快照）"],
        )))
        self._update_status()

    # --- /ask: the model proposes, the operator ticks ------------------------

    def _ask_model(self, utterance: str) -> None:
        if not utterance.strip():
            self._mount(self.dialogue.failed("用法：/ask <一句话>"))
            return
        if self._occupied():
            self._queued.append(utterance)
            self._mount(self.dialogue.said(utterance, queued=len(self._queued)))
            return
        self._busy = True
        self._busy_since = time.time()
        self._ask_inflight = True
        self.cancel_token = CancellationToken()
        block = self.dialogue.thinking(utterance, last_seconds=self._last_ask_seconds,
                                       model=str(self.dialogue.config["llm"].get("model") or ""))
        self._mount(block)
        self._propose_worker(utterance, self._ask_generation)

    @work(thread=True, exclusive=True, group="ask")
    def _propose_worker(self, utterance: str, generation: int) -> None:
        from .llm.propose import propose

        token = self.cancel_token
        # A chain of thought arrives one token group at a time -- hundreds of
        # them for one answer -- and a repaint per delta would spend the whole
        # wait laying out text.  Coalesced to a fixed cadence instead; nothing
        # is dropped, it just arrives in fewer pieces.
        pending: dict[str, Any] = {"text": "", "chars": 0, "at": 0.0}
        guard = threading.Lock()

        def flush() -> None:
            with guard:
                chunk, pending["text"] = pending["text"], ""
                chars, pending["chars"] = pending["chars"], 0
            if chunk or chars:
                self.call_from_thread(self._thinking_text, chunk, chars, generation)

        def due(now: float) -> bool:
            """Caller holds the guard.  One cadence for both streams."""
            if now - pending["at"] < THINKING_REPAINT_SECONDS:
                return False
            pending["at"] = now
            return True

        def thinking(text: str) -> None:
            with guard:
                pending["text"] += text
                ready = due(time.monotonic())
            if ready:
                flush()

        def counted(chars: int) -> None:
            """Output characters, for the live rate.  An answer streams even
            when the model does no reasoning at all, so this has its own path
            rather than riding on `thinking`."""
            with guard:
                pending["chars"] += chars
                ready = due(time.monotonic())
            if ready:
                flush()

        try:
            proposal = propose(
                utterance, self.dialogue.config,
                source=self.dialogue.source, report_directory=self.dialogue.report_directory,
                cancelled=(token.is_cancelled if token else None),
                on_phase=lambda name: self.call_from_thread(self._thinking_phase, name, generation),
                on_thinking=thinking, on_chunk=counted,
            )
        except Exception as exc:
            self.call_from_thread(
                self._proposed, None, f"{type(exc).__name__}: {single_line(str(exc))}", generation)
            return
        flush()
        self.call_from_thread(self._proposed, proposal, "", generation)

    def _thinking_text(self, text: str, chars: int, generation: int) -> None:
        """The model's reasoning and its output count; one repaint, UI thread."""
        if generation != self._ask_generation:
            return
        thinking = self.dialogue.live_thinking()
        if thinking is None:
            return
        thinking.saw(chars)
        if text:
            thinking.think(text)
        self._repaint_block(thinking.block_id)

    def _thinking_phase(self, name: str, generation: int) -> None:
        """The lane says what it is doing now; one repaint, on the UI thread."""
        if generation != self._ask_generation:
            return
        thinking = self.dialogue.live_thinking()
        if thinking is not None and thinking.phase != name:
            thinking.phase = name
            self._repaint_block(thinking.block_id)

    def _proposed(self, proposal: Any, error: str, generation: int = 0) -> None:
        """Render what the model suggested: unticked, itemised, with its reasons."""
        from .dialogue import ProposalBlock

        # Checked first, before any state is touched: an answer to a question
        # the operator already abandoned must change nothing at all.
        self._ask_inflight = False
        if generation != self._ask_generation:
            self._drain_queue()
            return
        self._busy = False
        self.cancel_token = None
        thinking = self.dialogue.live_thinking()
        if thinking is not None:
            thinking.settled = True
            thinking.summary = ""
            self._repaint_block(thinking.block_id)
        if proposal is not None and proposal.duration_seconds:
            self._last_ask_seconds = proposal.duration_seconds
            self._last_ask_rate = proposal.speed()[0]
        if proposal is not None and proposal.status == "completed":
            self._gate_reason = ""
        if proposal is None or proposal.status == "failed":
            self._mount(self.dialogue.failed(
                f"模型没能回答：{error or proposal.reason}", ["确定性命令不受影响，/help 列出全部"]))
            self._drain_queue()
            return
        if proposal.status == "skipped":
            self._offline(proposal.reason or "模型不可达", thinking)
            self._drain_queue()
            return
        notes = [line for line in [self._round_trip(proposal)] if line]
        if proposal.unclear:
            notes.append(f"  模型说不确定的地方：{proposal.unclear}")
        for item in proposal.dropped:
            notes.append(f"  已丢弃：{item}")
        if not proposal.steps:
            self._mount(self.dialogue.say("模型没有提出可执行的操作。", notes))
            self._drain_queue()
            return
        if self.journal is not None:
            self.journal.proposed(proposal.steps, proposal.dropped, proposal.unclear,
                                  proposal.duration_seconds, proposal.model)
        steps = [
            {"action": step.action, "label": step.label(),
             "impact": tuple(filter(None, [step.why, *by_name(step.action).impact]))}
            for step in proposal.steps
        ]
        # Every step is auto-runnable and none of them changes configuration:
        # nothing here writes, spends or blocks, so a second human beat would
        # be ceremony.  Anything else waits to be ticked.
        automatic = AUTO_RUN_READ_ONLY and all(self._auto_runnable(step) for step in proposal.steps)
        block = ProposalBlock(
            text=("模型理解为（只读，直接执行）：" if automatic else "模型建议的操作（默认都不勾选）："),
            steps=steps, lines=notes,
            chosen=tuple(range(len(steps))) if automatic else (),
        )
        self.dialogue.add(block)
        block.settled = automatic
        self._mount(block)
        if automatic:
            for step in proposal.steps:
                if self.journal is not None:
                    self.journal.auto_ran(step.action, step.subject,
                                          "auto_run: 不写入、不花钱、不阻塞")
            self._pending_steps = proposal.steps
            self._run_proposed(",".join(str(index + 1) for index in range(len(steps))))
            return
        self._pending_steps = proposal.steps
        if len(proposal.steps) == 1 and not proposal.steps[0].changes:
            # One step, and it confirms for itself.  Asking to tick it and then
            # asking again to run it is two prompts for one decision -- typing
            # `/scan ~/fw` by hand is one, and this should not be worse.
            block.text = "模型理解为（下面会各自确认）："
            block.chosen = (0,)
            block.settled = True
            self._repaint_block(block.block_id)
            self._run_proposed("1")
            return
        self._mount(self.dialogue.ask(Question(
            "ask.steps", "select",
            "要执行哪些？输入编号（如 1,2）、`全部`，或直接回车全部拒绝： ",
            options=tuple(step["label"] for step in steps),
        )))

    @staticmethod
    def _auto_runnable(step: Any) -> bool:
        """May a model-inferred step run without a second beat?

        Two conditions, and the second is not implied by the first.  A step
        that changes configuration never runs unattended whatever its action's
        policy: configuration is the model's measured highest-frequency error
        (live, it invented `llm.scanners=['memory-safety']`), and
        `validate_config` catches an invented leaf but cannot catch a valid
        value that is simply wrong for what the operator meant.
        """
        if getattr(step, "changes", None):
            return False
        try:
            return by_name(step.action).auto_run
        except UserError:
            return False

    def _offline(self, reason: str, thinking: Any = None) -> None:
        """Provider down is a gate, not a failure -- and it is said once.

        Free text is the main path now, so an unreachable host would otherwise
        paint the same wall of red after every line.  The first time it names
        the reason and what still works; after that it is one line.
        """
        utterance = getattr(thinking, "utterance", "") or ""
        # The hint is about *this* sentence, so it survives the repeat; the
        # explanation is about the host, and is said once.
        hint = offline_hint(utterance)
        hint_lines = [f"  你可能想要：{hint}"] if hint else []
        if reason == self._gate_reason:
            self._mount(self.dialogue.say("模型仍不可达（同上）", hint_lines))
            return
        self._gate_reason = reason
        self._mount(self.dialogue.say(f"模型不可达：{reason}", [
            "  离线仍然可用：/help 列出全部命令；/scan <目录>、/preflight <目录> 直接可用；",
            "  直接输入一个目录也可以。/llm-doctor 重新探测。",
            *hint_lines,
        ]))

    def _run_proposed(self, text: str) -> None:
        """Turn the ticked steps into the very commands the operator could type."""
        chosen = self._chosen(text, len(self._pending_steps))
        steps, self._pending_steps = self._pending_steps, []
        if not chosen:
            self._mount(self.dialogue.say("全部拒绝，什么也没执行。"))
            return
        for index in chosen:
            step = steps[index]
            line = f"/{step.action}"
            if step.subject is not None:
                line += f" {step.subject}"
            self._queued.append(line)
            for path, value in step.changes.items():
                # Quoted, so a value containing a space survives the round trip
                # through `submit()` -> `shlex.split`.
                self._queued.insert(len(self._queued) - 1,
                                    f"/set {path} {shlex.quote(str(value))}")
        self._drain_queue()

    @staticmethod
    def _chosen(text: str, total: int) -> list[int]:
        """Which steps the answer names: numbers, ranges, or all of them.

        `y` used to map to the question's `preselected`, which is empty for
        this question -- so "yes, all of them" selected nothing at all and
        silently ran nothing.
        """
        answer = text.strip().lower()
        if not answer or answer in {"n", "no", "否", "不", "取消", "全部拒绝"}:
            return []
        if answer in {"y", "yes", "全部", "all", "都要", "都跑", "确认"}:
            return list(range(total))
        chosen: list[int] = []
        for piece in answer.replace("，", ",").replace("、", ",").split(","):
            piece = piece.strip()
            if "-" in piece:
                low, _, high = piece.partition("-")
                if low.strip().isdigit() and high.strip().isdigit():
                    for index in range(int(low), int(high) + 1):
                        if 1 <= index <= total:
                            chosen.append(index - 1)
                continue
            if piece.isdigit() and 1 <= int(piece) <= total:
                chosen.append(int(piece) - 1)
        return list(dict.fromkeys(chosen))

    def _drain_queue(self) -> None:
        """One queued line at a time; the next starts when this one ends."""
        while self._queued and not self._occupied():
            self.submit(self._queued.pop(0))

    # --- running an action ---------------------------------------------------

    def _start(self, intent: Any) -> None:
        action = by_name(intent.action)
        if self._busy:
            self._mount(self.dialogue.failed("已经有一个操作在跑；等它结束，或用 /cancel 取消"))
            return
        try:
            request = self._request(action, intent)
        except UserError as exc:
            self._mount(self.dialogue.failed(single_line(str(exc))))
            return
        self._busy = True
        self._busy_since = time.time()
        block_id = ""
        # Every action gets a token, because Ctrl+C has to mean cancel for all
        # of them; only a long-running one gets a RunControl and a run block.
        self.cancel_token = CancellationToken()
        self._stop_event = threading.Event()
        if action.long_running:
            # The decider goes on the control, because that is the only channel
            # a run in flight has back to the conversation.  Without it
            # `RunControl.request_decision` fell through to its `_pending` map
            # and blocked forever: `ActionContext.decide` reaches the runner
            # only on the terminal branch, so the build-context patch -- which
            # `docs/usage.md` calls "a checkbox dialog in the TUI", and which
            # `_decider` below was written for -- could not be answered from
            # the conversation at all. Measured on TF-M: every run since the
            # feature landed sat at "待决策" until it was cancelled.
            self.control = RunControl(self.cancel_token,
                                      llm_jobs=int(request.config["llm"].get("jobs") or 1),
                                      decider=self._decider())
            # From the config this run will actually use, not from the session's.
            # The old run view drew its skeleton from `self.config` while the run
            # used the collected one, so a `--llm-scanner` on the command line
            # produced a diagram with five scanners that were never asked for.
            flow = RunFlow(request.config)
            run = self.dialogue.run(action.name, flow, control=self.control)
            self._mount(run)
            block_id = run.block_id
        self._run_action(action.name, request, block_id)

    def _request(self, action: Any, intent: Any) -> ActionRequest:
        """Turn a parsed line into what the registry takes.

        A subject is supplied only to an action that declares it needs one.
        Filling both for everything is how ``/serve`` in the conversation came
        to start a full analysis: ``_run_serve`` branches on
        ``request.source is not None``, and every request carried the
        session's source whether the action asked for one or not.
        """
        namespace = intent.values.get("namespace")
        source = report = None
        if action.subject == SUBJECT_SOURCE:
            source = intent.values.get("source") or self.dialogue.source
        elif action.subject == SUBJECT_REPORT:
            report = intent.values.get("report_directory") or self.dialogue.report_directory
        config = self.dialogue.config
        if namespace is not None:
            if action.subject == SUBJECT_SOURCE and getattr(namespace, "source", None):
                source = Path(namespace.source).expanduser().resolve()
            if action.subject == SUBJECT_REPORT and getattr(namespace, "report_directory", None):
                report = Path(namespace.report_directory).expanduser().resolve()
            overrides = (analyze_overrides(namespace) if action.cli_command in {"analyze", "serve"}
                         else assess_overrides(namespace) if hasattr(namespace, "llm_profile") else None)
            if overrides:
                # On top of the session's own config, not on top of DEFAULTS:
                # everything the operator set with /set has to survive a
                # command that also carries flags.
                config = apply_overrides(copy.deepcopy(config), overrides, sources=self.sources)
        if action.subject == SUBJECT_NONE and (source is not None or report is not None):
            raise UserError(f"{action.name} 不接受目标目录")
        if action.subject == SUBJECT_SOURCE and source is None:
            raise UserError(f"{action.name} 需要一个源码目录")
        if action.subject == SUBJECT_REPORT and report is None:
            raise UserError(f"{action.name} 需要一个报告目录")
        return ActionRequest(action.name, source=source, report_directory=report,
                             config=config, args=namespace,
                             values={"all": False, "filter": ""})

    @work(thread=True, exclusive=True, group="action")
    def _run_action(self, name: str, request: ActionRequest, block_id: str) -> None:
        action = by_name(name)
        asker = self._asker()
        try:
            if action.confirm == CONFIRM_ALWAYS:
                answer = asker(Question(
                    f"{action.name}.confirm", CONFIRM, "开始吗？ [y/N] ",
                    preview=(f"{action.summary}",
                             *(f"  {line}" for line in action.impact),
                             *(f"  将写入 {path}" for path in render_writes(action, request))),
                ))
                if not answer.yes:
                    self.call_from_thread(self._finished, block_id, name, None, "已取消")
                    return
            context = ActionContext(
                request=request,
                emit=self._emitter(block_id or name),
                ask=asker,
                decide=self._decider(),
                control=self.control,
                cancelled=(self.cancel_token.is_cancelled if self.cancel_token else (lambda: False)),
                terminal=False,
                stop=self._stop_event,
            )
            outcome = invoke(action, context)
        except UserError as exc:
            self.call_from_thread(self._finished, block_id, name, None, single_line(str(exc)), True)
            return
        except Exception as exc:  # a front end must not die of an action
            self.call_from_thread(self._finished, block_id, name, None,
                                  f"{type(exc).__name__}: {single_line(str(exc))}", True)
            return
        self.call_from_thread(self._finished, block_id, name, outcome, "")

    def _finished(self, block_id: str, name: str, outcome: Any, note: str, failed: bool = False) -> None:
        self._drain_events()
        self._busy = False
        run = self.dialogue.get(block_id) if block_id else None
        if isinstance(run, RunBlock):
            code = outcome.exit_code if outcome is not None else 130
            run.settle(code, outcome.summary if outcome is not None else note,
                       outcome.report_directory if outcome is not None else None)
            self._repaint_run(run)
        if outcome is not None:
            self.last_outcome = TuiOutcome(outcome.exit_code, outcome.report_directory)
            lines = list(outcome.lines)
            data = outcome.data if isinstance(outcome.data, dict) else {}
            if name == "llm-doctor" and isinstance(data.get("benchmark"), dict):
                self._last_benchmark = data["benchmark"]
                self._last_benchmark_at = time.time()
            if name in {"model", "llm-doctor"} and isinstance(data.get("models"), dict):
                # Reachability, not `ok`: a served context window smaller than
                # the configured one fails the probe while the endpoint is
                # answering perfectly well.
                served = data["models"]
                self._note_gate(bool(served.get("reachable") and served.get("model_present")),
                                served.get("reason"))
            if name == "model":
                lines.extend(self._measured_speeds())
            if not isinstance(run, RunBlock):
                self._mount(self.dialogue.say(outcome.summary, lines))
            if self.journal is not None:
                self.journal.finished(name, outcome.exit_code, outcome.report_directory)
        elif note:
            self._mount(self.dialogue.failed(note) if failed else self.dialogue.say(note))
        self.control = None
        self.cancel_token = None
        self._update_status()
        self._drain_queue()

    # --- the two seams a worker reaches back through -------------------------

    def _emitter(self, block_id: str) -> Any:
        """Called on the worker thread; queues, never repaints."""

        has_block = isinstance(self.dialogue.get(block_id), RunBlock)

        def emit(event: AnalysisEvent) -> None:
            self._queue_log_event(event)
            if event.status == "info" and not has_block:
                # An action with no run block has nowhere for progress to land,
                # so it was being dropped -- which is how `serve` announced its
                # URL to a transcript that never showed it.
                self.call_from_thread(self._mount, self.dialogue.say(single_line(event.message)))
                return
            with self._events_lock:
                if event.phase == "output" or event.status in {"heartbeat", "step", "info"}:
                    self._liveness_events.append((block_id, event))
                else:
                    self._pending_events.append((block_id, event))

        return emit

    def _asker(self) -> Asker:
        """A question becomes a block, and the worker waits for the answer.

        One ``call_from_thread`` per question -- which is a keystroke's worth
        of traffic, not an event's.  The wait polls a cancel predicate the way
        ``RunControl.request_decision`` does, so Ctrl+C releases it.
        """

        def reply(question: Question) -> Answer:
            done = threading.Event()
            box: dict[str, Answer] = {}
            self.call_from_thread(self._open_question, question, done, box)
            while not done.wait(0.1):
                if self.cancel_token is not None and self.cancel_token.is_cancelled():
                    return Answer(refused=True, interrupted=True, reason="run interrupted")
            return box.get("answer", Answer(refused=True, reason="no answer"))

        return Asker(reply, interactive=True)

    def _open_question(self, question: Question, done: threading.Event, box: dict[str, Answer]) -> None:
        block = self.dialogue.ask(question)
        self._waiting[block.block_id] = (done, box)
        self._mount(block)
        self._update_status()

    def _answer_pending(self, block_id: str, text: str) -> None:
        answer = Answer(text=text)
        question = self.dialogue.get(block_id)
        if question is not None and getattr(question, "question", None) is not None:
            spec = question.question
            if spec.kind == "select":
                answer = Answer(text=text, selected=self._ticked(spec, text))
        self.dialogue.answer(block_id, answer)
        if self.journal is not None:
            self.journal.answered(block_id, text)
        self._repaint_block(block_id)
        waiting = self._waiting.pop(block_id, None)
        if waiting is not None:
            done, box = waiting
            box["answer"] = answer
            done.set()
        elif getattr(question, "question", None) is not None and question.question.id == "save.confirm":
            target, self._pending_save = self._pending_save, None
            if answer.yes and target is not None:
                self._save_now(target)
            else:
                self._mount(self.dialogue.say("没有写入。"))
        elif self._pending_steps and getattr(question, "question", None) is not None \
                and question.question.id == "ask.steps":
            self._run_proposed(text)
        self._update_status()

    @staticmethod
    def _ticked(spec: Any, text: str) -> tuple[int, ...]:
        """Which items a select answer names.

        ``y`` keeps its historical meaning -- the pre-ticked set, which is
        exactly what the build-context dialog's own prompt offers -- and
        numbers, ranges and `全部` reach the items the dialog draws *unticked*.
        Without them the checkbox dialog was a yes/no question with checkboxes
        painted on it: a stub header is offered per item and deliberately never
        pre-ticked, so until now it could not be accepted at all, in the one
        front end whose documentation calls this a checkbox dialog.
        """
        answer = text.strip().lower()
        if answer in {"y", "yes", "确认"}:
            return tuple(spec.preselected)
        if answer in {"全部", "all", "都要", "都跑"}:
            return tuple(range(len(spec.options)))
        return tuple(AnalyzerApp._chosen(text, len(spec.options)))

    def _decider(self) -> Any:
        """The build-context patch, asked as the conversation asks anything."""
        from .ask import question_from_decision
        from .control import Decision

        asker = self._asker()

        def decide(request: Any) -> Decision:
            answer = asker(question_from_decision(request))
            # What the operator ticked, not what the dialog opened with: a
            # bare `y` still means the pre-ticked set, because `_ticked` says
            # so, but an answer naming items now reaches the patch instead of
            # being computed and thrown away.
            if answer.selected:
                return Decision("apply", tuple(answer.selected), decided_by="tui")
            if answer.yes:
                return Decision("apply", tuple(request.preselected), decided_by="tui")
            return Decision("reject", decided_by="tui", note="declined in the conversation")

        return decide

    # --- painting ------------------------------------------------------------

    def _mount(self, block: Block) -> Any:
        """One widget per block, mounted once.  Never one per event."""
        try:
            transcript = self.query_one("#transcript", VerticalScroll)
        except NoMatches:
            return None
        widget: Any
        if isinstance(block, RunBlock):
            widget = RunBlockWidget(block, id=f"b-{block.block_id}")
        else:
            widget = Static(self._block_text(block), id=f"b-{block.block_id}",
                            classes=f"block block-{block.kind}")
        transcript.mount(widget)
        transcript.scroll_end(animate=False)
        return widget

    def _block_text(self, block: Block) -> Text:
        from .dialogue import ThinkingBlock

        if isinstance(block, ThinkingBlock):
            text = Text()
            for index, line in enumerate(block.render(frame=self._frame())):
                if index:
                    text.append("\n")
                # The chain of thought is the model's, not the tool's: dim, so
                # the line that says what is happening stays the loud one.
                thought = line.lstrip().startswith(("▾ 思维链", "│ "))
                style = "dim" if (block.settled or thought) else "bold yellow"
                text.append(line, style=style)
            return text
        style = _BLOCK_STYLES.get(block.kind, "")
        text = Text()
        for index, line in enumerate(block.render()):
            if index:
                text.append("\n")
            text.append(line, style=style)
        return text

    def _repaint_block(self, block_id: str) -> None:
        block = self.dialogue.get(block_id)
        if block is None:
            return
        try:
            widget = self.query_one(f"#b-{block_id}", Static)
        except NoMatches:
            return
        text = self._block_text(block)
        widget.display = bool(text.plain.strip())
        widget.update(text)

    def _frame(self) -> int:
        """The frame every animated thing on screen shares; -1 when motion is off."""
        return self._flow_frame if self._flow_animated else -1

    def _tick(self) -> None:
        if not self.is_mounted:
            return
        moved = self._drain_events()
        if self._flow_animated:
            self._flow_frame += 1
        run = self.dialogue.live_run()
        if run is not None and (moved or self._flow_animated):
            self._repaint_run(run)
        if self._flow_animated and self._busy:
            # A spinner at 1 Hz reads as a stuck spinner, so the two things that
            # move without a run block are driven from here instead of the clock.
            thinking = self.dialogue.live_thinking()
            if thinking is not None:
                self._repaint_block(thinking.block_id)
            if run is None:
                # A short action has no run block to spin.  `/llm-doctor` is a
                # real generation -- 18-52s measured -- with nothing else moving.
                self._update_status()

    def _tick_clock(self) -> None:
        run = self.dialogue.live_run()
        if run is not None:
            self._repaint_run(run)
        # A seconds counter does not need 5 Hz; the 0.2s tick is the run budget.
        thinking = self.dialogue.live_thinking()
        if thinking is not None:
            self._repaint_block(thinking.block_id)
        self._update_status()  # the seconds still advance with the animation off

    def _drain_events(self) -> int:
        with self._events_lock:
            batch: list[tuple[str, AnalysisEvent]] = []
            while self._pending_events and len(batch) < DRAIN_PER_TICK:
                batch.append(self._pending_events.popleft())
            while self._liveness_events and len(batch) < DRAIN_PER_TICK:
                batch.append(self._liveness_events.popleft())
        for block_id, event in batch:
            self.dialogue.apply(block_id, event)
        return len(batch)

    def _repaint_run(self, run: RunBlock) -> None:
        try:
            widget = self.query_one(f"#b-{run.block_id}", RunBlockWidget)
        except NoMatches:
            return
        widget.title = run.headline()
        if widget.collapsed:
            return
        widget.body.update(self._run_body(run, widget.body.size.width or 80))

    def _run_body(self, run: RunBlock, width: int) -> Text:
        """The whole run view, as one Text: the diagram, the bars, the answers."""
        text = Text(no_wrap=True, overflow="ellipsis")
        flow = run.flow
        if flow is None:
            return text
        now = time.time()
        frame = self._frame()
        rows = flow.rows(capacity=self._flow_capacity, now=now, frame=frame)
        text.append_text(self._flow_text(rows))
        lanes = [lane for lane in flow.lanes() if lane.id != "total"]
        if lanes:
            text.append("\n")
            text.append_text(self._lane_text(lanes))
        if flow.llm_enabled and run.chat is not None:
            # A settled run kept its last summary when it released its turns.
            summary = run.final_summary if run.settled else run.chat.summary()
            text.append("\n")
            text.append("⚡ " + summary if summary else "⚡ 等待模型的第一个 token…",
                        style="" if summary else "dim")
            text.append("\n")
            text.append_text(self._llm_text(flow))
            chat_lines = self._chat_text(run, width)
            if chat_lines.plain:
                text.append("\n")
                text.append_text(chat_lines)
        problems = flow.problems(limit=6)
        if problems:
            text.append("\n")
            for item in problems:
                text.append(f"\n{'✕' if item.level == 'error' else '◐'} {item.tool:<24} {item.reason} ×{item.count}",
                            style="red" if item.level == "error" else "yellow")
        return text

    def _chat_text(self, run: RunBlock, width: int) -> Text:
        """The model's transcript, wrapped to the block so the tail stays exact."""
        if run.chat is None:
            return Text()
        rows = 14
        lines = run.chat.lines(capacity=rows * 4, show_prompts=self._show_prompts)
        wrapped: list[tuple[str, str]] = []
        for line in lines:
            style = _CHAT_STYLES.get(line.role, "")
            for piece in chop_cells(line.text, max(20, width)) or [""]:
                wrapped.append((piece, style))
        text = Text(no_wrap=True, overflow="crop")
        for index, (piece, style) in enumerate(wrapped[-rows:]):
            if index:
                text.append("\n")
            text.append(piece, style=style)
        return text

    def _flow_text(self, rows: list[Any]) -> Text:
        """Built segment by segment, never from markup.

        Scanned file names reach these rows, so a path literally named
        ``[bold red]x[/]`` must render as itself rather than as a style.
        """
        text = Text(no_wrap=True, overflow="ellipsis")
        for index, row in enumerate(rows):
            if index:
                text.append("\n")
            marker = "▶" if row.selected else " "
            if row.spine:
                text.append(row.spine + marker, style=_SPINE_STYLES[row.pulse % len(_SPINE_STYLES)])
            else:
                text.append(" " + marker)
            if row.glyph:
                text.append(row.glyph + " ", style=_STATE_STYLES[row.state])
            text.append(row.label.ljust(_LABEL_WIDTH) if row.detail else row.label)
            if row.detail:
                text.append(" " + row.detail, style="dim")
        return text

    @staticmethod
    def _lane_text(lanes: list[Lane]) -> Text:
        text = Text(no_wrap=True, overflow="ellipsis")
        for index, lane in enumerate(lanes):
            if index:
                text.append("\n")
            filled = max(0, min(_BAR_WIDTH, round(lane.fraction * _BAR_WIDTH)))
            text.append(lane.label + " " * max(1, _LANE_LABEL_CELLS - cell_len(lane.label)))
            text.append(_BAR_FULL * filled, style="cyan")
            text.append(_BAR_EMPTY * (_BAR_WIDTH - filled), style="dim")
            text.append(f" {int(lane.fraction * 100):>3}%  ")
            text.append(lane.detail, style="dim")
        return text

    @staticmethod
    def _llm_text(flow: RunFlow) -> Text:
        """The per-scanner panel, built segment by segment like the flow."""
        text = Text(no_wrap=True, overflow="ellipsis")
        for index, row in enumerate(flow.llm_rows()):
            if index:
                text.append("\n")
            glyph = {"success": "✓", "partial": "◐", "failed": "✕",
                     "running": "⏸" if row.paused else "●", "pending": "○"}[row.state]
            text.append(glyph + " ", style=_STATE_STYLES[row.state])
            text.append(f"{row.producer:<26} {row.counted:<12}")
            extras = []
            if row.failures:
                extras.append(f"{row.failures} 失败")
            if row.unscheduled:
                extras.append(f"{row.unscheduled} 未调度")
            if row.findings is not None:
                extras.append(f"{row.findings} findings")
            if row.step:
                extras.append(row.step)
            text.append(" " + " · ".join(extras), style="dim")
        return text

    def _note_gate(self, ok: bool, reason: str | None) -> None:
        from .llm.propose import note_gate

        note_gate(self.dialogue.config, ok, reason)
        self._gate_reason = "" if ok else (reason or self._gate_reason)

    @staticmethod
    def _round_trip(proposal: Any) -> str:
        """Model, seconds, tokens per second -- for the round trip just paid for.

        It was measured every time and shown nowhere: only the *next* wait ever
        mentioned it, as "上次 21.7s".
        """
        parts = [proposal.model or "", f"{proposal.duration_seconds:.1f}s"
                 if proposal.duration_seconds else ""]
        rate, basis = proposal.speed()
        if rate is not None:
            parts.append(f"{rate} tok/s（{basis}）")
        if proposal.completion_tokens:
            parts.append(f"输出 {proposal.completion_tokens} token")
        joined = " · ".join(part for part in parts if part)
        return f"  {joined}" if joined else ""

    def _scan_rate(self) -> float | None:
        """Tokens per second from the last run that measured any."""
        for block in reversed(self.dialogue.blocks):
            if isinstance(block, RunBlock) and block.final_stats is not None:
                return block.final_stats.session_tok_s
        run = self.dialogue.live_run()
        return run.chat.stats().session_tok_s if run is not None else None

    def _measured_rate(self) -> float | None:
        """The best tokens-per-second this session measured, or nothing."""
        if self._last_benchmark and self._last_benchmark.get("tokens_per_second"):
            return float(self._last_benchmark["tokens_per_second"])
        if self._last_ask_rate is not None:
            return self._last_ask_rate
        return self._scan_rate()

    def _model_mark(self) -> str:
        """The provider, ambiently.  Reads the gate's cache; never probes.

        Three states, not two: reachable, unreachable, and *not asked yet* --
        which is drawn as the bare name, because a status line that guesses is
        worse than one that stays quiet.
        """
        from .llm.propose import cached_gate

        llm = self.dialogue.config["llm"]
        name = str(llm.get("model") or "").strip()
        if not name:
            return "未配置模型"
        parts = [name]
        if not llm.get("enabled"):
            parts.append("未启用")
        else:
            ok, _reason, _age = cached_gate(self.dialogue.config)
            if ok is True:
                parts.append("✓")
            elif ok is False:
                parts.append("✕")
        rate = self._measured_rate()
        if rate is not None:
            parts.append(f"{rate} tok/s")
        return " ".join(parts)

    def _measured_speeds(self) -> list[str]:
        """Every speed this session measured, each said to be a measurement.

        The action itself cannot know these -- they are facts about this
        conversation, not about the configuration -- so the front end appends
        them to what `/model` read from the endpoint.
        """
        lines: list[str] = []
        benchmark = self._last_benchmark or {}
        if benchmark.get("tokens_per_second"):
            ago = max(0, int(time.time() - self._last_benchmark_at))
            lines.append(f"  · 一次生成：{benchmark['tokens_per_second']} tok/s，"
                         f"整个请求 {benchmark.get('latency_seconds')}s"
                         f"（/llm-doctor 实测，{ago}s 前）")
        if self._last_ask_seconds:
            rate = f"，{self._last_ask_rate} tok/s" if self._last_ask_rate is not None else ""
            lines.append(f"  · 理解一句话的往返：{self._last_ask_seconds:.1f}s{rate}（实测）")
        rate = self._scan_rate()
        if rate is not None:
            lines.append(f"  · 扫描时的模型对话：{rate} tok/s（会话均值，实测）")
        if not lines:
            return ["本会话还没有测到任何速度。`/llm-doctor` 实测一次（一次真实生成，"
                    "计费、18–52 秒），或者随便说一句话让它跑一趟。"]
        return ["本会话测得的速度：", *lines]

    def _update_status(self) -> None:
        try:
            status = self.query_one("#status", Static)
        except NoMatches:
            return
        parts: list[str] = []
        run = self.dialogue.live_run()
        thinking = self.dialogue.live_thinking()
        if thinking is not None:
            parts.append(f"{spin(self._frame())} 模型思考中 "
                         f"{max(0, int(time.time() - thinking.started_at))}s")
            parts.append("Ctrl+C 放弃")
        elif run is not None and run.flow is not None:
            head = run.flow.headline(time.time())
            parts.append(f"{head.percent}%")
            if run.flow.llm_enabled:
                parts.append("LLM ⏸" if run.flow.paused["llm"] else "LLM ▶")
            parts.append("Ctrl+C 取消")
        elif self._busy:
            # Not every action draws a run block; this is the only sign of life
            # a `/doctor` or an `/llm-doctor` has, and both take real minutes.
            elapsed = max(0, int(time.time() - self._busy_since))
            parts.append(f"{spin(self._frame())} 运行中 {elapsed}s")
            parts.append("Ctrl+C 取消")
        elif self.dialogue.pending_question() is not None:
            parts.append("等你回答上面的问题")
        else:
            parts.append(self._model_mark())
            parts.append(str(self.source))
        if self._queued:
            parts.append(f"排队 {len(self._queued)}")
        if self.dirty:
            parts.append("● 配置未保存")
        parts.append("/help")
        status.update(single_line(" · ".join(parts)))

    # --- the log -------------------------------------------------------------

    def _log_wanted(self, event: AnalysisEvent) -> bool:
        if event.phase == "output" and event.stream == "prompt":
            return False
        if self._log_filter == "all":
            return True
        level = LEVELS.index(level_of(event))
        return level >= LEVELS.index("warning" if self._log_filter == "warn" else "error")

    def _queue_log_event(self, event: AnalysisEvent) -> None:
        if not self._log_wanted(event):
            return
        line = self._format_log_event(event)
        with self._log_lock:
            if len(self._pending_log_lines) >= 2000:
                self._pending_log_lines.popleft()
                if not self._log_overflowed:
                    self._log_overflowed = True
                    while len(self._pending_log_lines) >= 1999:
                        self._pending_log_lines.popleft()
                    self._pending_log_lines.append(
                        time.strftime("%H:%M:%S")
                        + " [system/-][status] 界面日志过载：已丢弃最旧的待显示行；完整输出仍保存在报告目录"
                    )
            while len(self._pending_log_lines) >= 2000:
                self._pending_log_lines.popleft()
            self._pending_log_lines.append(line)

    @staticmethod
    def _format_log_event(event: AnalysisEvent) -> str:
        if event.phase == "output":
            clock = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
            return f"{clock}  {event.tool or event.phase}/{event.unit or '-'}  [{event.stream or 'stdout'}]  {single_line(event.message)}"
        return format_line(event, local=True)

    def _flush_log_queue(self) -> None:
        lines: list[str] = []
        with self._log_lock:
            for _ in range(min(200, len(self._pending_log_lines))):
                lines.append(self._pending_log_lines.popleft())
        if not lines or not self.is_mounted:
            return
        try:
            log = self.query_one("#log", RichLog)
        except NoMatches:
            with self._log_lock:
                self._pending_log_lines.extendleft(reversed(lines))
            return
        for line in lines:
            log.write(line)

    # --- actions -------------------------------------------------------------

    def action_focus_prompt(self) -> None:
        """Back to the box; on an empty box, drop whatever is queued.

        The queue exists so a minute of thinking does not lock the operator
        out.  It also needs an undo, or a line typed in haste runs a minute
        later when they have changed their mind.
        """
        prompt = self.query_one("#prompt", Input)
        if not prompt.value.strip() and self._queued:
            dropped, self._queued = len(self._queued), []
            self._mount(self.dialogue.say(f"已清空队列（{dropped} 条）。"))
            self._update_status()
        prompt.value = ""
        prompt.focus()

    def action_help(self) -> None:
        self._mount(self.dialogue.say("", help_lines()))

    def action_toggle_log(self) -> None:
        self.toggle_class("show-log")

    def action_cycle_filter(self) -> None:
        index = LOG_FILTERS.index(self._log_filter)
        self._log_filter = LOG_FILTERS[(index + 1) % len(LOG_FILTERS)]
        self.query_one("#log", RichLog).border_title = f"日志 · {FILTER_LABELS[self._log_filter]}"

    def action_toggle_prompts(self) -> None:
        self._show_prompts = not self._show_prompts
        run = self.dialogue.live_run()
        if run is not None:
            self._repaint_run(run)

    def action_toggle_last_run(self) -> None:
        widgets = list(self.query(RunBlockWidget))
        if widgets:
            widgets[-1].collapsed = not widgets[-1].collapsed
            self._repaint_run(widgets[-1].block)

    def action_save(self, destination: Path | None = None) -> None:
        """Ask before replacing a file on disk.

        The only write the conversation performs outside an action, so it needs
        the beat an action gets from `Action.confirm` -- it replaces a config
        file whole, comments and ordering included.
        """
        target = destination or (self.explicit_config or self.source / ".code-analyzer.toml")
        self._pending_save = target
        self._mount(self.dialogue.ask(Question(
            "save.confirm", CONFIRM, "写入吗？ [y/N] ",
            preview=("把当前会话配置写成完整的 schema v2 快照",
                     f"  将写入 {target}" + ("（覆盖已有文件）" if target.exists() else ""),
                     "  原文件的注释与键顺序不会保留。"),
        )))

    def _save_now(self, target: Path) -> None:
        try:
            saved = save_config_snapshot(self.source, self.dialogue.config, target, overwrite=True)
        except (UserError, OSError) as exc:
            self._mount(self.dialogue.failed(f"保存失败：{single_line(str(exc))}"))
            return
        self.dirty = False
        self._mount(self.dialogue.say(f"已保存配置快照：{saved}"))
        self._update_status()

    def action_cancel_or_exit(self) -> None:
        """Abandon, cancel, answer, exit -- in that order.

        The old first branch tested ``self.control is not None``, which is None
        for every action that is not long-running and for the ask lane. So
        Ctrl+C during a model round trip fell all the way through and **exited
        the application**, under a block that said 「Ctrl+C 打断」.
        """
        thinking = self.dialogue.live_thinking()
        if thinking is not None:
            self._abandon_thinking(thinking)
            return
        run = self.dialogue.live_run()
        if self._busy and self.cancel_token is not None:
            if self.control is not None:
                self.control.cancel("tui")
            else:
                self.cancel_token.cancel()
            if self._stop_event is not None:
                # An action that serves or waits watches this rather than the
                # token, because it never reaches a cancellation checkpoint.
                self._stop_event.set()
            if run is not None and run.flow is not None:
                run.flow.mark_stopping()
            self._mount(self.dialogue.say("已请求安全停止；正在等待当前进程终止并回收。"))
            return
        pending = self.dialogue.pending_question()
        if pending is not None:
            self._answer_pending(pending.block_id, "")
            return
        self._exit_with_last()

    def _abandon_thinking(self, thinking: Any) -> None:
        """Detach, which is not the same as killing it.

        ``HarnessRuntime`` polls the cancel predicate only inside its
        notification callback, and the SDK exposes no cancel handle, so the
        measured 18-52s before the first token is genuinely uninterruptible.
        We stop waiting, say so plainly, and drop the answer when it lands.
        """
        from .llm.profiles import third_party_warning

        self._ask_generation += 1
        if self.cancel_token is not None:
            self.cancel_token.cancel()
        thinking.settled = True
        thinking.summary = "已放弃这次理解；请求可能仍在提供方那边跑，晚到的回答会被丢弃。"
        if third_party_warning(self.dialogue.config["llm"]):
            thinking.summary += "第三方计费仍会发生。"
        self._repaint_block(thinking.block_id)
        self._busy = False
        self._update_status()

    def _exit_with_last(self) -> None:
        if self.journal is not None:
            self.journal.close()
        self.exit(self.last_outcome or TuiOutcome())


def run_tui(source: Path, explicit_config: Path | None = None) -> TuiOutcome:
    outcome = AnalyzerApp(source, explicit_config).run()
    return outcome if isinstance(outcome, TuiOutcome) else TuiOutcome()

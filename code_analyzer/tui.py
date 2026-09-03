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
from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import (
    Grid,
    Horizontal,
    HorizontalGroup,
    Vertical,
    VerticalScroll,
)
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    RichLog,
    Select,
    SelectionList,
    Static,
)

from .analysis import (
    AnalysisEvent,
    AnalysisRequest,
    AnalysisResult,
    CancellationToken,
    run_analysis,
)
from .chat import Transcript
from .config import (
    FIELD_BY_PATH,
    FieldSpec,
    config_value,
    load_config_with_sources,
    save_config_snapshot,
    set_config_value,
    validate_config,
)
from .control import Decision, DecisionRequest, RunControl
from .errors import UserError
from .flow import WIDE_BREAKPOINT, Lane, RunFlow, capacity
from .preflight import PreflightResult, run_preflight
from .progress import animation_disabled_by_env, single_line
from .runlog import LEVELS, format_line, level_of
from .tools import TOOL_NAMES

# Actions that only mean something while a scan runs; check_action keeps
# their keys free for the form otherwise.
RUN_ONLY_ACTIONS = frozenset({
    "cycle_pane", "cycle_filter", "toggle_pause_llm", "toggle_pause_static", "skip_selected",
    "jobs_up", "jobs_down", "cursor_up", "cursor_down", "node_detail", "open_decision", "retry_llm",
    "toggle_prompts",
})
# "chat" first: when a model is answering, the answer is what the operator is
# here for.  It is dropped from the cycle when the LLM lane is off, the way
# the LLM pane already is -- an empty transcript is not a pane worth a keypress.
PANES = ("chat", "log", "llm", "problems")
PANE_LABELS = {"chat": "对话", "log": "日志", "llm": "LLM 明细", "problems": "问题"}
LLM_ONLY_PANES = frozenset({"chat", "llm"})
LOG_FILTERS = ("all", "warn", "error", "selected")
FILTER_LABELS = {"all": "全部", "warn": "警告+", "error": "仅错误", "selected": "仅所选"}
# How many queued events one 5 Hz tick folds at most; liveness events
# (heartbeat, step, output) are dropped first when the queue overflows.
DRAIN_PER_TICK = 5000
LIVENESS_QUEUE = 5000

TUI_FIELDS = (
    "run.output_root",
    "build.compile_database_mode",
    "build.compile_database",
    "build.include",
    "build.define",
    "build.c_standard",
    "build.assist",
    "tools.cppcheck.enabled",
    "tools.flawfinder.enabled",
    "tools.splint.enabled",
    "run.shareable_export",
    "review.fail_on",
    "llm.enabled",
)
# List-valued fields are one Input each, items separated by ';'.
LIST_SEPARATOR = ";"


# Node state -> colour, and the three-step ramp the spine cell walks so a dot
# appears to travel down the fan-out without any character changing.
_STATE_STYLES = {"success": "green", "partial": "yellow", "failed": "red", "running": "bold cyan", "pending": "dim"}
_SPINE_STYLES = ("bold cyan", "cyan", "dim cyan")
_LABEL_WIDTH = 24
# Transcript line role -> colour.  The answer itself is left unstyled: it is
# the content, and everything around it is furniture.
_CHAT_STYLES = {
    "header": "bold cyan",
    "prompt-title": "bold yellow",
    "prompt": "yellow",
    "answer": "",
    "tool": "magenta",
    "note": "bold red",
    "footer": "dim",
    "omitted": "dim italic",
}
# The lane bars under the overall progress bar.
_LANE_LABEL_CELLS = 12
_BAR_WIDTH = 22
_BAR_FULL = "█"
_BAR_EMPTY = "░"

GRADING_NOTE = (
    "所有新报告固定采用 NXP i.MX RT700 AVA Test Plan 第 7 章的 "
    "Information / Style / Warning / Error 分级；未直接匹配的工具等级显示为 Unmapped。"
)


@dataclass(frozen=True)
class TuiOutcome:
    exit_code: int = 0
    report_directory: Path | None = None


class ConfirmScreen(ModalScreen[bool]):
    BINDINGS = [Binding("escape", "dismiss_no", "返回")]

    def __init__(self, title: str, message: str, *, yes: str = "确认", no: str = "返回") -> None:
        super().__init__()
        self.dialog_title = title
        self.message = message
        self.yes = yes
        self.no = no

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self.dialog_title, classes="dialog-title")
            yield Static(self.message, id="dialog-message")
            with Horizontal(classes="dialog-buttons"):
                yield Button(self.no, id="no")
                yield Button(self.yes, id="yes", variant="primary")

    @on(Button.Pressed, "#yes")
    def yes_pressed(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def no_pressed(self) -> None:
        self.dismiss(False)

    def action_dismiss_no(self) -> None:
        self.dismiss(False)


class PathScreen(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "返回")]

    def __init__(self, title: str, value: str) -> None:
        super().__init__()
        self.dialog_title = title
        self.value = value

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self.dialog_title, classes="dialog-title")
            yield Input(self.value, id="path-value")
            yield Static("已有文件将用完整 schema v2 快照替换；原注释和顺序不会保留。", classes="warning")
            with Horizontal(classes="dialog-buttons"):
                yield Button("返回", id="cancel")
                yield Button("继续", id="accept", variant="primary")

    @on(Button.Pressed, "#accept")
    def accept(self) -> None:
        self.dismiss(self.query_one("#path-value", Input).value.strip() or None)

    @on(Button.Pressed, "#cancel")
    def cancel_pressed(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class PatchScreen(ModalScreen[Decision]):
    """A build-context patch, item by item, with the probe's verdict and the impact.

    Built from ``Text`` segments like the flow panel: header names come from
    analyzer output about untrusted code and must render as themselves.
    """

    BINDINGS = [
        Binding("escape", "reject", "全部拒绝"),
        Binding("l", "defer", "稍后决定"),
    ]

    def __init__(self, request: DecisionRequest) -> None:
        super().__init__()
        self.request = request

    def compose(self) -> ComposeResult:
        request = self.request
        probe = request.probe or {}
        with Vertical(id="dialog"):
            yield Label(f"构建上下文补丁 · {request.id} · 第 {request.round} 轮", classes="dialog-title")
            yield Static(Text(single_line(request.summary)), id="patch-summary")
            if probe:
                yield Static(Text(
                    f"探针：{probe.get('sampled', 0)} 个样本，应用补丁后 {probe.get('reached_after', 0)} 个可完成预处理"
                    f"（此前 {probe.get('reached_before', 0)} 个）"
                ), classes="warning" if not probe.get("reached_after") else "")
            options = []
            for index, item in enumerate(request.items):
                label = Text()
                label.append(single_line(str(item.get("label") or item.get("op")))[:60])
                if item.get("evidence"):
                    label.append("  " + single_line(str(item["evidence"]))[:70], style="dim")
                label.append(f"  {'推断' if item.get('origin') == 'deterministic' else 'LLM'}", style="italic")
                options.append((label, index, index in request.preselected))
            yield SelectionList(*options, id="patch-items")
            yield Static(
                "影响：仅在本报告目录内重跑失败的单元（新单元目录，原报告保留）；不修改 .code-analyzer.toml；"
                "不运行任何构建命令；不安装工具。桩头文件写在报告目录内并放在 -I 最后。",
                classes="warning",
            )
            with Horizontal(classes="dialog-buttons"):
                yield Button("稍后决定 (l)", id="defer")
                yield Button("全部拒绝 (Esc)", id="reject")
                yield Button("应用所选", id="apply", variant="primary")

    @on(Button.Pressed, "#apply")
    def apply_pressed(self) -> None:
        selected = tuple(sorted(int(value) for value in self.query_one("#patch-items", SelectionList).selected))
        self.dismiss(Decision("apply" if selected else "reject", selected, "tui", "" if selected else "nothing selected"))

    @on(Button.Pressed, "#reject")
    def reject_pressed(self) -> None:
        self.action_reject()

    @on(Button.Pressed, "#defer")
    def defer_pressed(self) -> None:
        self.action_defer()

    def action_reject(self) -> None:
        self.dismiss(Decision("reject", (), "tui"))

    def action_defer(self) -> None:
        self.dismiss(Decision("defer", (), "tui"))


class RetryScreen(ModalScreen[str | None]):
    """Ask the LLM lane to try again: every unit that never got an answer, or only the transport failures."""

    BINDINGS = [Binding("escape", "cancel", "取消")]

    def __init__(self, failed: int, unscheduled: int, transport: int, reasons: dict[str, int]) -> None:
        super().__init__()
        self.failed, self.unscheduled, self.transport, self.reasons = failed, unscheduled, transport, reasons

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("重试 LLM 单元", classes="dialog-title")
            yield Static(Text(
                f"失败 {self.failed} · 未调度 {self.unscheduled} · 其中传输/提供方失败 {self.transport}\n"
                + ("原因：" + "；".join(f"{reason} {count}" for reason, count in sorted(self.reasons.items(), key=lambda kv: (-kv[1], kv[0]))[:6]) if self.reasons else "")
            ))
            yield Checkbox("仅重试传输/提供方失败的单元", value=bool(self.transport), id="transport-only")
            yield Static("重试会重新合上断路器，在当前运行内以新的一轮（r<N>/）重新扫描；已有证据保留。", classes="warning")
            with Horizontal(classes="dialog-buttons"):
                yield Button("取消 (Esc)", id="cancel")
                yield Button("重试", id="retry", variant="primary")

    @on(Button.Pressed, "#retry")
    def retry_pressed(self) -> None:
        self.dismiss("transport" if self.query_one("#transport-only", Checkbox).value else "all")

    @on(Button.Pressed, "#cancel")
    def cancel_pressed(self) -> None:
        self.action_cancel()

    def action_cancel(self) -> None:
        self.dismiss(None)


class InfoScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "close", "关闭")]

    def __init__(self, title: str, message: str) -> None:
        super().__init__()
        self.dialog_title = title
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self.dialog_title, classes="dialog-title")
            yield Static(self.message, id="dialog-message")
            yield Button("关闭", id="close", variant="primary")

    @on(Button.Pressed, "#close")
    def close_pressed(self) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


class AnalyzerApp(App[TuiOutcome]):
    TITLE = "Code Analyzer"
    SUB_TITLE = "基础扫描"
    BINDINGS = [
        Binding("ctrl+s", "save", "保存", priority=True),
        Binding("f5", "preflight", "预检", priority=True),
        Binding("f9", "run", "运行", priority=True),
        Binding("ctrl+c", "cancel_or_exit", "取消/退出", priority=True),
        Binding("escape", "escape", "返回", priority=True),
        Binding("f1", "grading_info", "分级说明"),
        Binding("f2", "toggle_flow", "流程图"),
        Binding("f3", "cycle_pane", "面板"),
        Binding("f4", "cycle_filter", "过滤"),
        Binding("f6", "toggle_prompts", "提示词"),
        Binding("p", "toggle_pause_llm", "暂停LLM", show=False),
        Binding("P", "toggle_pause_static", "暂停静态", show=False),
        Binding("s", "skip_selected", "跳过", show=False),
        Binding("plus", "jobs_up", "并发+", show=False),
        Binding("minus", "jobs_down", "并发-", show=False),
        Binding("up", "cursor_up", "上一节点", show=False),
        Binding("down", "cursor_down", "下一节点", show=False),
        Binding("enter", "node_detail", "节点详情", show=False),
        Binding("d", "open_decision", "决策", show=False),
        Binding("r", "retry_llm", "重试 LLM", show=False),
    ]
    CSS = """
    Screen { background: $surface; }
    #workspace { height: 1fr; }
    #forms { width: 100%; max-width: 96; height: 1fr; padding: 1 2 0 2; align-horizontal: center; }
    .wide #forms { max-width: 136; }
    #form-columns { layout: grid; grid-size: 1; grid-columns: 1fr; grid-rows: auto; grid-gutter: 0 2; height: auto; }
    .wide #form-columns { grid-size: 2; }
    .column { height: auto; }
    .section-title { text-style: bold; color: $primary; margin: 1 0 0 0; }
    .section-title.first { margin-top: 0; }
    .field { height: auto; margin-bottom: 1; }
    .field-bool { margin-bottom: 0; }
    .field Label { height: 1; color: $text-muted; }
    .field Input, .field Select { width: 100%; }
    .inline-row { height: auto; }
    .inline-row Input { width: 1fr; }
    .inline-row Button { margin-left: 1; }
    #grading-link { height: 1; margin-top: 1; color: $text-muted; }
    #basic-actions { height: auto; margin: 1 2 0 2; layout: horizontal; align-horizontal: right; }
    #basic-actions Button { margin-left: 1; }
    #status-line { height: 1; padding: 0 1; background: $boost; }
    #too-small { display: none; dock: top; height: 3; background: $error; color: $text; content-align: center middle; }
    .too-small #too-small { display: block; }
    #running { display: none; height: 1fr; background: $panel; padding: 1 2; }
    .running #workspace, .running #status-line { display: none; }
    .running #running { display: block; }
    #run-heading { height: 1; text-style: bold; }
    #run-details { height: 1; color: $text-muted; }
    #run-progress { height: 1; }
    #run-bars { height: auto; text-wrap: nowrap; text-overflow: ellipsis; }
    #run-speed { height: 1; color: $accent; text-wrap: nowrap; text-overflow: ellipsis; }
    #run-body { height: 1fr; layout: vertical; }
    #run-flow { height: auto; border: round $accent; background: $surface-darken-1;
                padding: 0 1; text-wrap: nowrap; text-overflow: ellipsis; }
    #run-side { height: 1fr; layout: vertical; }
    #run-log { height: 1fr; border: round $primary; background: $surface-darken-1; }
    #run-llm { display: none; height: auto; max-height: 10; border: round $accent; background: $surface-darken-1;
               padding: 0 1; text-wrap: nowrap; text-overflow: ellipsis; }
    #run-problems { display: none; height: 1fr; border: round $warning; background: $surface-darken-1; }
    #run-chat { display: none; height: 1fr; border: round $success; background: $surface-darken-1;
                padding: 0 1; }
    .pane-llm #run-llm { display: block; }
    .pane-llm #run-log { display: none; }
    .pane-problems #run-problems { display: block; }
    .pane-problems #run-log { display: none; }
    .pane-chat #run-chat { display: block; }
    .pane-chat #run-log { display: none; }
    .wide #run-body { layout: horizontal; }
    .wide #run-flow { width: 58; height: 1fr; margin-right: 1; }
    .wide #run-side { width: 1fr; }
    .wide.llm-lane #run-llm { display: block; }
    .wide.pane-llm #run-log { display: block; }
    .flow-hidden #run-flow { display: none; }
    #run-stop-hint { height: 1; color: $warning; }
    #result { display: none; height: 1fr; padding: 1 2; }
    .completed #workspace, .completed #status-line { display: none; }
    .completed #result { display: block; }
    #result-status { height: auto; padding: 0 1; text-style: bold; margin-bottom: 1; }
    #result-status.status-ok { background: $success 20%; color: $success; }
    #result-status.status-warn { background: $warning 20%; color: $warning; }
    #result-status.status-fail { background: $error 20%; color: $error; }
    #result-scroll { height: 1fr; }
    #result-kv { layout: grid; grid-size: 2; grid-columns: 12 1fr; grid-rows: auto; height: auto; margin-bottom: 1; }
    .kv-key { color: $text-muted; }
    #result-report-dir.has-report { text-style: bold; color: $success; }
    #result-tools { height: auto; }
    .tool-ok { color: $success; }
    .tool-warn { color: $warning; }
    .tool-fail { color: $error; }
    .tool-skip { color: $text-muted; }
    #result-buttons, .dialog-buttons { height: 3; layout: horizontal; align-horizontal: right; }
    #result-buttons Button, .dialog-buttons Button { margin-left: 1; }
    ModalScreen { align: center middle; background: rgba(0, 0, 0, 0.65); }
    #dialog { width: 90; max-width: 95%; height: auto; max-height: 90%; padding: 1 2; border: round $primary; background: $surface; }
    .dialog-title { text-style: bold; margin-bottom: 1; }
    #dialog-message { height: auto; max-height: 70vh; overflow-y: auto; }
    .warning { color: $warning; margin-top: 1; }
    """

    def __init__(self, source: Path, explicit_config: Path | None = None) -> None:
        super().__init__()
        self.source = source.expanduser().resolve()
        self.explicit_config = explicit_config.expanduser().resolve() if explicit_config else None
        loaded = load_config_with_sources(self.source, self.explicit_config)
        self.config = loaded.config
        self.sources = dict(loaded.sources)
        self.dirty = False
        self.running = False
        self.small = False
        self.last_result: AnalysisResult | None = None
        self.last_request: AnalysisRequest | None = None
        self.cancel_token: CancellationToken | None = None
        self._accept_changes = False
        self._pending_log_lines: deque[str] = deque()
        self._log_lock = threading.Lock()
        self._log_overflowed = False
        self._run_started_at: float | None = None
        self._last_preflight: PreflightResult | None = None
        self.flow: RunFlow | None = None
        # The run as a conversation, and whether the operator asked to see the
        # prompt beside each answer.
        self.chat: Transcript | None = None
        self._show_prompts = False
        self._flow_frame = 0
        self._flow_dirty = True
        self._flow_capacity = 7
        # The CLI honours these switches and the TUI used to ignore them.
        self._flow_animated = not animation_disabled_by_env()
        # The operator's hand on the run, and the queues the worker fills:
        # state events are never dropped, liveness events may be.
        self.control: RunControl | None = None
        self._pending_events: deque[AnalysisEvent] = deque()
        self._liveness_events: deque[AnalysisEvent] = deque(maxlen=LIVENESS_QUEUE)
        self._events_lock = threading.Lock()
        self._cursor: str | None = None
        self._pane = "log"
        self._log_filter = "all"
        self._problems_snapshot = ""
        self._decision_open: str | None = None
        self._deferred: set[str] = set()

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("终端至少需要 80×24；当前尺寸不足，已阻止运行。", id="too-small")
        with Vertical(id="workspace"):
            with VerticalScroll(id="forms"):
                with Grid(id="form-columns"):
                    with Vertical(id="column-left", classes="column"):
                        yield Label("扫描目标", classes="section-title first")
                        yield from self._special_basic_fields()
                        yield self._field_widget(FIELD_BY_PATH["run.output_root"])
                        yield Label("分析工具", classes="section-title")
                        for path in ("tools.cppcheck.enabled", "tools.flawfinder.enabled", "tools.splint.enabled"):
                            yield self._field_widget(FIELD_BY_PATH[path])
                        # The second detection path, off by default: a scan
                        # that may run for hours is never a side effect here
                        # either.  Endpoint and model stay in the config file.
                        yield self._field_widget(FIELD_BY_PATH["llm.enabled"])
                    with Vertical(id="column-right", classes="column"):
                        yield Label("构建上下文", classes="section-title first")
                        yield self._field_widget(FIELD_BY_PATH["build.compile_database_mode"])
                        yield self._field_widget(FIELD_BY_PATH["build.compile_database"])
                        yield self._field_widget(FIELD_BY_PATH["build.include"])
                        yield self._field_widget(FIELD_BY_PATH["build.define"])
                        yield self._field_widget(FIELD_BY_PATH["build.c_standard"])
                        yield self._field_widget(FIELD_BY_PATH["build.assist"])
                        yield Label("报告", classes="section-title")
                        yield self._field_widget(FIELD_BY_PATH["run.shareable_export"])
                        yield self._field_widget(FIELD_BY_PATH["review.fail_on"])
                        yield Static("[@click=app.grading_info]评分分级说明（F1）[/]", id="grading-link")
            with Horizontal(id="basic-actions"):
                yield Button("保存配置", id="save-config")
                yield Button("预检", id="preflight")
                yield Button("退出", id="exit")
                yield Button("开始扫描", id="run", variant="primary")
        yield Static("就绪 · 可直接开始扫描；高级选项沿用 TOML/CLI 配置", id="status-line")
        with Vertical(id="running"):
            yield Static("正在运行…", id="run-heading")
            yield Static("阶段：准备 · 工具/单元：— · 已运行：00:00", id="run-details")
            yield ProgressBar(total=100, id="run-progress")
            yield Static("", id="run-bars")
            yield Static("", id="run-speed")
            with Vertical(id="run-body"):
                yield Static("", id="run-flow")
                with Vertical(id="run-side"):
                    yield Static("", id="run-llm")
                    yield Static("", id="run-chat")
                    yield RichLog(max_lines=2000, auto_scroll=True, wrap=True, markup=False, id="run-log")
                    yield RichLog(max_lines=500, auto_scroll=False, wrap=True, markup=False, id="run-problems")
            yield Static("Ctrl+C 请求安全停止；将停止调度并回收当前进程组。", id="run-stop-hint")
        with Vertical(id="result"):
            yield Static("", id="result-status")
            with VerticalScroll(id="result-scroll"):
                with Grid(id="result-kv"):
                    yield Label("分析上下文", classes="kv-key")
                    yield Static("—", id="result-context")
                    yield Label("源码稳定", classes="kv-key")
                    yield Static("—", id="result-stable")
                    yield Label("报告目录", classes="kv-key")
                    yield Static("—", id="result-report-dir")
                yield Vertical(id="result-tools")
            with Horizontal(id="result-buttons"):
                yield Button("返回配置", id="result-back")
                yield Button("同配置重跑", id="result-rerun", variant="primary")
                yield Button("退出", id="result-exit")
        yield Footer()

    def _special_basic_fields(self) -> list[Vertical]:
        source_input = Input(str(self.source), id="special-source")
        source_input.tooltip = "源码根目录（绝对或相对路径）。"
        config_input = Input(
            str(self.explicit_config) if self.explicit_config else "", id="special-config", placeholder="可留空"
        )
        config_input.tooltip = "显式配置文件；留空则仅使用 SOURCE/.code-analyzer.toml。"
        return [
            Vertical(Label("SOURCE 源码根目录"), source_input, classes="field"),
            Vertical(
                Label("--config 显式配置文件"),
                HorizontalGroup(config_input, Button("加载", id="reload-config"), classes="inline-row"),
                classes="field",
            ),
        ]

    def _field_widget(self, field: FieldSpec) -> Vertical:
        value = config_value(self.config, field.path)
        widget_id = _widget_id(field.path)
        if field.kind == "bool":
            control: Any = Checkbox(field.label, bool(value), id=widget_id, disabled=field.readonly)
            control.tooltip = field.help
            return Vertical(control, classes="field field-bool")
        if field.kind == "choice":
            control = Select([(choice, choice) for choice in field.choices], value=value, allow_blank=False, id=widget_id, disabled=field.readonly)
        elif field.kind in {"list", "path_list"}:
            control = Input(
                (LIST_SEPARATOR + " ").join(str(item) for item in (value or [])), id=widget_id, disabled=field.readonly,
                placeholder=f"可留空；多个以 {LIST_SEPARATOR} 分隔",
            )
        else:
            control = Input(
                "" if value is None else str(value), id=widget_id, disabled=field.readonly,
                placeholder="可留空" if field.kind.startswith("optional") else None,
            )
        control.tooltip = field.help
        return Vertical(Label(field.label), control, classes="field")

    def on_mount(self) -> None:
        self.query_one("#run-log", RichLog).border_title = "实时日志"
        self.set_timer(0.2, self._mark_clean)
        self.set_interval(0.1, self._flush_log_queue)
        self.set_interval(1.0, self._update_elapsed)
        # 5 Hz over one Static: an order of magnitude under the log drain
        # above, and the only thing in the app that animates.
        self.set_interval(0.2, self._tick_flow)

    def _mark_clean(self) -> None:
        self.dirty = False
        self._accept_changes = True

    def on_resize(self, event: Any) -> None:
        width, height = event.size.width, event.size.height
        self.small = width < 80 or height < 24
        self.set_class(self.small, "too-small")
        self.set_class(width >= WIDE_BREAKPOINT, "wide")
        capacity_ = capacity(width, height)
        if capacity_ != self._flow_capacity:
            self._flow_capacity = capacity_
            self._flow_dirty = True

    def on_descendant_focus(self, event: events.DescendantFocus) -> None:
        tip = getattr(event.widget, "tooltip", None)
        if tip and not self.running:
            prefix = "● 未保存修改 · " if self.dirty else ""
            self.query_one("#status-line", Static).update(f"{prefix}{tip}")

    def action_toggle_flow(self) -> None:
        """Give the log its rows back on a small terminal."""
        self.toggle_class("flow-hidden")
        self._flow_dirty = True

    def check_action(self, action: str, parameters: tuple[object, ...]) -> bool | None:
        if action in RUN_ONLY_ACTIONS:
            return self.running
        return True

    # --- the operator's hand ------------------------------------------------

    def action_cycle_pane(self) -> None:
        order = self._pane_order()
        index = order.index(self._pane) if self._pane in order else 0
        self._set_pane(order[(index + 1) % len(order)])

    def _pane_order(self) -> list[str]:
        llm = self.flow is not None and self.flow.llm_enabled
        return [name for name in PANES if llm or name not in LLM_ONLY_PANES]

    def action_toggle_prompts(self) -> None:
        """Show, or stop showing, the prompt each unit was sent.

        Off by default: the prompt is a whole source unit plus its context, and
        an operator watching answers arrive does not want the question repeated
        in front of every one of them.  The full text is in the report
        directory either way -- the pane only ever had a preview.
        """
        self._show_prompts = not self._show_prompts
        if self._pane != "chat" and "chat" in self._pane_order():
            self._set_pane("chat")
        self._flow_dirty = True
        self._repaint_flow()

    def _set_pane(self, pane: str) -> None:
        self._pane = pane
        running = self.query_one("#running")
        for name in PANES:
            running.set_class(name == pane, f"pane-{name}")
        self._flow_dirty = True
        self._repaint_flow()

    def action_cycle_filter(self) -> None:
        index = LOG_FILTERS.index(self._log_filter)
        self._log_filter = LOG_FILTERS[(index + 1) % len(LOG_FILTERS)]
        self.query_one("#run-log", RichLog).border_title = f"实时日志 · {FILTER_LABELS[self._log_filter]}"
        self._flow_dirty = True

    def action_toggle_pause_llm(self) -> None:
        if self.control is not None:
            self.control.toggle_pause("llm", "tui")
            self._flow_dirty = True

    def action_toggle_pause_static(self) -> None:
        if self.control is not None:
            self.control.toggle_pause("static", "tui")
            self._flow_dirty = True

    def action_jobs_up(self) -> None:
        if self.control is not None:
            self.control.set_jobs("llm", self.control.jobs("llm") + 1, "tui")
            self._flow_dirty = True

    def action_jobs_down(self) -> None:
        if self.control is not None:
            self.control.set_jobs("llm", self.control.jobs("llm") - 1, "tui")
            self._flow_dirty = True

    def _selected_node(self) -> str | None:
        if self.flow is None:
            return None
        ids = self.flow.producer_ids()
        if not ids:
            return None
        if self._cursor in ids:
            return self._cursor
        running = [node.id for node in self.flow.nodes.values() if node.kind in {"static", "llm"} and node.state == "running"]
        return running[0] if running else ids[0]

    def _move_cursor(self, step: int) -> None:
        if self.flow is None:
            return
        ids = self.flow.producer_ids()
        if not ids:
            return
        current = self._selected_node()
        index = ids.index(current) if current in ids else 0
        self._cursor = ids[(index + step) % len(ids)]
        self._flow_dirty = True
        self._repaint_flow()

    def action_cursor_up(self) -> None:
        self._move_cursor(-1)

    def action_cursor_down(self) -> None:
        self._move_cursor(1)

    def action_node_detail(self) -> None:
        node_id = self._selected_node()
        if self.flow is None or node_id is None:
            return
        lines = self.flow.node_detail(node_id, time.time())
        self.push_screen(InfoScreen(f"节点详情 · {node_id}", "\n".join(lines)))

    def action_retry_llm(self) -> None:
        if self.control is None or self.flow is None:
            return
        if not self.flow.llm_active():
            self.query_one("#run-stop-hint", Static).update("LLM 阶段已结束：运行后用 llm-resume 续扫")
            return
        llm_nodes = [node for node in self.flow.nodes.values() if node.kind == "llm"]
        failed = sum(node.failures for node in llm_nodes)
        unscheduled = sum(node.unscheduled for node in llm_nodes)
        transport = len(self.flow.retryable_units(transport_only=True))
        if not failed and not unscheduled and not transport:
            self.query_one("#run-stop-hint", Static).update("没有需要重试的 LLM 单元")
            return
        reasons: dict[str, int] = {}
        for node in llm_nodes:
            for reason, count in node.reasons.items():
                reasons[reason] = reasons.get(reason, 0) + count
        self.push_screen(RetryScreen(failed, unscheduled, transport, reasons), self._retry_confirmed)

    def _retry_confirmed(self, choice: str | None) -> None:
        if choice is None or self.control is None or self.flow is None:
            return
        ids = self.flow.retryable_units(transport_only=True) if choice == "transport" else None
        self.control.request_retry("llm", ids, "tui")
        self.query_one("#run-stop-hint", Static).update(
            f"已请求重试 {len(ids) if ids is not None else '全部未得到回答的'} LLM 单元；将在本轮结束后执行"
        )
        self._flow_dirty = True

    def action_open_decision(self) -> None:
        if self.control is None:
            return
        pending = self.control.pending()
        if not pending:
            self.query_one("#run-stop-hint", Static).update("当前没有待决策项")
            return
        self._open_decision(pending[0])

    def _open_decision(self, request: DecisionRequest) -> None:
        if self._decision_open is not None:
            return
        self._decision_open = request.id
        self.push_screen(PatchScreen(request), lambda decision, req=request: self._decided(req, decision))

    def _decided(self, request: DecisionRequest, decision: Decision | None) -> None:
        self._decision_open = None
        if decision is None or self.control is None:
            return
        if decision.answer == "defer":
            self._deferred.add(request.id)
            self.query_one("#run-stop-hint", Static).update(f"补丁 {request.id} 稍后决定 · 按 d 重新打开")
            return
        self.control.decide(request.id, decision.answer, decision.selected, decision.decided_by, decision.note)
        self._flow_dirty = True

    def action_skip_selected(self) -> None:
        node_id = self._selected_node()
        if self.control is None or node_id is None or self.flow is None:
            return
        node = self.flow.nodes[node_id]
        if node.state not in {"pending", "running"}:
            self.query_one("#run-stop-hint", Static).update(f"{node_id} 已结束，无需跳过")
            return
        remaining = "" if node.total is None else f"（约 {max(0, node.total - node.done)} 个单元）"
        self.push_screen(
            ConfirmScreen(
                f"跳过 {node_id}？",
                f"将把 {node_id} 尚未开始的单元{remaining}标记为 unscheduled（skipped by operator）；已有证据保留，正在运行的单元会完成。",
                yes="跳过",
            ),
            lambda confirmed, name=node_id: self._skip_confirmed(confirmed, name),
        )

    def _skip_confirmed(self, confirmed: bool, name: str) -> None:
        if confirmed and self.control is not None:
            self.control.skip(name, "tui")
            self._flow_dirty = True

    def action_grading_info(self) -> None:
        self.push_screen(InfoScreen("评分分级说明", GRADING_NOTE))

    @on(Button.Pressed)
    def button_pressed(self, event: Button.Pressed) -> None:
        identity = event.button.id or ""
        if identity == "reload-config":
            self._request_reload()
        elif identity == "save-config":
            self.action_save()
        elif identity == "preflight":
            self.action_preflight()
        elif identity == "run":
            self.action_run()
        elif identity == "exit":
            self._exit_with_last()
        elif identity == "result-back":
            self.remove_class("completed")
        elif identity == "result-rerun":
            self.remove_class("completed")
            self.action_run()
        elif identity == "result-exit":
            self._exit_with_last()

    @on(Input.Changed)
    @on(Checkbox.Changed)
    @on(Select.Changed)
    def value_changed(self) -> None:
        if not self._accept_changes:
            return
        self.dirty = True
        self.query_one("#status-line", Static).update("会话配置已修改（尚未保存） · F5 预检 · F9 运行")

    def _collect(self) -> tuple[Path, dict[str, Any]]:
        source_text = self.query_one("#special-source", Input).value.strip()
        source = Path(source_text or ".").expanduser().resolve()
        config = copy.deepcopy(self.config)
        for path in TUI_FIELDS:
            field = FIELD_BY_PATH[path]
            control = self.query_one("#" + _widget_id(field.path))
            if isinstance(control, Checkbox):
                value: Any = control.value
            elif isinstance(control, Select):
                value = control.value
            else:
                text = control.value.strip()
                if field.kind in {"list", "path_list"}:
                    value = [item.strip() for item in text.split(LIST_SEPARATOR) if item.strip()]
                elif field.kind.startswith("optional") and not text:
                    value = None
                elif field.kind == "int":
                    value = int(text)
                elif field.kind == "float":
                    value = float(text)
                else:
                    value = text
            set_config_value(config, field.path, value)
        # Session-entered paths are interpreted relative to SOURCE.
        for path in ("run.output_root", "build.compile_database"):
            value = config_value(config, path)
            if value:
                candidate = Path(value).expanduser()
                set_config_value(config, path, str((candidate if candidate.is_absolute() else source / candidate).resolve()))
        for path in ("build.include", "build.system_include"):
            values = []
            for item in config_value(config, path):
                candidate = Path(item).expanduser()
                values.append(str((candidate if candidate.is_absolute() else source / candidate).resolve()))
            set_config_value(config, path, values)
        validate_config(config)
        config["_config_paths"] = list(self.config.get("_config_paths", []))
        config["_config_sources"] = {**self.sources, **{path: "session" for path in TUI_FIELDS}}
        return source, config

    def _request_reload(self) -> None:
        if self.dirty:
            self.push_screen(
                ConfirmScreen("放弃未保存修改？", "切换 SOURCE 或显式配置会重新加载四层配置，当前会话修改将丢失。", yes="放弃并加载"),
                self._reload_confirmed,
            )
        else:
            self._reload_confirmed(True)

    def _reload_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            return
        try:
            source = Path(self.query_one("#special-source", Input).value or ".").expanduser().resolve()
            config_text = self.query_one("#special-config", Input).value.strip()
            explicit = Path(config_text).expanduser().resolve() if config_text else None
            loaded = load_config_with_sources(source, explicit)
        except UserError as exc:
            self.push_screen(InfoScreen("加载失败", str(exc)))
            return
        self.source, self.explicit_config = source, explicit
        self.config, self.sources = loaded.config, dict(loaded.sources)
        # Recompose is the safest way to refresh all labels and typed controls.
        self._accept_changes = False
        self.refresh(recompose=True)
        self.set_timer(0.2, self._mark_clean)

    def action_escape(self) -> None:
        if self.running:
            return
        if self.has_class("completed"):
            self.remove_class("completed")

    def action_save(self) -> None:
        if self.running:
            return
        try:
            source, config = self._collect()
        except (UserError, ValueError) as exc:
            self.push_screen(InfoScreen("配置无效", str(exc)))
            return
        default = self.explicit_config or source / ".code-analyzer.toml"
        self._pending_save = (source, config)
        self.push_screen(PathScreen("保存完整配置快照", str(default)), self._save_path_chosen)

    def _save_path_chosen(self, value: str | None) -> None:
        if value is None:
            return
        destination = Path(value).expanduser().resolve()
        self._pending_destination = destination
        if destination.exists():
            self.push_screen(
                ConfirmScreen("确认覆盖", f"将覆盖：\n{destination}\n\n原注释和顺序会被完整快照替换。", yes="覆盖保存"),
                self._save_overwrite_confirmed,
            )
        else:
            self._save_overwrite_confirmed(True)

    def _save_overwrite_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            return
        source, config = self._pending_save
        try:
            saved = save_config_snapshot(source, config, self._pending_destination, overwrite=True)
        except UserError as exc:
            self.push_screen(InfoScreen("保存失败", str(exc)))
            return
        loaded = load_config_with_sources(source, saved)
        self.source = source
        self.config, self.sources = loaded.config, dict(loaded.sources)
        self.explicit_config = saved
        self.dirty = False
        self._accept_changes = False
        self.refresh(recompose=True)
        self.set_timer(0.2, self._mark_clean)
        self.call_after_refresh(lambda: self.query_one("#status-line", Static).update(f"已保存：{saved}"))

    def action_preflight(self) -> None:
        if self.running:
            return
        try:
            source, config = self._collect()
        except (UserError, ValueError) as exc:
            self.push_screen(InfoScreen("配置无效", str(exc)))
            return
        self.query_one("#status-line", Static).update("正在后台预检路径、Compile DB 和工具兼容性…")
        self._preflight_worker(source, config, False)

    @work(thread=True, exclusive=True, group="preflight")
    def _preflight_worker(self, source: Path, config: dict[str, Any], for_run: bool) -> None:
        try:
            result = run_preflight(source, config)
        except Exception as exc:
            self.call_from_thread(self._background_failed, "预检失败", str(exc))
        else:
            self.call_from_thread(self._preflight_done, source, config, result, for_run)

    def _preflight_done(self, source: Path, config: dict[str, Any], result: PreflightResult, for_run: bool) -> None:
        # Lets the discovery row say "318 文件 · compile-db 212 条" before the
        # first event has been emitted.
        self._last_preflight = result
        lines = [f"源码文件：{result.inventory_files if result.inventory_files is not None else '—'}"]
        if result.compile_database:
            lines.append(f"Compile DB：{result.compile_database['path'] or '未发现（降级上下文）'}")
            if not result.compile_database["path"]:
                lines.append("可复制的生成向导命令：" + shlex.join(["code-analyzer", "compile-db", str(source)]))
            candidates = result.compile_database["discovery"].get("candidates", [])
            if candidates:
                lines.append("候选：")
                for item in candidates:
                    lines.append(f"  • {item['path']} · coverage {item.get('source_coverage_ratio', 0):.1%} · {'usable' if item['usable'] else ', '.join(item['issues'])}")
        if result.issues:
            lines.append("问题：")
            lines.extend(f"  {'错误' if item.severity == 'error' else '警告'} · {item.field or 'general'} · {item.message}" for item in result.issues)
        else:
            lines.append("未发现阻塞问题或警告。")
        message = "\n".join(lines)
        self.query_one("#status-line", Static).update("预检完成" if result.ok else "预检发现阻塞错误")
        if for_run:
            if not result.ok:
                self.push_screen(InfoScreen("无法运行", message))
                return
            self._pending_run = (source, config)
            self.push_screen(ConfirmScreen("确认运行", self._confirmation_text(source, config, result), yes="开始扫描"), self._run_confirmed)
        else:
            self.push_screen(InfoScreen("预检结果", message))

    def action_run(self) -> None:
        if self.running or self.small:
            if self.small:
                self.push_screen(InfoScreen("终端尺寸不足", "运行至少需要 80 列 × 24 行。请调整终端尺寸后重试。"))
            return
        try:
            source, config = self._collect()
        except (UserError, ValueError) as exc:
            self.push_screen(InfoScreen("配置无效", str(exc)))
            return
        self.query_one("#status-line", Static).update("正在后台预检…")
        self._preflight_worker(source, config, True)

    def _confirmation_text(self, source: Path, config: dict[str, Any], preflight: PreflightResult) -> str:
        selected = [name for name in TOOL_NAMES if config["tools"][name]["enabled"]]
        compile_path = preflight.compile_database["path"] if preflight.compile_database else None
        warnings = [item.message for item in preflight.issues if item.severity == "warning"]
        warning_text = ("\n警告（确认后仍可运行）：\n  • " + "\n  • ".join(warnings) + "\n") if warnings else ""
        return (
            f"SOURCE：{source}\n"
            f"工具：{', '.join(selected)}\n"
            f"Compile DB：{compile_path or config['build']['compile_database_mode'] + '（无有效数据库时降级）'}\n"
            f"输出：{config['run']['output_root']}\n"
            f"排除：{', '.join(config['source']['exclude']) or '无'}\n"
            f"Review / gate：{'启用' if config['review']['enabled'] else '禁用'} / {config['review']['fail_on']}\n\n"
            f"{warning_text}"
            "文件系统影响：创建新的报告目录；可能创建脱敏 ZIP。不会生成 Compile DB、运行 CMake 或安装工具。"
        )

    def _run_confirmed(self, confirmed: bool) -> None:
        if not confirmed:
            return
        source, config = self._pending_run
        self.last_request = AnalysisRequest(source, config)
        self.cancel_token = CancellationToken()
        self.control = RunControl(self.cancel_token, llm_jobs=int(config["llm"].get("jobs") or 1))
        self.running = True
        self._reset_run_display()
        self.add_class("running")
        self._set_controls_disabled(True)
        self.query_one("#run-progress", ProgressBar).update(progress=1)
        self._analysis_worker(self.last_request, self.cancel_token, self.control)

    @work(thread=True, exclusive=True, group="analysis")
    def _analysis_worker(self, request: AnalysisRequest, token: CancellationToken, control: RunControl) -> None:
        try:
            result = run_analysis(request, events=self._event_from_worker, cancellation=token, control=control)
        except Exception as exc:
            self.call_from_thread(self._analysis_failed, str(exc))
        else:
            self.call_from_thread(self._analysis_done, result)

    def _background_failed(self, title: str, message: str) -> None:
        self.query_one("#status-line", Static).update(message)
        self.push_screen(InfoScreen(title, message))

    def _analysis_failed(self, message: str) -> None:
        self._flush_log_queue()
        self._update_elapsed()
        self.running = False
        self.remove_class("running")
        self._set_controls_disabled(False)
        self.query_one("#status-line", Static).update("扫描启动失败")
        self.push_screen(InfoScreen("扫描失败", message))

    def _event_from_worker(self, event: AnalysisEvent) -> None:
        """Called on the worker thread -- and, for control events, on the app thread.

        Nothing here crosses threads: the event is queued under a lock and the
        5 Hz ticker folds it.  A real run used to make one ``call_from_thread``
        per event (520 000 in an hour), and a control event raised from the
        app thread would have been refused outright.
        """
        self._queue_log_event(event)
        with self._events_lock:
            # Output events are the transcript's content, and they are also
            # the bulk of a real run's traffic: they queue as liveness, so an
            # overloaded display drops answer chunks rather than the state
            # events the flow and the counters are made of.
            if event.phase == "output" or event.status in {"heartbeat", "step", "info"}:
                self._liveness_events.append(event)
            else:
                self._pending_events.append(event)

    def _drain_events(self) -> int:
        """Fold the queued events; returns how many were folded."""
        with self._events_lock:
            batch = []
            while self._pending_events and len(batch) < DRAIN_PER_TICK:
                batch.append(self._pending_events.popleft())
            while self._liveness_events and len(batch) < DRAIN_PER_TICK:
                batch.append(self._liveness_events.popleft())
        for event in batch:
            self._analysis_event(event)
        return len(batch)

    def _analysis_event(self, event: AnalysisEvent) -> None:
        # Repainting here would redraw once per event; during the LLM phase
        # that is a burst of hundreds. The timer coalesces them instead.
        if self.flow is not None and self.flow.apply(event):
            self._flow_dirty = True
        if self.chat is not None and self.chat.apply(event):
            self._flow_dirty = True
        if event.progress is not None:
            self.query_one("#run-progress", ProgressBar).update(progress=max(1, event.progress * 100))

    def _tick_flow(self) -> None:
        if not self.running or not self.is_mounted:
            return
        if self._drain_events():
            self._flow_dirty = True
        # A decision the runner is waiting on opens its dialog on its own;
        # one the operator deferred waits for `d`.
        if self.control is not None and self._decision_open is None and not isinstance(self.screen, ModalScreen):
            for request in self.control.pending():
                if request.id not in self._deferred:
                    self._open_decision(request)
                    break
        if self._flow_animated:
            self._flow_frame += 1
        elif not self._flow_dirty:
            return
        self._flow_dirty = False
        self._repaint_flow()

    def _repaint_flow(self) -> None:
        """Redraw the panel, or quietly do nothing if it is not there.

        A 5 Hz timer outlives the widget tree during teardown, and a panel is
        decorative: it must never be the reason a scan dies.
        """
        if self.flow is None or not self.is_mounted:
            return
        try:
            heading = self.query_one("#run-heading", Static)
            details = self.query_one("#run-details", Static)
            panel = self.query_one("#run-flow", Static)
        except NoMatches:
            return
        # Wall clock, not monotonic: node clocks are derived from
        # AnalysisEvent.timestamp, which is time.time().
        now = time.time()
        headline = self.flow.headline(now)
        heading.update(headline.title)
        details.update(headline.detail)
        frame = self._flow_frame if self._flow_animated else -1
        rows = self.flow.rows(capacity=self._flow_capacity, now=now, frame=frame, selected=self._selected_node())
        panel.border_title = f"扫描流程 · {self.flow.run_name}" if self.flow.run_name else "扫描流程"
        panel.update(self._flow_text(rows))
        self._repaint_side()

    def _repaint_side(self) -> None:
        """The lane bars, the speed strip, the control bar and the panes."""
        if self.flow is None:
            return
        try:
            bar = self.query_one("#run-stop-hint", Static)
            llm_panel = self.query_one("#run-llm", Static)
            problems = self.query_one("#run-problems", RichLog)
        except NoMatches:
            return
        self._repaint_lanes()
        self._repaint_chat()
        bar.update(self._control_bar_text())
        if self.flow.llm_enabled:
            llm_panel.border_title = "LLM 扫描"
            llm_panel.update(self._llm_text())
        snapshot = "\n".join(
            f"{'✕' if item.level == 'error' else '◐'} {item.tool:<24} {item.reason} ×{item.count}"
            for item in self.flow.problems()
        )
        if snapshot != self._problems_snapshot:
            self._problems_snapshot = snapshot
            problems.border_title = "问题"
            problems.clear()
            for line in snapshot.splitlines() or ["（暂无失败原因）"]:
                problems.write(line)

    def _repaint_lanes(self) -> None:
        """One bar per lane, and the speed strip above the panes.

        The overall bar is the ProgressBar widget; these are the lanes it is a
        weighted sum of, so "62%" can be read as the facts it came from.  All
        of them share one Static: the set of lanes depends on the config, and
        mounting a widget per lane would churn the tree at every repaint.
        """
        if self.flow is None:
            return
        try:
            box = self.query_one("#run-bars", Static)
            speed = self.query_one("#run-speed", Static)
        except NoMatches:
            return
        lanes = [lane for lane in self.flow.lanes() if lane.id != "total"]
        box.update(self._lane_text(lanes))
        speed.update(self._speed_text())

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

    def _speed_text(self) -> Text:
        """How fast the model is answering, and what the number is based on."""
        if self.chat is None or self.flow is None or not self.flow.llm_enabled:
            return Text("")
        summary = self.chat.summary()
        if not summary:
            return Text("⚡ 等待模型的第一个 token…", style="dim")
        return Text("⚡ " + summary)

    def _repaint_chat(self) -> None:
        """The transcript's tail: the exchange happening now, at the bottom."""
        if self.chat is None:
            return
        try:
            panel = self.query_one("#run-chat", Static)
        except NoMatches:
            return
        rows = max(3, panel.size.height or 12)
        width = max(20, (panel.size.width or 80))
        # An answer is a JSON document on one line: ask for more logical lines
        # than there are rows, wrap them to the pane, then keep the last rows.
        # Wrapping here rather than in the model keeps the tail exact -- one
        # logical line can be four rows, and a pane that let Textual wrap would
        # clip the bottom, which is the part that is happening now.
        lines = self.chat.lines(capacity=rows * 4, show_prompts=self._show_prompts)
        stats = self.chat.stats()
        title = f"对话 · 已答 {stats.answered}/{stats.turns}"
        if stats.failed:
            title += f" · 失败 {stats.failed}"
        if stats.cached:
            title += f" · 缓存 {stats.cached}"
        title += " · F6 " + ("隐藏提示词" if self._show_prompts else "显示提示词")
        panel.border_title = title
        if not lines:
            panel.update(Text("等待模型的第一次回复…（F6 显示发送的提示词）", style="dim"))
            return
        wrapped: list[tuple[str, str]] = []
        for line in lines:
            style = _CHAT_STYLES.get(line.role, "")
            for piece in chop_cells(line.text, width) or [""]:
                wrapped.append((piece, style))
        text = Text(no_wrap=True, overflow="crop")
        for index, (piece, style) in enumerate(wrapped[-rows:]):
            if index:
                text.append("\n")
            text.append(piece, style=style)
        panel.update(text)

    def _control_bar_text(self) -> str:
        if self.flow is None:
            return ""
        if self.flow.stopping:
            return "已请求安全停止；正在等待当前进程终止并回收，请勿强制退出。"
        parts = []
        if self.flow.llm_enabled:
            parts.append(("LLM ⏸" if self.flow.paused["llm"] else "LLM ▶") + f" 并发 {self.flow.llm_jobs}")
        parts.append("静态 ⏸" if self.flow.paused["static"] else "静态 ▶")
        if self.flow.pending_decisions:
            parts.append(f"待决策 {len(self.flow.pending_decisions)}")
        keys = "p/P 暂停 · s 跳过 · +/- 并发 · ↑↓⏎ 详情 · F3 面板 · F4 过滤 · F6 提示词 · Ctrl+C 停止"
        return " · ".join(parts) + " · " + keys

    def _llm_text(self) -> Text:
        """The per-scanner panel, built segment by segment like the flow."""
        text = Text(no_wrap=True, overflow="ellipsis")
        text.append(self.flow.llm_summary() if self.flow else "", style="dim")
        for row in (self.flow.llm_rows() if self.flow else []):
            text.append("\n")
            glyph = {"success": "✓", "partial": "◐", "failed": "✕", "running": "⏸" if row.paused else "●", "pending": "○"}[row.state]
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

    def _log_wanted(self, event: AnalysisEvent) -> bool:
        """The F4 filter, applied when a line is queued, not when it is drawn."""
        # A prompt preview is thousands of characters of source; it belongs to
        # the transcript pane, which can lay it out, and would bury every other
        # line in a log that shows one event per row.
        if event.phase == "output" and event.stream == "prompt":
            return False
        if self._log_filter == "all":
            return True
        if self._log_filter == "selected":
            selected = self._selected_node()
            return selected is not None and event.tool == selected
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
        # The same line logs/runner.log gets, with the operator's clock; an
        # analyzer's raw output keeps a short stream form of its own.
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
            log = self.query_one("#run-log", RichLog)
        except NoMatches:
            # The run view is not up yet (or already torn down): keep the
            # lines for the next tick rather than lose them.
            with self._log_lock:
                self._pending_log_lines.extendleft(reversed(lines))
            return
        for line in lines:
            log.write(line)

    def _reset_run_display(self) -> None:
        with self._log_lock:
            self._pending_log_lines.clear()
            self._log_overflowed = False
        with self._events_lock:
            self._pending_events.clear()
            self._liveness_events.clear()
        self.query_one("#run-log", RichLog).clear()
        self.query_one("#run-problems", RichLog).clear()
        self._problems_snapshot = ""
        self._run_started_at = time.monotonic()
        self.flow = RunFlow(self.config, preflight=self._last_preflight)
        self.chat = Transcript()
        if self.control is None:
            self.control = RunControl(self.cancel_token or CancellationToken(), llm_jobs=int(self.config["llm"].get("jobs") or 1))
        self._cursor = None
        self._log_filter = "all"
        self.query_one("#run-log", RichLog).border_title = "实时日志 · 全部"
        self.set_class(self.flow.llm_enabled, "llm-lane")
        # A run with a model in it opens on the conversation; a static-only run
        # has nothing to say there and opens on the log, as it always did.
        self._set_pane("chat" if self.flow.llm_enabled else "log")
        # No widget holds the focus during a run, so the arrow keys and Enter
        # reach the app's own bindings instead of scrolling a form.
        self.screen.set_focus(None)
        self._flow_frame = 0
        self._flow_dirty = True
        self.query_one("#run-heading", Static).update("正在启动扫描…")
        self.query_one("#run-details", Static).update("0% · 已运行 00:00")
        self.query_one("#run-stop-hint", Static).update(self._control_bar_text())
        self._repaint_flow()

    def _elapsed_text(self) -> str:
        elapsed = 0 if self._run_started_at is None else max(0, int(time.monotonic() - self._run_started_at))
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"

    def _update_elapsed(self) -> None:
        """The clock lives in the model, not in the rendered string.

        This used to read the widget back and re-split its own text on
        " · 已运行："; any change to the line silently stopped the clock.
        """
        if not self.running or not self.is_mounted:
            return
        self._flow_dirty = True
        if not self._flow_animated:
            self._repaint_flow()

    def _analysis_done(self, result: AnalysisResult) -> None:
        self._drain_events()
        self._flush_log_queue()
        # The ticker stops with the run, so paint the terminal states once more
        # before it does; otherwise the panel keeps its second-to-last frame.
        self._repaint_flow()
        self.running = False
        self.remove_class("running")
        self._set_controls_disabled(False)
        self.last_result = result
        manifest = result.manifest or {}
        status = manifest.get("status", "interrupted" if result.exit_code == 130 else "unknown")
        severity = "ok" if result.exit_code == 0 else ("warn" if result.exit_code in (1, 10) else "fail")
        banner = self.query_one("#result-status", Static)
        banner.set_classes(f"status-{severity}")
        banner.update(f"总状态：{status} · 退出码 {result.exit_code}")
        self.query_one("#result-context", Static).update(str(manifest.get("analysis_context", "—")))
        self.query_one("#result-stable", Static).update(str(manifest.get("source_inventory", {}).get("stable", "—")))
        report_widget = self.query_one("#result-report-dir", Static)
        report_widget.set_class(bool(result.report_directory), "has-report")
        report_widget.update(str(result.report_directory or "未创建"))
        tools_box = self.query_one("#result-tools", Vertical)
        tools_box.remove_children()
        rows = []
        for name, value in manifest.get("tools", {}).items():
            tool_status = value.get("status", "—")
            marker = {
                "completed": "tool-ok",
                "not_applicable": "tool-skip",
                "skipped": "tool-skip",
                "partial": "tool-warn",
                "timed_out": "tool-warn",
            }.get(tool_status, "tool-fail")
            rows.append(Static(_result_line(name, value), classes=f"tool-row {marker}"))
        llm = manifest.get("llm") or {}
        if llm.get("requested"):
            rows.append(Static(_result_line("llm", llm), classes="tool-row " + {"completed": "tool-ok", "partial": "tool-warn"}.get(str(llm.get("status")), "tool-fail")))
        tools_box.mount_all(rows or [Static("—", classes="tool-skip")])
        self.add_class("completed")

    def _set_controls_disabled(self, disabled: bool) -> None:
        for control in self.query("Input, Checkbox, Select, #basic-actions Button"):
            control.disabled = disabled

    def action_cancel_or_exit(self) -> None:
        if self.running:
            self.push_screen(ConfirmScreen("取消扫描？", "将停止调度新工具，并对正在运行的进程组执行 TERM/KILL 安全清理。已有报告会保留。", yes="安全停止"), self._cancel_confirmed)
        else:
            self._exit_with_last()

    def _cancel_confirmed(self, confirmed: bool) -> None:
        if confirmed and self.cancel_token:
            # Through the control so the stop is journalled like every other
            # operator action; the token it wraps is the same one.
            if self.control is not None:
                self.control.cancel("tui")
            else:
                self.cancel_token.cancel()
            if self.flow is not None:
                self.flow.mark_stopping()
            self.query_one("#run-heading", Static).update("正在安全停止…")
            self.query_one("#run-stop-hint", Static).update("已请求安全停止；正在等待当前进程终止并回收，请勿强制退出。")

    def _exit_with_last(self) -> None:
        if self.last_result:
            self.exit(TuiOutcome(self.last_result.exit_code, self.last_result.report_directory))
        else:
            self.exit(TuiOutcome())

def _widget_id(path: str) -> str:
    return "field-" + path.replace(".", "-").replace("_", "-")


def _result_line(name: str, record: dict[str, Any]) -> str:
    """One producer on the result screen: status, then why, then what it analysed."""
    parts = [f"{name:<12} {record.get('status', '—')}"]
    reason = record.get("reason")
    if reason:
        parts.append(single_line(str(reason))[:120])
    counts = record.get("unit_counts") or {}
    coverage = record.get("coverage") or {}
    if counts.get("planned"):
        parts.append(f"单元 {counts.get('completed', 0)}/{counts['planned']}")
        if counts.get("failed"):
            parts.append(f"{counts['failed']} 失败")
        if counts.get("unscheduled"):
            parts.append(f"{counts['unscheduled']} 未调度")
    if coverage.get("analysis_reached") is not None and coverage.get("effective_total"):
        parts.append(f"实际分析 {coverage['analysis_reached']}/{coverage['effective_total']}")
    return " · ".join(parts)


def run_tui(source: Path, explicit_config: Path | None = None) -> TuiOutcome:
    result = AnalyzerApp(source, explicit_config).run()
    return result or TuiOutcome()

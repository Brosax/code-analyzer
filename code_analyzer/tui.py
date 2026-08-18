from __future__ import annotations

import copy
import shlex
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
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
    Static,
)

from .analysis import (
    AnalysisEvent,
    AnalysisRequest,
    AnalysisResult,
    CancellationToken,
    run_analysis,
)
from .config import (
    FIELD_BY_PATH,
    FieldSpec,
    config_value,
    load_config_with_sources,
    save_config_snapshot,
    set_config_value,
    validate_config,
)
from .errors import UserError
from .preflight import PreflightResult, run_preflight
from .progress import single_line
from .tools import TOOL_NAMES

TUI_FIELDS = (
    "run.output_root",
    "build.compile_database_mode",
    "build.compile_database",
    "tools.cppcheck.enabled",
    "tools.flawfinder.enabled",
    "tools.splint.enabled",
    "run.shareable_export",
    "review.fail_on",
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
    ]
    CSS = """
    Screen { background: $surface; }
    #workspace { height: 1fr; }
    #forms { width: 92; max-width: 100%; height: 1fr; padding: 1 2; align-horizontal: center; }
    .section-title { text-style: bold; color: $primary; margin: 1 0; }
    .field { height: auto; margin-bottom: 1; }
    .field Label { height: auto; color: $text-muted; }
    .field Input, .field Select { width: 100%; }
    #basic-actions { height: 3; layout: horizontal; align-horizontal: right; margin-top: 1; }
    #basic-actions Button { margin-left: 1; }
    #grading-reference { height: auto; border-left: solid $primary; padding-left: 1; margin: 1 0; color: $text-muted; }
    #status-line { dock: bottom; height: 3; padding: 1; background: $boost; }
    #too-small { display: none; dock: top; height: 3; background: $error; color: $text; content-align: center middle; }
    .too-small #too-small { display: block; }
    #running { display: none; height: 1fr; background: $panel; padding: 1 2; }
    .running #workspace, .running #status-line { display: none; }
    .running #running { display: block; }
    #run-heading { height: 1; text-style: bold; }
    #run-details { height: 1; color: $text-muted; margin-bottom: 1; }
    #run-progress { height: 2; margin-bottom: 1; }
    #run-log { height: 1fr; border: round $primary; background: $surface-darken-1; }
    #run-stop-hint { height: 2; padding-top: 1; color: $warning; }
    #result { display: none; height: 1fr; padding: 1 2; overflow-y: auto; }
    .completed #workspace, .completed #status-line { display: none; }
    .completed #result { display: block; }
    #result-buttons, .dialog-buttons { height: 3; layout: horizontal; align-horizontal: right; }
    #result-buttons Button, .dialog-buttons Button { margin-left: 1; }
    ModalScreen { align: center middle; background: rgba(0, 0, 0, 0.65); }
    #dialog { width: 72; max-width: 95%; height: auto; max-height: 90%; padding: 1 2; border: round $primary; background: $surface; }
    .dialog-title { text-style: bold; margin-bottom: 1; }
    #dialog-message { height: auto; max-height: 28; overflow-y: auto; }
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

    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("终端至少需要 80×24；当前尺寸不足，已阻止运行。", id="too-small")
        with Vertical(id="workspace"):
            with VerticalScroll(id="forms"):
                yield Label("扫描目标", classes="section-title")
                yield from self._special_basic_fields()
                yield self._field_widget(FIELD_BY_PATH["run.output_root"])
                yield Label("构建上下文", classes="section-title")
                yield self._field_widget(FIELD_BY_PATH["build.compile_database_mode"])
                yield self._field_widget(FIELD_BY_PATH["build.compile_database"])
                yield Label("分析工具", classes="section-title")
                for path in ("tools.cppcheck.enabled", "tools.flawfinder.enabled", "tools.splint.enabled"):
                    yield self._field_widget(FIELD_BY_PATH[path])
                yield Label("报告", classes="section-title")
                yield self._field_widget(FIELD_BY_PATH["run.shareable_export"])
                yield self._field_widget(FIELD_BY_PATH["review.fail_on"])
                yield Static(
                    "所有新报告固定采用 NXP i.MX RT700 AVA Test Plan 第 7 章的 Information / Style / Warning / Error 分级；未直接匹配的工具等级显示为 Unmapped。",
                    id="grading-reference",
                )
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
            yield RichLog(max_lines=2000, auto_scroll=True, wrap=True, markup=False, id="run-log")
            yield Static("Ctrl+C 请求安全停止；将停止调度并回收当前进程组。", id="run-stop-hint")
        with VerticalScroll(id="result"):
            yield Label("扫描完成", classes="dialog-title")
            yield Static("", id="result-body")
            with Horizontal(id="result-buttons"):
                yield Button("返回配置", id="result-back")
                yield Button("同配置重跑", id="result-rerun", variant="primary")
                yield Button("退出", id="result-exit")
        yield Footer()

    def _special_basic_fields(self) -> list[Vertical]:
        return [
            Vertical(Label("SOURCE · 源码根目录"), Input(str(self.source), id="special-source"), classes="field"),
            Vertical(
                Label("--config · 显式配置文件（可空）"),
                Input(str(self.explicit_config) if self.explicit_config else "", id="special-config"),
                Button("加载 SOURCE / 配置", id="reload-config"),
                classes="field",
            ),
        ]

    def _field_widget(self, field: FieldSpec) -> Vertical:
        value = config_value(self.config, field.path)
        title = field.label
        widget_id = _widget_id(field.path)
        if field.kind == "bool":
            control: Any = Checkbox(field.help, bool(value), id=widget_id, disabled=field.readonly)
            return Vertical(Label(title), control, classes="field")
        if field.kind == "choice":
            control = Select([(choice, choice) for choice in field.choices], value=value, allow_blank=False, id=widget_id, disabled=field.readonly)
        else:
            control = Input(
                "" if value is None else str(value), id=widget_id, disabled=field.readonly,
                placeholder="可留空" if field.kind.startswith("optional") else None,
            )
        return Vertical(Label(title + " · " + field.help), control, classes="field")

    def on_mount(self) -> None:
        self.set_timer(0.2, self._mark_clean)
        self.set_interval(0.1, self._flush_log_queue)
        self.set_interval(1.0, self._update_elapsed)

    def _mark_clean(self) -> None:
        self.dirty = False
        self._accept_changes = True

    def on_resize(self, event: Any) -> None:
        width, height = event.size.width, event.size.height
        self.small = width < 80 or height < 24
        self.set_class(self.small, "too-small")

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
                if field.kind.startswith("optional") and not text:
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
        self.running = True
        self._reset_run_display()
        self.add_class("running")
        self._set_controls_disabled(True)
        self.query_one("#run-progress", ProgressBar).update(progress=1)
        self._analysis_worker(self.last_request, self.cancel_token)

    @work(thread=True, exclusive=True, group="analysis")
    def _analysis_worker(self, request: AnalysisRequest, token: CancellationToken) -> None:
        try:
            result = run_analysis(request, events=self._event_from_worker, cancellation=token)
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
        self._queue_log_event(event)
        if event.phase != "output":
            self.call_from_thread(self._analysis_event, event)

    def _analysis_event(self, event: AnalysisEvent) -> None:
        context = event.tool or "—"
        if event.unit:
            context += "/" + event.unit
        self.query_one("#run-heading", Static).update(single_line(event.message))
        self.query_one("#run-details", Static).update(
            f"阶段：{event.phase} · 工具/单元：{context} · 已运行：{self._elapsed_text()}"
        )
        if event.progress is not None:
            self.query_one("#run-progress", ProgressBar).update(progress=max(1, event.progress * 100))

    def _queue_log_event(self, event: AnalysisEvent) -> None:
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
        clock = time.strftime("%H:%M:%S", time.localtime(event.timestamp))
        tool = event.tool or event.phase
        unit = event.unit or "-"
        stream = event.stream or "status"
        return f"{clock} [{tool}/{unit}][{stream}] {single_line(event.message)}"

    def _flush_log_queue(self) -> None:
        lines: list[str] = []
        with self._log_lock:
            for _ in range(min(200, len(self._pending_log_lines))):
                lines.append(self._pending_log_lines.popleft())
        if not lines or not self.is_mounted:
            return
        log = self.query_one("#run-log", RichLog)
        for line in lines:
            log.write(line)

    def _reset_run_display(self) -> None:
        with self._log_lock:
            self._pending_log_lines.clear()
            self._log_overflowed = False
        self.query_one("#run-log", RichLog).clear()
        self._run_started_at = time.monotonic()
        self.query_one("#run-heading", Static).update("正在启动扫描…")
        self.query_one("#run-details", Static).update("阶段：准备 · 工具/单元：— · 已运行：00:00")
        self.query_one("#run-stop-hint", Static).update("Ctrl+C 请求安全停止；将停止调度并回收当前进程组。")

    def _elapsed_text(self) -> str:
        elapsed = 0 if self._run_started_at is None else max(0, int(time.monotonic() - self._run_started_at))
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"

    def _update_elapsed(self) -> None:
        if not self.running or not self.is_mounted:
            return
        details = self.query_one("#run-details", Static)
        prefix = str(details.render()).rsplit(" · 已运行：", 1)[0]
        details.update(f"{prefix} · 已运行：{self._elapsed_text()}")

    def _analysis_done(self, result: AnalysisResult) -> None:
        self._flush_log_queue()
        self._update_elapsed()
        self.running = False
        self.remove_class("running")
        self._set_controls_disabled(False)
        self.last_result = result
        manifest = result.manifest or {}
        tools = manifest.get("tools", {})
        tool_lines = "\n".join(f"  • {name}: {value.get('status', '—')}" for name, value in tools.items()) or "  —"
        body = (
            f"总状态：{manifest.get('status', 'interrupted' if result.exit_code == 130 else 'unknown')}\n"
            f"退出码：{result.exit_code}\n"
            f"分析上下文：{manifest.get('analysis_context', '—')}\n"
            f"源码稳定：{manifest.get('source_inventory', {}).get('stable', '—')}\n"
            f"工具：\n{tool_lines}\n"
            f"报告目录：{result.report_directory or '未创建'}"
        )
        self.query_one("#result-body", Static).update(body)
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
            self.cancel_token.cancel()
            self.query_one("#run-heading", Static).update("正在安全停止…")
            self.query_one("#run-stop-hint", Static).update("已请求安全停止；正在等待当前进程终止并回收，请勿强制退出。")
            self._queue_log_event(AnalysisEvent("analysis", "stopping", "已请求安全停止；正在终止并回收当前进程"))

    def _exit_with_last(self) -> None:
        if self.last_result:
            self.exit(TuiOutcome(self.last_result.exit_code, self.last_result.report_directory))
        else:
            self.exit(TuiOutcome())

def _widget_id(path: str) -> str:
    return "field-" + path.replace(".", "-").replace("_", "-")


def run_tui(source: Path, explicit_config: Path | None = None) -> TuiOutcome:
    result = AnalyzerApp(source, explicit_config).run()
    return result or TuiOutcome()

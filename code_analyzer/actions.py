"""The registry: the one definition of what an operator can ask this tool to do.

Until now "what an operator can do" was written twice -- once as eleven
argparse subcommands in ``cli.py``, once as ``action_run`` / ``action_preflight``
/ ``action_save`` in ``tui.py`` -- and the two lists had already drifted:
``preflight`` exists only in the TUI, the compile-db wizard's questions exist
only on the CLI, and thirteen of eighty-three config leaves are reachable from
the form.  One registry, two thin front ends, no drift.

What an action does *not* do here: print.  An action reports progress by
emitting ``AnalysisEvent``s and returns an ``ActionOutcome``; the front end
decides what reaches a terminal.  That is ``analysis.run_analysis``'s existing
headless contract (``analysis.py:107-108``) generalised from "scan" to
"everything", and it is what gives the conversation live progress for
``llm-resume``, ``assess`` and ``tools-resume`` -- which it has never had.
"""
from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .analysis import AnalysisEvent, AnalysisRequest, CancellationToken, run_analysis
from .ask import Asker, refusing_asker
from .config import FIELD_BY_PATH
from .errors import UserError

# Where an action's subject comes from.  "report" resolves through the run's
# own manifest so the scanned tree's project config applies -- the behaviour
# `cli._scanned_source` gives assess and llm-resume today, and which the TUI
# has never had.
SUBJECT_NONE = "none"
SUBJECT_SOURCE = "source"
SUBJECT_REPORT = "report"

# When the front end must stop and confirm before running.  Both are derived
# from declared effects (see Action.confirm); neither is ever stored.
CONFIRM_NEVER = "never"
CONFIRM_ALWAYS = "always"


@dataclass(frozen=True)
class Param:
    """One argument an action takes.

    ``config_path`` points at a schema leaf, and then label/kind/choices come
    from ``FIELD_BY_PATH`` rather than being restated -- that is how
    ``--llm-jobs``, ``/set llm.jobs 4`` and the ``/config`` row stay one
    definition.  An argument that is not a schema leaf (a report directory,
    ``--json``) carries its own metadata, because inventing a fake leaf to
    describe it would corrupt the 83-leaf invariant.
    """

    name: str
    kind: str = "string"
    label: str = ""
    required: bool = False
    default: Any = None
    choices: tuple[str, ...] = ()
    config_path: str | None = None

    def spec(self) -> Any:
        return FIELD_BY_PATH.get(self.config_path) if self.config_path else None

    def resolved_kind(self) -> str:
        spec = self.spec()
        return spec.kind if spec is not None else self.kind

    def resolved_label(self) -> str:
        spec = self.spec()
        return spec.label if spec is not None else (self.label or self.name)

    def resolved_choices(self) -> tuple[str, ...]:
        spec = self.spec()
        return tuple(spec.choices) if spec is not None and spec.choices else self.choices


@dataclass
class ActionRequest:
    """What one invocation is about: the subject, the config, the raw argv."""

    action: str
    source: Path | None = None
    report_directory: Path | None = None
    config: dict[str, Any] = field(default_factory=dict)
    args: Any = None
    values: dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionContext:
    """Everything an action may reach for, and nothing else.

    ``terminal`` is the one front-end difference the registry admits, and it is
    real: ``runner.analyze`` wraps a ``ProgressDisplay`` that overwrites a
    terminal line, and a transcript has no line to overwrite.  Both reach the
    same ``runner._analyze`` underneath.  Naming it beats pretending it
    unifies and quietly changing what the CLI prints.
    """

    request: ActionRequest
    emit: Callable[[AnalysisEvent], None] = lambda _event: None
    ask: Asker = field(default_factory=refusing_asker)
    decide: Any = None
    control: Any = None
    cancelled: Callable[[], bool] = lambda: False
    terminal: bool = False
    event_sink: Any = None
    # A ``threading.Event`` an action that serves or waits can be told to stop
    # with.  Inert unless a front end sets one, so nothing else changes.
    stop: Any = None

    def say(self, phase: str, status: str, message: str, **fields: Any) -> None:
        self.emit(AnalysisEvent(phase, status, message, **fields))

    def progress(self, phase: str) -> Callable[[str], None]:
        """Adapt a ``progress: Callable[[str], None]`` parameter onto events.

        Three actions predate the event stream and still take a progress
        string.  Rather than rewrite them, their line becomes an event, which
        is what puts them in the conversation for the first time.
        """
        return lambda text: self.emit(AnalysisEvent(phase, "info", text))


@dataclass(frozen=True)
class ActionOutcome:
    """What happened.  ``summary`` is the one line a settled block collapses to."""

    exit_code: int = 0
    summary: str = ""
    lines: tuple[str, ...] = ()
    report_directory: Path | None = None
    data: dict[str, Any] | None = None


@dataclass(frozen=True)
class Action:
    """One thing an operator can ask for, and what it does to the world.

    The three effect fields are facts about the call tree, audited against it.
    ``confirm`` and ``auto_run`` are *derived* from them rather than stored,
    which is the whole point: a stored policy can disagree with what the code
    does, and three of them did -- ``rebuild-dashboard``, ``recover-report``
    and ``serve`` were all marked "never confirm" while rewriting
    ``manifest.json`` or opening a socket.  A declaration cannot disagree with
    a policy derived from it, and an under-declared ``writes`` can no longer be
    papered over by a hand-set ``confirm``.
    """

    name: str
    summary: str
    subject: str
    run: Callable[[ActionContext], ActionOutcome]
    aliases: tuple[str, ...] = ()
    params: tuple[Param, ...] = ()
    long_running: bool = False
    interactive: bool = False
    cli_command: str | None = None
    impact: tuple[str, ...] = ()
    # --- declared effects ---------------------------------------------------
    # Path templates using {source} {report} {output_root} {cwd}.  Empty means
    # this action writes nothing a person would miss -- a temporary directory
    # does not count, and the audit says so per action.
    writes: tuple[str, ...] = ()
    # Sends a *completion* request: tokens, money on a metered provider, and
    # minutes.  A model listing (preflight's endpoint probe) is not spending.
    spends: bool = False
    # Waits unboundedly on a person, or never returns on its own.
    blocks: bool = False
    # May a model name this action?  False keeps it out of the catalogue.
    conversational: bool = True

    @property
    def confirm(self) -> str:
        """A human named it: naming is the consent, so only effects need a prompt."""
        return CONFIRM_ALWAYS if (self.writes or self.blocks) else CONFIRM_NEVER

    @property
    def auto_run(self) -> bool:
        """A model inferred it: no writes, no money, no indefinite block."""
        return not self.writes and not self.spends and not self.blocks

    def names(self) -> tuple[str, ...]:
        return (self.name, *self.aliases)


def render_writes(action: Action, request: ActionRequest) -> tuple[str, ...]:
    """The paths this action will write, resolved for this request.

    A confirmation that says "开始吗？" asks the operator to consent to a
    sentence; one that names the files asks them to consent to the act.
    """
    values = {
        "source": str(request.source) if request.source else "<源码目录>",
        "report": str(request.report_directory) if request.report_directory else "<报告目录>",
        "output_root": str((request.config or {}).get("run", {}).get("output_root") or "<输出目录>"),
        "cwd": str(Path.cwd()),
    }
    resolved = []
    for template in action.writes:
        try:
            resolved.append(template.format(**values))
        except (KeyError, IndexError, ValueError):
            resolved.append(template)
    return tuple(resolved)


# --- the actions ------------------------------------------------------------
#
# Each `run` is a thin wrapper over the function that already did the work.
# The wrappers exist to give every action one shape: events out, an outcome
# back, and no printing.


def _run_doctor(ctx: ActionContext) -> ActionOutcome:
    from .doctor import probe_all

    ctx.say("doctor", "started", "probing the analyzers and the host")
    result = probe_all(ctx.request.config)
    for name, item in (result.get("tools") or {}).items():
        ctx.say("doctor", str(item.get("status") or "unknown"), f"{name}: {item.get('status')}", tool=name, data=item)
    ok = bool(result.get("ok"))
    return ActionOutcome(
        exit_code=0 if ok else 20,
        summary="环境就绪" if ok else "环境不满足要求",
        data=result,
    )


def _run_llm_doctor(ctx: ActionContext) -> ActionOutcome:
    from .llm.doctor import describe, probe_llm

    request = ctx.request
    ctx.say("llm", "started", "probing the provider")
    result = probe_llm(request.config, request.source)
    ok = bool(result.get("ok"))
    return ActionOutcome(
        exit_code=0 if ok else 20,
        summary=f"{result.get('model')} @ {result.get('endpoint')}" + ("" if ok else " · 不可用"),
        # It measures tokens per second and the conversation used to throw all
        # of it away: only the CLI ever rendered the probe.
        lines=describe(result),
        data=result,
    )


def _run_model(ctx: ActionContext) -> ActionOutcome:
    from .llm.doctor import connection, describe

    ctx.say("llm", "started", "reading the configured provider")
    result = connection(ctx.request.config)
    ok = bool(result.get("ok"))
    return ActionOutcome(
        exit_code=0 if ok else 20,
        summary=f"{result.get('model') or '（未配置模型）'} @ {result.get('endpoint')}"
                + ("" if ok else " · 不可用"),
        lines=describe(result),
        data=result,
    )


def _run_preflight(ctx: ActionContext) -> ActionOutcome:
    from .preflight import run_preflight

    request = ctx.request
    if request.source is None:
        raise UserError("preflight needs a source directory")
    ctx.say("preflight", "started", "checking the configuration and the tools")
    result = run_preflight(request.source, request.config)
    for issue in result.issues:
        ctx.say("preflight", issue.severity, issue.message, tool=issue.field)
    return ActionOutcome(
        exit_code=0 if result.ok else 2,
        summary=(f"预检通过 · {result.inventory_files} 个文件" if result.ok else "预检发现阻塞问题"),
        lines=tuple(f"{issue.severity}: {issue.message}" for issue in result.issues),
        data={"ok": result.ok, "inventory_files": result.inventory_files},
    )


def _run_compile_db(ctx: ActionContext) -> ActionOutcome:
    from .compile_db_wizard import run_compile_db

    exit_code = run_compile_db(ctx.request.args, ask=ctx.ask)
    return ActionOutcome(
        exit_code=exit_code,
        summary="compile database 就绪" if exit_code == 0 else "未生成 compile database",
    )


def _run_scan(ctx: ActionContext) -> ActionOutcome:
    from .runner import analyze

    request = ctx.request
    if request.source is None:
        raise UserError("scan needs a source directory")
    if ctx.terminal:
        exit_code, run_dir = analyze(
            request.source, request.config, event_sink=ctx.event_sink, decider=ctx.decide,
        )
        return ActionOutcome(exit_code=exit_code, summary=_scan_summary(exit_code), report_directory=run_dir)
    result = run_analysis(
        AnalysisRequest(request.source, request.config),
        events=ctx.emit,
        cancellation=getattr(ctx.control, "cancellation", None) or CancellationToken(),
        control=ctx.control,
    )
    return ActionOutcome(
        exit_code=result.exit_code,
        summary=_scan_summary(result.exit_code),
        report_directory=result.report_directory,
        data=result.manifest,
    )


def _scan_summary(exit_code: int) -> str:
    return {0: "扫描完成", 1: "扫描完成，门禁未通过", 10: "扫描部分完成", 130: "扫描已中断"}.get(
        exit_code, f"扫描失败（退出码 {exit_code}）"
    )


def _run_llm_resume(ctx: ActionContext) -> ActionOutcome:
    from .llm.resume import run_resume

    request = ctx.request
    if request.report_directory is None:
        raise UserError("llm-resume needs a report directory")
    block = run_resume(request.report_directory, request.config, progress=ctx.progress("llm"))
    exit_code = int(block["exit_code"])
    return ActionOutcome(
        exit_code=exit_code,
        summary=f"续扫结束 · {block.get('resumed', 0)} 个单元",
        report_directory=request.report_directory,
        data=block,
    )


def _run_tools_resume(ctx: ActionContext) -> ActionOutcome:
    from .reconfigure import run_tools_resume
    from .status import EXIT_COMPLETE, EXIT_PARTIAL

    request = ctx.request
    if request.report_directory is None:
        raise UserError("tools-resume needs a report directory")
    args = request.args
    block = run_tools_resume(
        request.report_directory,
        tool=getattr(args, "tool", None),
        assist=getattr(args, "build_assist", None),
        decider=ctx.decide,
        progress=ctx.progress("build_context"),
        event_sink=ctx.event_sink,
    )
    outcome = block.get("outcome")
    return ActionOutcome(
        exit_code=EXIT_COMPLETE if outcome in {"applied", "skipped"} else EXIT_PARTIAL,
        summary=f"构建上下文 {outcome}",
        report_directory=request.report_directory,
        data=block,
    )


def _run_assess(ctx: ActionContext) -> ActionOutcome:
    from .validate import run_assess

    request = ctx.request
    if request.report_directory is None:
        raise UserError("assess needs a report directory")
    block = run_assess(request.report_directory, request.config, progress=ctx.progress("audit"))
    return ActionOutcome(
        exit_code=int(block["exit_code"]),
        summary="验证结束",
        report_directory=request.report_directory,
        data=block,
    )


def _run_rebuild_dashboard(ctx: ActionContext) -> ActionOutcome:
    from .dashboard import rebuild_dashboard

    if ctx.request.report_directory is None:
        raise UserError("rebuild-dashboard needs a report directory")
    path = rebuild_dashboard(ctx.request.report_directory)
    return ActionOutcome(summary=f"已重建 {path.name}", report_directory=ctx.request.report_directory,
                         data={"index": str(path)})


def _run_recover_report(ctx: ActionContext) -> ActionOutcome:
    from .recovery import recover_report

    if ctx.request.report_directory is None:
        raise UserError("recover-report needs a report directory")
    path = recover_report(ctx.request.report_directory)
    return ActionOutcome(summary=f"已从原生证据重建 {path.name}",
                         report_directory=ctx.request.report_directory, data={"index": str(path)})


def _run_serve(ctx: ActionContext) -> ActionOutcome:
    """Serve a run, and be stoppable.

    Three things were wrong.  ``serve.serve`` accepts a ``stop`` event and was
    never given one, so it looped forever.  ``port`` was passed straight from
    an argparse namespace that a conversation does not have, so it arrived as
    ``None`` and ``ThreadingHTTPServer(("127.0.0.1", None))`` raised.  And the
    URL went to stderr, which a transcript never shows.
    """
    from .serve import DEFAULT_PORT, serve

    request = ctx.request
    args = request.args
    port = getattr(args, "port", None) or DEFAULT_PORT
    if ctx.terminal:
        announce = getattr(args, "_announce", None) or (
            lambda text: print(f"code-analyzer: {text}", file=sys.stderr))
    else:
        def announce(text: str) -> None:
            ctx.say("serve", "info", text)

    if request.source is not None:
        exit_code = serve(None, analyze=(request.source, request.config),
                          port=port, announce=announce, stop=ctx.stop)
    else:
        exit_code = serve(request.report_directory, port=port, announce=announce, stop=ctx.stop)
    return ActionOutcome(exit_code=exit_code, summary="实时页已关闭")


def _run_config(ctx: ActionContext) -> ActionOutcome:
    """Show the configuration.  Editing is the front end's business."""
    from .config import config_value

    config = ctx.request.config
    wanted = str(ctx.request.values.get("filter") or "").strip()
    rows = []
    for path, spec in FIELD_BY_PATH.items():
        if spec.advanced and not ctx.request.values.get("all"):
            continue
        if wanted and wanted not in path and wanted not in spec.label:
            continue
        try:
            rows.append(f"{path} = {config_value(config, path)!r}")
        except KeyError:
            continue
    return ActionOutcome(summary=f"{len(rows)} 项配置", lines=tuple(rows))


DOCTOR = Action(
    name="doctor", summary="探测分析器与运行环境", subject=SUBJECT_NONE, run=_run_doctor,
    aliases=("体检",), cli_command="doctor",
    # Writes only a canary.c inside a TemporaryDirectory (doctor.py:70-72).
    impact=("只读：探测三个分析器的版本与能力；只在临时目录里编译一个探针，不写任何会留下的文件。",),
)
LLM_DOCTOR = Action(
    name="llm-doctor", summary="探测 LLM 提供方并估算一次完整扫描", subject=SUBJECT_SOURCE,
    run=_run_llm_doctor, aliases=("模型体检",),
    cli_command="llm-doctor",
    # Writes nothing, but it is a real generation: tokens, money on a metered
    # provider, and 18-52s of time.  Typed is consent; inferred is not.
    spends=True,
    impact=("向配置的端点发一次真实的生成请求（计费、实测 18–52 秒），并走一遍整棵源码树；不修改任何文件。",),
)
MODEL = Action(
    name="model", summary="显示连接的模型：名字、端点、可达性与速度", subject=SUBJECT_NONE,
    run=_run_model, aliases=("模型",), cli_command="model",
    # A model listing, not a completion.  `spends` means a generation -- money,
    # tokens, minutes -- and this is the same request `preflight` already makes,
    # so a model may reach for it the way it may reach for `doctor`.
    impact=("只读：读配置，并向端点要一次模型列表（不是生成请求）；不写任何文件。",),
)
PREFLIGHT = Action(
    name="preflight", summary="运行前的只读检查", subject=SUBJECT_SOURCE, run=_run_preflight,
    aliases=("预检",), cli_command="preflight",
    impact=("只读：校验配置、探测工具、预测 include 缺失；不写任何文件。",),
)
COMPILE_DB = Action(
    name="compile-db", summary="发现或生成 JSON compilation database", subject=SUBJECT_SOURCE,
    run=_run_compile_db, aliases=("cdb", "编译数据库"),
    long_running=True, interactive=True, cli_command="compile-db",
    # Two corrections: the log does NOT go under the report directory (it goes
    # under the process CWD, compile_db_wizard.py:349-357) and the build tree
    # defaults to INSIDE the scanned source tree (:183).
    writes=("{cwd}/code-analyzer-reports/compile-db/…", "{source}/build/code-analyzer/…"),
    impact=("运行 CMake 配置（不编译目标）；日志写在当前工作目录下的 code-analyzer-reports/compile-db/，"
            "构建目录默认在源码树内的 build/code-analyzer/。--method command 会运行你给的任意命令。",),
)
SCAN = Action(
    name="scan", summary="对一个 C/C++ 源码树执行完整扫描", subject=SUBJECT_SOURCE, run=_run_scan,
    aliases=("analyze", "扫描"),
    params=(Param("source", kind="path", label="源码根目录", required=True),),
    long_running=True, interactive=True, cli_command="analyze",
    writes=("{output_root}/<报告目录>/…", "{output_root}/.llm-cache"),
    spends=True,
    impact=("在输出目录下新建一个报告目录，并写入跨运行缓存；不修改源码树。",),
)
LLM_RESUME = Action(
    name="llm-resume", summary="续扫一次运行里未调度或被中断的单元", subject=SUBJECT_REPORT,
    run=_run_llm_resume, aliases=("续扫",),
    long_running=True, cli_command="llm-resume",
    writes=("{report}/llm/…", "{report}/review/summary.{json,md,sarif}",
            "{report}/audit/assessment.json", "{report}/manifest.json", "{report}/index.html"),
    spends=True,
    impact=("向提供方发起新的会话，并重新派生该运行的 review / SARIF / 评估 / manifest / 报告页；"
            "原生证据保留。",),
)
TOOLS_RESUME = Action(
    name="tools-resume", summary="对已完成的运行继续构建上下文修补循环", subject=SUBJECT_REPORT,
    run=_run_tools_resume, aliases=("补构建上下文",),
    long_running=True, interactive=True, cli_command="tools-resume",
    writes=("{report}/manifest.json", "{report}/inputs/build-context/…",
            "{report}/suggested-config.toml", "{report}/tools/…"),
    # Consults the model independently of the LLM lane, and
    # build.approval_timeout_seconds = 0.0 becomes timeout=None: it waits for a
    # person forever (reconfigure.py:192-193).
    spends=True, blocks=True,
    impact=("只重跑失败的单元到新的单元目录；不修改配置文件，不运行构建。"
            "补丁被采纳时会调用 recover-report 重新派生全部产物。默认会无限期等待你的决定。",),
)
ASSESS = Action(
    name="assess", summary="用验证器复核已关联的候选项", subject=SUBJECT_REPORT, run=_run_assess,
    aliases=("验证",),
    long_running=True, cli_command="assess",
    writes=("{report}/llm/…", "{report}/audit/assessment.json",
            "{report}/manifest.json", "{report}/index.html"),
    spends=True,
    impact=("每个候选项一次模型会话，写入评估、manifest 与报告页；review/summary.json 不变。",),
)
REBUILD_DASHBOARD = Action(
    name="rebuild-dashboard", summary="从已有报告重建 index.html", subject=SUBJECT_REPORT,
    run=_run_rebuild_dashboard, aliases=("重建报告页",),
    cli_command="rebuild-dashboard",
    # It also rewrites manifest.json -- the only source of node truth
    # (dashboard.py:70).  The old string omitted that and the old policy was
    # "never confirm".
    writes=("{report}/index.html", "{report}/manifest.json"),
    impact=("重写 index.html，并重写 manifest.json。",),
)
RECOVER_REPORT = Action(
    name="recover-report", summary="从原生证据重建全部派生产物", subject=SUBJECT_REPORT,
    run=_run_recover_report, aliases=("恢复报告",),
    cli_command="recover-report",
    # Also manifest.json, audit/assessment.json, and one new timestamped ZIP
    # per call -- unconditionally (recovery.py:82), so it grows without bound.
    writes=("{report}/review/summary.{json,md,sarif}", "{report}/audit/assessment.json",
            "{report}/manifest.json", "{report}/index.html", "{report}/exports/<新的 ZIP>"),
    impact=("重新派生 review / SARIF / audit/assessment.json / manifest.json / index.html，"
            "并每次新导出一个 ZIP；不调用任何分析器。",),
)
SERVE = Action(
    # A report directory, declared: it was SUBJECT_NONE while `_run_serve` read
    # `request.source` anyway, which is how `/serve` in the conversation used to
    # start a full scan.  With subjects no longer leaking it needs to say what
    # it wants.  (`--analyze SOURCE` stays a CLI-only mode.)
    name="serve", summary="用浏览器看一次运行的实时视图", subject=SUBJECT_REPORT, run=_run_serve,
    aliases=("实时页",),
    # Not long_running in the display sense: that flag decides whether a flow
    # diagram is drawn, and serve has no flow.  It still blocks, so it confirms.
    cli_command="serve",
    # Still `blocks`: it runs until stopped, so it confirms.  But it can now be
    # stopped (`ctx.stop`), so a model may name it again.
    blocks=True,
    impact=("在 127.0.0.1 上监听一个端口，直到你停止它。",),
)
CONFIG = Action(
    name="config", summary="查看或修改本次会话的配置", subject=SUBJECT_NONE, run=_run_config,
    aliases=("配置",),
    cli_command="config",
    # _run_config cannot write; the config write is /save, which confirms.
    impact=("只读：列出当前配置与它们的来源。写入 TOML 是 /save，另行确认。",),
)

REGISTRY: tuple[Action, ...] = (
    DOCTOR, LLM_DOCTOR, MODEL, PREFLIGHT, COMPILE_DB, SCAN, LLM_RESUME,
    TOOLS_RESUME, ASSESS, REBUILD_DASHBOARD, RECOVER_REPORT, SERVE, CONFIG,
)

BY_NAME: dict[str, Action] = {name: action for action in REGISTRY for name in action.names()}
BY_CLI_COMMAND: dict[str, Action] = {
    action.cli_command: action for action in REGISTRY if action.cli_command
}


def by_name(name: str) -> Action:
    action = BY_NAME.get(name.strip())
    if action is None:
        raise UserError(f"unknown action: {name}")
    return action


def invoke(action: Action, ctx: ActionContext) -> ActionOutcome:
    """Run one action.  Errors stay the caller's to translate into an exit code."""
    return action.run(ctx)

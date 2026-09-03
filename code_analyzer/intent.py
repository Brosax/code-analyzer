"""What the operator typed, resolved to an action -- deterministically.

This is the trunk of the conversation, and it never reaches a model.  A slash
command, a bare path and a short phrase all name something in the registry;
anything this file cannot resolve is reported as unresolved rather than
guessed, and only then may the operator hand it to a model with ``/ask``.

The reason for the split is latency and honesty in equal measure.  Measured
against the operator's own provider on 2026-09-03, the first token of a reply
takes 18-52 s; an interface that asked a model what "pause" meant would take
half a minute to pause.  And a parser that guesses is worse than one that asks:
two readings of one phrase is a coin flip the operator can settle instantly.

Nothing here imports textual, the harness or ``llm.*`` -- a test asserts it,
the way ``tests/test_flow.py`` asserts the flow model imports no UI.
"""
from __future__ import annotations

import difflib
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .actions import BY_NAME, REGISTRY
from .argv import quiet, subparser_for
from .config import FIELD_BY_PATH
from .errors import UserError

# What a parsed line turned out to be.
ACTION = "action"
META = "meta"
CONFIG_SET = "config_set"
CONFIG_SHOW = "config_show"
ASK = "ask"
AMBIGUOUS = "ambiguous"
UNKNOWN = "unknown"
EMPTY = "empty"

# Commands that are not registry actions: they act on the conversation or on a
# run already in flight.  The run-control ones are the single letters the old
# TUI bound (p P s + - d r), promoted to names that can be discovered, typed
# and journalled.
META_COMMANDS: dict[str, str] = {
    "help": "列出可用命令",
    "quit": "退出",
    "exit": "退出",
    "cancel": "取消正在运行的操作",
    "pause": "暂停一条泳道（static / llm）",
    "resume": "恢复一条泳道（static / llm）",
    "skip": "跳过一个 producer 余下的单元",
    "jobs": "调整 LLM 并发",
    "retry": "重试未得到回答的 LLM 单元",
    "decide": "重新打开待决策的构建上下文补丁",
    "save": "把当前配置写成 TOML 快照",
    "clear": "折叠已结束的块",
}

# Shorthand is a closed lexical table, not a classifier.  It resolves a verb
# and a subject and nothing else: no flags, no negation.  Anything richer is
# either a slash command (explicit) or /ask (a model that can say what it
# understood) -- widening this table is where a deterministic parser starts to
# claim a comprehension it does not have.
_MIN_KEYWORD = 2


@dataclass(frozen=True)
class State:
    """What the conversation already knows, so a bare verb has a subject."""

    source: Path | None = None
    report_directory: Path | None = None
    running: bool = False


@dataclass(frozen=True)
class Intent:
    """One reading of one line."""

    kind: str
    action: str = ""
    argv: tuple[str, ...] = ()
    values: dict[str, Any] = field(default_factory=dict)
    text: str = ""
    # "exact" when the operator named it; "shorthand" when we resolved it.
    confidence: str = "exact"
    candidates: tuple[str, ...] = ()
    problem: str = ""

    @property
    def resolved(self) -> bool:
        return self.kind in {ACTION, META, CONFIG_SET, CONFIG_SHOW, ASK}


def parse(text: str, state: State | None = None) -> Intent:
    """Resolve one line.  Never raises for operator input; never guesses."""
    state = state or State()
    line = (text or "").strip()
    if not line:
        return Intent(EMPTY, text=text or "")
    if line.startswith("/") and _names_a_command(line):
        return _slash(line, state)
    bare = _bare_path(line, state)
    if bare is not None:
        return bare
    return _shorthand(line, state)


# --- slash commands ---------------------------------------------------------


def _names_a_command(line: str) -> bool:
    """Is this a slash command, or an absolute path?

    Both start with "/".  A command is one word of letters, digits and dashes;
    `/home/ubuntu/fw` is a path and must not come back as "no such command",
    which is the single most likely thing an operator types first.
    """
    first = line[1:].split()[0] if line[1:].split() else ""
    if not first or "/" in first or "\\" in first:
        return False
    return all(character.isalnum() or character in {"-", "_"} for character in first)


def _slash(line: str, state: State) -> Intent:
    try:
        tokens = shlex.split(line[1:])
    except ValueError as exc:
        return Intent(UNKNOWN, text=line, problem=f"引号不成对：{exc}")
    if not tokens:
        return Intent(UNKNOWN, text=line, problem="斜杠后面没有命令；/help 列出全部")
    name, tail = tokens[0], tokens[1:]

    if name in {"set"}:
        return _config_set(tail, line)
    if name in {"config", "配置"} and not tail:
        return Intent(CONFIG_SHOW, action="config", text=line, values={"all": False})
    if name in {"ask", "问"}:
        return Intent(ASK, text=" ".join(tail), values={"utterance": " ".join(tail)})
    if name in META_COMMANDS:
        return Intent(META, action=name, argv=tuple(tail), text=line)

    action = BY_NAME.get(name)
    if action is None:
        close = difflib.get_close_matches(name, sorted(_vocabulary()), n=3, cutoff=0.6)
        return Intent(
            UNKNOWN, text=line, candidates=tuple(close),
            problem=f"没有 /{name} 这个命令" + (f"；你是指 {'、'.join('/' + c for c in close)} 吗？" if close else "；/help 列出全部"),
        )
    return _with_subparser(action.name, tail, line, state)


def _with_subparser(name: str, tail: list[str], line: str, state: State) -> Intent:
    """Parse the tail with the CLI's own parser for this action.

    Borrowed rather than reimplemented: thirty-five analyze flags kept in step
    by hand is the version of this that drifts.
    """
    action = BY_NAME[name]
    command = action.cli_command
    parser = subparser_for(command) if command else None
    if parser is None:
        return Intent(ACTION, action=action.name, argv=tuple(tail), text=line)
    filled = _fill_subject(action, tail, state)
    try:
        namespace = quiet(parser).parse_args(filled)
    except UserError as exc:
        return Intent(UNKNOWN, text=line, problem=f"/{name}: {exc}")
    return Intent(ACTION, action=action.name, argv=tuple(filled), text=line,
                  values={"namespace": namespace})


def _fill_subject(action: Any, tail: list[str], state: State) -> list[str]:
    """Supply the subject the conversation is already on, when none was typed."""
    from .actions import SUBJECT_REPORT, SUBJECT_SOURCE

    if tail and not tail[0].startswith("-"):
        return tail
    if action.subject == SUBJECT_SOURCE and state.source is not None:
        return [str(state.source), *tail]
    if action.subject == SUBJECT_REPORT and state.report_directory is not None:
        return [str(state.report_directory), *tail]
    return tail


def _vocabulary() -> set[str]:
    names = {name for action in REGISTRY for name in action.names()}
    return names | set(META_COMMANDS) | {"set", "ask"}


# --- /set -------------------------------------------------------------------


def _config_set(tail: list[str], line: str) -> Intent:
    if not tail:
        return Intent(UNKNOWN, text=line, problem="用法：/set <配置路径> <值>")
    path = tail[0]
    spec = FIELD_BY_PATH.get(path)
    if spec is None:
        close = difflib.get_close_matches(path, sorted(FIELD_BY_PATH), n=3, cutoff=0.5)
        return Intent(UNKNOWN, text=line, candidates=tuple(close),
                      problem=f"没有 {path} 这个配置项" + (f"；你是指 {'、'.join(close)} 吗？" if close else ""))
    if spec.readonly:
        return Intent(UNKNOWN, text=line, problem=f"{path} 是只读的（{spec.label}）")
    if spec.kind == "table_list":
        # The one leaf a single line cannot express; saying so beats pretending.
        return Intent(UNKNOWN, text=line,
                      problem=f"{path} 是表格型配置（{spec.label}），只能在 TOML 里改")
    if len(tail) < 2:
        return Intent(UNKNOWN, text=line, problem=f"用法：/set {path} <值>（{spec.label}）")
    return Intent(CONFIG_SET, action="config", text=line,
                  values={"path": path, "raw": " ".join(tail[1:])})


def coerce(path: str, raw: str) -> Any:
    """A typed value for one config leaf, or a UserError naming the problem.

    ``FieldSpec.minimum`` is read here.  Eighty-three specs have carried that
    field since the registry was written and no front end has ever looked at
    it, so ``llm.jobs = 0`` reached ``validate_config`` rather than being
    refused where the operator typed it.
    """
    spec = FIELD_BY_PATH[path]
    text = raw.strip()
    kind = spec.kind
    try:
        if kind == "bool":
            lowered = text.lower()
            if lowered in {"true", "yes", "on", "1", "是"}:
                return True
            if lowered in {"false", "no", "off", "0", "否"}:
                return False
            raise UserError(f"{path} 要一个是/否的值，收到 {text!r}")
        if kind == "int":
            value: Any = int(text)
        elif kind == "float":
            value = float(text)
        elif kind in {"list", "path_list"}:
            value = [item for item in (part.strip() for part in text.split(";")) if item]
        elif kind in {"optional_string", "optional_path"}:
            value = text or None
        else:
            value = text
    except ValueError as exc:
        raise UserError(f"{path} 要一个 {kind}，收到 {text!r}（{exc}）") from exc
    if spec.choices and value not in spec.choices:
        raise UserError(f"{path} 只接受 {'、'.join(spec.choices)}，收到 {text!r}")
    if spec.minimum is not None and isinstance(value, (int, float)) and value < spec.minimum:
        raise UserError(f"{path} 不能小于 {spec.minimum}，收到 {value}")
    return value


# --- bare paths -------------------------------------------------------------


def _bare_path(line: str, state: State) -> Intent | None:
    """A path on its own line names a subject, and never runs by itself."""
    if len(line.split()) != 1 or line.startswith("-"):
        return None
    candidate = Path(line).expanduser()
    looks_like_path = any(mark in line for mark in ("/", "\\", "~", ".")) or candidate.exists()
    if not looks_like_path:
        return None
    if not candidate.exists():
        return Intent(UNKNOWN, text=line, problem=f"路径不存在：{candidate}")
    if candidate.is_file() and candidate.name == "compile_commands.json":
        return Intent(ACTION, action="scan", text=line, confidence="shorthand",
                      argv=(str(candidate.parent), "--compile-db", str(candidate)))
    if not candidate.is_dir():
        return Intent(UNKNOWN, text=line, problem=f"不是一个目录：{candidate}")
    if (candidate / "manifest.json").exists():
        # A finished run has five things one might want from it; guessing
        # between them would be a coin flip.
        return Intent(
            AMBIGUOUS, text=line, confidence="shorthand",
            candidates=("llm-resume", "assess", "tools-resume", "recover-report", "serve"),
            values={"report_directory": candidate},
            problem=f"{candidate.name} 是一次已完成的运行；你想对它做什么？",
        )
    return Intent(ACTION, action="scan", text=line, confidence="shorthand",
                  argv=(str(candidate),), values={"source": candidate})


# --- shorthand --------------------------------------------------------------


def _shorthand(line: str, state: State) -> Intent:
    lowered = line.lower()
    matched = [
        action for action in REGISTRY
        if any(word and len(word) >= _MIN_KEYWORD and word.lower() in lowered for word in action.keywords)
    ]
    subject = _subject_in(line)
    if len(matched) > 1:
        return Intent(AMBIGUOUS, text=line, confidence="shorthand",
                      candidates=tuple(action.name for action in matched),
                      problem="这句话同时像 " + "、".join(action.name for action in matched) + "；你指哪一个？")
    if not matched:
        return Intent(UNKNOWN, text=line,
                      problem="没看懂这句话。/help 列出全部命令，/ask 可以交给模型理解。")
    action = matched[0]
    argv: list[str] = []
    if subject is not None:
        argv.append(str(subject))
    return Intent(ACTION, action=action.name, text=line, confidence="shorthand",
                  argv=tuple(argv), values={"source": subject} if subject else {})


def _subject_in(line: str) -> Path | None:
    for token in line.split():
        if not any(mark in token for mark in ("/", "~", ".")):
            continue
        candidate = Path(token).expanduser()
        if candidate.exists():
            return candidate
    return None


def help_lines() -> list[str]:
    """What /help shows: every action, then the conversation's own commands."""
    lines = ["命令（/ 开头）："]
    for action in REGISTRY:
        names = "、".join("/" + name for name in action.names())
        lines.append(f"  {names:<34} {action.summary}")
    lines.append("")
    lines.append("会话与运行控制：")
    for name, summary in META_COMMANDS.items():
        lines.append(f"  /{name:<33} {summary}")
    lines.append("")
    lines.append("  /set <配置路径> <值>                 改一项配置")
    lines.append("  /ask <一句话>                        交给模型理解")
    lines.append("")
    lines.append("也可以直接输入一个目录（提议扫描它），或用简写，例如「扫描 ~/fw」。")
    return lines

"""What the operator typed: a command, a path, or something to be understood.

Two shapes resolve here, instantly and offline, because both are unambiguous:
a **slash command** and a **bare path**.  Everything else is a sentence, and a
sentence goes to the model automatically -- no prefix, no `/ask`, no keyword
table pretending to understand it.

There used to be a third shape: a closed table of keywords matched as
substrings anywhere in the line, so "扫描" won a scan and "配置一下扫描" won an
argument with itself.  It is deleted.  It was imitating comprehension with a
lookup, and once the model is on the main path there is nothing left for it to
do except disagree with the model about what a word means.

What stays deterministic, and why each one earns it:

* **A slash command** is the operator naming an action.  Its tail is parsed by
  the very argparse subparser the CLI builds for that subcommand, so it accepts
  exactly what `code-analyzer analyze` accepts.
* **A path that exists** is a subject, not a sentence.  Handing it to a model
  would spend seconds arriving at the reading the filesystem already gave us.
* **A path that does not exist** is a typo.  The intent model has no
  filesystem (`allowed-tools: []`), so it cannot repair `~/fwm`; routing the
  commonest keyboard error to the most expensive operation would be absurd.
* **A directory holding a manifest.json** has five readings and four of them
  write.  The model would receive exactly what this parser received and choose
  among the same five.  The presentation is upgraded; the reader is not.

Nothing here imports textual, the harness or ``llm.*``.  ``ASK`` is returned as
*data* -- this module never calls ``gate()`` or ``propose()``, so the trunk
still answers with nothing installed and nothing reachable, and a test asserts
it the way ``tests/test_flow.py`` asserts the flow model imports no UI.
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

# CJK needs no spaces, so "扫描~/fw" is ONE token containing "/" and "~" and
# would otherwise be claimed by the bare-path lane and die on 路径不存在 --
# which is the primary input form of the operator this tool is written for.
_CJK = (
    (0x3000, 0x30FF),   # punctuation and kana
    (0x3400, 0x4DBF),   # extension A
    (0x4E00, 0x9FFF),   # unified ideographs
    (0xF900, 0xFAFF),   # compatibility ideographs
)


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
    # Everything else is a sentence.  Returned as data: resolving it is the
    # front end's business, and this module still reaches no provider.
    return Intent(ASK, text=line, values={"utterance": line}, confidence="model")


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


def _has_cjk(line: str) -> bool:
    return any(any(low <= ord(ch) <= high for low, high in _CJK) for ch in line)


def _bare_path(line: str, state: State) -> Intent | None:
    """A path on its own line names a subject, and never runs by itself."""
    if len(line.split()) != 1 or line.startswith("-") or _has_cjk(line):
        return None
    candidate = Path(line).expanduser()
    looks_like_path = any(mark in line for mark in ("/", "\\", "~", ".")) or candidate.exists()
    if not looks_like_path:
        return None
    if not candidate.exists():
        return Intent(UNKNOWN, text=line, problem=f"路径不存在：{candidate}")
    if candidate.is_file() and candidate.name == "compile_commands.json":
        return Intent(ACTION, action="scan", text=line, confidence="path",
                      argv=(str(candidate.parent), "--compile-db", str(candidate)))
    if not candidate.is_dir():
        return Intent(UNKNOWN, text=line, problem=f"不是一个目录：{candidate}")
    if (candidate / "manifest.json").exists():
        # A finished run has five things one might want from it; guessing
        # between them would be a coin flip.
        return Intent(
            AMBIGUOUS, text=line, confidence="path",
            candidates=("llm-resume", "assess", "tools-resume", "recover-report", "serve"),
            values={"report_directory": candidate},
            problem=f"{candidate.name} 是一次已完成的运行；你想对它做什么？",
        )
    return Intent(ACTION, action="scan", text=line, confidence="path",
                  argv=(str(candidate),), values={"source": candidate})


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
    lines.append("")
    lines.append("其余的直接说就行——不认识的输入会自动交给模型理解，不需要前缀。")
    lines.append("直接输入一个目录会提议扫描它。`/ask <一句话>` 可以强制走模型。")
    return lines

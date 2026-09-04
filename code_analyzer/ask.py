"""One seam for "an action stopped to ask the operator something".

Three of these existed, in three shapes: the build-context patch dialog
(``control.stdin_decider`` on the terminal, ``PatchScreen`` in the TUI), and
the compile-db wizard's two prompts (``compile_db_wizard.input_from``).  They
are the same event -- an action is half done and cannot finish without an
answer -- so they get one vocabulary here.  The front end decides how a
question is *rendered*: the CLI prints it and reads a line, the conversation
appends a block and waits, a test answers from a script.

``interactive`` is part of the seam rather than a property of a stream because
the two things an action asks are different questions: "may I ask at all?" is
what decides whether the compile-db wizard refuses a non-interactive session,
and "what is the answer?" is what it does once it may.  A bare callable can
only answer the second.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TextIO

# The kinds a front end must know how to draw.  `select` is the multi-choice
# the build-context patch needs (tick some of N); `choose` is one of N.
CONFIRM = "confirm"
TEXT = "text"
CHOOSE = "choose"
SELECT = "select"
KINDS = frozenset({CONFIRM, TEXT, CHOOSE, SELECT})

_YES = frozenset({"y", "yes", "确认"})
_ALL = frozenset({"全部", "all", "都要", "都跑"})
_NO = frozenset({"n", "no", "否", "不", "取消", "全部拒绝"})
# What a `select` answer may say, in the words the prompt offers.  One
# definition, because two front ends ask the same question and an answer that
# works in the conversation and not on the terminal is a worse dialog than one
# that only ever took yes.
SELECT_HELP = "y=已勾选的 · 编号 1,3 · 范围 1-6 · 全部 · 回车或 n 全拒绝"


def selection(question: "Question", text: str) -> tuple[int, ...]:
    """Which options an answer names.

    ``y`` means the pre-ticked set, which is what the dialog opened with.
    Numbers, ranges and `全部` reach the items it drew *unticked* -- a stub
    header is offered per item and deliberately never pre-ticked, so without
    them the checkbox dialog was a yes/no question with checkboxes painted on
    it.
    """
    answer = text.strip().lower()
    if not answer or answer in _NO:
        return ()
    if answer in _YES:
        return tuple(question.preselected)
    if answer in _ALL:
        return tuple(range(len(question.options)))
    chosen: list[int] = []
    for piece in answer.replace("，", ",").replace("、", ",").split(","):
        piece = piece.strip()
        low, dash, high = piece.partition("-")
        if dash and low.strip().isdigit() and high.strip().isdigit():
            chosen.extend(
                index - 1 for index in range(int(low), int(high) + 1)
                if 1 <= index <= len(question.options)
            )
        elif piece.isdigit() and 1 <= int(piece) <= len(question.options):
            chosen.append(int(piece) - 1)
    return tuple(dict.fromkeys(chosen))


@dataclass(frozen=True)
class Question:
    """What an action needs to know, and enough context to answer it."""

    id: str
    kind: str
    prompt: str
    default: str = ""
    # For `choose` and `select`: the options, and which are pre-ticked.
    options: tuple[str, ...] = ()
    preselected: tuple[int, ...] = ()
    # Lines the operator should read before answering: the argv about to run,
    # the title of the patch.  The front end prints them above the options.
    preview: tuple[str, ...] = ()
    # And below them: the probe's verdict, the impact paragraph.  Two fields
    # rather than one because the terminal dialog has always put the items
    # between the title and the impact, and that reads correctly.
    footer: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown question kind: {self.kind}")


@dataclass(frozen=True)
class Answer:
    """What came back.  ``refused`` means nobody could be asked."""

    text: str = ""
    selected: tuple[int, ...] = ()
    refused: bool = False
    interrupted: bool = False
    reason: str = ""

    @property
    def yes(self) -> bool:
        return not self.refused and not self.interrupted and self.text.strip().lower() in _YES


@dataclass
class Asker:
    """How this front end asks.  Call it with a Question, get an Answer.

    ``interactive`` is False when there is nobody to ask; an action reads it to
    take the branch it already takes today rather than asking into a void.
    """

    reply: Any
    interactive: bool = True

    def __call__(self, question: Question) -> Answer:
        return self.reply(question)


def stdin_asker(stdin: TextIO, stderr: TextIO, *, interactive: bool | None = None) -> Asker:
    """The terminal's version: the preview, the prompt, one line back.

    Byte-for-byte what ``compile_db_wizard.input_from`` and
    ``control.stdin_decider`` printed, so a session that was scripted against
    the old prompts still answers the new ones.
    """

    def reply(question: Question) -> Answer:
        for line in question.preview:
            print(line, file=stderr)
        if question.kind in {CHOOSE, SELECT}:
            for index, option in enumerate(question.options, 1):
                tick = "x" if index - 1 in question.preselected else " "
                # Numbered, because the prompt asks for numbers.  Unnumbered
                # ticks with a "type 1,3" prompt made the operator count rows.
                print(f"  {index:>2} [{tick}] {option}", file=stderr)
        for line in question.footer:
            print(line, file=stderr)
        print(question.prompt, end="", file=stderr, flush=True)
        try:
            value = stdin.readline()
        except (OSError, ValueError):
            return Answer(refused=True, reason="stdin is not readable")
        except KeyboardInterrupt:
            return Answer(interrupted=True)
        text = "" if value == "" else value.rstrip("\n")
        if question.kind == SELECT:
            # The same vocabulary the conversation takes.  A bare yes still
            # means the pre-ticked set; the terminal used to accept nothing else,
            # so an item the run drew unticked could not be applied from a CLI.
            return Answer(text=text, selected=selection(question, text))
        return Answer(text=text)

    if interactive is None:
        try:
            interactive = bool(stdin.isatty())
        except (AttributeError, OSError):
            interactive = False
    return Asker(reply, interactive=interactive)


def refusing_asker(reason: str = "no interactive session") -> Asker:
    """Nobody to ask: every question comes back refused, with the reason."""
    return Asker(lambda _question: Answer(refused=True, reason=reason), interactive=False)


def scripted_asker(*answers: str | Answer) -> Asker:
    """Answers in order, for tests; refuses once the script runs out."""
    queue = [item if isinstance(item, Answer) else Answer(text=item) for item in answers]
    asked: list[Question] = []

    def reply(question: Question) -> Answer:
        asked.append(question)
        if not queue:
            return Answer(refused=True, reason="the script ran out of answers")
        return queue.pop(0)

    asker = Asker(reply, interactive=True)
    asker.asked = asked  # type: ignore[attr-defined]
    return asker


def question_from_decision(request: Any) -> Question:
    """A build-context ``DecisionRequest`` as a `select` question.

    The patch dialog is the oldest of the three askers and the only one with
    per-item ticks; it keeps its own request type (``control.py`` journals it
    and its tests pin it) and is adapted here rather than replaced.
    """
    options = tuple(
        f"{item.get('label', item.get('op'))}  {item.get('evidence', '')}  ({item.get('origin', '')})".strip()
        for item in request.items
    )
    footer = []
    if request.probe:
        footer.append(
            f"  probe: {request.probe.get('reached_after', 0)}/{request.probe.get('sampled', 0)}"
            " sampled unit(s) now preprocess"
        )
    footer.append(
        "  impact: re-runs only the failed units into new unit directories;"
        " no source, config file or build is touched."
    )
    return Question(
        id=f"build-context.{request.id}",
        kind=SELECT,
        prompt=f"Apply and re-run? ({SELECT_HELP}) ",
        options=options,
        preselected=tuple(request.preselected),
        preview=(f"\nBuild-context patch ({request.kind}, round {request.round}): {request.summary}",),
        footer=tuple(footer),
    )

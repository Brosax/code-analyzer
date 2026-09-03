"""The operator's conversation with the tool, as a model.

``chat.py`` is the *model's* conversation about the code -- one turn per scan
unit, folded from provider events.  This is the operator's conversation with
the tool: one block per thing they asked for.  They are siblings rather than
one class, for three reasons that are not stylistic:

* **The eviction rules are opposites.**  ``chat.Transcript`` forgets the oldest
  settled turns because a scan produces thousands of them and the transcript is
  a live view.  The operator's first question must still be scrollable an hour
  later.
* **The keying is different.**  A ``Turn`` is keyed by producer and unit and is
  created by an event; a block is created by a keystroke and has neither.
* **``CONVERSANTS`` exists to keep non-model producers out** of the transcript.
  Adding the operator to it would invert what that gate means.

So a ``RunBlock`` *composes* them: it owns a ``RunFlow``, a ``Transcript`` and
the ``RunControl`` for one run.  ``apply`` returns the id of the block that
changed rather than a bare bool, so a front end repaints one widget instead of
all of them -- with a real run emitting half a million events an hour, that
distinction is the difference between a live interface and a dead one.

Nothing here imports a UI.
"""
from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .analysis import AnalysisEvent
from .ask import Answer, Question
from .chat import Transcript
from .flow import RunFlow
from .progress import multi_line, single_line

# What a block is.  The front end resolves these to widgets and colours.
USER = "user"
SAY = "say"
RUN = "run"
CONFIG = "config"
QUESTION = "question"
ERROR = "error"
PROPOSAL = "proposal"

# A settled run keeps its summary and lets its turns go: ten scans in one
# session would otherwise hold ten transcripts of up to 240 turns each, and
# the evidence is on disk anyway -- which is chat.py's own argument for
# bounding itself in the first place.
_STATES_THAT_SETTLE = frozenset({"complete", "partial", "failed", "interrupted"})

_ids = itertools.count(1)


def _next_id(prefix: str) -> str:
    return f"{prefix}-{next(_ids)}"


@dataclass
class Block:
    """One thing in the conversation."""

    kind: str
    block_id: str = ""
    created_at: float = field(default_factory=time.time)
    text: str = ""
    lines: list[str] = field(default_factory=list)
    settled: bool = True
    summary: str = ""

    def __post_init__(self) -> None:
        if not self.block_id:
            self.block_id = _next_id(self.kind)

    def render(self) -> list[str]:
        """The lines a front end draws when this block is expanded."""
        return [line for line in ([self.text] if self.text else []) + list(self.lines) if line != ""]


@dataclass
class UserBlock(Block):
    """What the operator typed, kept verbatim so the record reads back."""

    kind: str = USER
    # How it was understood: the action name, or why it could not be.
    reading: str = ""

    def render(self) -> list[str]:
        lines = [f"› {single_line(self.text)}"]
        if self.reading:
            lines.append(f"  ↳ {single_line(self.reading)}")
        return lines


@dataclass
class SayBlock(Block):
    """The tool answering: a result, a listing, an explanation."""

    kind: str = SAY


@dataclass
class ErrorBlock(Block):
    """A refusal or a failure.  Scrollable, which a modal never was."""

    kind: str = ERROR


@dataclass
class QuestionBlock(Block):
    """An action stopped to ask something; the answer releases its worker."""

    kind: str = QUESTION
    question: Question | None = None
    answer: Answer | None = None
    settled: bool = False

    def render(self) -> list[str]:
        if self.question is None:
            return []
        lines = [*self.question.preview]
        for index, option in enumerate(self.question.options):
            tick = "x" if index in self.question.preselected else " "
            lines.append(f"  [{tick}] {option}")
        lines.extend(self.question.footer)
        lines.append(f"  {self.question.prompt.strip()}")
        if self.answer is not None:
            lines.append(f"  › {single_line(self.answer.text) or '（无）'}")
        return lines


@dataclass
class ConfigBlock(Block):
    """A configuration change, or a listing of what is set."""

    kind: str = CONFIG
    changes: list[tuple[str, Any, Any]] = field(default_factory=list)

    def render(self) -> list[str]:
        lines = list(self.lines)
        for path, before, after in self.changes:
            lines.append(f"  {path}: {before!r} → {after!r}")
        return lines


@dataclass
class RunBlock(Block):
    """One long-running action: the flow, the model's transcript, the control.

    Collapsed it is a few live lines; expanded it is the diagram the old run
    view drew.  Both come from the same two models, which is why the painters
    move across unchanged.
    """

    kind: str = RUN
    action: str = ""
    flow: RunFlow | None = None
    chat: Transcript | None = None
    control: Any = None
    settled: bool = False
    exit_code: int | None = None
    report_directory: Path | None = None
    # Kept after the transcript's turns are released.
    final_summary: str = ""
    final_stats: Any = None

    def apply(self, event: AnalysisEvent) -> bool:
        changed = False
        if self.flow is not None and self.flow.apply(event):
            changed = True
        if self.chat is not None and self.chat.apply(event):
            changed = True
        return changed

    def headline(self, now: float | None = None) -> str:
        """The one line the collapsed block shows while it runs."""
        if self.settled:
            return self.summary or "已结束"
        if self.flow is None:
            return self.text or "运行中"
        now = time.time() if now is None else now
        head = self.flow.headline(now)
        running = self.flow.running_producers()
        detail = f" · {'、'.join(running)}" if running else ""
        return single_line(f"{head.title} · {head.detail}{detail}")

    def settle(self, exit_code: int, summary: str, report_directory: Path | None = None) -> None:
        """Keep what the block will show forever; let the turns go."""
        self.exit_code = exit_code
        self.report_directory = report_directory
        self.settled = True
        if self.chat is not None:
            self.final_summary = self.chat.summary()
            self.final_stats = self.chat.stats()
            # The turns were a live view; the run directory keeps the evidence.
            self.chat = Transcript()
        clock = ""
        if self.flow is not None and self.flow.started_at:
            clock = f" · 用时 {_clock(time.time() - self.flow.started_at)}"
        where = f" · {report_directory}" if report_directory else ""
        mark = "✓" if exit_code == 0 else ("✕" if exit_code not in {1, 10} else "◐")
        self.summary = single_line(f"{mark} {summary} · 退出码 {exit_code}{clock}{where}")


@dataclass
class ProposalBlock(Block):
    """What a model suggested, per item, nothing pre-ticked."""

    kind: str = PROPOSAL
    steps: list[dict[str, Any]] = field(default_factory=list)
    chosen: tuple[int, ...] = ()
    settled: bool = False

    def render(self) -> list[str]:
        lines = list(self.lines)
        for index, step in enumerate(self.steps):
            tick = "x" if index in self.chosen else " "
            lines.append(f"  [{tick}] {step.get('label') or step.get('action')}")
            for note in step.get("impact", ()):
                lines.append(f"      {note}")
        return lines


class Dialogue:
    """Every block of one session, and the state the parser reads."""

    def __init__(self, *, source: Path | None = None, config: dict[str, Any] | None = None) -> None:
        self.blocks: list[Block] = []
        self.source = source
        self.report_directory: Path | None = None
        self.config: dict[str, Any] = config if config is not None else {}
        self._by_id: dict[str, Block] = {}

    # --- building -----------------------------------------------------------

    def add(self, block: Block) -> Block:
        self.blocks.append(block)
        self._by_id[block.block_id] = block
        if isinstance(block, RunBlock) and block.report_directory is not None:
            self.report_directory = block.report_directory
        return block

    def said(self, text: str, reading: str = "") -> UserBlock:
        return self.add(UserBlock(text=text, reading=reading))  # type: ignore[return-value]

    def say(self, text: str, lines: list[str] | None = None) -> SayBlock:
        return self.add(SayBlock(text=text, lines=list(lines or [])))  # type: ignore[return-value]

    def failed(self, text: str, lines: list[str] | None = None) -> ErrorBlock:
        return self.add(ErrorBlock(text=text, lines=list(lines or [])))  # type: ignore[return-value]

    def ask(self, question: Question) -> QuestionBlock:
        return self.add(QuestionBlock(question=question, text=question.prompt))  # type: ignore[return-value]

    def run(self, action: str, flow: RunFlow, control: Any = None) -> RunBlock:
        block = RunBlock(action=action, flow=flow, chat=Transcript(), control=control, text=action)
        return self.add(block)  # type: ignore[return-value]

    # --- folding ------------------------------------------------------------

    def apply(self, block_id: str, event: AnalysisEvent) -> str | None:
        """Fold one event into one block; return its id when the view changed.

        The id rather than a bool: a front end repaints the block that moved,
        not the whole transcript.
        """
        block = self._by_id.get(block_id)
        if not isinstance(block, RunBlock):
            return None
        return block.block_id if block.apply(event) else None

    def get(self, block_id: str) -> Block | None:
        return self._by_id.get(block_id)

    # --- what the front end and the parser ask for --------------------------

    def live_run(self) -> RunBlock | None:
        """The run in flight, if any.  At most one at a time, by construction."""
        for block in reversed(self.blocks):
            if isinstance(block, RunBlock) and not block.settled:
                return block
        return None

    def pending_question(self) -> QuestionBlock | None:
        for block in reversed(self.blocks):
            if isinstance(block, QuestionBlock) and block.answer is None:
                return block
        return None

    def answer(self, block_id: str, answer: Answer) -> bool:
        block = self._by_id.get(block_id)
        if not isinstance(block, QuestionBlock) or block.answer is not None:
            return False
        block.answer = answer
        block.settled = True
        return True

    def state(self) -> Any:
        from .intent import State

        return State(
            source=self.source,
            report_directory=self.report_directory,
            running=self.live_run() is not None,
        )

    def lines(self, *, limit: int | None = None) -> list[str]:
        """The whole conversation as text, for a test or a journal."""
        out: list[str] = []
        for block in self.blocks:
            if isinstance(block, RunBlock):
                out.append(block.headline())
                continue
            out.extend(multi_line(line) for line in block.render())
        return out[-limit:] if limit else out


def _clock(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}" if hours else f"{minutes:02d}:{secs:02d}"

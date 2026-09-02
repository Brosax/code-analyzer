"""The live run flow the TUI draws, folded from the event stream.

``serve`` projects ``manifest.json``; this projects ``AnalysisEvent`` objects.
They are two views of one vocabulary (``status.NODE_STATES``), and both are
needed: while a run is in flight the manifest is deliberately coarse -- a
running tool's ``unit_counts`` are zeroed (``runner._running_state``) and the
LLM phase publishes ``scanners: {}`` (``llm_scan.running``) -- so a per-scanner
live view has to come from the events.  Once the run ends the manifest is the
fine-grained one, which is why the result screen still reads it.

Pure: no Textual, no Rich, no I/O.  Rows are plain strings and the caller
decides how to paint them, so this module is unit-tested the way
``serve.graph`` is.

Two rules the design leans on:

* **Count units; read the denominator from the event's data.**  The numerator
  is an integer incremented on terminal ``unit`` events; the total is the
  ``data["total"]`` a producer announces and is only ever ratcheted upwards.
  A total that never arrives leaves the denominator unknown and the row says
  "已完成 7 单元" instead of inventing "7/12".
* **Untrusted text is cleaned on the way in, not on the way out.**  Scanned
  file names and analyzer output reach these rows; every string lifted from an
  event goes through ``single_line`` and a length cap at ingestion, so no
  renderer can be the one that forgets.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .analysis import AnalysisEvent
from .progress import BRAILLE_FRAMES, single_line
from .status import NODE_STATES, STATE_GLYPHS
from .tools import LLM_PRODUCERS, TOOL_NAMES

# Two balanced columns at this width or wider; below it the flow panel and the
# log stack, and the flow gets far fewer rows.
WIDE_BREAKPOINT = 120
MAX_DETAIL = 200
SPINE_RAMP = 3

TAIL_NODES: tuple[tuple[str, str], ...] = (
    ("stability", "稳定"),
    ("review", "审查"),
    ("audit", "关联"),
    ("export", "导出"),
    ("dashboard", "报告"),
)
# The node ids are the ones `serve.graph` uses (`status.PHASE_NODES`), so the
# two front ends draw one run; only the labels are the TUI's.

# Statuses that say "this unit is alive", not "this unit moved".  Pinned as
# carrying no progress value by tests/test_events.py.
_LIVENESS = frozenset({"heartbeat", "info", "started", "step"})

# Phase events speak started/finished/failed; the status ladder speaks
# running/completed/failed.  Translating first keeps one projection table
# instead of two, and a phase word that fell through NODE_STATES used to leave
# a finished node drawn as pending.
_PHASE_WORDS = {"started": "running", "finished": "completed", "failed": "failed"}

# Batched statuses that mean "never ran" as opposed to "ran and ended".
_NEVER_RAN = frozenset({"unscheduled", "skipped"})


@dataclass(frozen=True)
class Row:
    """One rendered line.  ``glyph`` is already resolved, spinner included."""

    node_id: str
    spine: str
    glyph: str
    label: str
    detail: str
    state: str
    pulse: int = 0


@dataclass(frozen=True)
class Headline:
    title: str
    detail: str
    percent: int


@dataclass
class Node:
    id: str
    kind: str
    label: str
    state: str = "pending"
    status: str = "pending"
    detail: str = ""
    method: str = ""
    done: int = 0
    total: int | None = None
    failures: int = 0
    unscheduled: int = 0
    excluded: int = 0
    findings: int | None = None
    started_at: float | None = None
    finished_at: float | None = None
    last_seen: float | None = None
    order: int = 0
    in_flight: dict[str, str] = field(default_factory=dict)
    # Why units ended the way they did: failure class (or status word) -> count.
    reasons: dict[str, int] = field(default_factory=dict)

    @property
    def counted(self) -> str:
        if self.total is None:
            return f"已完成 {self.done} 单元" if self.done else ""
        # A replan round legitimately rescans a unit, so `done` can pass the
        # round-0 plan; showing 42/41 would read as a bug in the counter.
        return f"单元 {min(self.done, self.total)}/{self.total}"


def capacity(width: int, height: int) -> int:
    """How many rows the flow panel may draw at this terminal size.

    Computed rather than measured so the renderer never has to ask "how many
    lines fit" in order to decide how many lines to produce.
    """
    if width >= WIDE_BREAKPOINT:
        return max(6, min(16, height - 8))
    return max(5, min(13, height - 17))


def _clean(value: Any) -> str:
    return single_line(str(value))[:MAX_DETAIL]


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


class RunFlow:
    """Every node of one run, and what the last event did to it."""

    def __init__(self, config: dict[str, Any], *, preflight: Any = None) -> None:
        llm = config.get("llm") or {}
        tools = config.get("tools") or {}
        review = config.get("review") or {}
        run = config.get("run") or {}
        self.nodes: dict[str, Node] = {}
        self._order = 0
        self._add("discovery", "phase", "发现")
        for name in TOOL_NAMES:
            if (tools.get(name) or {}).get("enabled"):
                self._add(name, "static", name)
        if llm.get("enabled"):
            selected = set(llm.get("scanners") or ())
            for name in LLM_PRODUCERS:
                if name in selected:
                    self._add(name, "llm", name)
        for node_id, label in TAIL_NODES:
            self._add(node_id, "phase", label)
        if not review.get("enabled", True):
            self._disable("review")
            self._disable("audit")
        if not run.get("shareable_export", True):
            self._disable("export")
        self.percent = 0.0
        self.run_name = ""
        self.stopping = False
        self.finished = False
        self.started_at: float | None = None
        self.llm_planned: int | None = None
        self.llm_scanners: int | None = None
        self.llm_done = 0
        self.llm_unscheduled = 0
        self.llm_total: int | None = None
        self.tokens_spent = 0
        self.token_budget = int(llm.get("total_prompt_tokens") or 0) if llm.get("enabled") else 0
        self.llm_jobs = int(llm.get("jobs") or 0) if llm.get("enabled") else 0
        self.model = str(llm.get("model") or "") if llm.get("enabled") else ""
        self._method_from_config(tools)
        self._seed_from_preflight(preflight)

    # --- construction -------------------------------------------------------

    def _add(self, node_id: str, kind: str, label: str) -> None:
        self._order += 1
        self.nodes[node_id] = Node(id=node_id, kind=kind, label=label, order=self._order)

    def _disable(self, node_id: str) -> None:
        node = self.nodes.get(node_id)
        if node is not None:
            node.status = "disabled"
            node.detail = "未启用"

    def _method_from_config(self, tools: dict[str, Any]) -> None:
        splint = self.nodes.get("splint")
        if splint is not None:
            settings = tools.get("splint") or {}
            scope = settings.get("scope", "auto")
            splint.method = f"范围 {scope} · jobs {settings.get('jobs', 1)}"

    def _seed_from_preflight(self, preflight: Any) -> None:
        """Give the discovery row content before the first event arrives."""
        if preflight is None:
            return
        node = self.nodes["discovery"]
        files = getattr(preflight, "inventory_files", None)
        database = getattr(preflight, "compile_database", None) or {}
        parts = [f"{files} 文件"] if files is not None else []
        if database:
            path = database.get("path")
            parts.append(f"compile-db {Path(path).name}" if path else "无 compile-db · 降级上下文")
        node.detail = " · ".join(parts)

    # --- folding ------------------------------------------------------------

    def apply(self, event: AnalysisEvent) -> bool:
        """Fold one event in.  True when the drawn view would change.

        ``output`` is most of a real run's traffic and is rejected on the
        first line: it never reaches a counter or a node.
        """
        if event.phase == "output":
            return False
        if event.progress is not None:
            self.percent = max(self.percent, float(event.progress))
        handler = getattr(self, f"_on_{event.phase}", None)
        if handler is None:
            return True
        handler(event)
        return True

    def mark_stopping(self) -> None:
        self.stopping = True

    def _on_analysis(self, event: AnalysisEvent) -> None:
        if event.status == "started":
            self.started_at = event.timestamp
            return
        if event.status == "stopping":
            self.stopping = True
            return
        self.finished = True
        state = "failed" if event.status == "interrupted" else "success"
        for node in self.nodes.values():
            if node.state == "running":
                node.state = state
                node.status = event.status
                node.finished_at = event.timestamp
        report = self.nodes.get("dashboard")
        if report is not None and report.status in {"pending", "running"}:
            report.state = state
            report.status = event.status
            report.detail = "index.html" if state == "success" else _clean(event.message)

    def _on_run(self, event: AnalysisEvent) -> None:
        if event.status == "created":
            self.run_name = Path(_clean(event.message)).name

    def _on_discovery(self, event: AnalysisEvent) -> None:
        node = self.nodes["discovery"]
        data = event.data or {}
        if event.status == "started":
            self._start(node, event)
            return
        if event.status == "info":
            if data.get("degraded") or "compile database" in event.message:
                node.method = "降级上下文"
            return
        self._finish(node, event)
        files = _count(data.get("files"))
        if files is not None:
            parts = [f"{files} 文件"]
            entries = _count(data.get("compile_db_entries"))
            if entries:
                parts.append(f"compile-db {entries} 条")
            elif data.get("compile_db_path") is None:
                parts.append("无 compile-db")
            node.detail = " · ".join(parts)

    def _on_tool(self, event: AnalysisEvent) -> None:
        node = self.nodes.get(str(event.tool or ""))
        if node is None:
            return
        if event.status == "started":
            self._start(node, event)
            return
        self._finish(node, event)
        node.in_flight.clear()
        data = event.data or {}
        if data.get("reason"):
            node.detail = _clean(data["reason"])
        elif event.status in {"missing", "incompatible", "interrupted", "skipped", "failed"}:
            # A tool that never ran has only its message to explain itself.
            node.detail = _clean(event.message)

    def _on_llm(self, event: AnalysisEvent) -> None:
        if event.status == "started":
            return
        data = event.data or {}
        if event.status == "planned":
            units, tasks = _count(data.get("units")), _count(data.get("tasks"))
            if units is not None:
                self.llm_planned = units
                for node in self.nodes.values():
                    if node.kind == "llm":
                        node.total = max(node.total or 0, units)
            self.llm_scanners = _count(data.get("scanners"))
            if tasks is not None:
                self.llm_total = max(self.llm_total or 0, tasks)
            return
        if event.status in {"replan", "breaker_open"}:
            return
        # The phase's own terminal word settles every scanner still running;
        # a scanner that finished its own units has already settled itself.
        for node in self.nodes.values():
            if node.kind == "llm" and node.state in {"pending", "running"}:
                self._finish(node, event)
                node.in_flight.clear()

    def _on_unit(self, event: AnalysisEvent) -> None:
        node = self.nodes.get(str(event.tool or ""))
        if node is None:
            return
        unit = _clean(event.unit or "")
        data = event.data or {}
        node.last_seen = event.timestamp
        # Any unit event is proof the producer is working, including a
        # terminal one that arrives before its own "started" was folded in.
        if node.state == "pending":
            self._start(node, event)
        total = _count(data.get("total"))
        if total is not None:
            # A static tool's total is its own; an LLM task index runs over
            # every scanner, so it feeds the phase total and the per-scanner
            # denominator comes from the plan (`llm/planned`).
            if node.kind == "llm":
                self.llm_total = max(self.llm_total or 0, total)
            else:
                node.total = max(node.total or 0, total)
        if event.status in _LIVENESS:
            if event.status == "started":
                token = self._unit_token(node, unit, event)
                node.in_flight[unit] = token
                node.method = token
            elif event.status == "step" and unit in node.in_flight:
                node.in_flight[unit] = self._unit_token(node, unit, event) + " · " + _clean(event.message)
            self._absorb_tokens(data)
            return
        node.in_flight.pop(unit, None)
        node.done += 1
        if event.status != "completed":
            node.failures += 1
            self._remember_reason(node, str(data.get("failure_class") or event.status), 1)
        found = data.get("findings") if data.get("findings") is not None else data.get("finding_count")
        if _count(found) is not None:
            node.findings = (node.findings or 0) + int(found)
        node.detail = _clean(event.message)
        if node.kind == "llm":
            self.llm_done += 1
            if node.total is not None and node.done >= node.total and not node.failures:
                self._settle(node, "completed", event.timestamp)

    def _on_units(self, event: AnalysisEvent) -> None:
        """A batch of units that never ran (or, for flawfinder, files it never saw)."""
        node = self.nodes.get(str(event.tool or ""))
        if node is None:
            return
        data = event.data or {}
        count = _count(data.get("count")) or 0
        node.last_seen = event.timestamp
        if event.status == "info":
            if data.get("reason") == "encoding":
                node.excluded += count
            return
        if node.state == "pending":
            self._start(node, event)
        total = _count(data.get("total"))
        if total is not None:
            if node.kind == "llm":
                self.llm_total = max(self.llm_total or 0, total)
            else:
                node.total = max(node.total or 0, total)
        if event.status in _NEVER_RAN:
            node.unscheduled += count
            if node.kind == "llm":
                self.llm_unscheduled += count
        else:
            node.done += count
            node.failures += count
            if node.kind == "llm":
                self.llm_done += count
        self._remember_reason(node, str(data.get("reason") or event.status), count)

    def _on_stability(self, event: AnalysisEvent) -> None:
        self._phase_event("stability", event)

    def _on_review(self, event: AnalysisEvent) -> None:
        self._phase_event("review", event)

    def _on_audit(self, event: AnalysisEvent) -> None:
        self._phase_event("audit", event)

    def _on_export(self, event: AnalysisEvent) -> None:
        self._phase_event("export", event)

    def _on_report(self, event: AnalysisEvent) -> None:
        self._phase_event("dashboard", event)

    # --- helpers ------------------------------------------------------------

    def _phase_event(self, node_id: str, event: AnalysisEvent) -> None:
        node = self.nodes.get(node_id)
        if node is None:
            return
        if event.status == "started":
            self._start(node, event)
            return
        self._finish(node, event)
        node.detail = _clean(event.message)

    def _start(self, node: Node, event: AnalysisEvent) -> None:
        node.state = "running"
        node.status = "running"
        node.started_at = node.started_at or event.timestamp
        node.last_seen = event.timestamp

    def _finish(self, node: Node, event: AnalysisEvent) -> None:
        self._settle(node, event.status, event.timestamp)

    def _settle(self, node: Node, status: str, when: float) -> None:
        word = _PHASE_WORDS.get(status, status)
        node.status = status
        node.state = NODE_STATES.get(word, "pending")
        node.finished_at = when
        if node.kind in {"static", "llm"} and node.state != "running":
            # The last "scanning …" line is not what a finished producer has
            # to say; its counters and findings are.
            node.detail = ""

    @staticmethod
    def _remember_reason(node: Node, reason: str, count: int) -> None:
        key = _clean(reason)[:80] or "unknown"
        if key in node.reasons or len(node.reasons) < 20:
            node.reasons[key] = node.reasons.get(key, 0) + count

    def _unit_token(self, node: Node, unit: str, event: AnalysisEvent) -> str:
        """What this unit says about the *method* being used.

        For cppcheck the unit id is the method outright -- ``compile-db`` is the
        build-aware pass, ``fallback`` the source-only one -- for splint it is
        the translation unit's path, and for the LLM the path plus risk tier.
        """
        data = event.data or {}
        if node.kind == "llm":
            path, tier = data.get("path"), data.get("tier")
            if path:
                return _clean(f"{path} ({tier})" if tier else path)
            message = _clean(event.message)
            return message[len("scanning "):] if message.startswith("scanning ") else message
        label = data.get("label")
        return _clean(label) if label else unit

    def _absorb_tokens(self, data: dict[str, Any]) -> None:
        spent = _count(data.get("prompt_tokens_estimated"))
        if spent is not None:
            self.tokens_spent = max(self.tokens_spent, spent)

    # --- rendering ----------------------------------------------------------

    def headline(self, now: float) -> Headline:
        running = [node for node in self._producers() if node.state == "running"]
        active = running[0] if running else None
        if self.finished:
            title = "扫描结束"
        elif self.stopping:
            title = "正在安全停止…"
        elif active is None:
            title = "正在扫描"
        else:
            title = f"正在扫描 · {active.label} {active.method or active.detail}".rstrip()
        parts = [f"{int(self.percent * 100)}%", f"已运行 {_clock(self.started_at, now)}"]
        static = [node for node in self.nodes.values() if node.kind == "static"]
        if static:
            done = sum(1 for node in static if node.state in {"success", "partial", "failed"})
            parts.append(f"静态 {done}/{len(static)}")
        if self.llm_total:
            llm = f"LLM {self.llm_done}/{self.llm_total}"
            if self.llm_unscheduled:
                llm += f"（{self.llm_unscheduled} 未调度）"
            parts.append(llm)
        if self.token_budget:
            parts.append(f"prompt {_thousands(self.tokens_spent)}/{_thousands(self.token_budget)}（估算：字符/4）")
        return Headline(title=_clean(title), detail=" · ".join(parts), percent=int(self.percent * 100))

    def rows(self, *, capacity: int, now: float, frame: int) -> list[Row]:
        """The panel's lines, most important first when space runs out."""
        head = self.nodes["discovery"]
        rows = [Row("discovery", "", self._glyph(head, frame), head.label, self._detail(head, now), head.state)]
        producers = self._producers()
        room = max(0, capacity - 2)
        shown, omitted = self._select(producers, room)
        for index, node in enumerate(shown):
            rows.append(Row(
                node.id, "├", self._glyph(node, frame), node.label, self._detail(node, now),
                node.state, (frame + index) % SPINE_RAMP,
            ))
        if omitted:
            rows.append(Row("", "│", " ", f"… 另外 {len(omitted)} 个", _summarise(omitted), "pending"))
        rows.append(self._tail(frame))
        return rows

    def _producers(self) -> list[Node]:
        return [node for node in self.nodes.values() if node.kind in {"static", "llm"}]

    def _select(self, producers: list[Node], room: int) -> tuple[list[Node], list[Node]]:
        """Running nodes are never hidden -- they are why this panel exists."""
        if len(producers) <= room:
            return producers, []
        rank = {"running": 0, "failed": 1, "partial": 1, "success": 2, "pending": 3}
        ordered = sorted(producers, key=lambda node: (rank.get(node.state, 3), -(node.finished_at or 0), node.order))
        keep = ordered[: max(0, room - 1)]
        kept = {node.id for node in keep}
        return (
            [node for node in producers if node.id in kept],
            [node for node in producers if node.id not in kept],
        )

    def _tail(self, frame: int) -> Row:
        cells = []
        for node_id, label in TAIL_NODES:
            node = self.nodes[node_id]
            cells.append(f"{self._glyph(node, frame)} {label}")
        return Row("", "└→", "", " → ".join(cells), "", "pending", frame % SPINE_RAMP)

    def _glyph(self, node: Node, frame: int) -> str:
        if node.state != "running":
            return STATE_GLYPHS[node.state]
        if frame < 0:
            return STATE_GLYPHS["running"]
        return BRAILLE_FRAMES[frame % len(BRAILLE_FRAMES)]

    def _detail(self, node: Node, now: float) -> str:
        if node.status == "disabled":
            return "未启用"
        parts = []
        # A producer that has not started yet says "等待", not "0/41": the
        # denominator is a plan, and a plan is not progress.
        counted = "" if node.state == "pending" and not node.done else node.counted
        if counted:
            parts.append(counted)
        if node.state == "running":
            # The structured label names splint's translation unit by its
            # source path and cppcheck's pass by its name; where a unit is in
            # flight, that is what the row shows.
            token = node.method or next(iter(node.in_flight.values()), "")
            if token:
                parts.append(token)
            if node.detail and node.detail not in parts:
                parts.append(node.detail)
            elapsed = _clock(node.started_at, now)
            if elapsed != "00:00":
                parts.append(elapsed)
        elif node.state == "pending":
            parts.append("等待")
            if node.method:
                parts.append(node.method)
        else:
            if node.findings is not None:
                parts.append(f"{node.findings} findings")
            if node.detail:
                parts.append(node.detail)
            if node.failures:
                parts.append(f"{node.failures} 失败")
            if node.unscheduled:
                parts.append(f"{node.unscheduled} 未调度")
            if node.excluded:
                parts.append(f"{node.excluded} 文件编码排除")
        return _clean(" · ".join(part for part in parts if part))


def _summarise(nodes: list[Node]) -> str:
    buckets = {"pending": "等待", "running": "运行", "success": "完成", "partial": "部分", "failed": "失败"}
    counted = {key: sum(1 for node in nodes if node.state == key) for key in buckets}
    return " · ".join(f"{value} {buckets[key]}" for key, value in counted.items() if value)


def _clock(started: float | None, now: float) -> str:
    elapsed = 0 if started is None else max(0, int(now - started))
    hours, remainder = divmod(elapsed, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"


def _thousands(value: int) -> str:
    """Token counts run to millions once the budget scales with scanners."""
    for step, suffix in ((1_000_000, "M"), (1_000, "k")):
        if value >= step:
            scaled = value / step
            return f"{scaled:.0f}{suffix}" if scaled >= 100 or scaled.is_integer() else f"{scaled:.1f}{suffix}"
    return str(value)

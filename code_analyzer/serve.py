"""``code-analyzer serve``: a live view of one run over stdlib HTTP and SSE.

Two modes, one page.  ``serve REPORT_DIR`` is a read-only tailer of a run
another process is writing (or has finished); it cannot cancel anything.
``serve --analyze SOURCE`` runs the analysis in this process and can, because
the cancellation token is a ``threading.Event`` that has to live where the
analysis does.

The page is served from memory and derives everything it shows from two
files: ``events.jsonl`` for the timeline and ``manifest.json`` for node
state.  There is no second source of truth -- the DAG is ``graph(manifest)``
-- and the offline ``index.html`` with its tested no-network contract is not
touched; the live page links to it once the run has written it.

Binds 127.0.0.1 only.  ``POST /cancel`` additionally requires a same-origin
``Origin`` header so that another local page cannot cancel a scan.
"""
from __future__ import annotations

import json
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from .analysis import AnalysisEvent, AnalysisRequest, CancellationToken, run_analysis
from .chat import CONVERSANTS
from .control import LANES, RunControl
from .errors import UserError
from .events import RUN_DIRECTORY_PHASE, clean_data
from .persist import json_bytes
from .status import EXIT_INTERRUPTED, NODE_STATES, PHASE_NODES, STATE_GLYPHS

BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8765
EVENTS_FILENAME = "events.jsonl"
POLL_SECONDS = 0.5



def graph(manifest: dict[str, Any]) -> dict[str, Any]:
    """The DAG the page draws, derived from the manifest and nothing else."""
    tools = manifest.get("tools") or {}
    scanners = ((manifest.get("llm") or {}).get("scanners")) or {}
    nodes: list[dict[str, Any]] = [{"id": "discovery", "kind": "phase", "state": _phase_state(manifest, "discovery")}]
    producers: list[str] = []
    for name, record in tools.items():
        producers.append(name)
        nodes.append({"id": name, "kind": "static", "state": _state(record.get("status")),
                      "status": record.get("status"), "units": record.get("unit_counts"),
                      "findings": record.get("findings")})
    llm = manifest.get("llm") or {}
    for name, record in scanners.items():
        producers.append(name)
        nodes.append({"id": name, "kind": "llm", "state": _state(record.get("status")),
                      "status": record.get("status"), "units": record.get("unit_counts"),
                      "findings": record.get("total_findings")})
    if not scanners and llm.get("requested"):
        producers.append("llm")
        nodes.append({"id": "llm", "kind": "llm", "state": _state(llm.get("status")), "status": llm.get("status")})
    for phase in PHASE_NODES[1:]:
        nodes.append({"id": phase, "kind": "phase", "state": _phase_state(manifest, phase)})
    edges = [{"from": "discovery", "to": name} for name in producers]
    edges += [{"from": name, "to": "review"} for name in producers]
    edges += [{"from": "review", "to": "audit"}, {"from": "audit", "to": "export"}, {"from": "export", "to": "dashboard"}]
    return {"nodes": nodes, "edges": edges, "run": {"id": manifest.get("run_id"), "status": manifest.get("status"),
                                                    "exit_code": manifest.get("exit_code")}}


def _state(status: Any) -> str:
    return NODE_STATES.get(str(status or ""), "pending")


def _phase_state(manifest: dict[str, Any], phase: str) -> str:
    status = str(manifest.get("status") or "")
    if phase == "discovery":
        return "success" if manifest.get("source_inventory") else "pending"
    if phase == "dashboard":
        paths = {item.get("path") for item in manifest.get("artifacts") or []}
        return "success" if "index.html" in paths else ("running" if status == "running" else "pending")
    record = manifest.get(phase) or {}
    return _state(record.get("status"))


class LiveRun:
    """What the handlers read: the run directory plus, in --analyze mode, the token."""

    def __init__(
        self, report_directory: Path | None, *, cancellation: CancellationToken | None = None,
        control: RunControl | None = None,
    ) -> None:
        self.report_directory = report_directory
        self.cancellation = cancellation
        self.control = control
        self.exit_code: int | None = None
        self.error: str | None = None
        self._lock = threading.Lock()
        self._buffer: list[dict[str, Any]] = []

    def record(self, event: AnalysisEvent) -> None:
        with self._lock:
            self._buffer.append(_event_dict(event))
        # The run directory does not exist when the first events fire; the
        # runner announces it with this event once it does.
        if (event.phase, event.status) == RUN_DIRECTORY_PHASE and event.message:
            self.attach(Path(event.message))

    def attach(self, report_directory: Path) -> None:
        with self._lock:
            self.report_directory = report_directory

    def events_since(self, cursor: int) -> tuple[list[dict[str, Any]], int]:
        """Events after ``cursor``, from the file when it exists, else from the buffer.

        The cursor is a byte offset into ``events.jsonl`` once the file exists,
        so each poll reads only the tail (a real run's log runs to hundreds of
        megabytes).  Before the file exists it is ``-(n + 1)`` for ``n`` events
        already served from the in-process buffer; the switch-over skips those
        ``n`` lines of the file, which are the same events.
        """
        with self._lock:
            directory = self.report_directory
            buffered = list(self._buffer)
        path = directory / EVENTS_FILENAME if directory is not None else None
        if path is not None and path.is_file():
            offset = cursor if cursor >= 0 else 0
            skip = -(cursor + 1) if cursor < 0 else 0
            events = []
            with path.open("rb") as stream:
                stream.seek(offset)
                while True:
                    line = stream.readline()
                    if not line or not line.endswith(b"\n"):
                        # A partial last line belongs to the next poll.
                        break
                    offset += len(line)
                    if skip:
                        skip -= 1
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return events, offset
        served = -(cursor + 1) if cursor < 0 else 0
        return buffered[served:], -(len(buffered) + 1)

    def manifest(self) -> dict[str, Any] | None:
        directory = self.report_directory
        if directory is None:
            return None
        try:
            value = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def cancel(self) -> bool:
        if self.cancellation is None:
            return False
        if self.control is not None:
            self.control.cancel("serve")
        else:
            self.cancellation.cancel()
        return True

    def apply_control(self, body: dict[str, Any]) -> tuple[bool, str]:
        """One operator action from the page; ``(ok, reason)``."""
        control = self.control
        if control is None:
            return False, "view-only"
        action = str(body.get("action") or "")
        lane = str(body.get("lane") or "llm")
        if lane not in LANES:
            return False, f"unknown lane {lane}"
        if action == "pause":
            control.pause(lane, "serve")
        elif action == "resume":
            control.resume(lane, "serve")
        elif action == "skip":
            name = str(body.get("name") or "")
            if not name:
                return False, "skip needs a producer name"
            control.skip(name, "serve")
        elif action == "jobs":
            try:
                control.set_jobs(lane, int(body.get("value")), "serve")
            except (TypeError, ValueError):
                return False, "jobs needs an integer value"
        elif action == "retry":
            units = body.get("units")
            control.request_retry("llm", [str(item) for item in units] if isinstance(units, list) else None, "serve")
        elif action == "decide":
            answer = str(body.get("answer") or "reject")
            selected = tuple(int(item) for item in body.get("selected") or [])
            if not control.decide(str(body.get("id") or ""), answer, selected, "serve"):
                return False, "no such pending decision"
        else:
            return False, f"unknown action {action}"
        return True, ""


def _event_dict(event: AnalysisEvent) -> dict[str, Any]:
    return {"phase": event.phase, "status": event.status, "message": event.message, "tool": event.tool,
            "unit": event.unit, "progress": event.progress, "timestamp": event.timestamp, "stream": event.stream,
            "data": clean_data(event.data)}


def make_handler(run: LiveRun, page: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "code-analyzer-serve"

        def log_message(self, *_args: Any) -> None:  # stdout is the operator's, not ours
            return

        def do_GET(self) -> None:  # noqa: N802  (http.server API)
            path = urlsplit(self.path).path
            if path == "/":
                self._send(HTTPStatus.OK, "text/html; charset=utf-8", page.encode("utf-8"))
            elif path == "/manifest":
                manifest = run.manifest()
                self._send(HTTPStatus.OK if manifest else HTTPStatus.NOT_FOUND, "application/json",
                           json_bytes(manifest or {"error": "no manifest yet"}))
            elif path == "/graph":
                manifest = run.manifest()
                self._send(HTTPStatus.OK, "application/json", json_bytes(graph(manifest or {})))
            elif path == "/events":
                self._stream()
            elif path == "/state":
                self._send(HTTPStatus.OK, "application/json", json_bytes({
                    "report_directory": str(run.report_directory) if run.report_directory else None,
                    "cancellable": run.cancellation is not None, "exit_code": run.exit_code, "error": run.error,
                    "control": run.control.state() if run.control is not None else None,
                    "pending": [
                        {"id": item.id, "kind": item.kind, "summary": item.summary, "items": list(item.items)}
                        for item in (run.control.pending() if run.control is not None else [])
                    ],
                }))
            else:
                self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"not found")

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path not in {"/cancel", "/control"}:
                self._send(HTTPStatus.NOT_FOUND, "text/plain; charset=utf-8", b"not found")
                return
            origin = self.headers.get("Origin", "")
            host = self.headers.get("Host", "")
            if not origin or urlsplit(origin).netloc != host:
                self._send(HTTPStatus.FORBIDDEN, "text/plain; charset=utf-8", b"control requires a same-origin request")
                return
            if path == "/cancel":
                if run.cancel():
                    self._send(HTTPStatus.OK, "application/json", b'{"cancelled": true}')
                else:
                    self._send(HTTPStatus.CONFLICT, "application/json", b'{"cancelled": false, "reason": "view-only"}')
                return
            length = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            except (UnicodeError, json.JSONDecodeError):
                body = None
            if not isinstance(body, dict):
                self._send(HTTPStatus.BAD_REQUEST, "application/json", b'{"ok": false, "reason": "body must be a JSON object"}')
                return
            ok, reason = run.apply_control(body)
            state = run.control.state() if run.control is not None else None
            self._send(
                HTTPStatus.OK if ok else HTTPStatus.CONFLICT, "application/json",
                json_bytes({"ok": ok, "reason": reason or None, "control": state}),
            )

        def _stream(self) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            index = -1
            try:
                while True:
                    events, index = run.events_since(index)
                    for event in events:
                        self.wfile.write(b"data: " + json_bytes(event).replace(b"\n", b" ") + b"\n\n")
                    self.wfile.flush()
                    finished = run.exit_code is not None or any(
                        e.get("phase") == "analysis" and e.get("status") == "finished" for e in events
                    )
                    if finished:
                        self.wfile.write(b"event: end\ndata: {}\n\n")
                        self.wfile.flush()
                        return
                    time.sleep(POLL_SECONDS)
            except (BrokenPipeError, ConnectionResetError):
                return

        def _send(self, status: HTTPStatus, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def serve(
    report_directory: Path | None,
    *,
    analyze: tuple[Path, dict[str, Any]] | None = None,
    port: int = DEFAULT_PORT,
    announce: Callable[[str], None] | None = None,
    ready: threading.Event | None = None,
    stop: threading.Event | None = None,
) -> int:
    """Serve the live page until the analysis ends (``--analyze``) or ``stop`` is set.

    Returns the analysis exit code in ``--analyze`` mode, else 0.
    """
    if report_directory is None and analyze is None:
        raise UserError("serve needs a report directory or --analyze SOURCE")
    cancellation = CancellationToken() if analyze is not None else None
    control = None
    if analyze is not None:
        control = RunControl(cancellation, llm_jobs=int(analyze[1]["llm"].get("jobs") or 1))
    run = LiveRun(report_directory, cancellation=cancellation, control=control)
    server = ThreadingHTTPServer((BIND_HOST, port), make_handler(run, page()))
    server.daemon_threads = True
    bound_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, name="code-analyzer-serve", daemon=True)
    thread.start()
    if announce is not None:
        announce(f"live view: http://{BIND_HOST}:{bound_port}/")
    if ready is not None:
        ready.set()
    try:
        if analyze is not None:
            source, config = analyze
            try:
                result = run_analysis(AnalysisRequest(source, config), events=run.record, cancellation=cancellation, control=control)
            except UserError as exc:
                run.error = str(exc)
                run.exit_code = 2
                return 2
            run.exit_code = result.exit_code
            if result.report_directory is not None:
                run.attach(result.report_directory)
            # Let a connected page drain the tail before the server goes.
            time.sleep(POLL_SECONDS * 2)
            return result.exit_code
        while not (stop is not None and stop.is_set()):
            time.sleep(POLL_SECONDS)
        return 0
    except KeyboardInterrupt:
        if cancellation is not None:
            cancellation.cancel()
        return EXIT_INTERRUPTED
    finally:
        server.shutdown()
        server.server_close()


def page() -> str:
    """The live page with the shared vocabularies injected, so the two front ends agree.

    The state glyphs and the set of producers that talk to a model both come
    from Python: two front ends that disagree about either would be showing
    the operator two different runs.
    """
    return (
        PAGE
        .replace("__STATE_GLYPHS__", json.dumps(STATE_GLYPHS, ensure_ascii=False))
        .replace("__CONVERSANTS__", json.dumps(sorted(CONVERSANTS), ensure_ascii=False))
    )


PAGE = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>code-analyzer · live</title>
<style>
:root{color-scheme:light dark;--bg:#f3efe7;--surface:#fdfcf9;--ink:#221d15;--muted:#6d6659;--line:#d9d2c2;
--ok:#24855d;--part:#c26a1b;--bad:#b23a1e;--run:#a57b00;--pend:#8a8478;--mono:ui-monospace,SFMono-Regular,Menlo,monospace}
@media(prefers-color-scheme:dark){:root{--bg:#17140f;--surface:#201c15;--ink:#efe9dc;--muted:#a89e8c;--line:#3a342a}}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:1.2rem 1.4rem}
h1{font-size:1.15rem;margin:.2rem 0 .8rem}h2{font-size:.95rem;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:1.4rem 0 .5rem}
.bar{display:flex;gap:1rem;align-items:center;flex-wrap:wrap;font-family:var(--mono);font-size:.85rem}
.track{flex:1;height:.5rem;background:var(--line);border-radius:3px;overflow:hidden;min-width:10rem}
.fill{height:100%;background:var(--ok);width:0;transition:width .3s}
button{font:inherit;padding:.3rem .8rem;border:1px solid var(--line);background:var(--surface);color:var(--ink);border-radius:3px;cursor:pointer}
button[disabled]{opacity:.5;cursor:default}
.dag{display:grid;grid-template-columns:repeat(auto-fill,minmax(11rem,1fr));gap:.6rem}
.node{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--pend);border-radius:4px;padding:.5rem .7rem;font-family:var(--mono);font-size:.82rem}
.node.success{border-left-color:var(--ok)}.node.partial{border-left-color:var(--part)}.node.failed{border-left-color:var(--bad)}.node.running{border-left-color:var(--run)}
.node b{display:block;font-weight:600}.node span{color:var(--muted)}
.log{background:var(--surface);border:1px solid var(--line);border-radius:4px;padding:.6rem .8rem;max-height:22rem;overflow:auto;font-family:var(--mono);font-size:.8rem;white-space:pre-wrap}
.muted{color:var(--muted)}.small{font-size:.8rem}a{color:inherit}
.lanes{display:grid;gap:.35rem;margin:.6rem 0}
.lane{display:flex;gap:.6rem;align-items:center;font-family:var(--mono);font-size:.8rem}
.lane b{font-weight:600;min-width:6rem}.lane span{color:var(--muted);min-width:9rem}
.turn{border-top:1px solid var(--line);padding:.5rem 0}.turn:first-child{border-top:0}
.turn b{display:block;font-weight:600}
.turn.bad b{color:var(--bad)}.turn.done b{color:var(--ok)}.turn.live b{color:var(--run)}
.turn pre{margin:.3rem 0;white-space:pre-wrap;word-break:break-word}
.turn .ask{margin:.3rem 0;padding:.3rem .5rem;border-left:3px solid var(--part);color:var(--muted);white-space:pre-wrap}
.turn .meta{color:var(--muted)}
#chat{max-height:30rem}
</style></head><body><main>
<h1>code-analyzer · <span id="title">live</span> <span class="muted small" id="state"></span></h1>
<div class="bar"><div class="track"><div class="fill" id="fill"></div></div><span id="pct">0%</span>
<button id="cancel" disabled>取消 / Cancel</button><a id="report" hidden href="#">index.html</a></div>
<div class="bar" id="controls" hidden><button id="pause-llm">暂停 LLM</button><button id="pause-static">暂停静态</button>
<button id="jobs-down">并发 −</button><span id="jobs">并发 -</span><button id="jobs-up">并发 +</button><button id="retry-llm">重试 LLM</button><span class="muted small" id="control-state"></span></div>
<div class="log" id="decision" hidden></div>
<div class="lanes" id="lanes"></div>
<h2>对话 / Conversation <span class="muted small" id="chat-stats"></span></h2>
<div class="bar"><span id="speed" class="muted">等待模型的第一个 token…</span>
<label class="small"><input type="checkbox" id="show-prompts"> 显示发送给模型的提示词</label></div>
<div class="log" id="chat"><span class="muted">等待模型的第一次回复…</span></div>
<h2>DAG</h2><div class="dag" id="dag"></div>
<h2>Events</h2><div class="log" id="log"></div>
<p class="muted small">此页面只读取 events.jsonl 与 manifest.json；节点状态是 manifest 的投影，不是另一份事实。
提示词与回复均为预览：完整内容在报告目录的 llm/units/ 与 llm/sessions/ 下。</p>
</main><script>
(() => {
  const $ = id => document.getElementById(id);
  const line = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = String(text); return n; };
  // Injected from status.STATE_GLYPHS by serve.page(): one vocabulary for both front ends.
  const glyph = __STATE_GLYPHS__;
  // Injected from chat.CONVERSANTS: a native analyzer emits unit events of the
  // same shape, and a subprocess is not an exchange with a model.
  const CONVERSANTS = new Set(__CONVERSANTS__);
  let progress = 0, ended = false;

  /* ---------- the run as a conversation ----------
     The same model as code_analyzer/chat.py, over the same events: one turn
     per scan unit, the answer as it streams, and two speeds that are never
     conflated -- an estimate from characters while the answer is arriving,
     the provider's own count once the session settles. */
  const CHARS_PER_TOKEN = 4, MAX_TURNS = 120, MAX_ANSWER = 20000, RATE_WINDOW = 10;
  const CHAT_STREAMS = { prompt: 1, answer: 1, tool: 1, note: 1 };
  const LABELS = { waiting: "等待模型", streaming: "接收中", reading: "读取工具", parsing: "解析响应",
    completed: "完成", partial: "截断", failed: "失败", timed_out: "超时", interrupted: "已中断",
    unscheduled: "未调度", cached: "缓存命中" };
  const SETTLED = { completed: 1, partial: 1, failed: 1, timed_out: 1, interrupted: 1, unscheduled: 1 };
  const BAD = { failed: 1, timed_out: 1, interrupted: 1, unscheduled: 1 };
  const turns = new Map();
  const conversant = (producer) => !!producer && (CONVERSANTS.has(producer)
    || [...turns.values()].some(t => t.producer === producer));
  // The same quantity counted two ways: the phase publishes its ledger on a
  // heartbeat, so the last session's usage lands after the last heartbeat and
  // the ledger alone under-reports the end of every run.  Neither can exceed
  // the truth, so the strip shows whichever has seen more.
  const totals = { prompt_tokens: 0, completion_tokens: 0, requests: 0 };
  const fromTurns = { prompt_tokens: 0, completion_tokens: 0, requests: 0 };
  const total = k => Math.max(totals[k], fromTurns[k]);
  let model = "", eta = null, sessionRate = null, inFlight = 0, peak = null, dropped = 0;
  let recent = [], chatDirty = false, runClock = 0;
  const num = n => (n || 0).toLocaleString("en-US");
  const clock = s => { s = Math.max(0, Math.round(s)); const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60;
    const pad = v => String(v).padStart(2, "0"); return h ? pad(h) + ":" + pad(m) + ":" + pad(x) : pad(m) + ":" + pad(x); };

  const turnOf = (e) => {
    const key = e.tool + "/" + e.unit;
    let t = turns.get(key);
    if (!t) {
      t = { key: key, producer: e.tool, unit: e.unit, path: "", tier: "", index: null, total: null,
            state: "waiting", started: e.timestamp, first: null, last: null, prompt: "", promptChars: 0,
            promptOmitted: 0, answer: "", answerChars: 0, answerCut: false, tools: [], notes: [], cached: false,
            duration: null, ct: null, pt: null, findings: null, malformed: null, reason: "", finish: "" };
      turns.set(key, t);
      // Forget the oldest settled turn; one still streaming is the one being watched.
      while (turns.size > MAX_TURNS) {
        const stale = [...turns.keys()].find(k => SETTLED[turns.get(k).state]);
        if (!stale) break;
        turns.delete(stale); dropped += 1;
      }
    }
    return t;
  };

  const speedOf = t => {
    if (t.ct && t.duration) return [Math.round(t.ct / t.duration * 10) / 10, "测量"];
    if (t.first !== null && t.last !== null && t.answerChars && t.last - t.first >= 0.05) {
      return [Math.round(t.answerChars / CHARS_PER_TOKEN / (t.last - t.first) * 10) / 10, "估算"];
    }
    return [null, ""];
  };

  // Measured against the run's own clock, not the browser's: the timestamps in
  // the stream are the server's, and a stream that has gone quiet must report
  // no current speed rather than the last one it saw -- a stalled provider is
  // not a fast one.  Heartbeats keep this clock moving while a unit is silent.
  const liveRate = () => {
    const window = recent.filter(r => r[0] >= runClock - RATE_WINDOW);
    if (window.length < 2) return null;
    const span = window[window.length - 1][0] - window[0][0];
    if (span < 0.05) return null;
    return Math.round(window.reduce((a, r) => a + r[1], 0) / CHARS_PER_TOKEN / span * 10) / 10;
  };

  const foldTotals = (d) => {
    if (!d) return;
    if (d.measured) { for (const k in totals) { const v = d.measured[k]; if (typeof v === "number" && v > totals[k]) totals[k] = v; } }
    if (typeof d.eta_seconds === "number") eta = d.eta_seconds;
    if (typeof d.tok_s === "number") sessionRate = d.tok_s;
    if (typeof d.in_flight === "number") inFlight = d.in_flight;
  };

  const foldChat = (e) => {
    const d = e.data || {};
    if (e.phase === "llm") {
      if (d.model) model = String(d.model);
      // A phase that has ended has nothing in flight; the last heartbeat is
      // not the last word.
      if (SETTLED[e.status] && inFlight) { inFlight = 0; return true; }
      return false;
    }
    if (e.phase === "output") {
      if (!CHAT_STREAMS[e.stream] || !e.tool || !e.unit || !conversant(e.tool)) return false;
      const t = turnOf(e);
      if (e.stream === "prompt") {
        t.prompt = String(e.message || ""); t.promptChars = d.chars || t.prompt.length;
        t.promptOmitted = d.omitted_lines || 0;
      } else if (e.stream === "answer") {
        const text = String(e.message || "");
        if (!text) return false;
        if (t.first === null) t.first = e.timestamp;
        t.last = e.timestamp; t.answerChars += text.length;
        const joined = t.answer + text;
        if (joined.length > MAX_ANSWER) t.answerCut = true;
        t.answer = joined.slice(-MAX_ANSWER);
        if (t.state === "waiting" || t.state === "reading") t.state = "streaming";
        const now = e.timestamp;
        recent.push([now, text.length]);
        recent = recent.filter(r => r[0] >= now - RATE_WINDOW);
      } else if (e.stream === "tool") {
        t.tools.push(String(e.message || "")); if (!SETTLED[t.state]) t.state = "reading";
      } else { t.notes.push(String(e.message || "")); }
      return true;
    }
    if (e.phase !== "unit" || !conversant(e.tool)) return false;
    if (e.status === "heartbeat" || e.status === "info" || !e.unit) { foldTotals(d); return true; }
    const t = turnOf(e);
    foldTotals(d);
    if (d.path) t.path = String(d.path);
    if (d.tier) t.tier = String(d.tier);
    if (typeof d.index === "number") t.index = d.index;
    if (typeof d.total === "number") t.total = d.total;
    if (e.status === "started") { t.started = e.timestamp; t.cached = !!d.cached; t.state = d.cached ? "cached" : "waiting"; return true; }
    if (e.status === "step") { const w = String(d.step || ""); if (LABELS[w] && !SETTLED[t.state]) t.state = w; return true; }
    if (SETTLED[e.status]) {
      t.state = e.status; t.reason = String(d.reason || ""); t.finish = String(d.finish_reason || "");
      t.duration = typeof d.duration_seconds === "number" ? d.duration_seconds : null;
      t.findings = typeof d.finding_count === "number" ? d.finding_count : null;
      t.malformed = d.malformed_count || 0;
      if (d.cache_hit) t.cached = true;
      const u = d.usage || {};
      t.pt = typeof u.prompt_tokens === "number" ? u.prompt_tokens : null;
      t.ct = typeof u.completion_tokens === "number" ? u.completion_tokens : null;
      for (const k in fromTurns) { if (typeof u[k] === "number" && u[k] > 0) fromTurns[k] += u[k]; }
      const sp = speedOf(t);
      if (sp[1] === "测量" && (peak === null || sp[0] > peak)) peak = sp[0];
      return true;
    }
    return true;
  };

  const headerOf = (t) => {
    const mark = BAD[t.state] ? "✕" : (SETTLED[t.state] ? "✓" : "●");
    const bits = [mark + " " + t.producer, t.path || t.unit];
    if (t.index && t.total) bits.push(t.index + "/" + t.total);
    if (t.tier) bits.push(t.tier);
    bits.push((LABELS[t.state] || t.state) + (t.cached && SETTLED[t.state] ? " · 缓存" : ""));
    return bits.filter(Boolean).join(" · ");
  };

  const footerOf = (t) => {
    const bits = [], sp = speedOf(t);
    if (sp[0] !== null) bits.push(sp[0] + " tok/s（" + sp[1] + "）");
    if (t.first !== null && t.started) bits.push("首字 " + Math.max(0, t.first - t.started).toFixed(1) + "s");
    if (t.ct) bits.push("输出 " + num(t.ct) + " tok");
    else if (t.answerChars) bits.push("输出 ~" + num(Math.floor(t.answerChars / CHARS_PER_TOKEN)) + " tok");
    if (t.pt) bits.push("输入 " + num(t.pt) + " tok");
    if (t.duration !== null) bits.push("耗时 " + t.duration.toFixed(1) + "s");
    if (t.findings !== null && SETTLED[t.state]) bits.push("发现 " + t.findings);
    if (t.malformed) bits.push("格式错误 " + t.malformed);
    if (t.reason && BAD[t.state]) bits.push(t.reason);
    else if (t.finish && t.state === "partial") bits.push(t.finish);
    return bits.join(" · ");
  };

  const drawChat = () => {
    const showPrompts = $("show-prompts").checked;
    const box = $("chat");
    const pinned = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
    box.replaceChildren();
    const list = [...turns.values()];
    if (!list.length) { box.append(line("span", "muted", "等待模型的第一次回复…")); }
    if (dropped) box.append(line("div", "muted small", "… 更早的 " + dropped + " 个单元已从本页折叠（完整记录见报告目录）"));
    list.forEach(t => {
      const cls = BAD[t.state] ? "bad" : (SETTLED[t.state] ? "done" : "live");
      const box2 = line("div", "turn " + cls);
      box2.append(line("b", "", headerOf(t)));
      if (showPrompts && t.prompt) {
        // The preview carries a marker per block for what the sender left out,
        // so this line points at the whole prompt rather than re-counting it.
        box2.append(line("div", "ask", "▸ 发送的提示词 · " + num(t.promptChars) + " 字符 · 约 "
          + num(Math.ceil(t.promptChars / CHARS_PER_TOKEN)) + " tok\n" + t.prompt
          + "\n…（完整提示词见报告目录 llm/units/）"));
      }
      t.tools.slice(-4).forEach(name => box2.append(line("div", "meta", "⚒ 工具调用 " + name)));
      t.notes.slice(-3).forEach(note => box2.append(line("div", "meta", "! " + note)));
      if (t.answerCut) box2.append(line("div", "meta small", "…（回复开头已折叠；完整回复见报告目录 llm/sessions/）"));
      if (t.answer) box2.append(line("pre", "", t.answer));
      const foot = footerOf(t);
      if (foot) box2.append(line("div", "meta small", foot));
      box.append(box2);
    });
    if (pinned) box.scrollTop = box.scrollHeight;

    const answered = list.filter(t => t.state === "completed" || t.state === "partial").length;
    const failed = list.filter(t => BAD[t.state]).length;
    const cached = list.filter(t => t.cached).length;
    $("chat-stats").textContent = "已答 " + answered + "/" + (list.length + dropped)
      + (failed ? " · 失败 " + failed : "") + (cached ? " · 缓存 " + cached : "");

    const live = liveRate();
    if (live !== null && (peak === null || live > peak)) peak = live;
    const bits = [];
    if (model) bits.push(model);
    if (live !== null) bits.push(live + " tok/s（估算）");
    else if (sessionRate !== null) bits.push(sessionRate + " tok/s（会话均值）");
    if (peak !== null) bits.push("峰值 " + peak);
    if (inFlight) bits.push("在途 " + inFlight);
    if (total("prompt_tokens") || total("completion_tokens")) {
      bits.push("输入 " + num(total("prompt_tokens")) + " · 输出 " + num(total("completion_tokens")) + " tok（测量）");
    }
    if (total("requests")) bits.push("请求 " + num(total("requests")));
    if (eta !== null) bits.push("ETA " + clock(eta));
    const speed = $("speed");
    speed.textContent = bits.length ? "⚡ " + bits.join(" · ") : "等待模型的第一个 token…";
    speed.className = bits.length ? "" : "muted";
  };

  const drawLanes = (nodes) => {
    const root = $("lanes"); root.replaceChildren();
    const lanes = [];
    const stat = nodes.filter(n => n.kind === "static");
    if (stat.length) {
      const done = stat.filter(n => ["success", "partial", "failed"].includes(n.state)).length;
      lanes.push(["静态分析", done / stat.length, done + "/" + stat.length + " 工具"]);
    }
    const llm = nodes.filter(n => n.kind === "llm" && n.units);
    if (llm.length) {
      const done = llm.reduce((a, n) => a + (n.units.completed || 0) + (n.units.failed || 0)
        + (n.units.partial || 0) + (n.units.unscheduled || 0), 0);
      const planned = llm.reduce((a, n) => a + (n.units.planned || 0), 0);
      lanes.push(["LLM 扫描", planned ? Math.min(1, done / planned) : 0, done + "/" + planned + " 单元"]);
    }
    lanes.forEach(([label, fraction, detail]) => {
      const row = line("div", "lane");
      row.append(line("b", "", label));
      const track = line("div", "track"), fill = line("div", "fill");
      fill.style.width = (fraction * 100) + "%"; track.append(fill);
      row.append(track, line("span", "", Math.round(fraction * 100) + "%  " + detail));
      root.append(row);
    });
  };
  $("show-prompts").onchange = drawChat;
  setInterval(() => { if (chatDirty) { chatDirty = false; drawChat(); } }, 200);
  const drawGraph = async () => {
    const r = await fetch("/graph"); if (!r.ok) return;
    const g = await r.json(); const root = $("dag"); root.replaceChildren();
    g.nodes.forEach(n => {
      const box = line("div", "node " + n.state);
      box.append(line("b", "", glyph[n.state] + " " + n.id));
      const detail = [n.status, n.kind].filter(Boolean).join(" · ");
      box.append(line("span", "", detail));
      if (n.units) box.append(line("span", "", " " + (n.units.completed || 0) + "/" + (n.units.planned || 0) + " units"));
      if (n.findings !== undefined && n.findings !== null) box.append(line("span", "", " · " + n.findings + " findings"));
      root.append(box);
    });
    drawLanes(g.nodes);
    $("state").textContent = g.run.status ? g.run.status + (g.run.exit_code !== null && g.run.exit_code !== undefined ? " · exit " + g.run.exit_code : "") : "";
    if (g.nodes.some(n => n.id === "dashboard" && n.state === "success")) { $("report").hidden = false; }
  };
  const post = async (body) => fetch("/control", { method: "POST", headers: { "Origin": window.location.origin, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  let lanes = null;
  $("pause-llm").onclick = () => post({ action: lanes && lanes.llm.paused ? "resume" : "pause", lane: "llm" }).then(pollState);
  $("pause-static").onclick = () => post({ action: lanes && lanes.static.paused ? "resume" : "pause", lane: "static" }).then(pollState);
  $("jobs-up").onclick = () => post({ action: "jobs", lane: "llm", value: (lanes ? lanes.llm.jobs : 1) + 1 }).then(pollState);
  $("retry-llm").onclick = () => post({ action: "retry" }).then(pollState);
  $("jobs-down").onclick = () => post({ action: "jobs", lane: "llm", value: Math.max(1, (lanes ? lanes.llm.jobs : 1) - 1) }).then(pollState);
  const pollState = async () => {
    const r = await fetch("/state"); if (!r.ok) return; const s = await r.json();
    $("cancel").disabled = !s.cancellable || ended;
    if (s.control && !ended) {
      lanes = s.control.lanes; $("controls").hidden = false;
      $("pause-llm").textContent = lanes.llm.paused ? "继续 LLM" : "暂停 LLM";
      $("pause-static").textContent = lanes.static.paused ? "继续静态" : "暂停静态";
      $("jobs").textContent = "并发 " + lanes.llm.jobs;
      $("control-state").textContent = (s.control.skipped.length ? "已跳过 " + s.control.skipped.join(", ") : "") + (s.pending.length ? " · 待决策 " + s.pending.length : "");
      const box = $("decision"); box.replaceChildren();
      if (s.pending.length) {
        const p = s.pending[0];
        box.hidden = false;
        box.append(line("div", "", "待决策 " + p.id + " · " + p.summary));
        (p.items || []).forEach((it, i) => box.append(line("div", "", (it.preselected === false ? "[ ] " : "[x] ") + (it.label || it.op) + "  " + (it.evidence || "") + "  (" + (it.origin || "") + ")")));
        const yes = line("button", "", "应用预选项并重跑"); const no = line("button", "", "拒绝");
        yes.onclick = () => post({ action: "decide", id: p.id, answer: "apply", selected: (p.items || []).map((it, i) => it.preselected === false ? -1 : i).filter(i => i >= 0) }).then(pollState);
        no.onclick = () => post({ action: "decide", id: p.id, answer: "reject" }).then(pollState);
        box.append(yes, no);
      } else { box.hidden = true; }
    } else { $("controls").hidden = true; $("decision").hidden = true; }
    if (s.report_directory) { $("title").textContent = s.report_directory.split("/").pop(); $("report").href = "file://" + s.report_directory + "/index.html"; }
  };
  $("cancel").onclick = async () => { $("cancel").disabled = true; await fetch("/cancel", { method: "POST", headers: { "Origin": window.location.origin } }); };
  const log = $("log");
  const es = new EventSource("/events");
  es.onmessage = ev => {
    let e; try { e = JSON.parse(ev.data); } catch (err) { return; }
    if (typeof e.progress === "number" && e.progress >= progress) { progress = e.progress; $("fill").style.width = (progress * 100) + "%"; $("pct").textContent = Math.round(progress * 100) + "%"; }
    if (typeof e.timestamp === "number" && e.timestamp > runClock) runClock = e.timestamp;
    if (foldChat(e)) chatDirty = true;
    // The model's own words belong to the conversation panel: a prompt preview
    // is thousands of characters of source, and an answer arrives in dozens of
    // chunks -- either one would bury every other line in a one-row-per-event log.
    if (!(e.phase === "output" && CHAT_STREAMS[e.stream])) {
      const when = e.timestamp ? new Date(e.timestamp * 1000).toISOString().slice(11, 19) : "";
      log.append(line("div", "", when + "  " + e.phase + "/" + e.status + (e.tool ? "  " + e.tool : "") + (e.unit ? "/" + e.unit : "") + "  " + e.message));
      log.scrollTop = log.scrollHeight;
    }
    if (["tool", "llm", "unit", "units", "review", "audit", "export", "report", "build_context"].includes(e.phase)) drawGraph();
  };
  es.addEventListener("end", () => { ended = true; es.close(); $("cancel").disabled = true; drawChat(); drawGraph(); pollState(); });
  drawGraph(); pollState(); setInterval(() => { if (!ended) { drawGraph(); pollState(); } }, 3000);
})();
</script></body></html>
"""

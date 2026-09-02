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
    """The live page with the shared state glyphs injected, so the two front ends agree."""
    return PAGE.replace("__STATE_GLYPHS__", json.dumps(STATE_GLYPHS, ensure_ascii=False))


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
</style></head><body><main>
<h1>code-analyzer · <span id="title">live</span> <span class="muted small" id="state"></span></h1>
<div class="bar"><div class="track"><div class="fill" id="fill"></div></div><span id="pct">0%</span>
<button id="cancel" disabled>取消 / Cancel</button><a id="report" hidden href="#">index.html</a></div>
<div class="bar" id="controls" hidden><button id="pause-llm">暂停 LLM</button><button id="pause-static">暂停静态</button>
<button id="jobs-down">并发 −</button><span id="jobs">并发 -</span><button id="jobs-up">并发 +</button><span class="muted small" id="control-state"></span></div>
<div class="log" id="decision" hidden></div>
<h2>DAG</h2><div class="dag" id="dag"></div>
<h2>Events</h2><div class="log" id="log"></div>
<p class="muted small">此页面只读取 events.jsonl 与 manifest.json；节点状态是 manifest 的投影，不是另一份事实。</p>
</main><script>
(() => {
  const $ = id => document.getElementById(id);
  const line = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text !== undefined) n.textContent = String(text); return n; };
  // Injected from status.STATE_GLYPHS by serve.page(): one vocabulary for both front ends.
  const glyph = __STATE_GLYPHS__;
  let progress = 0, ended = false;
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
    $("state").textContent = g.run.status ? g.run.status + (g.run.exit_code !== null && g.run.exit_code !== undefined ? " · exit " + g.run.exit_code : "") : "";
    if (g.nodes.some(n => n.id === "dashboard" && n.state === "success")) { $("report").hidden = false; }
  };
  const post = async (body) => fetch("/control", { method: "POST", headers: { "Origin": window.location.origin, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  let lanes = null;
  $("pause-llm").onclick = () => post({ action: lanes && lanes.llm.paused ? "resume" : "pause", lane: "llm" }).then(pollState);
  $("pause-static").onclick = () => post({ action: lanes && lanes.static.paused ? "resume" : "pause", lane: "static" }).then(pollState);
  $("jobs-up").onclick = () => post({ action: "jobs", lane: "llm", value: (lanes ? lanes.llm.jobs : 1) + 1 }).then(pollState);
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
    const when = e.timestamp ? new Date(e.timestamp * 1000).toISOString().slice(11, 19) : "";
    log.append(line("div", "", when + "  " + e.phase + "/" + e.status + (e.tool ? "  " + e.tool : "") + (e.unit ? "/" + e.unit : "") + "  " + e.message));
    log.scrollTop = log.scrollHeight;
    if (["tool", "llm", "unit", "units", "review", "audit", "export", "report", "build_context"].includes(e.phase)) drawGraph();
  };
  es.addEventListener("end", () => { ended = true; es.close(); $("cancel").disabled = true; drawGraph(); pollState(); });
  drawGraph(); pollState(); setInterval(() => { if (!ended) { drawGraph(); pollState(); } }, 3000);
})();
</script></body></html>
"""

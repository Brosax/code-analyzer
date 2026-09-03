"""code-analyzer serve: a live view derived from events.jsonl and manifest.json."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from code_analyzer.serve import BIND_HOST, NODE_STATES, graph, page, serve


def _manifest(**over):
    base = {
        "run_id": "run-1", "status": "running", "exit_code": None,
        "source_inventory": {"total": 3},
        "tools": {"cppcheck": {"status": "completed", "unit_counts": {"planned": 2, "completed": 2}},
                  "flawfinder": {"status": "running"},
                  "splint": {"status": "not_requested"}},
        "llm": {"requested": True, "status": "running", "scanners": {"llm-memory-safety": {"status": "running", "unit_counts": {"planned": 7, "completed": 3}}}},
        "review": {"status": "pending"}, "audit": {"status": "pending"}, "export": {"status": "pending"},
        "artifacts": [],
    }
    base.update(over)
    return base


def test_graph_is_a_projection_of_the_manifest_and_nothing_else() -> None:
    g = graph(_manifest())
    by = {n["id"]: n for n in g["nodes"]}
    assert by["discovery"]["state"] == "success"
    assert by["cppcheck"]["state"] == "success" and by["cppcheck"]["units"]["completed"] == 2
    assert by["flawfinder"]["state"] == "running"
    assert by["splint"]["state"] == "pending" and by["splint"]["status"] == "not_requested"
    assert by["llm-memory-safety"]["kind"] == "llm" and by["llm-memory-safety"]["state"] == "running"
    assert by["review"]["state"] == "pending" and by["dashboard"]["state"] == "running"
    edges = {(e["from"], e["to"]) for e in g["edges"]}
    assert ("discovery", "cppcheck") in edges and ("llm-memory-safety", "review") in edges
    assert ("review", "audit") in edges and ("export", "dashboard") in edges
    # Every status word the ladder can produce projects onto exactly four states.
    assert set(NODE_STATES.values()) == {"success", "partial", "failed", "running", "pending"}
    for word in ("completed", "partial", "timed_out", "failed", "interrupted", "unscheduled",
                 "not_requested", "missing", "incompatible", "not_applicable", "running"):
        assert word in NODE_STATES
    done = graph(_manifest(status="complete", exit_code=0, artifacts=[{"path": "index.html"}], review={"status": "completed"}))
    assert {n["id"]: n["state"] for n in done["nodes"]}["dashboard"] == "success"
    assert done["run"] == {"id": "run-1", "status": "complete", "exit_code": 0}


def test_view_only_mode_streams_the_file_and_refuses_cancel(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text(json.dumps(_manifest()), encoding="utf-8")
    events = [
        {"phase": "analysis", "status": "started", "message": "go", "tool": None, "unit": None, "progress": 0.0, "timestamp": 1.0, "stream": None},
        {"phase": "tool", "status": "completed", "message": "cppcheck finished", "tool": "cppcheck", "unit": None, "progress": 0.4, "timestamp": 2.0, "stream": None},
    ]
    (run_dir / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")

    ready, stop = threading.Event(), threading.Event()
    announced: list[str] = []
    thread = threading.Thread(target=serve, kwargs={"report_directory": run_dir, "port": 0, "announce": announced.append,
                                                     "ready": ready, "stop": stop}, daemon=True)
    thread.start()
    assert ready.wait(5)
    url = announced[0].split("live view: ")[1].rstrip("/")
    try:
        page = urllib.request.urlopen(url + "/", timeout=5).read().decode("utf-8")
        assert "EventSource" in page and "http://" not in page.replace(url, "").replace("file://", "")
        g = json.loads(urllib.request.urlopen(url + "/graph", timeout=5).read())
        assert {n["id"] for n in g["nodes"]} >= {"cppcheck", "llm-memory-safety", "review"}
        # SSE: the two events arrive as data: frames; a finished run ends the stream.
        (run_dir / "events.jsonl").open("a", encoding="utf-8").write(json.dumps(
            {"phase": "analysis", "status": "finished", "message": "done", "tool": None, "unit": None, "progress": 1.0, "timestamp": 3.0, "stream": None}) + "\n")
        with urllib.request.urlopen(url + "/events", timeout=10) as stream:
            body = b""
            deadline = time.time() + 8
            while b"event: end" not in body and time.time() < deadline:
                body += stream.readline()
        frames = [json.loads(row[6:]) for row in body.decode("utf-8").splitlines() if row.startswith("data: {")]
        assert [f["phase"] + "/" + f["status"] for f in frames] == ["analysis/started", "tool/completed", "analysis/finished"]
        assert b"event: end" in body
        # Cancel: refused without a same-origin Origin header, and refused in view-only mode even with one.
        for headers, expect in (({}, 403), ({"Origin": url}, 409)):
            request = urllib.request.Request(url + "/cancel", data=b"", method="POST", headers=headers)
            try:
                urllib.request.urlopen(request, timeout=5)
                code = 200
            except urllib.error.HTTPError as exc:
                code = exc.code
            assert code == expect, (headers, code)
        assert BIND_HOST in url
    finally:
        stop.set()
        thread.join(5)


def test_the_control_endpoint_reaches_the_run_control_and_names_what_it_refuses() -> None:
    from code_analyzer.analysis import CancellationToken
    from code_analyzer.control import RunControl
    from code_analyzer.serve import LiveRun

    assert LiveRun(None).apply_control({"action": "pause"}) == (False, "view-only")
    control = RunControl(CancellationToken(), llm_jobs=2)
    live = LiveRun(None, cancellation=control.cancellation, control=control)
    assert live.apply_control({"action": "pause", "lane": "llm"}) == (True, "") and control.paused("llm")
    assert live.apply_control({"action": "resume", "lane": "llm"}) == (True, "") and not control.paused("llm")
    assert live.apply_control({"action": "jobs", "lane": "llm", "value": 3}) == (True, "") and control.jobs("llm") == 3
    assert live.apply_control({"action": "jobs", "lane": "llm", "value": "many"}) == (False, "jobs needs an integer value")
    assert live.apply_control({"action": "skip"}) == (False, "skip needs a producer name")
    assert live.apply_control({"action": "retry", "units": ["a.c:f"]}) == (True, "") and control.drain_retries("llm") == ["a.c:f"]
    assert live.apply_control({"action": "retry"}) == (True, "") and control.drain_retries("llm") is None
    assert live.apply_control({"action": "decide", "id": "nope", "answer": "apply"}) == (False, "no such pending decision")
    assert live.apply_control({"action": "dance"}) == (False, "unknown action dance")
    assert live.apply_control({"action": "pause", "lane": "warp"}) == (False, "unknown lane warp")


# --- the live page's conversation panel -------------------------------------
#
# The page's JavaScript is the second implementation of the transcript model in
# code_analyzer/chat.py, over the same events.  It is exercised the way the
# Python one is -- feed events, read the rendered text -- against a DOM stub,
# because a contract asserted on only one of two front ends is a contract half
# of the product does not have.

_DOM_STUB = r"""
class El {
  constructor(tag) {
    this.tagName = tag; this.children = []; this._text = ""; this.style = {};
    this.className = ""; this.hidden = false; this.disabled = false; this.checked = false;
    this.scrollTop = 0; this.scrollHeight = 0; this.clientHeight = 0; this.href = "";
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; this._text = ""; }
}
const ELEMENTS = {};
const document = {
  getElementById: id => (ELEMENTS[id] = ELEMENTS[id] || new El("div")),
  createElement: tag => new El(tag),
};
let GRAPH = { nodes: [], edges: [], run: {} };
const fetch = async (path) => {
  if (path === "/graph") return { ok: true, json: async () => GRAPH };
  return { ok: false };
};
const TIMERS = [];
const setInterval = (fn) => { TIMERS.push(fn); return TIMERS.length; };
const tick = () => TIMERS.forEach(fn => fn());
let SOURCE = null;
class EventSource {
  constructor(url) { this.url = url; this.listeners = {}; SOURCE = this; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  close() {}
}
const window = { location: { origin: "http://127.0.0.1:1" } };
const send = (event) => SOURCE.onmessage({ data: JSON.stringify(event) });
const text = (id) => document.getElementById(id).textContent;
const assert = (condition, why) => { if (!condition) { console.error("FAIL: " + why); process.exit(1); } };
"""

_DRIVER = r"""
const main = async () => {
  await new Promise(resolve => setTimeout(resolve, 0));
  send({ phase: "llm", status: "started", message: "starting", timestamp: 0, data: { model: "qwen3.8:27b" } });
  send({ phase: "unit", status: "started", message: "scanning (high)", tool: "llm-security", unit: "u1",
         timestamp: 1, data: { index: 1, total: 4, path: "src/parse.c", tier: "high" } });
  send({ phase: "output", status: "running", message: "# Scan unit\nfile: src/parse.c", tool: "llm-security",
         unit: "u1", stream: "prompt", timestamp: 1, data: { chars: 12000, omitted_lines: 340 } });
  send({ phase: "output", status: "running", message: "{\"findings\": [", tool: "llm-security", unit: "u1",
         stream: "answer", timestamp: 2 });
  send({ phase: "output", status: "running", message: "{\"cwe\": \"CWE-787\"}]}", tool: "llm-security", unit: "u1",
         stream: "answer", timestamp: 3 });
  tick();

  // The answer is in the conversation, and neither it nor the prompt is in the log.
  assert(text("chat").includes("{\"findings\": [{\"cwe\": \"CWE-787\"}]}"), "the answer streams into the panel");
  assert(text("chat").includes("● llm-security · src/parse.c · 1/4 · high · 接收中"), "the header names the exchange");
  assert(!text("log").includes("findings"), "the answer is not repeated in the flat log");
  assert(!text("log").includes("Scan unit"), "the prompt preview is not in the flat log");
  assert(text("log").includes("unit/started"), "state events still reach the flat log");

  // The prompt waits to be asked for.
  assert(!text("chat").includes("file: src/parse.c"), "the prompt is off by default");
  document.getElementById("show-prompts").checked = true;
  document.getElementById("show-prompts").onchange();
  assert(text("chat").includes("file: src/parse.c"), "the checkbox shows the prompt");
  assert(text("chat").includes("12,000 字符 · 约 3,000 tok"), "the prompt says how big the whole one is");
  assert(text("chat").includes("完整提示词见报告目录 llm/units/"), "the preview points at the whole prompt");
  assert(!text("chat").includes("340"), "and does not re-count what the sender already marked");

  // Streaming: an estimate, and it says so.
  assert(text("speed").includes("qwen3.8:27b"), "the strip names the model");
  assert(text("speed").includes("tok/s（估算）"), "a streaming rate is an estimate");

  // Settled: the provider's own counts win.
  send({ phase: "unit", status: "completed", message: "completed; 2 finding(s)", tool: "llm-security", unit: "u1",
         timestamp: 9, data: { index: 1, total: 4, finding_count: 2, duration_seconds: 4.0,
                               usage: { prompt_tokens: 2100, completion_tokens: 400, requests: 1 } } });
  send({ phase: "unit", status: "heartbeat", message: "heartbeat", tool: "llm-security", unit: "u2",
         timestamp: 20, data: { measured: { prompt_tokens: 2100, completion_tokens: 400, requests: 1 },
                                tok_s: 88.0, eta_seconds: 90.0, in_flight: 2 } });
  tick();
  assert(text("chat").includes("✓ llm-security"), "a settled exchange is marked");
  assert(text("chat").includes("100 tok/s（测量）"), "400 output tokens over 4.0s is a measurement");
  assert(text("chat").includes("首字 1.0s"), "time to the first token is reported");
  assert(text("chat").includes("发现 2"), "the findings are reported");
  // A heartbeat carries the phase's totals, not an exchange of its own: the
  // unit it names already had a `started` event, or has not started yet.
  assert(text("chat-stats").includes("已答 1/1"), "the totals count the exchanges");
  assert(text("speed").includes("88 tok/s（会话均值）"), "with nothing streaming, the session mean is shown");
  // The heartbeat's ledger says 2,100/400 and so does the settled turn; the
  // strip shows whichever ledger has seen more, never their sum.
  assert(text("speed").includes("输入 2,100 · 输出 400 tok（测量）"), "the provider's totals are labelled measured");
  assert(text("speed").includes("ETA 01:30") && text("speed").includes("在途 2"), "the scheduler's facts are shown");
  assert(text("speed").includes("峰值 100"), "the peak is kept");

  // A failure says why, and claims no throughput.
  send({ phase: "unit", status: "started", message: "scanning", tool: "llm-security", unit: "u3",
         timestamp: 21, data: { index: 3, total: 4, path: "src/b.c" } });
  send({ phase: "unit", status: "failed", message: "failed", tool: "llm-security", unit: "u3",
         timestamp: 22, data: { index: 3, total: 4, reason: "provider TRANSPORT: connection reset" } });
  tick();
  assert(text("chat").includes("✕ llm-security · src/b.c"), "a failed exchange is marked");
  assert(text("chat").includes("provider TRANSPORT: connection reset"), "the failure says why");
  assert(text("chat-stats").includes("失败 1"), "the totals count the failures");

  // A native analyzer emits unit events of exactly the same shape.
  send({ phase: "unit", status: "completed", message: "completed", tool: "flawfinder", unit: "shard-0001",
         timestamp: 23, data: { index: 1, total: 1, duration_seconds: 0.1 } });
  tick();
  assert(!text("chat").includes("flawfinder"), "a subprocess is not an exchange with a model");
  assert(text("log").includes("flawfinder"), "but it is still a line in the flat log");

  // A phase that has ended has nothing in flight.
  send({ phase: "llm", status: "completed", message: "LLM scan finished with status completed", timestamp: 24 });
  tick();
  assert(!text("speed").includes("在途"), "a settled phase reports nothing in flight");

  // The lane bars come from the manifest projection, not from the events.
  GRAPH = { nodes: [
    { id: "cppcheck", kind: "static", state: "success" },
    { id: "flawfinder", kind: "static", state: "running" },
    { id: "llm-security", kind: "llm", state: "running", units: { planned: 4, completed: 2, failed: 1 } },
  ], edges: [], run: { status: "running" } };
  await drawGraphForTest();
  const lanes = text("lanes");
  assert(lanes.includes("静态分析") && lanes.includes("1/2 工具"), "the static lane counts tools");
  assert(lanes.includes("LLM 扫描") && lanes.includes("3/4 单元"), "the LLM lane counts units");
  assert(lanes.includes("75%"), "the LLM lane has a percentage of its own");
  console.log("OK");
};
main();
"""


def test_the_live_page_lays_the_run_out_as_a_conversation(tmp_path: Path) -> None:
    if shutil.which("node") is None:
        pytest.skip("node is required to exercise the live page's script")
    body = re.search(r"<script>(?P<js>.*?)</script>", page(), re.DOTALL).group("js")
    # The page's script is an IIFE; the driver needs the one function it calls
    # on a graph refresh, so the last line of the IIFE hands it out.
    body = body.replace("  drawGraph(); pollState();", "  globalThis.drawGraphForTest = drawGraph;\n  drawGraph(); pollState();")
    assert "drawGraphForTest" in body
    script = tmp_path / "live-driver.js"
    script.write_text(_DOM_STUB + body + _DRIVER, encoding="utf-8")
    completed = subprocess.run(["node", str(script)], text=True, capture_output=True, timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout.strip().endswith("OK")


def test_the_live_page_script_is_syntax_checked_by_node(tmp_path: Path) -> None:
    if shutil.which("node") is None:
        pytest.skip("node is required to syntax-check the live page's script")
    html = page()
    assert html.count("</script>") == html.count("<script")
    assert "__STATE_GLYPHS__" not in html
    body = re.search(r"<script>(?P<js>.*?)</script>", html, re.DOTALL).group("js")
    script = tmp_path / "live.js"
    script.write_text(body, encoding="utf-8")
    completed = subprocess.run(["node", "--check", str(script)], text=True, capture_output=True, timeout=10)
    assert completed.returncode == 0, completed.stderr
    # No third party: the live view is served on the loopback of a machine that
    # may have no route to the internet at all.
    assert 'src="http' not in html and 'href="http://' not in html.replace('href="http://127.0.0.1', "")

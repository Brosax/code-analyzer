"""code-analyzer serve: a live view derived from events.jsonl and manifest.json."""
from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path

from code_analyzer.serve import BIND_HOST, NODE_STATES, graph, serve


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
    assert set(NODE_STATES.values()) == {"success", "failed", "running", "pending"}
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

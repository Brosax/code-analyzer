"""M3: the local web server -- its security boundary and the deterministic evaluation flow."""
from __future__ import annotations

import http.client
import io
import json
import threading
import time
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from test_evaluate import fake_tools, project

from code_analyzer.evidence.analyze import _record_buildctx
from code_analyzer.evidence.buildctx_schema import default_buildctx
from code_analyzer.evidence.workspace import Workspace
from code_analyzer.settings import Settings
from code_analyzer.web.blocks import blocks
from code_analyzer.web.server import App, make_handler


@pytest.fixture
def server(tmp_path: Path):
    app = App(Settings(data_root=tmp_path / "evaluations"))
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
    httpd.daemon_threads = True
    app.port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield app
    httpd.shutdown()


class Client:
    def __init__(self, app: App, *, host: str | None = None) -> None:
        self.app = app
        self.host = host or f"127.0.0.1:{app.port}"
        self.cookie = ""

    def request(self, method: str, path: str, body: Any = None, *, headers: dict[str, str] | None = None,
                origin: bool = True, raw: bytes | None = None) -> tuple[int, dict[str, str], bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.app.port, timeout=30)
        sent = {"Host": self.host, **(headers or {})}
        if self.cookie:
            sent["Cookie"] = self.cookie
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            sent.setdefault("Content-Type", "application/json")
        if method == "POST" and origin:
            sent.setdefault("Origin", f"http://{self.host}")
        conn.request(method, path, body=data, headers=sent)
        response = conn.getresponse()
        payload = response.read()
        result = response.status, {k.lower(): v for k, v in response.getheaders()}, payload
        conn.close()
        return result

    def login(self) -> Client:
        token = self.app.login_url().split("token=")[1]
        status, headers, _ = self.request("GET", f"/login?token={token}")
        assert status == 303
        self.cookie = headers["set-cookie"].split(";")[0]
        return self

    def get(self, path: str) -> Any:
        status, _, payload = self.request("GET", path)
        assert status == 200, payload
        return json.loads(payload)

    def post(self, path: str, body: Any, expect: int = 200) -> Any:
        status, _, payload = self.request("POST", path, body)
        assert status == expect, payload
        return json.loads(payload)


def test_everything_needs_the_one_time_login(server: App) -> None:
    anonymous = Client(server)
    for path in ("/", "/static/app.js", "/api/state"):
        status, headers, _ = anonymous.request("GET", path)
        assert status == 403
    client = Client(server).login()
    status, headers, _ = client.request("GET", "/api/state")
    assert status == 200 and "default-src 'self'" in headers["content-security-policy"]
    assert "HttpOnly" in Client(server).request("GET", "/login?token=x")[1].get("set-cookie", "HttpOnly")
    # the token works once
    again = Client(server)
    token = server.login_url().split("token=")[1]
    assert again.request("GET", f"/login?token={token}")[0] == 403


def test_host_origin_and_content_type_are_enforced(server: App) -> None:
    client = Client(server).login()
    rebinding = Client(server, host="evil.example:80")
    rebinding.cookie = client.cookie
    assert rebinding.request("GET", "/api/state")[0] == 403
    assert client.request("POST", "/api/evaluations", {"source": "/tmp"}, origin=False)[0] == 403
    assert client.request("POST", "/api/evaluations", {"source": "/tmp"},
                          headers={"Origin": "http://evil.example"})[0] == 403
    status, _, _ = client.request("POST", "/api/evaluations", raw=b"source=/tmp",
                                  headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 415


def _evaluation(server: App, client: Client, tmp_path: Path, profile: str = "generic-sesip") -> tuple[str, Workspace]:
    source = project(tmp_path)
    created = client.post("/api/evaluations", {"source": str(source), "confidentiality": "public",
                                               "profile": profile}, expect=201)
    workspace = Workspace(server.data_root / created["id"])
    context = default_buildctx()
    for name, path in fake_tools(tmp_path, source / "a.c").items():
        context["tools"][name]["executable"] = str(path)
    _record_buildctx(workspace, context)
    return created["id"], workspace


def _wait(client: Client, evaluation: str, timeout: float = 60) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        jobs = client.get(f"/api/e/{evaluation}")["jobs"]
        if jobs and all(job["status"] != "running" for job in jobs):
            return jobs[-1]
        time.sleep(0.2)
    raise AssertionError("job did not finish")


def test_the_whole_flow_with_buttons_only(server: App, tmp_path: Path) -> None:
    client = Client(server).login()
    evaluation, workspace = _evaluation(server, client, tmp_path)
    started = client.post(f"/api/e/{evaluation}/run_tools", {}, expect=202)
    assert started["job"]["id"] == "J1"
    assert client.request("POST", f"/api/e/{evaluation}/run_tools", {})[0] in (202, 409)
    job = _wait(client, evaluation)
    assert job["status"] == "finished" and job["exit_code"] == 0, job

    view = client.get(f"/api/e/{evaluation}")
    assert view["triage"]["partition_main"] == 1 and view["profile"]["status"] == "builtin"
    kinds = [b["kind"] for b in view["blocks"]]
    assert kinds[:2] == ["event", "profile"] and "summary" in kinds

    listing = client.get(f"/api/e/{evaluation}/pvs?partition=main")
    [row] = listing["rows"]
    detail = client.get(f"/api/e/{evaluation}/pvs/{row['pv_id']}")
    assert len(detail["members"]) == 2 and any(line["marked"] for line in detail["source"]["lines"])

    marked = client.post(f"/api/e/{evaluation}/pvs/{row['pv_id']}/status",
                         {"status": "false_positive", "note": "bounds checked by caller"})
    assert marked["pv"]["status"] == "false_positive"
    assert client.request("POST", f"/api/e/{evaluation}/pvs/{row['pv_id']}/status", {"status": "maybe"})[0] == 400

    exported = client.post(f"/api/e/{evaluation}/export", {"variant": "shareable", "formats": ["xlsx", "md", "csv"]})
    export = exported["export"]
    assert export["leak_check"] == "passed" and export["dispositioned"] == 1 and export["entries"] == 0
    status, headers, data = client.request("GET", f"/api/e/{evaluation}/exports/{export['id']}/pv-list.xlsx")
    assert status == 200 and "attachment" in headers["content-disposition"]
    with zipfile.ZipFile(io.BytesIO(data)) as book:
        sheet = book.read("xl/worksheets/sheet2.xml").decode()
    assert "bounds checked by caller" in sheet and str(tmp_path) not in sheet

    # the disposition survives a rebuild of the index
    client.post(f"/api/e/{evaluation}/profile/confirm", {"by": "fgt"})
    _wait(client, evaluation)
    assert client.get(f"/api/e/{evaluation}/pvs/{row['pv_id']}")["pv"]["status"] == "false_positive"
    assert client.get(f"/api/e/{evaluation}")["profile"]["status"] == "confirmed"


def test_source_never_leaves_the_scanned_tree(server: App, tmp_path: Path) -> None:
    client = Client(server).login()
    evaluation, _ = _evaluation(server, client, tmp_path)
    (tmp_path / "secret.txt").write_text("key", encoding="utf-8")
    for path in ("../secret.txt", "/etc/passwd", "a.c/../../secret.txt"):
        status, _, _ = client.request("GET", f"/api/e/{evaluation}/source?path={path}&line=1")
        assert status in (400, 404), path
    view = client.get(f"/api/e/{evaluation}/source?path=a.c&line=4&radius=2")
    assert [line["n"] for line in view["lines"]] == [2, 3, 4, 5, 6]


def _zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


@pytest.mark.parametrize(("name", "data", "expect"), [
    ("st.pdf", b"%PDF-1.7\n...", 200),
    ("st.pdf", b"not a pdf", 400),
    ("st.exe", b"MZ", 400),
    ("st.docx", _zip({"word/document.xml": b"<w:document/>"}), 200),
    ("bomb.docx", _zip({"word/document.xml": b"0" * (5 * 1024 * 1024)}), 400),
    ("empty.docx", _zip({"other.xml": b"x"}), 400),
])
def test_document_uploads_are_checked(server: App, tmp_path: Path, name: str, data: bytes, expect: int) -> None:
    client = Client(server).login()
    evaluation, workspace = _evaluation(server, client, tmp_path)
    status, _, payload = client.request("POST", f"/api/e/{evaluation}/documents", raw=data,
                                        headers={"Content-Type": "application/octet-stream", "X-Filename": name})
    assert status == expect, payload
    if expect == 200:
        assert workspace.ledger.of("document_added")[-1]["name"] == name


def test_blocks_are_derived_from_the_ledger_only() -> None:
    records = [{"seq": 1, "kind": "evaluation_created", "source": "/s", "confidentiality": "client"},
               {"seq": 2, "kind": "something_internal"},
               {"seq": 3, "kind": "pv_status", "pv_id": "PV-0001", "status": "false_positive", "note": "n", "by": "a"}]
    out = blocks(records)
    assert [b["id"] for b in out] == ["1", "3"] and out[1]["refs"] == {"pv": "PV-0001"}
    assert blocks(records, after=1)[0]["id"] == "3"


def test_saying_something_needs_the_model_lane(server: App, tmp_path: Path) -> None:
    client = Client(server).login()
    evaluation, _ = _evaluation(server, client, tmp_path)
    status, _, payload = client.request("POST", f"/api/e/{evaluation}/say", {"text": "你好"})
    assert status == 409 and "CODE_ANALYZER_NO_MODEL" in json.loads(payload)["error"]
    view = client.get(f"/api/e/{evaluation}")
    assert view["agent"]["available"] is False and view["approvals"] == []


def test_an_approval_card_is_decided_by_the_page_only_with_its_hash(server: App, tmp_path: Path) -> None:
    from code_analyzer.kernel import approvals

    client = Client(server).login()
    evaluation, workspace = _evaluation(server, client, tmp_path)
    client.post(f"/api/e/{evaluation}/run_tools", {}, expect=202)
    _wait(client, evaluation)
    card = approvals.show(workspace, {"tool": "export", "arguments": {"variant": "internal", "formats": ["csv"]},
                                      "summary": "导出清单", "writes": ["pv-list.csv"]})
    view = client.get(f"/api/e/{evaluation}")
    assert [a["approval_id"] for a in view["approvals"]] == [card["approval_id"]]
    [shown] = [b for b in view["blocks"] if b["kind"] == "approval"]
    assert shown["refs"]["sha"] == card["args_sha256"] and shown["refs"]["expires_at"] == card["expires_at"]
    status, _, _ = client.request("POST", f"/api/e/{evaluation}/approvals/{card['approval_id']}/decide",
                                  {"decision": "approve", "sha": "bad"})
    assert status == 400
    card = approvals.show(workspace, {"tool": "export", "arguments": {"variant": "internal", "formats": ["csv"]},
                                      "summary": "导出清单", "writes": ["pv-list.csv"]})
    decided = client.post(f"/api/e/{evaluation}/approvals/{card['approval_id']}/decide",
                          {"decision": "approve", "sha": card["args_sha256"]})
    assert decided["card"]["kind"] == "export" and workspace.ledger.of("export_written")


def test_review_is_planned_by_the_page_and_started_only_with_a_budget(server: App, tmp_path: Path) -> None:
    client = Client(server).login()
    evaluation, workspace = _evaluation(server, client, tmp_path)
    client.post(f"/api/e/{evaluation}/run_tools", {}, expect=202)
    _wait(client, evaluation)
    plan = client.post(f"/api/e/{evaluation}/review/plan", {"depth": "quick"})["plan"]
    assert plan["counts"]["T1"] == 1 and plan["budget_minutes"] >= 1 and plan["basis"].startswith("估算")
    status, _, _ = client.request("POST", f"/api/e/{evaluation}/review/start", {"depth": "quick"})
    assert status == 400                      # no budget, no GPU time
    status, _, payload = client.request("POST", f"/api/e/{evaluation}/review/start",
                                        {"depth": "quick", "budget_minutes": 5})
    assert status == 409 and "CODE_ANALYZER_NO_MODEL" in json.loads(payload)["error"]
    assert not workspace.ledger.of("review_granted")
    view = client.get(f"/api/e/{evaluation}/coverage")["coverage"]
    assert view["listed"] == 1 and view["verified"] == 0 and view["triage"]["partition_main"] == 1


def test_an_unpinned_evaluation_is_pinned_by_a_click(server: App, tmp_path: Path) -> None:
    client = Client(server).login()
    evaluation, workspace = _evaluation(server, client, tmp_path)
    data = workspace.evaluation
    data["model_pin"] = None
    (workspace.root / "evaluation.json").write_text(json.dumps(data), encoding="utf-8")
    assert client.get(f"/api/e/{evaluation}")["model_pin"] is None
    pinned = client.post(f"/api/e/{evaluation}/pin_model", {})["model_pin"]
    assert pinned["addresses"] and workspace.evaluation["model_pin"]["host"] == pinned["host"]
    assert workspace.ledger.of("model_pinned")[-1]["by"] == "analyst"
    assert any(b["title"].startswith("模型主机已钉住") for b in client.get(f"/api/e/{evaluation}")["blocks"])


def test_an_index_from_an_older_version_is_rebuilt_when_the_page_opens(server: App, tmp_path: Path) -> None:
    client = Client(server).login()
    evaluation, workspace = _evaluation(server, client, tmp_path)
    client.post(f"/api/e/{evaluation}/run_tools", {}, expect=202)
    _wait(client, evaluation)
    import sqlite3
    with sqlite3.connect(workspace.index_path) as db:
        db.execute("UPDATE meta SET value = '1' WHERE key = 'schema_version'")
    view = client.get(f"/api/e/{evaluation}")
    assert view["jobs"][-1]["kind"] == "reindex"
    _wait(client, evaluation)
    assert client.get(f"/api/e/{evaluation}")["triage"]["partition_main"] == 1


def test_only_a_public_evaluation_can_switch_the_public_model_on(server: App, tmp_path: Path) -> None:
    client = Client(server).login()
    evaluation, workspace = _evaluation(server, client, tmp_path)          # created public
    view = client.get(f"/api/e/{evaluation}")["public_model"]
    assert view["configured"] is False and view["allowed"] is False
    switched = client.post(f"/api/e/{evaluation}/allow_public_model", {"allow": True})["public_model"]
    assert switched["switched_on"] is True and switched["allowed"] is False   # nothing configured to use
    assert workspace.ledger.of("public_model_allowed")[-1]["by"] == "analyst"
    data = workspace.evaluation
    data["confidentiality"], data["allow_public_model"] = "client", False
    (workspace.root / "evaluation.json").write_text(json.dumps(data), encoding="utf-8")
    status, _, payload = client.request("POST", f"/api/e/{evaluation}/allow_public_model", {"allow": True})
    assert status == 400 and "local GPU" in json.loads(payload)["error"]

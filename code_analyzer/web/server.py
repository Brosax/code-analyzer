"""The local web server: the evaluation page and its JSON API (docs/v3-web-api.md).

Security, in order of the checks every request meets:

1. Bound to 127.0.0.1 only.
2. ``Host`` must be ``127.0.0.1:<port>`` or ``localhost:<port>`` -- a page on
   another origin that DNS-rebinds a name to 127.0.0.1 is refused.
3. A session cookie is required for everything, the page included.  The only
   way to get it is the one-time URL printed at startup; the token works once.
   The cookie is HttpOnly and SameSite=Strict.
4. A POST also needs a same-origin ``Origin`` and a JSON body (uploads: an
   octet-stream with ``X-Filename``), so another local page cannot drive it.
5. Responses carry ``Content-Security-Policy: default-src 'self'``; the page
   has no inline script and inserts every piece of data with textContent.

No endpoint reaches a model in M3; the agent arrives in M5.
"""
from __future__ import annotations

import errno
import hashlib
import http.cookies
import io
import json
import re
import secrets
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from ..errors import UserError
from ..evidence import overlays
from ..evidence.analyze import ensure_index, evaluate, reindex
from ..evidence.store import Store, index_current
from ..evidence.workspace import EVALUATION_FILE, Workspace, _atomic
from ..export.listing import LeakFound, export
from ..jobs import buildctx_job, extract_job
from ..jobs.manager import Job, JobManager
from ..kernel import approvals, tools
from ..kernel.loop import Kernel
from ..kernel.session import Conversation
from ..model.broker import Broker
from ..model.client import disabled_by_env
from ..model.evaluation import client_for, local_endpoint, pin_local
from ..model.probe import latest_probe
from ..persist import json_bytes
from ..sesip import active
from ..sesip.profile import BUILTINS
from ..settings import Settings, load_settings
from .blocks import blocks

BIND_HOST = "127.0.0.1"
COOKIE = "ca_session"
MAX_JSON = 1024 * 1024
MAX_DOCUMENT = 64 * 1024 * 1024
DOCX_LIMITS = {"unpacked": 200 * 1024 * 1024, "entries": 2000, "part": 50 * 1024 * 1024, "ratio": 100}
SOURCE_RADIUS = 40
STATIC = {"app.js": "text/javascript; charset=utf-8", "app.css": "text/css; charset=utf-8"}
_ID = r"[A-Za-z0-9._-]+"


class HttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class App:
    def __init__(self, settings: Settings | None = None, *, port: int = 0) -> None:
        self.settings = settings or load_settings()
        self.data_root = self.settings.data_root.expanduser()
        self.data_root.mkdir(parents=True, exist_ok=True)
        self.port = port
        self.jobs = JobManager(on_finish=self._job_finished)
        # One GPU, one broker, shared by every evaluation this server hosts.
        self.broker = Broker()
        self._conversations: dict[str, Conversation] = {}
        self._deltas: dict[str, list[dict[str, Any]]] = {}
        self.codec = _probed_codec(self.settings)
        self._token: str | None = secrets.token_urlsafe(24)
        self._sessions: set[str] = set()
        self._lock = threading.Lock()
        # Reconcile once, at startup: a call left open now was left by a process
        # that died.  Never again while serving -- a call open then is this
        # server's own running job.
        for root in self.data_root.iterdir():
            if (root / EVALUATION_FILE).is_file():
                try:
                    Workspace.open(root)
                except (OSError, UserError, ValueError):
                    continue

    # -- session --------------------------------------------------------------------
    def login_url(self) -> str:
        return f"http://{BIND_HOST}:{self.port}/login?token={self._token}"

    def redeem(self, token: str) -> str | None:
        with self._lock:
            if not self._token or not secrets.compare_digest(token, self._token):
                return None
            self._token = None  # one use
            session = secrets.token_urlsafe(32)
            self._sessions.add(session)
            return session

    def authorised(self, session: str | None) -> bool:
        return bool(session) and session in self._sessions

    # -- evaluations ------------------------------------------------------------------
    def workspace(self, evaluation: str) -> Workspace:
        if not re.fullmatch(_ID, evaluation):
            raise HttpError(404, "no such evaluation")
        root = self.data_root / evaluation
        if not (root / EVALUATION_FILE).is_file():
            raise HttpError(404, "no such evaluation")
        return Workspace(root)

    def evaluations(self) -> list[dict[str, Any]]:
        out = []
        for root in sorted(self.data_root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if (root / EVALUATION_FILE).is_file():
                try:
                    out.append(self.summary(Workspace(root)))
                except (OSError, ValueError):
                    continue
        return out

    def summary(self, workspace: Workspace) -> dict[str, Any]:
        evaluation = workspace.evaluation
        profile = active.active_profile(workspace)
        running = self.jobs.running(workspace.root.name)
        return {"id": workspace.root.name, "name": workspace.root.name, "source": evaluation["source"],
                "confidentiality": evaluation["confidentiality"], "created_at": evaluation.get("created_at"),
                "profile": {"name": profile.name, "status": profile.status}, "counts": self.triage(workspace),
                "running_job": running.summary() if running else None}

    def triage(self, workspace: Workspace) -> dict[str, int] | None:
        if not index_current(workspace.index_path):
            return None
        store = Store(workspace.index_path)
        try:
            return store.triage_counts() or None
        finally:
            store.close()

    def create(self, body: dict[str, Any]) -> dict[str, Any]:
        source = Path(str(body.get("source") or "")).expanduser()
        if not source.is_absolute() or not source.is_dir():
            raise HttpError(400, "the source must be an absolute path to a directory")
        confidentiality = body.get("confidentiality", "client")
        if confidentiality not in ("client", "public"):
            raise HttpError(400, "confidentiality must be client or public")
        workspace = Workspace.create(self.data_root, source, confidentiality=confidentiality,
                                     pin=pin_local(self.settings))
        profile = str(body.get("profile") or "rt700-tp-v1.1")
        if profile not in BUILTINS:
            raise HttpError(400, f"unknown built-in profile {profile}")
        active.select_builtin(workspace, profile)
        return {"id": workspace.root.name}

    # -- the conversation -------------------------------------------------------------------
    def agent_available(self) -> tuple[bool, str]:
        if disabled_by_env():
            return False, "CODE_ANALYZER_NO_MODEL=1：模型通道已关闭，按钮仍可用"
        return True, ""

    def conversation(self, workspace: Workspace) -> Conversation:
        key = workspace.root.name
        with self._lock:
            conversation = self._conversations.get(key)
            if conversation is None:
                conversation = Conversation(workspace, lambda: self._kernel(workspace),
                                            on_delta=lambda event, key=key: self._delta(key, event))
                conversation.start()
                self._conversations[key] = conversation
            return conversation

    def _kernel(self, workspace: Workspace) -> Kernel:
        client = client_for(workspace, self.settings, tool_mode="native" if self.codec == "native" else "text")
        return Kernel(workspace, client, self.broker, self.services(), codec=self.codec,
                      triage=lambda: self.triage(workspace),
                      jobs=lambda: [job.summary() for job in self.jobs.jobs(workspace.root.name)])

    def services(self) -> tools.Services:
        return tools.Services(
            run_tools=lambda ws, chosen: self.run_tools(ws, chosen),
            jobs=lambda ws: [job.summary() for job in self.jobs.jobs(ws.root.name)],
            export=lambda ws, variant, formats: export(ws, variant, formats),
            rebuild=lambda ws: self.rebuild(ws),
            apply_patch=lambda ws, patch_id, selected: self.apply_patch(ws, patch_id, selected))

    def apply_patch(self, workspace: Workspace, patch_id: str, selected: list[int]) -> Job:
        def work(job: Job) -> int:
            outcome = buildctx_job.apply(workspace, patch_id, selected, progress=lambda line: self.jobs.log(job, line),
                                         cancelled=job.token.is_cancelled)
            self.jobs.log(job, f"{outcome['tool']}: failed units {outcome['failed_before']} -> "
                               f"{outcome['failed_after']}, reached {outcome['reached_before']} -> "
                               f"{outcome['reached_after']}")
            return 0
        return self.jobs.start(workspace.root.name, "patch", work)

    def _delta(self, key: str, event: dict[str, Any]) -> None:
        with self._lock:
            events = self._deltas.setdefault(key, [])
            events.append(event)
            del events[:-2000]
        self.jobs.poke()

    def deltas_since(self, key: str, index: int) -> tuple[list[dict[str, Any]], int]:
        with self._lock:
            events = self._deltas.get(key, [])
            start = max(0, len(events) - 2000) if index > len(events) else index
            return events[start:], len(events)

    def _job_finished(self, job: Job) -> None:
        conversation = self._conversations.get(job.evaluation)
        if conversation is None or not self.agent_available()[0]:
            return
        if job.kind == "reindex":
            return
        outcome = {"finished": "结束", "failed": "失败", "stopped": "已停止"}.get(job.status, job.status)
        text = f"任务 {job.id}（{job.kind}）{outcome}，退出码 {job.exit_code}" + (f"：{job.error}" if job.error else "")
        conversation.event(job.id, text)

    # -- jobs ---------------------------------------------------------------------------
    def run_tools(self, workspace: Workspace, tools: list[str] | None) -> Job:
        def work(job: Job) -> int:
            outcome = evaluate(workspace.source, eval_dir=workspace.root, tools=tools or None,
                               progress=lambda line: self.jobs.log(job, line), cancellation=job.token)
            job.call_id = outcome.call_id
            return outcome.exit_code
        return self.jobs.start(workspace.root.name, "static", work)

    def extract_profile(self, workspace: Workspace) -> Job:
        def work(job: Job) -> int:
            extract_job.run(workspace, self.settings, self.broker, token=job.token,
                            progress=lambda line: self.jobs.log(job, line))
            return 0
        return self.jobs.start(workspace.root.name, "extract", work)

    def rebuild(self, workspace: Workspace) -> Job | None:
        """Re-grade and renumber under a changed profile.  Skipped while a job runs: that job
        rebuilds the list itself when it finishes, with the profile current then."""
        if not workspace.ledger.of("call_finished") or self.jobs.running(workspace.root.name):
            return None

        def work(job: Job) -> int:
            reindex(workspace, progress=lambda line: self.jobs.log(job, line))
            return 0
        return self.jobs.start(workspace.root.name, "reindex", work)


def make_handler(app: App) -> type[BaseHTTPRequestHandler]:
    routes_get: list[tuple[re.Pattern[str], str]] = [
        (re.compile(r"/api/state"), "state"),
        (re.compile(rf"/api/e/({_ID})"), "evaluation"),
        (re.compile(rf"/api/e/({_ID})/pvs"), "pvs"),
        (re.compile(rf"/api/e/({_ID})/pvs/(PV-\d+)"), "pv"),
        (re.compile(rf"/api/e/({_ID})/findings"), "findings"),
        (re.compile(rf"/api/e/({_ID})/source"), "source"),
        (re.compile(rf"/api/e/({_ID})/stream"), "stream"),
        (re.compile(rf"/api/e/({_ID})/exports/(E\d+)/({_ID})"), "download"),
    ]
    routes_post: list[tuple[re.Pattern[str], str]] = [
        (re.compile(r"/api/evaluations"), "create"),
        (re.compile(rf"/api/e/({_ID})/run_tools"), "run_tools"),
        (re.compile(rf"/api/e/({_ID})/jobs/(J\d+)/stop"), "stop"),
        (re.compile(rf"/api/e/({_ID})/pvs/(PV-\d+)/status"), "status"),
        (re.compile(rf"/api/e/({_ID})/pvs/accept_proposed"), "accept"),
        (re.compile(rf"/api/e/({_ID})/profile"), "profile"),
        (re.compile(rf"/api/e/({_ID})/profile/confirm"), "confirm"),
        (re.compile(rf"/api/e/({_ID})/export"), "export"),
        (re.compile(rf"/api/e/({_ID})/documents"), "document"),
        (re.compile(rf"/api/e/({_ID})/extract"), "extract"),
        (re.compile(rf"/api/e/({_ID})/say"), "say"),
        (re.compile(rf"/api/e/({_ID})/interrupt"), "interrupt"),
        (re.compile(rf"/api/e/({_ID})/typing"), "typing"),
        (re.compile(rf"/api/e/({_ID})/approvals/(A\d+)/decide"), "decide"),
    ]

    class Handler(BaseHTTPRequestHandler):
        server_version = "code-analyzer"
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args: Any) -> None:
            return

        # -- plumbing -----------------------------------------------------------------
        def _host_ok(self) -> bool:
            host = self.headers.get("Host", "")
            return host in {f"127.0.0.1:{app.port}", f"localhost:{app.port}"}

        def _session(self) -> str | None:
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            morsel = cookie.get(COOKIE)
            return morsel.value if morsel else None

        def _send(self, status: int, body: bytes, content_type: str = "application/json",
                  headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, value: Any) -> None:
            self._send(status, json_bytes(value))

        def _error(self, status: int, message: str) -> None:
            self._json(status, {"error": message})

        def _guard(self) -> bool:
            if not self._host_ok():
                self._error(403, "wrong Host header")
                return False
            path = urlsplit(self.path).path
            if path == "/login":
                return True
            if not app.authorised(self._session()):
                self._error(403, "open the one-time URL printed by code-analyzer to sign in")
                return False
            return True

        def _body(self, limit: int = MAX_JSON) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            if length > limit:
                raise HttpError(413, f"request body exceeds {limit} bytes")
            return self.rfile.read(length)

        def _json_body(self) -> dict[str, Any]:
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                raise HttpError(415, "the request body must be application/json")
            try:
                value = json.loads(self._body().decode("utf-8") or "{}")
            except (UnicodeError, json.JSONDecodeError):
                raise HttpError(400, "the request body is not valid JSON") from None
            if not isinstance(value, dict):
                raise HttpError(400, "the request body must be a JSON object")
            return value

        # -- GET ----------------------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            if not self._guard():
                return
            split = urlsplit(self.path)
            path, query = split.path, {k: v[-1] for k, v in parse_qs(split.query).items()}
            try:
                if path == "/login":
                    return self._login(query.get("token", ""))
                if path in ("/", "/index.html"):
                    return self._static("index.html", "text/html; charset=utf-8")
                if path.startswith("/static/") and path[8:] in STATIC:
                    return self._static(path[8:], STATIC[path[8:]])
                for pattern, name in routes_get:
                    match = pattern.fullmatch(path)
                    if match:
                        return getattr(self, f"get_{name}")(*match.groups(), query=query)
                self._error(404, "not found")
            except HttpError as error:
                self._error(error.status, str(error))
            except (UserError, ValueError, KeyError) as error:
                self._error(400, str(error).strip("'"))
            except (BrokenPipeError, ConnectionResetError):
                return

        def _login(self, token: str) -> None:
            session = app.redeem(token)
            if session is None:
                return self._error(403, "this sign-in link has already been used or is wrong; restart code-analyzer")
            self._send(303, b"", "text/plain", {
                "Location": "/", "Set-Cookie": f"{COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/"})

        def _static(self, name: str, content_type: str) -> None:
            data = resources.files("code_analyzer.web").joinpath("static", name).read_bytes()
            self._send(200, data, content_type)

        def get_state(self, *, query: dict[str, str]) -> None:
            self._json(200, {"evaluations": app.evaluations(), "builtin_profiles": list(BUILTINS), "agent": False,
                             "settings": {"local_model": app.settings.local_endpoint,
                                          "model_name": app.settings.local_model, "data_root": str(app.data_root)}})

        def get_evaluation(self, evaluation: str, *, query: dict[str, str]) -> None:
            workspace = app.workspace(evaluation)
            available, reason = app.agent_available()
            conversation = app._conversations.get(evaluation)
            self._json(200, {"evaluation": app.summary(workspace),
                             "profile": active.view(active.active_profile(workspace)),
                             "jobs": [job.summary() for job in app.jobs.jobs(evaluation)],
                             "blocks": blocks(workspace.ledger.read()), "triage": app.triage(workspace),
                             "agent": {"available": available, "reason": reason, "codec": app.codec,
                                       "busy": bool(conversation and conversation.busy),
                                       "model": app.settings.local_model},
                             "approvals": [_card(a) for a in approvals.pending(workspace)]})

        def _store(self, workspace: Workspace) -> Store:
            if app.jobs.running(workspace.root.name) is None and not ensure_index(workspace):
                raise HttpError(409, "no list yet: run the tools first")
            if not workspace.index_path.exists():
                raise HttpError(409, "the list is being built; try again when the job finishes")
            return Store(workspace.index_path)

        def get_pvs(self, evaluation: str, *, query: dict[str, str]) -> None:
            store = self._store(app.workspace(evaluation))
            try:
                where = {k: query[k] for k in ("partition", "level", "module", "sfr", "status", "path", "family")
                         if query.get(k)}
                result = store.list_pvs(where, sort=query.get("sort", "priority"), page=_page(query))
            finally:
                store.close()
            self._json(200, {**result, "page_size": 20})

        def get_pv(self, evaluation: str, pv_id: str, *, query: dict[str, str]) -> None:
            workspace = app.workspace(evaluation)
            store = self._store(workspace)
            try:
                entry = store.pv(pv_id)
                if entry is None:
                    raise HttpError(404, f"no {pv_id}")
                members = store.cluster_members(entry["cluster_id"])
            finally:
                store.close()
            fields = ("tool", "rule_id", "line", "column", "review_level", "original_severity", "message", "cwe",
                      "evidence_context", "fingerprint")
            rows = [{k: m.get(k, "") for k in fields} for m in members]
            marked = {_int(m.get("line")) for m in members}
            source = _source(workspace, entry["path"], int(entry["line_start"]), 12, marked)
            self._json(200, {"pv": entry, "members": rows, "source": source})

        def get_findings(self, evaluation: str, *, query: dict[str, str]) -> None:
            store = self._store(app.workspace(evaluation))
            try:
                where = {k: query[k] for k in ("view_class", "tool", "level", "path", "rule", "cluster") if query.get(k)}
                result = store.list_findings(where, page=_page(query))
            finally:
                store.close()
            self._json(200, {**result, "page_size": 20})

        def get_source(self, evaluation: str, *, query: dict[str, str]) -> None:
            workspace = app.workspace(evaluation)
            radius = min(max(int(query.get("radius", "12")), 1), SOURCE_RADIUS)
            self._json(200, _source(workspace, query.get("path", ""), int(query.get("line", "1")), radius, set()))

        def get_download(self, evaluation: str, export_id: str, name: str, *, query: dict[str, str]) -> None:
            workspace = app.workspace(evaluation)
            target = workspace.root / "exports" / export_id / name
            if not target.is_file() or target.resolve().parent != (workspace.root / "exports" / export_id).resolve():
                raise HttpError(404, "no such export file")
            kind = {"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "md": "text/markdown; charset=utf-8", "csv": "text/csv; charset=utf-8"}.get(
                target.suffix.lstrip("."), "application/octet-stream")
            self._send(200, target.read_bytes(), kind,
                       {"Content-Disposition": f'attachment; filename="{workspace.root.name}-{export_id}-{name}"'})

        def get_stream(self, evaluation: str, *, query: dict[str, str]) -> None:
            workspace = app.workspace(evaluation)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                after = int(self.headers.get("Last-Event-ID") or query.get("after") or 0)
            except ValueError:
                after = 0
            version = -1
            seen_jobs: dict[str, str] = {}
            _, delta_index = app.deltas_since(evaluation, 0)
            deadline = time.monotonic() + 3600
            try:
                while time.monotonic() < deadline:
                    records = workspace.ledger.read()
                    for item in blocks(records, after):
                        self._event("block", item, item["id"])
                        if item["kind"] == "summary":
                            self._event("triage", app.triage(workspace) or {})
                    if records:
                        after = max(after, int(records[-1]["seq"]))
                    deltas, delta_index = app.deltas_since(evaluation, delta_index)
                    for item in deltas:
                        self._event("delta", item)
                    for job in app.jobs.jobs(evaluation):
                        summary = job.summary()
                        key = json.dumps([summary["status"], len(summary["progress"]), summary["progress"][-1:]])
                        if seen_jobs.get(job.id) != key:
                            seen_jobs[job.id] = key
                            self._event("job", summary)
                    self.wfile.write(b": keep-alive\n\n")
                    self.wfile.flush()
                    version = app.jobs.wait(version, timeout=1.0)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

        def _event(self, name: str, data: Any, event_id: str | None = None) -> None:
            payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            head = f"id: {event_id}\n" if event_id else ""
            self.wfile.write(f"{head}event: {name}\ndata: {payload}\n\n".encode("utf-8"))

        # -- POST ---------------------------------------------------------------------
        def do_POST(self) -> None:  # noqa: N802
            if not self._guard():
                return
            origin = self.headers.get("Origin", "")
            if not origin or urlsplit(origin).netloc != self.headers.get("Host", ""):
                return self._error(403, "a change needs a same-origin request")
            path = urlsplit(self.path).path
            try:
                for pattern, name in routes_post:
                    match = pattern.fullmatch(path)
                    if match:
                        return getattr(self, f"post_{name}")(*match.groups())
                self._error(404, "not found")
            except HttpError as error:
                self._error(error.status, str(error))
            except LeakFound as error:
                self._error(409, str(error))
            except (UserError, ValueError) as error:
                self._error(400, str(error))
            except KeyError as error:
                self._error(404, f"not found: {str(error).strip(chr(39))}")

        def post_create(self) -> None:
            self._json(201, app.create(self._json_body()))

        def post_run_tools(self, evaluation: str) -> None:
            body = self._json_body()
            workspace = app.workspace(evaluation)
            tools = [t for t in body.get("tools") or [] if t in ("cppcheck", "flawfinder", "splint")]
            try:
                job = app.run_tools(workspace, tools)
            except UserError as error:
                raise HttpError(409, str(error)) from None
            self._json(202, {"job": job.summary()})

        def post_stop(self, evaluation: str, job_id: str) -> None:
            self._json_body()
            self._json(200, {"job": app.jobs.stop(evaluation, job_id).summary()})

        def post_status(self, evaluation: str, pv_id: str) -> None:
            body = self._json_body()
            workspace = app.workspace(evaluation)
            store = self._store(workspace)
            try:
                entry = overlays.set_status(workspace, store, pv_id, str(body.get("status", "")),
                                            str(body.get("note", "")), by="analyst")
            finally:
                store.close()
            self._json(200, {"pv": entry})

        def post_accept(self, evaluation: str) -> None:
            body = self._json_body()
            ids = [str(i) for i in body.get("pv_ids") or [] if re.fullmatch(r"PV-\d+", str(i))]
            workspace = app.workspace(evaluation)
            store = self._store(workspace)
            try:
                count = overlays.accept_proposed(workspace, store, ids, by="analyst")
            finally:
                store.close()
            self._json(200, {"accepted": count})

        def post_profile(self, evaluation: str) -> None:
            body = self._json_body()
            workspace = app.workspace(evaluation)
            if body.get("builtin"):
                profile = active.select_builtin(workspace, str(body["builtin"]))
            elif isinstance(body.get("toml"), str):
                profile = active.save_draft(workspace, body["toml"])
            else:
                raise HttpError(400, "send either builtin or toml")
            app.rebuild(workspace)
            self._json(200, {"profile": active.view(profile)})

        def post_confirm(self, evaluation: str) -> None:
            body = self._json_body()
            workspace = app.workspace(evaluation)
            profile = active.confirm(workspace, str(body.get("by", "")))
            app.rebuild(workspace)
            self._json(200, {"profile": active.view(profile)})

        def post_export(self, evaluation: str) -> None:
            body = self._json_body()
            workspace = app.workspace(evaluation)
            if not workspace.index_path.exists():
                raise HttpError(409, "no list yet: run the tools first")
            result = export(workspace, str(body.get("variant", "internal")),
                            [str(f) for f in body.get("formats") or []])
            self._json(200, {"export": result})

        def post_say(self, evaluation: str) -> None:
            body = self._json_body()
            available, reason = app.agent_available()
            if not available:
                raise HttpError(409, reason)
            workspace = app.workspace(evaluation)
            if not workspace.evaluation.get("model_pin"):
                raise HttpError(409, "this evaluation has no pinned model host yet; pin one on the profile page")
            self._json(202, app.conversation(workspace).say(str(body.get("text", ""))))

        def post_interrupt(self, evaluation: str) -> None:
            self._json_body()
            conversation = app._conversations.get(evaluation)
            self._json(200, {"interrupted": bool(conversation and conversation.interrupt())})

        def post_typing(self, evaluation: str) -> None:
            self._json_body()
            app.broker.note_activity()
            conversation = app._conversations.get(evaluation)
            if conversation is not None:
                conversation.typing()
            self._json(200, {"ok": True})

        def post_decide(self, evaluation: str, approval_id: str) -> None:
            body = self._json_body()
            decision = str(body.get("decision", ""))
            if decision not in ("approve", "reject"):
                raise HttpError(400, "decision must be approve or reject")
            workspace = app.workspace(evaluation)
            context = tools.ToolContext(workspace, app.services())
            result = approvals.decide(workspace, context, approval_id, decision, by="analyst",
                                      sha=str(body.get("sha", "")))
            self._json(200, {"result": result.content, "card": result.card})

        def post_document(self, evaluation: str) -> None:
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/octet-stream":
                raise HttpError(415, "upload the document as application/octet-stream")
            # Browsers only send Latin-1 headers, so the page percent-encodes the name.
            name = Path(unquote(self.headers.get("X-Filename", "document"))).name[:200] or "document"
            data = self._body(MAX_DOCUMENT)
            kind = _document_kind(name, data)
            workspace = app.workspace(evaluation)
            digest = hashlib.sha256(data).hexdigest()
            docs = workspace.root / "docs"
            docs.mkdir(exist_ok=True)
            _atomic(docs / f"{digest}.{kind}", data)
            role = self.headers.get("X-Role", "") or extract_job.guess_role(name)
            if role not in extract_job.ROLES:
                raise HttpError(400, "X-Role must be security_target or test_plan")
            workspace.ledger.append("document_added", name=name, sha256=digest, doc_kind=kind, bytes=len(data),
                                    role=role)
            self._json(200, {"document": {"sha256": digest, "name": name, "role": role, "pages": None}})

        def post_extract(self, evaluation: str) -> None:
            self._json_body()
            workspace = app.workspace(evaluation)
            try:
                job = app.extract_profile(workspace)
            except UserError as error:
                raise HttpError(409, str(error)) from None
            self._json(202, {"job": job.summary()})

    return Handler


def serve(settings: Settings | None = None, *, port: int | None = None,
          announce: Any = print) -> None:  # pragma: no cover - interactive
    app = App(settings)
    chosen = port if port is not None else app.settings.port
    try:
        server = ThreadingHTTPServer((BIND_HOST, chosen), make_handler(app))
    except OSError as error:
        if error.errno == errno.EADDRINUSE:
            raise UserError(f"port {chosen} is already in use (another code-analyzer?); pass --port") from None
        raise
    server.daemon_threads = True
    app.port = server.server_address[1]
    announce(f"code-analyzer: open {app.login_url()}")
    try:
        server.serve_forever()
    finally:
        server.server_close()


def _card(record: dict[str, Any]) -> dict[str, Any]:
    return {"approval_id": record["approval_id"], "tool": record["tool"], "arguments": record["arguments"],
            "sha": record["args_sha256"], "summary": record.get("summary", ""), "writes": record.get("writes", []),
            "expires_at": record["expires_at"]}


def _probed_codec(settings: Settings) -> str:
    """The codec the last full probe chose for the configured model; native when never probed."""
    probe = latest_probe(local_endpoint(settings))
    codec = (probe or {}).get("verdict", {}).get("codec")
    return codec if codec in ("native", "json") else "native"


def _page(query: dict[str, str]) -> int:
    try:
        return max(1, int(query.get("page", "1")))
    except ValueError:
        return 1


def _int(value: Any) -> int:
    try:
        return int(str(value).split("-")[0])
    except ValueError:
        return 0


def _source(workspace: Workspace, relative: str, line: int, radius: int, marked: set[int]) -> dict[str, Any]:
    """Lines of one file of the scanned tree.  Anything that resolves outside it is refused."""
    root = workspace.source.resolve()
    if not relative or relative.startswith("/") or "\x00" in relative:
        raise HttpError(400, "path must be relative to the scanned tree")
    target = (root / relative).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        raise HttpError(404, "no such file in the scanned tree")
    text = target.read_bytes()[:8 * 1024 * 1024].decode("utf-8", "replace").splitlines()
    start, end = max(1, line - radius), min(len(text), line + radius)
    return {"path": relative, "start": start, "end": end,
            "lines": [{"n": n, "text": text[n - 1][:2000], "marked": n in marked or n == line}
                      for n in range(start, end + 1)]}


def _document_kind(name: str, data: bytes) -> str:
    lower = name.lower()
    if lower.endswith(".pdf") and data.startswith(b"%PDF-"):
        return "pdf"
    if lower.endswith(".docx") and data.startswith(b"PK\x03\x04"):
        _check_docx(data)
        return "docx"
    raise HttpError(400, "only .pdf or .docx files are accepted, and the content must match the extension")


def _check_docx(data: bytes) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise HttpError(400, "the .docx is not a valid zip archive") from None
    infos = archive.infolist()
    if len(infos) > DOCX_LIMITS["entries"]:
        raise HttpError(400, "the .docx has too many parts")
    total = 0
    for info in infos:
        total += info.file_size
        if info.file_size > DOCX_LIMITS["part"]:
            raise HttpError(400, "a part of the .docx is too large")
        if info.compress_size and info.file_size / info.compress_size > DOCX_LIMITS["ratio"]:
            raise HttpError(400, "the .docx is compressed suspiciously well (possible zip bomb)")
    if total > DOCX_LIMITS["unpacked"]:
        raise HttpError(400, "the .docx unpacks to more than 200 MB")
    if "word/document.xml" not in archive.namelist():
        raise HttpError(400, "the .docx has no word/document.xml")

# v3 web API

Served by `code-analyzer` (web/server.py) on 127.0.0.1 only. All responses are JSON unless noted.
The page is `/` (index.html) plus `/static/app.js` and `/static/app.css`. No inline script or style:
the CSP is `default-src 'self'`.

## Security
- Startup prints `http://127.0.0.1:<port>/login?token=<one-time token>`. `GET /login?token=` sets the
  `ca_session` cookie (HttpOnly, SameSite=Strict, Path=/) and redirects to `/`. The token works once.
- Every request, `/` and static files included, needs the cookie. Without it: 403.
- `Host` must be `127.0.0.1:<port>` or `localhost:<port>`; anything else: 403.
- Every POST needs a same-origin `Origin` header and `Content-Type: application/json`. The one exception is
  `POST /api/e/<id>/documents`, which takes `application/octet-stream` with an `X-Filename` header.
- Untrusted text (paths, messages, source) must be inserted into the page with `textContent`, never `innerHTML`.

## Errors
A non-2xx response carries `{"error": "<human sentence>"}`.

## Endpoints

### Global
- `GET /api/state` → `{"evaluations": [EvalSummary], "settings": {"local_model": "http://…", "model_name": "qwen3.8:27b",
  "data_root": "…"}, "builtin_profiles": ["rt700-tp-v1.1", "generic-sesip"], "agent": false}`
  - EvalSummary = `{"id", "name", "source", "confidentiality": "client"|"public", "created_at", "profile": {"name",
    "status"}, "counts": Triage|null, "running_job": JobSummary|null}`
- `POST /api/evaluations` body `{"source": "/abs/path", "confidentiality": "client"|"public", "profile": "generic-sesip"}`
  → `201 {"id": …}`

### One evaluation (`<id>` = evaluation id)
- `GET /api/e/<id>` → `{"evaluation": EvalSummary, "profile": ProfileView, "jobs": [JobSummary],
  "blocks": [Block], "triage": Triage|null}`
  - Triage = `{"in_toe", "partition_main", "partition_unmapped", "partition_below", "outside_toe", "listed", "kept",
    "new", "retired", "findings", "clusters"}` (integers)
  - ProfileView = `{"name", "status": "builtin"|"draft"|"confirmed", "sha256", "text": "<toml>", "sfr": [{"id", "title"}],
    "levels": [{"id", "label", "rank", "description"}], "toe_modules": [{"id", "paths": [...]}], "excludes": [...],
    "grading_rules": [{"match", "level", "basis"}]}`
- `GET /api/e/<id>/pvs?partition=main|unmapped&level=&module=&sfr=&status=&path=&sort=priority|level|path&page=1`
  → `{"total", "page", "page_size": 20, "rows": [PvRow], "by_partition": {…}, "by_level": {…}}`
  - PvRow = `{"pv_id", "partition", "level", "level_basis", "proposed_level", "module", "sfr": [{"id", "basis"}], "path",
    "function", "family", "line_start", "line_end", "members", "tools": "cppcheck,flawfinder", "priority",
    "status": "open"|"confirmed"|"false_positive"|"not_exploitable"|"needs_test", "note"}`
- `GET /api/e/<id>/pvs/<pv_id>` → `{"pv": PvRow + {"priority_why": {…}, "anchor", "cluster_id"}, "members": [FindingRow],
  "source": SourceView}`
  - FindingRow = `{"tool", "rule_id", "line", "column", "review_level", "original_severity", "message", "cwe",
    "evidence_context", "fingerprint"}`
  - SourceView = `{"path", "start", "end", "lines": [{"n": 12, "text": "…", "marked": true}]}` (untrusted text)
- `GET /api/e/<id>/findings?view_class=finding|diagnostic|out_of_tree|superseded|*&tool=&level=&path=&page=`
  → like pvs but rows are FindingRow + `{"path", "view_class", "cluster_id"}`
- `GET /api/e/<id>/source?path=<relative>&line=<n>&radius=<≤40>` → SourceView (only files in the scanned tree)
- `POST /api/e/<id>/run_tools` body `{"tools": ["cppcheck", …]?}` → `202 {"job": JobSummary}`. 409 if a job is running.
  - JobSummary = `{"id": "J1", "kind": "static", "status": "running"|"finished"|"failed"|"stopped", "started_at",
    "finished_at", "exit_code", "progress": ["…last 50 lines…"], "call_id"}`
- `POST /api/e/<id>/jobs/<job_id>/stop` → `{"job": JobSummary}`
- `POST /api/e/<id>/pvs/<pv_id>/status` body `{"status": …, "note": "…"}` → `{"pv": PvRow}`
- `POST /api/e/<id>/pvs/accept_proposed` body `{"pv_ids": ["PV-0003", …]}`: an analyst accepts the level that
  a proposed rule suggested. The entry moves from `unmapped` to `main` with `level_basis: "analyst"`.
  → `{"accepted": n}`
- `POST /api/e/<id>/profile` body `{"builtin": "generic-sesip"}` or `{"toml": "<text>"}` → `{"profile": ProfileView}`
  (validated; a TOML becomes the next draft version)
- `POST /api/e/<id>/profile/confirm` body `{"by": "<analyst name>"}` → `{"profile": ProfileView}`. A draft becomes
  confirmed. A builtin is copied into the evaluation, then confirmed.
- `POST /api/e/<id>/export` body `{"variant": "internal"|"shareable", "formats": ["xlsx", "md", "csv"]}`
  → `{"export": {"id": "E1", "files": [{"name", "sha256", "bytes"}], "leak_check": "passed"}}`
- `GET /api/e/<id>/exports/<export_id>/<name>` → the file (`Content-Disposition: attachment`)
- `POST /api/e/<id>/documents` (octet-stream, `X-Filename`) → `{"document": {"sha256", "name", "pages": null}}`.
  pdf/docx only, ≤64 MB, magic bytes checked; a docx must be a sane zip (≤200 MB unpacked, ≤2000 entries,
  ≤50 MB per part, compression ratio ≤100).
- `GET /api/e/<id>/stream` → SSE. Events: `block` (a new Block), `job` (JobSummary), `triage` (Triage). Honours
  `Last-Event-ID`.

### Block (the timeline, derived from the ledger)
`{"id": "<ledger seq>", "kind": "event"|"job"|"summary"|"status"|"export"|"profile", "title": "…", "detail": "…",
"at": "…", "refs": {"job"?, "pv"?, "export"?}}`

## M5: the conversation

- `GET /api/e/<id>` additionally returns
  `"agent": {"available": bool, "reason": "…", "codec": "native"|"json", "busy": bool, "model": "qwen3.8:27b"}`
  and `"approvals": [{"approval_id": "A1", "tool": "export", "arguments": {…}, "sha": "<args sha256>",
  "summary": "导出清单（shareable）", "writes": ["pv-list.xlsx"], "expires_at": <epoch seconds>}]` (pending cards only).
- `POST /api/e/<id>/say` `{"text": "…"}` → `202 {"queued": false}` or `{"queued": true}` when a turn is running
  (the message is sent after it, marked as written during it). 409 with a reason when the model lane is off or
  the evaluation has no pinned model host.
- `POST /api/e/<id>/interrupt` `{}` → `{"interrupted": bool}`. Stops the running turn.
- `POST /api/e/<id>/typing` `{}`: call at most every 2 s while the evaluator types. It keeps background GPU
  work paused and holds off wake-ups.
- `POST /api/e/<id>/approvals/<A…>/decide` `{"decision": "approve"|"reject", "sha": "<the card's sha>"}`
  → `{"result": "…", "card": {…}|null}`. 400 when the card is expired, already decided, or its state changed.
  **Only the approve button may call this; typed text is never an approval.**
- SSE `delta` events: `{"kind": "text"|"reasoning"|"tool"|"end", "text": "…"}`. They carry the agent's reply as
  it streams; "end" means the turn is over and the final `agent` block follows.
- New Block kinds:
  - `user`: detail is the evaluator's text.
  - `queued`: the text was queued during a turn.
  - `agent`: detail is the agent's answer in Markdown-ish text. Render it as text; code fences may be shown in
    monospace. refs `{"calls": "list、show", "meta": "第 2 步 · 首字 5.1s · 输入 2549 token"}`.
  - `tool`: title "show → R3"; detail is the tool result (untrusted text; show it collapsed). refs
    `{"card": {"kind": "job"|"export"|"profile", …}, "handle": "R3"}`.
  - `approval`: refs `{"approval": "A1", "sha": "…", "tool": "export", "arguments": {…}, "expires_at": <epoch>}`.
    Draw 批准 / 拒绝 buttons while the card is pending: listed in `approvals` on load, or arrived on the stream
    and not yet closed by a `status` block with the same `refs.approval`.
  - `status`: an approval decided or expired, a turn interrupted, or "no conclusion in 3 steps".
  - `error`: the agent failed (for example the model host is unreachable). Show it plainly; buttons still work.

## M7: targeted AI review

- `GET /api/e/<id>` additionally returns `"review": {"verified", "listed"}` (listed entries with a grounded AI
  verdict) and `"model_pin": {"host", "port", "model", "addresses"}|null`. With no pin, `agent.available` is false
  and says to pin on the profile page.
- `POST /api/e/<id>/pin_model` `{}` → `{"model_pin": {…}}`: pins the configured local model host (a human act,
  recorded as `model_pinned`). 409 when the host cannot be resolved.
- `POST /api/e/<id>/review/plan` `{"focus": {"sfr": "SESIP-SIP,SESIP-SS"?, "module"?, "partition"?}, "targets":
  ["PV-0007"]?, "depth": "quick"|"normal", "lens"?}` → `{"plan": {"counts": {"T1", "T2", "V"}, "targets", "skipped":
  {reason: n}, "estimate_seconds", "basis": "估算：…", "budget_minutes", "sample": [Target], "grant": {"granted",
  "used", "left"}}}`. Deterministic; no model call. `quick` = verify listed entries only (T1); `normal` adds T2
  (functions with no tool alarm that the profile ties to an SFR or TSFI).
- `POST /api/e/<id>/review/start` same body + `"budget_minutes"` (1–240) → `202 {"job": JobSummary}` (kind
  `review`). The click is the grant (`review_granted`). 400 without a budget, 409 when the model lane is off or a
  job is running.
- `GET /api/e/<id>/coverage` → `{"coverage": {"triage", "sfr": [{"id", "title"}], "modules": [...], "matrix":
  {sfr: {module: {"listed", "verified", "looked"}}}, "lenses": {lens: {"asked", "answered", "failed",
  "unscheduled", "claims", "grounded", "grounding_failure_rate", "gpu_seconds"}}, "verdicts": {"CONFIRMED", …,
  "none"}, "listed", "verified", "promoted", "origin", "unreviewed": {reason: n}, "jobs", "granted_seconds"}}`.
- PvRow gains `ai_verdict` (list), and the entry (`GET …/pvs/<pv_id>`) gains `ai`: `{"verdict", "confidence",
  "decisive_line", "evidence_quote", "rationale", "exploit_note", "level_suggestion", "category_suggestion", "sfr",
  "lens", "lens_version", "model", "prompt_sha256", "job", "at"}|null` (grounded verdicts only), `proposed_from`
  (`rule`|`ai`|""), and `origin` (`tool`|`tool+ai`|`ai`). Filter `?ai=CONFIRMED`.
- Members of a promoted AI finding carry `engine: "llm"`, `af_id`, `lens`, `verdict`, `evidence_quote`.
- New Block titles: 模型主机已钉住, AI 审查 J… 开始 / 结束 (planned = reviewed + unscheduled, with reasons),
  AI 发现 AF-n 经复核进入未分级分区.
- The chat's `review` tool plans the same way; it shows an approval card (GPU minutes) unless the plan has at
  most 3 units and the GPU time already granted covers the estimate.

## M8: the public channel and re-evaluation

- `GET /api/e/<id>` additionally returns `"public_model": {"configured", "allowed", "reason", "switched_on", "model",
  "host"}`.
- `POST /api/e/<id>/allow_public_model` `{"allow": bool}` → `{"public_model": {…}}`: only a public evaluation may
  switch it on (400 otherwise); recorded as `public_model_allowed` with `by`. The conversation never uses the
  public model; a review job uses it only when its plan/start body says `"channel": "public"` and the switch is on.
- `POST /api/evaluations` accepts `"buildctx_from": "<evaluation id>"`: the new evaluation starts from that
  evaluation's build context with paths into the old source tree moved to the new one (`buildctx_carried`).
- `GET /api/e/<id>/diff?against=<base evaluation id>` → `{"diff": {"base", "head", "counts": {"kept", "new", "gone",
  "how": {"fingerprint", "anchor", "moved"}, "dispositions_to_reuse"}, "kept": [...], "new": [...], "gone": [...],
  "truncated_to": 200}}`. Kept rows carry the base's `base_pv_id`, `base_status`, `base_note`.

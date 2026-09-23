"""Extract a draft profile from the uploaded ST and test plan (a background GPU job).

Matching runs first and always; the model pass runs when the pinned model is
reachable and fills in what matching cannot see.  If the model is down, the
draft carries only matched items and says so -- the evaluator can still edit
and confirm it by hand.  Each chunk is one background request through the
broker: when the conversation needs the GPU the request is preempted and the
same chunk is asked again once the GPU is quiet.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..core.cancel import CancellationToken
from ..core.tomlw import dumps
from ..errors import UserError
from ..evidence.workspace import Workspace, _atomic
from ..model.broker import BACKGROUND, Broker, Preempted
from ..model.client import CancelToken, ModelError
from ..model.evaluation import client_for
from ..persist import json_bytes
from ..sesip import active
from ..sesip.documents import Page, extract
from ..sesip.extract import (
    ST_SCHEMA,
    Extraction,
    deterministic,
    merge,
    model_pass,
    unverified,
)
from ..settings import Settings

ROLES = ("security_target", "test_plan")
MAX_PREEMPTIONS = 20


def guess_role(name: str) -> str:
    lower = name.lower()
    if any(word in lower for word in ("tp", "test_plan", "test plan", "testplan", "ava")):
        return "test_plan"
    return "security_target"


def documents(workspace: Workspace) -> list[dict[str, Any]]:
    """The latest upload per role."""
    latest: dict[str, dict[str, Any]] = {}
    for record in workspace.ledger.of("document_added"):
        latest[record.get("role") or guess_role(record["name"])] = record
    return [latest[role] for role in ROLES if role in latest]


def run(workspace: Workspace, settings: Settings, broker: Broker, *, token: CancellationToken,
        progress: Callable[[str], None]) -> dict[str, Any]:
    docs = documents(workspace)
    if not docs:
        raise UserError("upload the Security Target and/or the test plan first")
    pages: dict[str, list[Page]] = {}
    for doc in docs:
        path = workspace.root / "docs" / f"{doc['sha256']}.{doc.get('doc_kind', 'pdf')}"
        progress(f"reading {doc['name']}")
        extracted = extract(path)
        _atomic(path.with_suffix(".pages.json"), json_bytes([p.as_dict() for p in extracted]))
        pages[doc.get("role") or guess_role(doc["name"])] = extracted
    matched = deterministic(pages.get("security_target"), pages.get("test_plan"))
    progress(f"matched {len(matched.sfr)} SFRs, {len(matched.level)} levels, {len(matched.category)} categories")
    found = Extraction()
    if pages.get("security_target"):
        try:
            found = model_pass(pages["security_target"], _asker(workspace, settings, broker, token), progress=progress)
        except (ModelError, UserError) as error:
            found.problems.append(f"the model pass did not run ({error}); only matched items are in the draft")
    merged = merge(matched, found)
    listed = [{"role": d.get("role") or guess_role(d["name"]), "file": d["name"], "sha256": d["sha256"]} for d in docs]
    profile = active.save_draft(workspace, dumps(merged.profile(listed)))
    report = {"version": profile.name, "unverified": unverified(merged), "problems": merged.problems,
              "sfr": len(merged.sfr), "levels": len(merged.level), "categories": len(merged.category),
              "toe_modules": len(merged.toe_module), "tsfi": len(merged.tsfi)}
    workspace.ledger.append("profile_extracted", **report)
    progress(f"draft {profile.name}: {report['sfr']} SFRs, {len(report['unverified'])} unverified items")
    return report


def _asker(workspace: Workspace, settings: Settings, broker: Broker, token: CancellationToken) -> Callable[[str], str]:
    client = client_for(workspace, settings)
    stop = CancelToken()
    fmt = {"type": "json_schema", "json_schema": {"name": "st_facts", "schema": ST_SCHEMA, "strict": True}}

    def ask(prompt: str) -> str:
        for _ in range(MAX_PREEMPTIONS):
            if token.is_cancelled():
                stop.cancel("stopped")
            try:
                reply = broker.chat(client, BACKGROUND, stop=stop, messages=[{"role": "user", "content": prompt}],
                                    max_tokens=1500, response_format=fmt, timeout=600, purpose="extract")
                return reply.text
            except Preempted:
                continue
        raise ModelError("PREEMPTED", "the conversation kept the GPU busy; extraction gave up for now")
    return ask


def pages_of(workspace: Workspace, doc: dict[str, Any]) -> list[Page]:
    path = workspace.root / "docs" / f"{doc['sha256']}.pages.json"
    return [Page(**item) for item in json.loads(Path(path).read_text(encoding="utf-8"))]

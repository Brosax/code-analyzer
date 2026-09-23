"""Which profile an evaluation uses right now, and how that changes.

The ledger records every change as ``profile_selected``:

* a builtin by name (read-only; its rules as shipped, proposed ones inert);
* a saved TOML, which becomes the next immutable ``profile/profile.vN.toml`` as a
  **draft**;
* ``confirm``: a human confirms the current profile.  A builtin is copied in
  first.  Confirming stamps every ``proposed`` rule as ``evaluator-rule`` with
  who and when -- the analyst reviewed them on the profile page -- and marks
  the version ``confirmed``.  Only a human request reaches this function; the
  model's ``profile_edit`` tool can change a draft, never confirm one.
"""
from __future__ import annotations

import tomllib
from typing import Any

from ..core.tomlw import dumps
from ..errors import UserError
from ..evidence.workspace import Workspace, utc_now
from .profile import BUILTINS, Profile, load_profile, parse_profile


def active_profile(workspace: Workspace) -> Profile:
    records = workspace.ledger.of("profile_selected")
    if not records:
        return load_profile("rt700-tp-v1.1")
    last = records[-1]
    if last.get("source") == "version":
        return parse_profile(workspace.version_text("profile", int(last["version"])), name=f"v{last['version']}")
    return load_profile(str(last["name"]))


def select_builtin(workspace: Workspace, name: str) -> Profile:
    if name not in BUILTINS:
        raise UserError(f"unknown built-in profile {name!r}; known: {', '.join(BUILTINS)}")
    profile = load_profile(name)
    workspace.ledger.append("profile_selected", name=name, sha256=profile.sha256, status=profile.status,
                            source="builtin")
    return profile


def save_draft(workspace: Workspace, text: str) -> Profile:
    data = _draft_data(text)
    profile = parse_profile(dumps(data), name="draft")
    number, sha = workspace.save_version("profile", profile.text)
    workspace.ledger.append("profile_selected", name=f"v{number}", sha256=sha, status="draft", source="version",
                            version=number)
    return parse_profile(profile.text, name=f"v{number}")


def confirm(workspace: Workspace, by: str) -> Profile:
    by = by.strip()
    if not by:
        raise UserError("confirming a profile needs the analyst's name")
    current = active_profile(workspace)
    if current.status == "confirmed":
        return current
    data = tomllib.loads(current.text)
    now = utc_now()
    evaluation = data.setdefault("evaluation", {})
    base = evaluation.get("id") if current.status == "builtin" else evaluation.get("base", "draft")
    evaluation.update({"status": "confirmed", "confirmed_by": by, "confirmed_at": now, "base": base or "draft"})
    for rule in data.get("grading_rule", []) + data.get("category_rule", []):
        if rule.get("basis") == "proposed":
            rule.update({"basis": "evaluator-rule", "by": by, "at": now})
    confirmed = parse_profile(dumps(data), name="confirmed")
    number, sha = workspace.save_version("profile", confirmed.text)
    workspace.ledger.append("profile_selected", name=f"v{number}", sha256=sha, status="confirmed", source="version",
                            version=number, by=by)
    return parse_profile(confirmed.text, name=f"v{number}")


def view(profile: Profile) -> dict[str, Any]:
    data = profile.data
    return {
        "name": profile.name, "status": profile.status, "sha256": profile.sha256, "text": profile.text,
        "sfr": [{"id": s["id"], "title": s.get("title") or s.get("catalogue", "")} for s in data.get("sfr", [])],
        "levels": [{k: level.get(k) for k in ("id", "label", "rank", "description")} for level in profile.levels],
        "toe_modules": [{"id": m["id"], "paths": m.get("paths", [])} for m in data.get("toe_module", [])],
        "excludes": [{"paths": e.get("paths", []), "reason": e.get("reason", "")} for e in data.get("exclude", [])],
        "grading_rules": [{"match": r.get("match", {}), "level": r.get("level"), "basis": r.get("basis")}
                          for r in data.get("grading_rule", [])],
    }


def _draft_data(text: str) -> dict[str, Any]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise UserError(f"profile: {error}") from error
    evaluation = data.setdefault("evaluation", {})
    if evaluation.get("status") in ("confirmed", "builtin"):
        evaluation["status"] = "draft"  # only confirm() may confirm
    evaluation.pop("confirmed_by", None)
    evaluation.pop("confirmed_at", None)
    for rule in data.get("grading_rule", []) + data.get("category_rule", []):
        if rule.get("basis") == "evaluator-rule" and not rule.get("by"):
            rule["basis"] = "proposed"
    return data

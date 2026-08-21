"""One scanner session over one scan unit, and the evidence it leaves behind.

The evidence equivalent of a single completion is one response; the evidence
equivalent of an agent loop is the whole event stream, so events.jsonl is
persisted alongside the request, the response and the parsed findings.  Volatile
values -- durations, counters, cache state -- live in meta.json alone, so that
findings.json stays byte-identical for identical model output.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Callable

from ..errors import UserError
from ..persist import write_json
from ..tools.common import attach_artifacts
from .runtime import (
    HarnessRunFailed,
    HarnessRuntime,
    RunOutcome,
    finish_status,
    redact_credential,
    request_description,
)
from .schema import SCHEMA_VERSION, parse_findings, response_unparsed, schema_hash

SESSIONS_ROOT = ("llm", "sessions")

# request.json answers one question: which of the operator's [llm] knobs
# actually reached the scan, and through which channel.  The pinned SDK takes
# provider/model/max_tokens/cwd/timeouts/cordis and nothing else (design
# appendix A3), so each knob is filed under the gate that really applies it and
# the ones no channel carries are named as such instead of being listed beside
# the ones that work.
TRANSMITTED_KEYS: tuple[str, ...] = ("max_completion_tokens",)
LOCAL_KEYS: tuple[str, ...] = ("max_steps", "max_turns", "request_timeout_seconds")
CORDIS_KEYS: tuple[str, ...] = ("context_window",)
UNAPPLIED_KEYS: tuple[str, ...] = ("temperature", "top_p", "seed")

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def unit_directory(run_dir: Path, producer: str, unit_id: str) -> Path:
    """Evidence directory for one (producer, unit) pair."""
    return Path(run_dir).joinpath(*SESSIONS_ROOT, _safe(producer, "producer"), _safe(unit_id, "unit id"))


def run_unit(
    runtime: HarnessRuntime,
    *,
    run_dir: Path,
    producer: str,
    unit_id: str,
    prompt: str | list[dict[str, Any]],
    unit_sha256: str,
    skill_version: str,
    input_files: list[str] | None = None,
    settings: dict[str, Any] | None = None,
    session_id: str | None = None,
    cache: dict[str, Any] | None = None,
    cancelled: Callable[[], bool] | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Run one scanner over one unit and persist its four evidence files.

    Returns a unit record shaped like the ones the native adapters produce, so
    the same status algebra, coverage accounting and artifact index apply.
    """
    active = settings if settings is not None else runtime.settings
    directory = unit_directory(run_dir, producer, unit_id)
    directory.mkdir(parents=True, exist_ok=True)
    write_json(
        directory / "request.json",
        _request(active, producer, unit_id, unit_sha256, skill_version, prompt),
    )

    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    outcome: RunOutcome | None = None
    status = "failed"
    reason: str | None = None
    if cancelled is not None and cancelled():
        status, reason = "interrupted", "run interrupted"
    else:
        try:
            outcome = runtime.run(prompt, session_id=session_id, on_event=on_event)
        except HarnessRunFailed as exc:
            status, reason = exc.outcome, exc.reason

    findings: list[dict[str, Any]] = []
    malformed: list[str] = []
    valid = False
    if outcome is not None:
        findings, malformed = parse_findings(outcome.final_response)
        valid = not response_unparsed(malformed)
        status = finish_status(outcome.finish_reason, valid)
        if not valid:
            reason = malformed[0] if malformed else "scanner produced no parsable report"
        elif malformed:
            reason = f"{len(malformed)} malformed finding(s) dropped"

    # Everything below is persisted evidence that rebuild-dashboard and
    # recover-report re-derive the review from, so the credential is stripped
    # here rather than only on the way into a shareable archive.
    findings = redact_credential(findings, active)
    malformed = redact_credential(malformed, active)
    reason = redact_credential(reason, active)
    write_json(
        directory / "response.json",
        redact_credential({
            "final_response": outcome.final_response if outcome else "",
            "finish_reason": outcome.finish_reason if outcome else "",
            "notifications": outcome.notifications if outcome else [],
        }, active),
    )
    _write_events(directory / "events.jsonl", outcome.events if outcome else [])
    write_json(
        directory / "findings.json",
        {
            "producer": producer,
            "unit_id": unit_id,
            "schema_version": SCHEMA_VERSION,
            "valid_report": valid,
            "findings": findings,
            "malformed": malformed,
        },
    )
    write_json(
        directory / "meta.json",
        _meta(producer, unit_id, status, started_at, outcome, findings, malformed, cache),
    )

    unit: dict[str, Any] = {
        "id": unit_id,
        "producer": producer,
        "status": status,
        "input_files": list(input_files or []),
        "valid_report": valid,
        "reason": reason,
        "evidence_context": "source-only",
        "finish_reason": outcome.finish_reason if outcome else "",
        "finding_count": len(findings),
        "malformed_count": len(malformed),
    }
    attach_artifacts(unit, directory, run_dir)
    return unit


def _request(
    settings: dict[str, Any],
    producer: str,
    unit_id: str,
    unit_sha256: str,
    skill_version: str,
    prompt: str | list[dict[str, Any]],
) -> dict[str, Any]:
    """Everything that influences the result, and no credential.

    The unit payload itself lives in llm/units/<unit_id>.json, so only its
    digest is repeated here.
    """
    return {
        **request_description(settings),
        "producer": producer,
        "unit_id": unit_id,
        "unit_sha256": str(unit_sha256),
        "skill": producer,
        "skill_version": str(skill_version),
        "prompt_sha256": hashlib.sha256(_prompt_text(prompt).encode("utf-8")).hexdigest(),
        "output_schema": {
            "version": SCHEMA_VERSION,
            "sha256": schema_hash(),
            # The Python SDK exposes no outputSchema channel, so this schema is
            # what the parser enforces, not something the provider was asked for.
            "enforced_by": "parser",
        },
        "parameters": {
            "transmitted": _knobs(settings, TRANSMITTED_KEYS),
            "enforced_locally": _knobs(settings, LOCAL_KEYS),
            "declared_in_cordis": _knobs(settings, CORDIS_KEYS),
            "requested_but_not_applied": _knobs(settings, UNAPPLIED_KEYS),
        },
    }


def _knobs(settings: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {key: settings[key] for key in keys if settings.get(key) is not None}


def _meta(
    producer: str,
    unit_id: str,
    status: str,
    started_at: str,
    outcome: RunOutcome | None,
    findings: list[dict[str, Any]],
    malformed: list[str],
    cache: dict[str, Any] | None,
) -> dict[str, Any]:
    events = outcome.events if outcome else []
    return {
        "producer": producer,
        "unit_id": unit_id,
        "status": status,
        "started_at": started_at,
        "duration_seconds": round(outcome.duration_seconds, 3) if outcome else 0.0,
        "session_id": outcome.session_id if outcome else "",
        "finish_reason": outcome.finish_reason if outcome else "",
        "event_count": len(events),
        "tool_call_count": _tool_calls(events),
        "notification_count": len(outcome.notifications) if outcome else 0,
        "finding_count": len(findings),
        "malformed_count": len(malformed),
        "cache": {
            "hit": bool((cache or {}).get("hit", False)),
            "key": str((cache or {}).get("key", "")),
            "source_run": (cache or {}).get("source_run"),
        },
    }


def _write_events(path: Path, events: list[dict[str, Any]]) -> None:
    """One JSON object per line.

    JSON Lines is not a JSON document, so persist.json_bytes cannot encode it;
    the same encoder settings keep the bytes stable all the same.
    """
    lines = [
        json.dumps(event if isinstance(event, dict) else {"value": event}, sort_keys=True, ensure_ascii=False) + "\n"
        for event in events
    ]
    path.write_bytes("".join(lines).encode("utf-8"))


def _tool_calls(events: list[dict[str, Any]]) -> int:
    return sum("tool" in str(event.get("type", "")).lower() for event in events if isinstance(event, dict))


def _prompt_text(prompt: str | list[dict[str, Any]]) -> str:
    if isinstance(prompt, str):
        return prompt
    return json.dumps(prompt, sort_keys=True, ensure_ascii=False)


def _safe(value: str, label: str) -> str:
    text = str(value)
    if not _SAFE_NAME.match(text) or ".." in text:
        raise UserError(f"invalid {label} for an evidence path: {value!r}")
    return text

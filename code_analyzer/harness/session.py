"""One agent session over one subject, and the evidence it leaves behind.

The evidence equivalent of a single completion is one response; the evidence
equivalent of an agent loop is the whole event stream, so events.jsonl is
persisted alongside the request, the response and the parsed result.  Volatile
values -- durations, counters, cache state -- live in meta.json alone, so that
findings.json (a scanner over a unit) and verdict.json (the validator over a
candidate) stay byte-identical for identical model output.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
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
    measured_usage,
    provider_failure,
    redact_credential,
    request_description,
    timeline,
)
from .schema import SCHEMA_VERSION, parse_findings, response_unparsed, schema_hash
from .verdict import VERDICT_SCHEMA_VERSION, parse_verdict, verdict_schema_hash

SESSIONS_ROOT = ("llm", "sessions")
VERDICT_FILENAME = "verdict.json"

# request.json answers one question: which of the operator's [llm] knobs
# actually reached the scan, and through which channel.  The pinned SDK takes
# provider/model/max_tokens/cwd/timeouts/cordis and nothing else (design
# appendix A3), so each knob is filed under the gate that really applies it and
# the ones no channel carries are named as such instead of being listed beside
# the ones that work.
TRANSMITTED_KEYS: tuple[str, ...] = ("max_completion_tokens", "request_timeout_seconds")
LOCAL_KEYS: tuple[str, ...] = ("max_steps", "max_turns")
CORDIS_KEYS: tuple[str, ...] = ("context_window",)
UNAPPLIED_KEYS: tuple[str, ...] = ("temperature", "top_p", "seed")

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def unit_directory(run_dir: Path, producer: str, unit_id: str, round_index: int = 0) -> Path:
    """Evidence directory for one (producer, unit) pair in one round.

    Round 0 keeps the historical path exactly.  ``unit_id`` deliberately carries
    no risk tier, so a later round re-scanning the same unit with the same
    producer would otherwise overwrite the blind first-pass evidence that the
    llm-only metrics are counted from -- the second pass is a different
    observation and gets its own directory.
    """
    base = Path(run_dir).joinpath(*SESSIONS_ROOT, _safe(producer, "producer"), _safe(unit_id, "unit id"))
    return base if round_index <= 0 else base / f"r{int(round_index)}"


def resync_meta_status(directory: Path, status: str, reason: str) -> None:
    """Re-file meta.json after a caller demotes the unit it describes.

    run_unit persists meta.json before the scanner can reclassify a provider
    stop, so without this the per-unit evidence and the manifest report
    different words for the same unit -- and an offline auditor reads the
    evidence, not the manifest.  Missing or unreadable meta is not worth
    failing a run over; the manifest remains authoritative.
    """
    path = Path(directory) / "meta.json"
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(meta, dict) or meta.get("status") == status:
        return
    meta["status"] = status
    meta["reason"] = reason
    write_json(path, meta)


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
    round_index: int = 0,
) -> dict[str, Any]:
    """Run one scanner over one unit and persist its four evidence files.

    Returns a unit record shaped like the ones the native adapters produce, so
    the same status algebra, coverage accounting and artifact index apply.
    """
    return _run_session(
        runtime,
        directory=unit_directory(run_dir, producer, unit_id, round_index),
        run_dir=run_dir,
        producer=producer,
        subject={"unit_id": unit_id},
        prompt=prompt,
        unit_sha256=unit_sha256,
        skill_version=skill_version,
        schema={"version": SCHEMA_VERSION, "sha256": schema_hash()},
        parse=_parse_report,
        result_file="findings.json",
        input_files=input_files,
        settings=settings,
        session_id=session_id,
        cache=cache,
        cancelled=cancelled,
        on_event=on_event,
    )


def run_candidate(
    runtime: HarnessRuntime,
    *,
    run_dir: Path,
    producer: str,
    candidate_id: str,
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
    """Run the validator over one candidate with the same evidence discipline.

    verdict.json takes the place of findings.json: it holds either the parsed
    verdict or the reason the response was rejected, so an auditor can tell a
    model that said nothing from one that said something unusable.
    """
    return _run_session(
        runtime,
        directory=unit_directory(run_dir, producer, candidate_id),
        run_dir=run_dir,
        producer=producer,
        subject={"candidate_id": candidate_id},
        prompt=prompt,
        unit_sha256=unit_sha256,
        skill_version=skill_version,
        schema={"version": VERDICT_SCHEMA_VERSION, "sha256": verdict_schema_hash()},
        parse=lambda text: _parse_verdict(text, candidate_id),
        result_file=VERDICT_FILENAME,
        input_files=input_files,
        settings=settings,
        session_id=session_id,
        cache=cache,
        cancelled=cancelled,
        on_event=on_event,
    )


@dataclass(frozen=True)
class _Parsed:
    """What one response reduced to: the result file body and its record counts."""

    valid: bool
    reason: str | None
    result: dict[str, Any]
    counts: dict[str, int]
    # Returned to the caller but never persisted twice: the result file
    # already holds it.
    record: dict[str, Any]


def _parse_report(text: str | None) -> _Parsed:
    """``None`` is a session that produced no response at all, not an empty one."""
    findings: list[dict[str, Any]] = []
    malformed: list[str] = []
    valid = False
    reason = None
    if text is not None:
        findings, malformed = parse_findings(text)
        valid = not response_unparsed(malformed)
        if not valid:
            reason = malformed[0] if malformed else "scanner produced no parsable report"
        elif malformed:
            reason = f"{len(malformed)} malformed finding(s) dropped"
    return _Parsed(
        valid, reason, {"findings": findings, "malformed": malformed},
        {"finding_count": len(findings), "malformed_count": len(malformed)},
        # Tallies, not text.  A re-planning round is allowed to see how a unit
        # came out but never what a finding said about untrusted source, and
        # the mix per unit is worth having in the manifest anyway.
        {"finding_mix": _mix(findings)},
    )


def _mix(findings: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    categories: dict[str, int] = {}
    severities: dict[str, int] = {}
    for item in findings:
        for table, key in ((categories, "category"), (severities, "severity")):
            name = str(item.get(key) or "unknown")
            table[name] = table.get(name, 0) + 1
    return {"categories": dict(sorted(categories.items())), "severities": dict(sorted(severities.items()))}


def _parse_verdict(text: str | None, candidate_id: str) -> _Parsed:
    verdict, reason = (None, None) if text is None else parse_verdict(text, candidate_id=candidate_id)
    return _Parsed(
        verdict is not None, reason, {"verdict": verdict, "rejected": reason},
        {"verdict_count": int(verdict is not None)}, {"verdict": verdict},
    )


def _run_session(
    runtime: HarnessRuntime,
    *,
    directory: Path,
    run_dir: Path,
    producer: str,
    subject: dict[str, str],
    prompt: str | list[dict[str, Any]],
    unit_sha256: str,
    skill_version: str,
    schema: dict[str, Any],
    parse: Callable[[str | None], _Parsed],
    result_file: str,
    input_files: list[str] | None,
    settings: dict[str, Any] | None,
    session_id: str | None,
    cache: dict[str, Any] | None,
    cancelled: Callable[[], bool] | None,
    on_event: Callable[[dict[str, Any]], None] | None,
) -> dict[str, Any]:
    active = settings if settings is not None else runtime.settings
    directory.mkdir(parents=True, exist_ok=True)
    write_json(
        directory / "request.json",
        _request(active, producer, subject, unit_sha256, skill_version, prompt, schema),
    )

    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    outcome: RunOutcome | None = None
    status = "failed"
    reason: str | None = None
    # What the runtime reported before it stopped, when it stopped early.  The
    # session that hit a ceiling is the one that spent the most tokens; its
    # stream is worth persisting and measuring precisely because it failed.
    partial: list[dict[str, Any]] = []
    if cancelled is not None and cancelled():
        status, reason = "interrupted", "run interrupted"
    else:
        try:
            outcome = runtime.run(prompt, session_id=session_id, on_event=on_event)
        except HarnessRunFailed as exc:
            status, reason = exc.outcome, exc.reason
            partial = list(exc.events)

    parsed = parse(None if outcome is None else outcome.final_response)
    failure = provider_failure(outcome.events, outcome.notifications) if outcome is not None else None
    failure_class: str | None = None
    if outcome is not None:
        status = finish_status(outcome.finish_reason, parsed.valid)
        reason = parsed.reason
        if str(outcome.finish_reason or "").strip().lower() == "error" and failure is not None:
            # The provider's own account beats "response: empty response":
            # nothing reached the model, and the reason should say so.
            status = "failed"
            reason = (
                f"provider {failure['code']}: {failure['message']} "
                f"({failure['requests']} requests, {failure['retries']} retries)"
            )
            failure_class = failure["class"]
        elif status == "timed_out":
            failure_class = "timeout"
        elif not parsed.valid:
            failure_class = "parse"
    elif status == "timed_out":
        failure_class = "timeout"
    elif status == "failed":
        failure_class = "ceiling" if "ceiling" in str(reason or "") else "provider"

    # Everything below is persisted evidence that rebuild-dashboard and
    # recover-report re-derive the review from, so the credential is stripped
    # here rather than only on the way into a shareable archive.
    result = redact_credential(parsed.result, active)
    reason = redact_credential(reason, active)
    failure = redact_credential(failure, active) if failure is not None else None
    write_json(
        directory / "response.json",
        redact_credential({
            "final_response": outcome.final_response if outcome else "",
            "finish_reason": outcome.finish_reason if outcome else "",
            "notifications": outcome.notifications if outcome else [],
        }, active),
    )
    # Redacted like every other write in this block.  A provider that answers
    # 401 with the request headers echoed puts the key in an event, and the
    # cross-run cache copies this file outside the run directory entirely.
    _write_events(directory / "events.jsonl", redact_credential(outcome.events if outcome else partial, active))
    write_json(
        directory / result_file,
        {
            "producer": producer,
            **subject,
            "schema_version": schema["version"],
            "valid_report": parsed.valid,
            **result,
        },
    )
    write_json(
        directory / "meta.json",
        _meta(producer, subject, status, started_at, outcome, parsed.counts, cache, partial, failure=failure),
    )

    record: dict[str, Any] = {
        "id": next(iter(subject.values())),
        "producer": producer,
        "status": status,
        "input_files": list(input_files or []),
        "valid_report": parsed.valid,
        "reason": reason,
        "evidence_context": "source-only",
        "finish_reason": outcome.finish_reason if outcome else "",
        "usage_measured": measured_usage(outcome.events if outcome else partial),
        "duration_seconds": round(outcome.duration_seconds, 3) if outcome else None,
        "failure_class": failure_class,
        "provider_failure": failure,
        "cache": {"hit": bool((cache or {}).get("hit", False)), "source_run": (cache or {}).get("source_run")},
        **parsed.counts,
        **redact_credential(parsed.record, active),
    }
    attach_artifacts(record, directory, run_dir)
    return record


def _request(
    settings: dict[str, Any],
    producer: str,
    subject: dict[str, str],
    unit_sha256: str,
    skill_version: str,
    prompt: str | list[dict[str, Any]],
    schema: dict[str, Any],
) -> dict[str, Any]:
    """Everything that influences the result, and no credential.

    The unit payload itself lives in llm/units/<unit_id>.json, so only its
    digest is repeated here.
    """
    return {
        **request_description(settings),
        "producer": producer,
        **subject,
        "unit_sha256": str(unit_sha256),
        "skill": producer,
        "skill_version": str(skill_version),
        "prompt_sha256": hashlib.sha256(_prompt_text(prompt).encode("utf-8")).hexdigest(),
        "output_schema": {
            **schema,
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
    subject: dict[str, str],
    status: str,
    started_at: str,
    outcome: RunOutcome | None,
    counts: dict[str, int],
    cache: dict[str, Any] | None,
    partial: list[dict[str, Any]] | None = None,
    *,
    failure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    events = outcome.events if outcome else list(partial or [])
    return {
        "producer": producer,
        **subject,
        "status": status,
        "started_at": started_at,
        "duration_seconds": round(outcome.duration_seconds, 3) if outcome else 0.0,
        "session_id": outcome.session_id if outcome else "",
        "finish_reason": outcome.finish_reason if outcome else "",
        "event_count": len(events),
        "tool_call_count": _tool_calls(events),
        "notification_count": len(outcome.notifications) if outcome else 0,
        "usage_measured": measured_usage(events),
        # The provider's own account of a failed session, and the session's
        # steps in order: what an auditor wants first, kept in the file that
        # already holds the volatile facts so the evidence set stays five files.
        "provider_failure": failure,
        "timeline": timeline(events),
        **counts,
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

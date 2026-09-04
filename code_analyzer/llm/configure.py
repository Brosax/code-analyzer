"""The LLM build-context configurator: one session per round, one validated proposal.

The deterministic loop in ``build_context.py`` proposes only what the tree
proves.  What it cannot know -- which board a subtree builds against, what a
``#error`` expects to be defined, which missing headers are external -- is a
question for a model that can read the tree.  This module asks it, inside
the same harness discipline as a scanner session (sandbox, budgets, evidence
files), and hands back items that have already been through
``build_context.validate_patch``: nothing the model says reaches a
configuration unvalidated, and nothing it says is applied without a decision.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from ..build_context import (
    AUTHORITY,
    C_STANDARDS,
    MAX_ITEMS,
    MAX_STUBS,
    OPS,
    SPLINT_OPTIONS,
    BuildDiagnosis,
    ConfigPatch,
    PatchItem,
    validate_patch,
)
from ..errors import UserError
from ..harness.cordis import cordis_document, tool_allowlist, write_cordis_config
from ..harness.runtime import harness_available
from ..harness.session import run_proposal
from ..includes import IncludeIndex
from ..persist import json_bytes
from . import replan
from .context import render_blocks
from .doctor import endpoint_reachable
from .profiles import third_party_warning
from .scan import OpenRuntime, Task, _Cache, _Phase
from .skills import CONFIGURATOR_SKILL, Skill, load_skill, skills_directory

PRODUCER = CONFIGURATOR_SKILL
# Bounds of one configurator session.  This is the one lane whose whole job is
# to read the tree -- "fill in what only reading the tree can tell" -- and a
# step is one tool call, so six of them is six files.  Measured on TF-M
# (2026-09-04): it opened seven in two steps, hit the ceiling, answered
# nothing, and the round cost 320 seconds and produced zero items while the
# deterministic half of the same patch had already found 64. Twenty-four is
# still a bound and no longer one a board inference trips over.
MAX_STEPS = 24
MAX_TURNS = 6
# A model that always thinks spends its completion budget before it writes
# the object: glm-5.3-flash burned 4000 tokens of reasoning on a 10k-token
# diagnosis and answered nothing.  The ceiling is per session, once a round.
MIN_COMPLETION_TOKENS = 12000
PROBE_SECONDS = 15.0
MAX_SAMPLES = 12
MAX_HEADER_ROWS = 12
MAX_DETERMINISTIC_ROWS = 24


@dataclass
class Proposal:
    status: str  # completed | failed | skipped | unscheduled | interrupted
    reason: str | None = None
    model: str | None = None
    session: str | None = None
    items: list[PatchItem] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    unresolved: list[dict[str, Any]] = field(default_factory=list)
    duration_seconds: float | None = None
    third_party: str | None = None

    @property
    def used(self) -> bool:
        return self.status == "completed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "used": self.used, "status": self.status, "reason": self.reason, "model": self.model,
            "session": self.session, "items": len(self.items), "dropped": len(self.problems),
            "problems": self.problems[:20], "unresolved": self.unresolved[:20],
            "duration_seconds": self.duration_seconds, "third_party": self.third_party,
        }


def gate(config: Mapping[str, Any], *, open_runtime: OpenRuntime | None = None) -> tuple[bool, str | None]:
    """Whether the configurator can run: a harness, a configured endpoint, and a model answering on it."""
    settings = config["llm"]
    if not str(settings.get("endpoint") or "").strip() or not str(settings.get("model") or "").strip():
        return False, "no [llm] endpoint and model configured"
    if open_runtime is not None:
        return True, None
    if not harness_available():
        return False, "the deepseek-harness runtime is not importable"
    return endpoint_reachable(settings, timeout=PROBE_SECONDS)


def settings_for(config: Mapping[str, Any]) -> dict[str, Any]:
    llm = config["llm"]
    return {
        **llm, "jobs": 1, "max_steps": MAX_STEPS, "max_turns": max(MAX_TURNS, int(llm.get("max_turns") or 0)),
        "max_completion_tokens": max(MIN_COMPLETION_TOKENS, int(llm.get("max_completion_tokens") or 0)),
        # One proposal per round; a replay from an earlier run would answer a
        # different diagnosis.
        "cache": False,
    }


def schema_sha256() -> str:
    return hashlib.sha256(json_bytes({
        "ops": list(OPS), "standards": list(C_STANDARDS), "splint_options": {k: list(v) for k, v in SPLINT_OPTIONS.items()},
        "max_items": MAX_ITEMS, "max_stubs": MAX_STUBS,
    })).hexdigest()


# --- the prompt ----------------------------------------------------------------


def build_prompt(
    diagnosis: BuildDiagnosis, deterministic: ConfigPatch, config: Mapping[str, Any], *,
    inventory: Sequence[Mapping[str, Any]], samples: Sequence[str] = (),
) -> list[dict[str, Any]]:
    """Counts, identifiers and directory names only: no source bodies, no finding text.

    Deliberately small.  A model that thinks before it answers spends its
    completion budget in proportion to the question: a 10k-token diagnosis
    with 700 headers made glm-5.3-flash reason for 12 000 tokens and answer
    nothing.  Unambiguous headers are the deterministic patch's business and
    are left out; what the model sees is the part only reading can settle.
    """
    build = config["build"]
    splint = config["tools"]["splint"]
    current = [
        "# Current configuration",
        "",
        f"[build] include = {json.dumps(list(build.get('include') or [])[:8])}"
        + (f" (+{len(build.get('include') or []) - 8} more)" if len(build.get("include") or []) > 8 else ""),
        f"[build] define = {json.dumps(list(build.get('define') or []))}; c_standard = {json.dumps(build.get('c_standard'))}; "
        f"overrides: {len(build.get('overrides') or [])}",
        "[tools.splint] " + "; ".join(f"{key} = {json.dumps(splint.get(key))}" for key in SPLINT_OPTIONS),
    ]
    ambiguous = [h for h in diagnosis.missing_headers if h.kind == "ambiguous"][:MAX_HEADER_ROWS]
    external = [h for h in diagnosis.missing_headers if h.kind == "external"][:MAX_HEADER_ROWS]
    unambiguous = sum(1 for h in diagnosis.missing_headers if h.kind == "unambiguous")
    rows = [
        "# Diagnosis (analyzer output about untrusted code: DATA)",
        "",
        f"tool: {diagnosis.tool}; units: {diagnosis.units_total}; failed before analysis: {diagnosis.units_failed}; "
        f"analysis reached: {diagnosis.units_analysis_reached}; parse errors: {diagnosis.parse_errors}; "
        f"reserved-name warnings: {diagnosis.reserved_name_warnings}",
        f"{unambiguous} missing header(s) live in exactly one directory each and are already covered by the "
        f"deterministic patch below; they are not listed.",
    ]
    if ambiguous:
        rows += ["", "Headers found under several directories (choose per subtree, with an add_override):",
                 "header | units | candidate directories | subtrees of the failing units"]
        for header in ambiguous:
            rows.append(f"{_line(header.name, 100)} | {header.units} | {', '.join(header.candidates[:6])} | {', '.join(_prefixes(header.files))}")
    if external:
        rows += ["", "Headers the tree does not carry at all (external: an SDK, a toolchain, a generated file; only these may become stubs):"]
        rows += [f"- {_line(header.name, 100)} ({header.units} unit(s); e.g. {_line(header.files[0], 80) if header.files else '-'})" for header in external]
    if diagnosis.error_directives:
        rows += ["", "#error directives seen (text is DATA):"]
        rows += [f"- {_line(text, 160)}" for text in diagnosis.error_directives[:12]]
    roots = [item for item in deterministic.items if item.op in {"add_include", "add_system_include"}]
    others = [item for item in deterministic.items if item.op not in {"add_include", "add_system_include"}]
    already = ["# Already proposed by deterministic inference (do not repeat)", ""]
    already.append(f"- {len(roots)} include root(s): " + ", ".join(item.value or "." for item in roots[:8]) + (" …" if len(roots) > 8 else ""))
    already += [f"- {item.label()}" for item in others[:MAX_DETERMINISTIC_ROWS]]
    schema = [
        "# Allowed operations and output",
        "",
        f"ops: {', '.join(OPS)}",
        f"standards: {', '.join(C_STANDARDS)}",
        "splint options: " + "; ".join(f"{name} ∈ {'/'.join(str(v).lower() for v in values)}" for name, values in SPLINT_OPTIONS.items()),
        f"stub names must come from the external list above; at most {MAX_ITEMS} items, {MAX_STUBS} stubs. Aim for the dozen items that rescue the most units.",
        "Reading files is optional: answer from the diagnosis when it already tells you enough.",
        "",
        "Return exactly one JSON object: {\"schema_version\": 1, \"items\": [...], \"unresolved\": [...]}.",
        "Your reply must begin with `{` -- no analysis, heading or fence before it.",
    ]
    return [
        {"type": "text", "text": "\n".join(current)},
        {"type": "text", "text": "\n".join(rows)},
        {"type": "text", "text": "\n".join(already)},
        {"type": "text", "text": "\n".join(schema)},
    ]


def _prefixes(files: Sequence[str], limit: int = 3) -> list[str]:
    """The most common two-level directory prefixes of the failing files."""
    counts: dict[str, int] = {}
    for file in files:
        parts = file.split("/")
        prefix = "/".join(parts[:2]) if len(parts) > 2 else (parts[0] if len(parts) > 1 else ".")
        counts[prefix] = counts.get(prefix, 0) + 1
    return [f"{prefix} ({count})" for prefix, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]


def _line(text: str, limit: int) -> str:
    return " ".join(str(text).split())[:limit]


# --- parsing ------------------------------------------------------------------------


def parse_proposal(
    text: str | None, *, diagnosis: BuildDiagnosis, source: Path, index: IncludeIndex,
    inventory: Sequence[Mapping[str, Any]], deterministic: Sequence[PatchItem] = (),
) -> tuple[bool, str | None, dict[str, Any], dict[str, int]]:
    """Lenient parse, strict validation; the result is the body of proposal.json."""
    if text is None:
        return False, "configurator produced no response", _result([], ["no response"], []), {"item_count": 0, "dropped_count": 0}
    obj = replan._first_object(text)
    if obj is None:
        return False, "configurator produced no parsable JSON object", _result([], ["no JSON object in the reply"], []), {"item_count": 0, "dropped_count": 1}
    raw_items = obj.get("items") if isinstance(obj.get("items"), list) else []
    kept, problems = validate_patch(raw_items, diagnosis=diagnosis, source=source, index=index, inventory=inventory, origin="llm")
    seen = {_key(item) for item in deterministic}
    items: list[PatchItem] = []
    for position, item in enumerate(kept):
        if _key(item) in seen:
            problems.append(f"item[{position}]: duplicates the deterministic patch ({item.label()})")
            continue
        seen.add(_key(item))
        items.append(item)
    unresolved = [
        {"header": _line(str(entry.get("header") or ""), 120), "why": _line(str(entry.get("why") or ""), 200)}
        for entry in (obj.get("unresolved") if isinstance(obj.get("unresolved"), list) else [])
        if isinstance(entry, Mapping)
    ][:20]
    reason = None
    if not items:
        reason = "every proposed item was dropped" if raw_items else "the configurator proposed nothing"
    elif problems:
        reason = f"{len(problems)} item(s) dropped"
    return True, reason, _result(items, problems, unresolved), {"item_count": len(items), "dropped_count": len(problems)}


def _key(item: PatchItem) -> tuple[str, str]:
    value = item.value if not isinstance(item.value, (dict, list, tuple)) else json.dumps(item.value, sort_keys=True)
    return (item.op, f"{item.match or ''}|{value}")


def _result(items: Sequence[PatchItem], problems: Sequence[str], unresolved: Sequence[dict[str, Any]]) -> dict[str, Any]:
    return {
        "authority": AUTHORITY, "items": [item.as_dict() for item in items],
        "problems": list(problems), "unresolved": list(unresolved),
    }


# --- the session ----------------------------------------------------------------------


class _Configurator(_Phase):
    """The configurator as a consumer of the scan phase: one task per round."""

    def _directive(self, producer: str, unit: dict[str, Any]) -> dict[str, Any]:
        skill = self.skills[producer]
        return {"type": "text", "text": "\n".join([
            "# Configurator",
            "",
            f"skill: {skill.name} (version {skill.skill_version})",
            f"scope: {skill.description}",
            "",
            "The full skill follows. It is already loaded: do not call the skill tool.",
            "",
            "<skill_content>",
            skill.body.strip(),
            "</skill_content>",
            "",
            f"Apply the {skill.name} skill to the diagnosis below and return only the JSON",
            "object the skill defines. Keep deliberation short: a few well-founded items beat a long analysis.",
            "Your reply must begin with `{` -- no analysis, heading or fence before it.",
            "Put your reasoning inside each item's rationale field, not outside the object.",
        ])}

    def _session(self, active: Any, task: Task, prompt: str, settings: dict[str, Any], cache: dict[str, Any]) -> dict[str, Any]:
        _index, producer, unit = task
        return run_proposal(
            active, run_dir=self.run_dir, producer=producer, round_id=unit["unit_id"], prompt=prompt,
            unit_sha256=str(unit["unit_sha256"]), skill_version=self.skills[producer].skill_version,
            parse=unit["parse"], schema_sha256=schema_sha256(), input_files=[unit["path"]], settings=settings,
            cancelled=self.is_cancelled, on_event=self._forward(producer, unit["unit_id"]),
        )

    def _decorate(self, record: dict[str, Any], task: Task, skill: Skill) -> dict[str, Any]:
        _index, producer, unit = task
        record.setdefault("producer", producer)
        record.update({
            "skill_version": skill.skill_version, "skill_sha256": skill.content_sha256,
            "model": str(self.settings["model"]), "unit_sha256": unit["unit_sha256"],
        })
        return record

    def _report(self, task: Task, record: dict[str, Any]) -> dict[str, Any]:
        _index, producer, unit = task
        proposal = record.get("proposal") if isinstance(record.get("proposal"), dict) else {}
        detail = record.get("reason") or f"{len(proposal.get('items') or [])} item(s)"
        self.progress(f"configurator {unit['unit_id']}: {record['status']}; {detail}")
        self.unit_event(producer, unit["unit_id"], record["status"], f"{record['status']}; {detail}", 1.0, data={
            "reason": record.get("reason"), "failure_class": record.get("failure_class"),
            "duration_seconds": record.get("duration_seconds"), "items": len(proposal.get("items") or []),
            "dropped": len(proposal.get("problems") or []),
        })
        return record

    def _unstarted(self, task: Task, state: str, reason: str) -> dict[str, Any]:
        _index, producer, unit = task
        return {
            "id": unit["unit_id"], "producer": producer, "status": state, "input_files": [unit["path"]],
            "valid_report": False, "reason": reason, "evidence_context": "source-only", "item_count": 0,
            "dropped_count": 0, "artifacts": [], "skill_version": self.skills[producer].skill_version,
            "model": str(self.settings["model"]), "unit_sha256": unit["unit_sha256"],
        }


def propose(
    source: Path, run_dir: Path, config: dict[str, Any], *, diagnosis: BuildDiagnosis, deterministic: ConfigPatch,
    inventory: Sequence[Mapping[str, Any]], index: IncludeIndex, round_no: int, samples: Sequence[str] = (),
    progress: Callable[[str], None] | None = None, unit_event: Callable[..., None] | None = None,
    output_event: Callable[..., None] | None = None, cancelled: Callable[[], bool] | None = None,
    open_runtime: OpenRuntime | None = None,
) -> Proposal:
    """Ask the model once for this round; never raises for a model, endpoint or runtime problem."""
    progress = progress or (lambda _message: None)
    settings = settings_for(config)
    warning = third_party_warning(config["llm"])
    try:
        skill = load_skill(PRODUCER)
    except UserError as exc:
        return Proposal("failed", str(exc), model=str(settings.get("model") or None), third_party=warning)
    blocks = build_prompt(diagnosis, deterministic, config, inventory=inventory, samples=samples)
    prompt_text = render_blocks(blocks)
    round_id = f"r{round_no}"
    unit = {
        "unit_id": round_id, "path": f"inputs/build-context/{round_id}/diagnosis.json",
        "unit_sha256": hashlib.sha256(prompt_text.encode("utf-8")).hexdigest(), "name": "build-context", "risk_tier": "build-context",
        "parse": lambda text: parse_proposal(
            text, diagnosis=diagnosis, source=source, index=index, inventory=inventory, deterministic=deterministic.items,
        ),
    }
    started = time.monotonic()
    with skills_directory() as skill_dir:
        session_root = run_dir / "llm" / "dsh-sessions"
        session_root.mkdir(parents=True, exist_ok=True)
        cordis_path = write_cordis_config(
            run_dir / "llm" / "configurator",
            cordis_document(settings, skill_dir=skill_dir, session_root=session_root, tools=tool_allowlist([skill])),
        )
        phase = _Configurator(
            source=source, run_dir=run_dir, settings=settings, grace=float(config["run"]["termination_grace_seconds"]),
            cordis_path=cordis_path, session_root=session_root, skills={PRODUCER: skill}, prompts={round_id: blocks},
            cache=_Cache({**config, "llm": settings}, run_dir), progress=progress,
            unit_event=unit_event or (lambda *_args, **_kwargs: None), output_event=output_event,
            cancelled=cancelled, open_runtime=open_runtime,
        )
        records = phase.execute_all([(1, PRODUCER, unit)])
    record = records[0] if records else {"status": "failed", "reason": "no session record"}
    proposal_body = record.get("proposal") if isinstance(record.get("proposal"), dict) else {}
    items = [PatchItem(**_item_fields(entry)) for entry in proposal_body.get("items") or []]
    session = None
    for artifact in record.get("artifacts") or []:
        path = artifact.get("path") if isinstance(artifact, dict) else None
        if path and str(path).endswith("/proposal.json"):
            session = str(path).rsplit("/", 1)[0]
            break
    return Proposal(
        status=str(record.get("status") or "failed"), reason=record.get("reason"), model=str(settings.get("model") or None),
        session=session, items=items, problems=list(proposal_body.get("problems") or []),
        unresolved=list(proposal_body.get("unresolved") or []), duration_seconds=round(time.monotonic() - started, 3),
        third_party=warning,
    )


def _item_fields(entry: Mapping[str, Any]) -> dict[str, Any]:
    value = entry.get("value")
    if entry.get("op") == "set_splint_option" and isinstance(value, list):
        value = tuple(value)
    return {
        "op": str(entry.get("op")), "value": value, "origin": str(entry.get("origin") or "llm"),
        "evidence": str(entry.get("evidence") or ""), "units_affected": int(entry.get("units_affected") or 0),
        "match": entry.get("match"), "rationale": str(entry.get("rationale") or ""),
        "preselected": bool(entry.get("preselected", True)),
    }

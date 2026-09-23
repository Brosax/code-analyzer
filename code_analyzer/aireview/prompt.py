"""One lens request: the messages, the schema, and exactly what the model was shown.

The system message is the lens and its contract only -- identical for every
unit a lens reviews, so dispatching by lens keeps the host's prefix cache warm.
The user message carries the evaluation context (the SFR in the ST's own words,
the attacker model), why this unit was chosen, the candidate for a verdict, and
the unit's numbered lines inside a DATA fence.  ``Shown`` records those lines as
sent (escaped), which is what grounding checks quotes and line numbers against.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..evidence.grounding import Shown
from ..kernel.codecs import data_block, escape_untrusted, finding_text
from ..sesip.profile import Profile
from ..sesip.relevance import Target
from . import contracts
from .code import CodeIndex
from .lenses import Lens

MAX_MEMBERS = 8
MAX_NEIGHBOURS = 4
MAX_SFR_TEXT = 700
MAX_NEED_LINES = 60


@dataclass
class Request:
    messages: list[dict[str, Any]]
    schema: dict[str, Any]
    shown: Shown
    contract: str
    lens: Lens


def profile_enums(profile: Profile) -> tuple[list[str], list[str], list[str]]:
    sfr_ids = [str(s["id"]) for s in profile.data.get("sfr", [])]
    levels = [str(level["id"]) for level in profile.levels]
    categories = [str(c["id"]) for c in profile.data.get("category", []) if c.get("id")]
    return sfr_ids, levels, categories


def build(target: Target, lens: Lens, code: CodeIndex, profile: Profile, *,
          candidate: dict[str, Any] | None = None, allow_need: bool = True,
          extra_code: list[tuple[str, str]] | None = None) -> Request:
    sfr_ids, levels, categories = profile_enums(profile)
    if lens.contract == "verdict":
        schema = contracts.verdict_schema(sfr_ids=sfr_ids, levels=levels, categories=categories,
                                          allow_need=allow_need)
    else:
        schema = contracts.findings_schema(sfr_ids=sfr_ids, levels=levels, allow_need=allow_need)
    sfr = next((s for s in profile.data.get("sfr", []) if s["id"] == target.sfr_id), None)
    sfr_text = _sfr_wording(sfr) if sfr else ""
    system = "\n\n".join([lens.text(sfr_id=target.sfr_id, sfr_text=sfr_text),
                          contracts.instructions(lens.contract, allow_need=allow_need), contracts.DATA_RULE])
    raw = code.lines(target.path, target.line_start, target.line_end)
    lines = {n: escape_untrusted(text) for n, text in raw.items()}
    width = len(str(max(lines))) if lines else 1
    listing = "\n".join(f"{n:>{width}}| {lines[n]}" for n in sorted(lines))
    shown = Shown(target.path, lines, target.function,
                  (target.line_start, target.line_end) if target.function else None)
    parts = [_context(target, profile, sfr_ids)]
    if candidate is not None:
        parts.append(_candidate(target, candidate))
    else:
        parts.append(f"Review the unit below for defects that bear on {_scope(target, profile)}.")
    where = f"{target.path}, function {target.function}()" if target.function else target.path
    parts.append(f"The unit ({where}, lines {target.line_start}-{target.line_end}):\n"
                 + data_block(listing, source=target.path, handle=target.key))
    neighbours = _neighbours(target, code)
    if neighbours:
        parts.append("Callers and callees (signatures only, static approximation):\n"
                     + data_block(neighbours, source="call graph"))
    for name, text in extra_code or []:
        parts.append(f"Definition of {name}, as requested (context only; report defects in the unit above):\n"
                     + data_block(text, source=name))
    messages = [{"role": "system", "content": system}, {"role": "user", "content": "\n\n".join(parts)}]
    return Request(messages, schema, shown, lens.contract, lens)


def need_code(code: CodeIndex, names: list[str]) -> list[tuple[str, str]]:
    """The definitions a lens asked for, bounded; unknown names are said to be unknown."""
    out = []
    for name in names[:contracts.MAX_NEED]:
        found = code.named(name)
        if not found:
            out.append((name, f"(no definition of {name} in the scanned tree)"))
            continue
        function = found[0]
        lines = code.lines(function.path, function.line_start,
                           min(function.line_end, function.line_start + MAX_NEED_LINES - 1))
        text = "\n".join(f"{n}| {lines[n]}" for n in sorted(lines))
        if function.line_end > function.line_start + MAX_NEED_LINES - 1:
            text += f"\n... ({function.lines - MAX_NEED_LINES} more lines not shown)"
        out.append((name, f"{function.path}:\n{text}"))
    return out


def estimate_tokens(request: Request) -> int:
    """Characters over three: code and English run ~3.2-4 chars/token on qwen; err high."""
    return sum(len(m["content"]) for m in request.messages) // 3 + 800  # + the schema in response_format


def _sfr_wording(sfr: dict[str, Any]) -> str:
    source = sfr.get("source") if isinstance(sfr.get("source"), dict) else {}
    text = str(sfr.get("text") or sfr.get("description") or source.get("quote") or sfr.get("title") or "")
    return escape_untrusted(" ".join(text.split())[:MAX_SFR_TEXT])


def _scope(target: Target, profile: Profile) -> str:
    if target.sfr_id:
        return f"SFR {target.sfr_id}"
    linked = [s["id"] for s in profile.data.get("sfr", [])]
    return "the Security Target's SFRs" if linked else "the security of the platform"


def _context(target: Target, profile: Profile, sfr_ids: list[str]) -> str:
    attacker = profile.data.get("attacker", {})
    physical = "yes" if attacker.get("physical") else "no (software attacker through the TSFIs)"
    lines = ["Evaluation context:",
             f"- SESIP evaluation; TOE module: {target.module or '-'}; attacker is physical: {physical}.",
             f"- SFR ids you may cite: {', '.join(sfr_ids) or '(none)'}."]
    if target.sfr_id:
        sfr = next((s for s in profile.data.get("sfr", []) if s["id"] == target.sfr_id), {})
        lines.append(f"- Requirement in focus: {target.sfr_id} ({escape_untrusted(str(sfr.get('title', '')))}).")
    lines.append("- Why this unit was chosen: " + "; ".join(target.reasons[:3]) + ".")
    return "\n".join(lines)


def _candidate(target: Target, candidate: dict[str, Any]) -> str:
    members = candidate.get("members") or []
    rows = [f"{m.get('tool')} {m.get('rule_id')} [{m.get('review_level') or m.get('original_severity') or '-'}] "
            f"line {m.get('line')}: {finding_text(str(m.get('message', '')))}" for m in members[:MAX_MEMBERS]]
    if len(members) > MAX_MEMBERS:
        rows.append(f"... and {len(members) - MAX_MEMBERS} more finding(s) on the same lines")
    label = candidate.get("label") or target.key
    head = (f"The candidate {label}: {candidate.get('family') or 'defect'} at lines "
            f"{target.focus[0]}-{target.focus[1]}, reported by:")
    question = "\nQuestion: is this candidate a real defect on the shown code, and is it reachable?"
    if candidate.get("ai"):
        question = ("\nQuestion: these rows were written by another AI reviewer.  Is the defect they claim real at "
                    "the lines they name?  Judge the claim, not the function: if the named lines are correct code "
                    "(they only declare, set up or print) and the claimed fault is not at them, answer "
                    "FALSE_POSITIVE with the line that shows it.")
    return head + "\n" + data_block("\n".join(rows), source="findings") + question


def _neighbours(target: Target, code: CodeIndex) -> str:
    if not target.function:
        return ""
    function = next((f for f in code.named(target.function) if f.path == target.path), None)
    if function is None:
        return ""
    callers = code.callers(function)[:MAX_NEIGHBOURS]
    callees = code.callees(function)[:MAX_NEIGHBOURS]
    rows = [f"caller {f.path}:{f.line_start} {f.signature}" for f in callers]
    rows += [f"callee {f.path}:{f.line_start} {f.signature}" for f in callees]
    return "\n".join(rows)

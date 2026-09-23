"""What the AI review looks at, chosen deterministically.  The model never picks its own targets.

T1 -- verify: every listed entry (main and unmapped partitions) in the focus
      that has not been verified on its current code, highest priority first,
      through the ``verify`` lens.
T2 -- look: functions in the TOE that the profile ties to an SFR -- a TSFI
      entry point, a function up to two calls below one (static
      approximation), or a name in the SFR's lens vocabulary -- each through at
      most two lenses.  A function is left out of a lens's look only when a
      tool already alarmed on it in a defect family that lens covers (T1
      verifies those); an unrelated alarm does not hide it.
      The evaluator can also name functions (``path::function`` or
      ``path:line``); they get the named lens, or the two general code lenses.

Every (unit, lens) pair carries the reasons it was chosen, so the coverage
page can say why something was or was not looked at.  Re-review is keyed on
the text of the unit: unchanged code with the same lens version is not paid
for twice.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from ..aireview import lenses as lens_mod
from ..aireview.code import CodeIndex, Function
from ..sesip.catalogue import BY_NAME
from .profile import Profile

MAX_LENSES_PER_UNIT = 2
TSFI_DEPTH = 2
MODULE_SCOPE_RADIUS = 30
MAX_T2 = 2000
GENERAL_LENSES = ("memory", "error-path")


@dataclass
class Target:
    tier: str                 # T1 | T2 | V (second look at an AI finding)
    key: str                  # PV-0007 | path::function | AF-3
    lens: str
    path: str
    function: str
    line_start: int           # the unit shown
    line_end: int
    focus: tuple[int, int]    # the lines the question is about
    score: float
    reasons: list[str] = field(default_factory=list)
    sfr_id: str = ""          # the SFR a sfr-generic look is for
    module: str = ""
    text_sha: str = ""        # sha256 of the unit's lines: the re-review key
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def review_key(self) -> str:
        version = lens_mod.get(self.lens).version
        return f"{self.tier}:{self.key}:{self.lens}@{version}:{self.text_sha[:16]}"

    def as_dict(self) -> dict[str, Any]:
        return {"tier": self.tier, "key": self.key, "lens": self.lens, "path": self.path, "function": self.function,
                "line_start": self.line_start, "line_end": self.line_end, "focus": list(self.focus),
                "score": self.score, "reasons": self.reasons, "sfr_id": self.sfr_id, "module": self.module,
                "text_sha": self.text_sha}


@dataclass
class Plan:
    targets: list[Target]
    skipped: dict[str, int]         # reason -> count (already reviewed, lens not applicable, ...)
    focus: dict[str, Any]

    def counts(self) -> dict[str, int]:
        out = {"T1": 0, "T2": 0, "V": 0}
        for target in self.targets:
            out[target.tier] = out.get(target.tier, 0) + 1
        return out


def unit_text_sha(code: CodeIndex, path: str, start: int, end: int) -> str:
    lines = code.lines(path, start, end)
    return hashlib.sha256("\n".join(lines[n] for n in sorted(lines)).encode("utf-8")).hexdigest()


def pv_unit(code: CodeIndex, row: dict[str, Any]) -> tuple[str, int, int]:
    """The function around an entry, or a window when it sits at file scope."""
    path, start, end = str(row["path"]), int(row["line_start"]), int(row["line_end"])
    function = code.function_at(path, start)
    if function is not None and function.line_end >= end:
        return function.name, function.line_start, function.line_end
    return "", max(1, start - MODULE_SCOPE_RADIUS), end + MODULE_SCOPE_RADIUS


def plan(*, pvs: list[dict[str, Any]], code: CodeIndex, profile: Profile, reviewed: set[str],
         focus: dict[str, Any] | None = None, targets: list[str] | None = None, depth: str = "normal",
         lens: str = "") -> Plan:
    focus = {k: v for k, v in (focus or {}).items() if v}
    skipped: dict[str, int] = {}
    chosen: list[Target] = []

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    def keep(target: Target, *, named: bool = False) -> None:
        target.text_sha = unit_text_sha(code, target.path, target.line_start, target.line_end)
        if not target.text_sha or not code.text_lines(target.path):
            skip("source not readable")
        elif target.review_key in reviewed and not named:  # asked for by name: look again (the cache answers)
            skip("already reviewed on this code")
        else:
            chosen.append(target)

    # -- T1: verify listed entries --------------------------------------------------------------
    explicit = {t for t in targets or [] if t.startswith("PV-")}
    sfr_focus = {part.strip() for part in str(focus.get("sfr", "")).split(",") if part.strip()}
    module_focus = str(focus.get("module", ""))
    partition_focus = str(focus.get("partition", ""))
    module_sfrs = {m["id"]: set(m.get("sfr", [])) for m in profile.data.get("toe_module", [])}
    for row in sorted(pvs, key=lambda r: (-int(r.get("priority", 0)), str(r["pv_id"]))):
        if row.get("partition") not in ("main", "unmapped"):
            continue
        if targets:  # the evaluator named what to look at: exactly that
            if row["pv_id"] not in explicit:
                continue
        else:
            if partition_focus and row.get("partition") != partition_focus:
                continue
            if module_focus and row.get("module") != module_focus:
                continue
            if sfr_focus and not sfr_focus & {s["id"] for s in row.get("sfr", [])} \
                    and not sfr_focus & module_sfrs.get(str(row.get("module")), set()):
                continue
            if row.get("status") in ("false_positive", "not_exploitable"):
                skip("dispositioned by the analyst")
                continue
        name, start, end = pv_unit(code, row)
        why = [f"listed entry ({row.get('partition')}, priority {row.get('priority')})"]
        if row["pv_id"] in explicit:
            why.insert(0, "named by the evaluator")
        keep(Target("T1", str(row["pv_id"]), lens_mod.VERIFY, str(row["path"]), name, start, end,
                    (int(row["line_start"]), int(row["line_end"])), 100.0 + float(row.get("priority", 0)),
                    why, module=str(row.get("module") or ""), extra={"cluster_id": row.get("cluster_id"),
                                                                     "anchor": row.get("anchor")}),
             named=row["pv_id"] in explicit)
    named_functions = _named_functions(code, [t for t in targets or [] if not t.startswith("PV-")], skip)
    for function in named_functions:
        module = profile.module_of(function.path) or ""
        for lens_id in ([lens] if lens else list(GENERAL_LENSES)):
            keep(Target("T2", function.key, lens_id, function.path, function.name, function.line_start,
                        function.line_end, (function.line_start, function.line_end), 50.0,
                        ["named by the evaluator"], module=module), named=True)
    if explicit or named_functions or targets or depth == "quick":
        return Plan(chosen, skipped, focus)

    # -- T2: SFR-relevant functions nobody flagged ---------------------------------------------
    flagged: dict[str, list[tuple[int, int, str]]] = {}
    for row in pvs:
        flagged.setdefault(str(row["path"]), []).append((int(row["line_start"]), int(row["line_end"]),
                                                         str(row.get("family") or "")))

    def alarmed(function: Function, families: tuple[str, ...]) -> bool:
        """A tool already reported, in this function, a defect of a kind this lens is for."""
        return any((function.line_start <= a <= function.line_end or function.line_start <= b <= function.line_end)
                   and family in families for a, b, family in flagged.get(function.path, ()))

    sfrs = [s for s in profile.data.get("sfr", []) if not sfr_focus or s["id"] in sfr_focus]
    tsfi = profile.data.get("tsfi", [])
    candidates: dict[tuple[str, str], Target] = {}

    def consider(function: Function, lens: lens_mod.Lens, score: float, reason: str, sfr_id: str) -> None:
        module = profile.module_of(function.path)
        if module is None or (module_focus and module != module_focus):
            return
        if alarmed(function, lens.rule_families):
            return
        key = (function.key, lens.id)
        target = candidates.get(key)
        if target is None:
            candidates[key] = Target("T2", function.key, lens.id, function.path, function.name, function.line_start,
                                     function.line_end, (function.line_start, function.line_end), score, [reason],
                                     sfr_id=sfr_id if lens.id == lens_mod.GENERIC else "", module=module)
        else:
            target.score = max(target.score, score)
            if reason not in target.reasons:
                target.reasons.append(reason)

    functions = list(code.functions())
    for sfr in sfrs:
        catalogue = str(sfr.get("catalogue", ""))
        chosen_lens = lens_mod.get(lens) if lens else lens_mod.for_catalogue(catalogue)
        if not chosen_lens.applies(profile.data) or chosen_lens.contract != "findings":
            skip(f"lens {chosen_lens.id} not applicable to this attacker model")
            continue
        entry_points = [f for item in tsfi if not item.get("sfr") or sfr["id"] in item.get("sfr", [])
                        for symbol in item.get("symbols", []) for f in code.named(str(symbol))]
        if entry_points:
            distance = code.distances(entry_points, TSFI_DEPTH)
            by_key = {f.key: f for f in functions}
            for key, hops in distance.items():
                if key in by_key:
                    reason = f"TSFI entry point for {sfr['id']}" if hops == 0 else \
                        f"{hops} call(s) below a TSFI entry for {sfr['id']} (static approximation)"
                    consider(by_key[key], chosen_lens, 3.0 - hops, reason, sfr["id"])
        vocabulary = chosen_lens.symbols or tuple(w.lower() for w in (BY_NAME.get(catalogue) or {}).get("keywords", []))
        vocabulary = tuple(sfr.get("keywords", [])) + tuple(vocabulary)
        for function in functions:
            haystack = function.name.lower()
            hits = [word for word in vocabulary if word and word.lower() in haystack]
            if hits:
                consider(function, chosen_lens, 1.0, f"name matches {sfr['id']} vocabulary ({hits[0]})", sfr["id"])
    # a second lens when another lens's own vocabulary names the function
    if not lens:
        relevant = {key for key, _ in candidates}
        for function in functions:
            if function.key not in relevant:
                continue
            for other in lens_mod.by_symbol(function.name):
                if (function.key, other.id) not in candidates and other.applies(profile.data):
                    consider(function, other, 0.5, f"name matches the {other.id} lens vocabulary", "")
    per_unit: dict[str, list[Target]] = {}
    for target in sorted(candidates.values(), key=lambda t: (-t.score, t.path, t.line_start, t.lens)):
        per_unit.setdefault(target.key, []).append(target)
    ranked = []
    for items in per_unit.values():
        ranked.extend(items[:MAX_LENSES_PER_UNIT])
        for _ in items[MAX_LENSES_PER_UNIT:]:
            skip("more than two lenses for one unit")
    ranked.sort(key=lambda t: (-t.score, t.path, t.line_start, t.lens))
    for target in ranked[:MAX_T2]:
        keep(target)
    if len(ranked) > MAX_T2:
        skipped["beyond the first 2000 relevant units"] = len(ranked) - MAX_T2
    return Plan(chosen, skipped, focus)


def _named_functions(code: CodeIndex, names: list[str], skip: Any) -> list[Function]:
    """``path::function`` or ``path:line`` the evaluator named; unknown names are counted, not guessed."""
    out: list[Function] = []
    for name in names:
        function = None
        if "::" in name:
            path, _, symbol = name.partition("::")
            function = next((f for f in code.named(symbol) if f.path == path), None)
        elif ":" in name and name.rsplit(":", 1)[1].isdigit():
            path, line = name.rsplit(":", 1)
            function = code.function_at(path, int(line))
        if function is None:
            skip(f"no function {name} in the scanned tree")
        elif function not in out:
            out.append(function)
    return out

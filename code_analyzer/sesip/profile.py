"""The evaluation profile: what the review is anchored on.

A profile says, from the Security Target and the test plan: which SFRs are
claimed, which source paths are the TOE and which are not, what the test
plan's levels (§7.4.1) and issue categories (§7.4.2) are, and which rules map
a native finding onto a level.  Every item extracted from a document carries
``source = {doc, page|loc, quote}`` so an evaluator can check it.

Grading is only ever *provable*: a rule counts when its basis is
``native-exact`` (the test plan names the tool's own level literally),
``evaluator-rule`` (a human confirmed the mapping) or ``analyst`` (a human set
it on one entry).  A ``proposed`` rule -- pre-filled for a human to confirm --
is shown but not applied; the finding stays **unmapped** and goes to the
"needs manual verification" partition instead of silently disappearing.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from ..errors import UserError
from .catalogue import BY_NAME as CATALOGUE

PROVABLE_BASES = ("native-exact", "evaluator-rule", "analyst")
BASES = (*PROVABLE_BASES, "proposed", "ai-proposed")
BUILTINS = ("rt700-tp-v1.1", "generic-sesip")
DEFAULT_HEADLESS = "rt700-tp-v1.1"
UNMAPPED = "unmapped"

_TABLE_KEYS: dict[str, set[str]] = {
    "evaluation": {"id", "name", "confidentiality", "status", "version", "confirmed_by", "confirmed_at", "base",
                   "allow_public_model"},
    "attacker": {"potential", "physical", "source"},
    "toe_configuration": {"platform", "defines", "source"},
    "test_plan": {"reference", "levels_section", "categories_section", "category_kind"},
    "export": {"template"},
    "advanced": {"pv_min_level"},
}
_ARRAY_KEYS: dict[str, set[str]] = {
    "documents": {"role", "file", "sha256", "title"},
    "sfr": {"id", "catalogue", "title", "source", "keywords", "families"},
    "toe_module": {"id", "paths", "sfr", "description", "source"},
    "exclude": {"paths", "reason"},
    "tsfi": {"id", "symbols", "attributes", "sfr", "description", "source"},
    "level": {"id", "label", "rank", "description", "source"},
    "category": {"id", "label", "definition", "source"},
    "grading_rule": {"match", "level", "basis", "by", "at"},
    "category_rule": {"match", "category", "basis", "by", "at"},
}
_MATCH_KEYS = {"tool", "native", "rule", "family", "cwe"}


@dataclass
class Profile:
    data: dict[str, Any]
    text: str
    sha256: str
    name: str = ""
    _globs: list[tuple[str, re.Pattern[str]]] = field(default_factory=list, repr=False)
    _excludes: list[re.Pattern[str]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        for module in self.data.get("toe_module", []):
            for glob in module.get("paths", []):
                self._globs.append((str(module["id"]), _glob(glob)))
        for item in self.data.get("exclude", []):
            self._excludes.extend(_glob(glob) for glob in item.get("paths", []))

    # -- identity ------------------------------------------------------------------------
    @property
    def status(self) -> str:
        return str(self.data.get("evaluation", {}).get("status", "draft"))

    @property
    def levels(self) -> list[dict[str, Any]]:
        return sorted(self.data.get("level", []), key=lambda level: -int(level.get("rank", 0)))

    def rank(self, level: str) -> int:
        for item in self.data.get("level", []):
            if item["id"] == level:
                return int(item.get("rank", 0))
        return 0

    @property
    def min_level(self) -> str:
        return str(self.data.get("advanced", {}).get("pv_min_level", "warning"))

    # -- TOE ------------------------------------------------------------------------------
    def module_of(self, path: str) -> str | None:
        """The TOE module a source path belongs to, or None when it is outside the TOE."""
        if any(pattern.fullmatch(path) for pattern in self._excludes):
            return None
        for module, pattern in self._globs:
            if pattern.fullmatch(path):
                return module
        return None

    # -- grading --------------------------------------------------------------------------
    def grade(self, row: dict[str, Any]) -> tuple[str, str, str]:
        """(level, basis, proposed_level) for one finding row.

        The first matching rule decides.  A proposed rule that matches first
        leaves the row unmapped and reports what it would have said.
        """
        for rule in self.data.get("grading_rule", []):
            if _matches(rule.get("match", {}), row):
                basis = str(rule.get("basis", "proposed"))
                if basis in PROVABLE_BASES:
                    return str(rule["level"]), basis, ""
                return UNMAPPED, UNMAPPED, str(rule["level"])
        return UNMAPPED, UNMAPPED, ""

    def categorize(self, row: dict[str, Any]) -> tuple[str, str]:
        for rule in self.data.get("category_rule", []):
            if _matches(rule.get("match", {}), row) and rule.get("basis") in PROVABLE_BASES:
                return str(rule["category"]), str(rule["basis"])
        return "", UNMAPPED

    # -- SFR links -------------------------------------------------------------------------
    def sfrs_for(self, row: dict[str, Any], module: str | None) -> list[dict[str, str]]:
        """Which SFRs a finding bears on, each with the basis of the link.

        Strong: the finding's family is one that defeats the SFR ("family").
        Weak, shown but never ranked: the module's claimed SFRs
        ("module-default"), a keyword in the path or function ("keyword").
        """
        links: dict[str, str] = {}
        family = str(row.get("family") or "")
        haystack = f"{row.get('canonical_path', '')} {row.get('function', '')}".lower()
        for sfr in self.data.get("sfr", []):
            reference = CATALOGUE.get(str(sfr.get("catalogue", "")), {})
            families = set(sfr.get("families", [])) | set(reference.get("families", []))
            if family and family in families:
                links[sfr["id"]] = "family"
                continue
            keywords = list(sfr.get("keywords", [])) or list(reference.get("keywords", []))
            if any(word.lower() in haystack for word in keywords):
                links.setdefault(sfr["id"], "keyword")
        if module is not None:
            for item in self.data.get("toe_module", []):
                if item["id"] == module:
                    for sfr_id in item.get("sfr", []):
                        links.setdefault(sfr_id, "module-default")
        return [{"id": sfr_id, "basis": basis} for sfr_id, basis in sorted(links.items())]


STRONG_SFR_BASES = frozenset({"family", "tsfi", "ai-confirmed", "analyst"})


def load_profile(source: str | Path) -> Profile:
    """A builtin name, or a path to a profile TOML."""
    if isinstance(source, str) and source in BUILTINS:
        text = resources.files("code_analyzer.sesip").joinpath("builtin", f"{source}.toml").read_text(encoding="utf-8")
        return parse_profile(text, name=source)
    path = Path(source).expanduser()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise UserError(f"cannot read profile {path}: {error}") from error
    return parse_profile(text, name=path.stem)


def parse_profile(text: str, *, name: str = "") -> Profile:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise UserError(f"profile {name or '<text>'}: {error}") from error
    problems = validate_profile(data)
    if problems:
        raise UserError(f"profile {name or '<text>'} is invalid: " + "; ".join(problems[:8]))
    return Profile(data, text, hashlib.sha256(text.encode("utf-8")).hexdigest(), name)


def validate_profile(data: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for key, value in data.items():
        if key in _TABLE_KEYS:
            if not isinstance(value, dict):
                problems.append(f"[{key}] must be a table")
                continue
            problems += [f"[{key}] unknown key {extra!r}" for extra in sorted(set(value) - _TABLE_KEYS[key])]
        elif key in _ARRAY_KEYS:
            if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
                problems.append(f"[[{key}]] must be an array of tables")
                continue
            for index, item in enumerate(value):
                problems += [f"[[{key}]] #{index + 1} unknown key {extra!r}"
                             for extra in sorted(set(item) - _ARRAY_KEYS[key])]
        else:
            problems.append(f"unknown section {key!r}")
    levels = {str(item.get("id")) for item in data.get("level", []) if isinstance(item, dict)}
    if not levels:
        problems.append("at least one [[level]] is required")
    for kind in ("level", "sfr", "toe_module", "category", "tsfi"):
        ids = [str(item.get("id")) for item in data.get(kind, []) if isinstance(item, dict)]
        if len(ids) != len(set(ids)):
            problems.append(f"[[{kind}]] ids must be unique")
    sfr_ids = {str(item.get("id")) for item in data.get("sfr", []) if isinstance(item, dict)}
    for module in data.get("toe_module", []):
        if isinstance(module, dict):
            problems += [f"toe_module {module.get('id')!r} names unknown SFR {s!r}"
                         for s in module.get("sfr", []) if s not in sfr_ids]
            confirmed = isinstance(data.get("evaluation"), dict) and data["evaluation"].get("status") == "confirmed"
            if not module.get("paths") and confirmed:
                problems.append(f"toe_module {module.get('id')!r} has no paths; map it to source before confirming")
    for kind, target, known in (("grading_rule", "level", levels),
                                ("category_rule", "category",
                                 {str(c.get("id")) for c in data.get("category", []) if isinstance(c, dict)})):
        for index, rule in enumerate(data.get(kind, [])):
            if not isinstance(rule, dict):
                continue
            where = f"[[{kind}]] #{index + 1}"
            if rule.get("basis") not in BASES:
                problems.append(f"{where}: basis must be one of {', '.join(BASES)}")
            if rule.get(target) not in known:
                problems.append(f"{where}: {target} {rule.get(target)!r} is not defined")
            match = rule.get("match")
            if not isinstance(match, dict) or not match:
                problems.append(f"{where}: match must be a non-empty table")
            else:
                problems += [f"{where}: unknown match key {k!r}" for k in sorted(set(match) - _MATCH_KEYS)]
            if rule.get("basis") in ("evaluator-rule", "analyst") and not rule.get("by"):
                problems.append(f"{where}: an {rule.get('basis')} needs 'by' (who confirmed it)")
    status = data.get("evaluation", {}).get("status", "draft") if isinstance(data.get("evaluation"), dict) else "draft"
    if status not in ("draft", "confirmed", "builtin"):
        problems.append("[evaluation] status must be draft, confirmed or builtin")
    minimum = data.get("advanced", {}).get("pv_min_level") if isinstance(data.get("advanced"), dict) else None
    if minimum is not None and minimum not in levels:
        problems.append(f"[advanced] pv_min_level {minimum!r} is not a defined level")
    return problems


def _matches(match: dict[str, Any], row: dict[str, Any]) -> bool:
    for key, wanted in match.items():
        values = [str(v).lower() for v in (wanted if isinstance(wanted, list) else [wanted])]
        if key == "tool":
            actual = str(row.get("tool", "")).lower()
        elif key == "native":
            actual = str(row.get("original_severity", "")).strip().lower()
        elif key == "rule":
            actual = str(row.get("rule_id", "")).lower()
            if any(fnmatch.fnmatchcase(actual, v) for v in values):
                continue
            return False
        elif key == "family":
            actual = str(row.get("family", "")).lower()
        else:  # cwe
            actual = str(row.get("cwe", "")).lower()
        if actual not in values:
            return False
    return True


def _glob(pattern: str) -> re.Pattern[str]:
    """Git-style globs: ``**`` spans directories, ``*`` and ``?`` do not."""
    out = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            out.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            out.append(".*")
            index += 2
        elif pattern[index] == "*":
            out.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            out.append("[^/]")
            index += 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(out))

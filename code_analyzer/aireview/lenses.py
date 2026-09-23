"""The fifteen lenses: what to look for, for one kind of targeted look.

A lens is a Markdown file with TOML front matter (``aireview/lenses/*.md``)::

    +++
    id = "memory"            # the file's stem
    version = "1.0.0"        # part of the cache key: edit the text, bump it
    contract = "findings"    # or "verdict" (only ``verify``)
    title = "..."
    sfr_catalogue = [...]    # SESIP catalogue names this lens serves
    rule_families = [...]    # tool-finding families it is the natural reviewer for
    symbols = [...]          # identifier substrings that make a function relevant
    requires = ""            # "attacker.physical": only when the ST's attacker is physical
    +++
    guidance ...

The body is guidance only; the answer format and the untrusted-data rule are
appended by the program (contracts.py), so every lens is held to the same
contract.  ``sfr-generic`` carries ``{sfr_id}`` and ``{sfr_text}``, filled with
the Security Target's own wording of the SFR it is used for.
"""
from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

from ..errors import UserError
from ..sesip.catalogue import BY_NAME

KEYS = {"id", "version", "contract", "title", "sfr_catalogue", "rule_families", "symbols", "requires"}
CONTRACTS = ("verdict", "findings")
MAX_WORDS = 600
VERIFY = "verify"
GENERIC = "sfr-generic"


@dataclass(frozen=True)
class Lens:
    id: str
    version: str
    contract: str
    title: str
    sfr_catalogue: tuple[str, ...]
    rule_families: tuple[str, ...]
    symbols: tuple[str, ...]
    requires: str
    body: str
    sha256: str

    def text(self, *, sfr_id: str = "", sfr_text: str = "") -> str:
        if self.id != GENERIC:
            return self.body
        return self.body.replace("{sfr_id}", sfr_id or "(unnamed SFR)").replace(
            "{sfr_text}", sfr_text or "(the Security Target gives no wording for this SFR)")

    def applies(self, profile_data: dict[str, Any]) -> bool:
        if self.requires == "attacker.physical":
            return bool(profile_data.get("attacker", {}).get("physical"))
        return True

    def matches_symbol(self, name: str) -> bool:
        lowered = name.lower()
        return any(symbol in lowered for symbol in self.symbols)


def parse_lens(text: str, name: str) -> Lens:
    parts = text.split("+++")
    if len(parts) < 3 or parts[0].strip():
        raise UserError(f"lens {name}: expected TOML front matter between +++ lines")
    header = tomllib.loads(parts[1])
    body = "+++".join(parts[2:]).strip() + "\n"
    problems = []
    if set(header) != KEYS:
        problems.append(f"keys {sorted(set(header) ^ KEYS)} differ from {sorted(KEYS)}")
    if header.get("id") != name:
        problems.append(f"id {header.get('id')!r} is not the file name {name!r}")
    if header.get("contract") not in CONTRACTS:
        problems.append(f"contract must be one of {CONTRACTS}")
    unknown = [n for n in header.get("sfr_catalogue", []) if n not in BY_NAME]
    if unknown:
        problems.append(f"sfr_catalogue names not in the SESIP catalogue: {unknown}")
    if len(body.split()) > MAX_WORDS:
        problems.append(f"body has {len(body.split())} words (at most {MAX_WORDS})")
    if problems:
        raise UserError(f"lens {name}: " + "; ".join(problems))
    return Lens(name, str(header["version"]), str(header["contract"]), str(header["title"]),
                tuple(header["sfr_catalogue"]), tuple(header["rule_families"]),
                tuple(s.lower() for s in header["symbols"]), str(header["requires"]), body,
                hashlib.sha256(text.encode("utf-8")).hexdigest())


@lru_cache(maxsize=1)
def load_all() -> dict[str, Lens]:
    folder = resources.files("code_analyzer.aireview").joinpath("lenses")
    lenses = {}
    for item in sorted(folder.iterdir(), key=lambda entry: entry.name):
        if item.name.endswith(".md"):
            name = item.name[:-3]
            lenses[name] = parse_lens(item.read_text(encoding="utf-8"), name)
    if VERIFY not in lenses or GENERIC not in lenses:
        raise UserError("the review lenses are incomplete: verify and sfr-generic are required")
    return lenses


def get(lens_id: str) -> Lens:
    lenses = load_all()
    if lens_id not in lenses:
        raise UserError(f"no lens {lens_id!r}; known: {', '.join(sorted(lenses))}")
    return lenses[lens_id]


def for_catalogue(name: str) -> Lens:
    """The lens that serves a SESIP catalogue SFR: the catalogue's own assignment first, then any lens
    that lists the SFR, then sfr-generic."""
    entry = BY_NAME.get(name) or {}
    named = load_all().get(str(entry.get("lens", "")))
    if named is not None and named.contract == "findings":
        return named
    for lens in load_all().values():
        if lens.contract == "findings" and name in lens.sfr_catalogue and lens.id != GENERIC:
            return lens
    return get(GENERIC)


def for_family(family: str) -> Lens | None:
    for lens in load_all().values():
        if lens.contract == "findings" and family in lens.rule_families:
            return lens
    return None


def by_symbol(name: str) -> list[Lens]:
    return [lens for lens in load_all().values()
            if lens.contract == "findings" and lens.id != GENERIC and lens.matches_symbol(name)]

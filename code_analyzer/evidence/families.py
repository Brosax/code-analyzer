"""The defect family a finding belongs to -- the axis findings of different tools correlate on.

The same vocabulary for every engine: CWE numbers first (a flawfinder CWE-190 whose message says "integer
overflow" must meet a cppcheck integer-overflow), then the tools' own rule ids and messages, then an AI
reviewer's declared category.  Moved unchanged from audit.py and review.py (v3 M9); triage clusters on it and
the list shows it.
"""
from __future__ import annotations

import re
from typing import Any

_CWE_CATEGORIES: tuple[tuple[str, frozenset[int]], ...] = (
    ("integer-overflow", frozenset({190, 191, 192, 194, 195, 196, 197, 680, 681})),
    ("lifetime", frozenset({415, 416, 562, 590, 761, 825})),
    ("input-validation", frozenset({20, 129, 1284})),
    ("protocol-parsing", frozenset({112, 130, 240, 444})),
    ("info-leak", frozenset({200, 209, 212, 226, 532})),
    ("hardcoded-secret", frozenset({259, 321, 798})),
    ("authentication", frozenset({287, 288, 290, 306, 592})),
    ("trust-boundary", frozenset({250, 269, 501, 668, 807})),
    ("crypto-misuse", frozenset({261, 310, 326, 328, 347, 916})),
    ("race", frozenset({362, 364, 366, 367, 421, 543, 821})),
    ("firmware-update", frozenset({345, 494, 565, 829})),
    ("debug-backdoor", frozenset({489, 506, 511, 912})),
    ("stack-usage", frozenset({674, 770, 789})),
    ("undefined-behavior", frozenset({188, 469, 588, 704, 758})),
)

_KEYWORD_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("null-dereference", r"null pointer|nullpointer|nullderef"),
    ("buffer", r"buffer|overflow|strcpy|strcat|memcpy|memmove"),
    ("uninitialized", r"uninit|used before definition|use.?def"),
    ("resource-leak", r"memory leak|resource leak|not released"),
    ("format", r"format|string format|printf|scanf"),
    ("randomness", r"random|srand|rand\("),
)

_LLM_KEYWORD_CATEGORIES: tuple[tuple[str, str], ...] = _KEYWORD_CATEGORIES + (
    ("integer-overflow", r"integer overflow|signed overflow|unsigned wrap"),
    ("lifetime", r"use.?after.?free|double free|dangling|freed memory|after it is freed"),
    ("race", r"\brace\b|data race|concurrent|reentran|thread.?unsafe"),
    ("isr-safety", r"\bisr\b|\birq\b|interrupt (?:handler|context|service)"),
    ("volatile-misuse", r"\bvolatile\b"),
    ("atomicity", r"atomic|read.?modify.?write"),
    ("rtos-sync", r"\brtos\b|mutex|semaphore|spinlock|critical section|freertos"),
    ("watchdog", r"watchdog"),
    ("mmio", r"\bmmio\b|memory.?mapped|register (?:access|write|read)"),
    ("dma", r"\bdma\b"),
    ("timeout", r"timeout|deadline|busy.?wait|infinite loop"),
    ("reset-behavior", r"\breset\b|reboot|power.?on"),
    ("protocol-parsing", r"protocol|packet|frame header|decoder|\btlv\b"),
    ("input-validation", r"input validation|unvalidated|untrusted input|sanitiz"),
    ("trust-boundary", r"trust boundary|privilege|attacker.?controlled"),
    ("crypto-misuse", r"crypto|cipher|\baes\b|\brsa\b|\bhmac\b|nonce"),
    ("hardcoded-secret", r"hard.?coded (?:key|secret|password|credential)|api key"),
    ("info-leak", r"information (?:leak|disclosure)|leaks? (?:the )?(?:key|address|memory)"),
    ("authentication", r"authenticat|authoriz|password check"),
    ("firmware-update", r"firmware update|\bota\b|image signature|signature verif"),
    ("debug-backdoor", r"backdoor|debug port|\bjtag\b|\bswd\b"),
    ("stack-usage", r"stack (?:usage|overflow|frame)|alloca|variable.?length array"),
    ("undefined-behavior", r"undefined behaviou?r|strict aliasing|unsequenced"),
    ("sign-conversion", r"sign.?(?:ed )?conversion|signed.?unsigned|narrowing"),
    ("error-path", r"error path|on failure|early return|without (?:releasing|unlocking|freeing|closing)"),
    ("unchecked-return", r"unchecked return|return value (?:is )?ignored|ignores? the (?:return|result)|discarded result"),
    ("handle-misuse", r"after (?:it is |being )?closed|double close|closed twice|released twice|use.?after.?close"),
    ("state-machine", r"state machine|\bfsm\b|transition"),
    ("inverted-condition", r"inverted|reversed (?:condition|check)|wrong sense|negat(?:ed|ion) of the wrong"),
    ("dead-code", r"dead code|never (?:read|executed|used)|overwritten before"),
    ("unreachable-branch", r"unreachable|always (?:true|false)|cannot execute"),
)


_CATEGORY_ALIASES = {
    "": "unknown",
    "other": "unknown",
    "out-of-bounds": "buffer",
    "unsafe-copy": "buffer",
    "overflow": "buffer",
    "use-after-free": "lifetime",
    "undefined-behaviour": "undefined-behavior",
    "concurrency": "race",
    "isr": "isr-safety",
    "isr-race": "isr-safety",
    "interrupt": "isr-safety",
    "register-access": "mmio",
    "reset-behaviour": "reset-behavior",
    "information-leak": "info-leak",
    "volatile": "volatile-misuse",
    "rtos": "rtos-sync",
    "secrets": "hardcoded-secret",
    "hardcoded-key": "hardcoded-secret",
    "crypto": "crypto-misuse",
    "protocol": "protocol-parsing",
    "auth": "authentication",
    "leak": "resource-leak",
    "memory-leak": "resource-leak",
    "error-handling": "error-path",
    "ignored-return": "unchecked-return",
    "fsm": "state-machine",
    "unreachable": "unreachable-branch",
    "unreachable-code": "unreachable-branch",
}


# The static rule set the review layer freezes for its own overlap groups
# (review.py _finding_category, the CWE sets inlined there at 4dbb5c0).
# Every category a static row can be classified as.  Derived from the tables
# themselves so the two vocabularies cannot drift apart silently.
_SHARED_CATEGORIES: frozenset[str] = frozenset()


_FROZEN_STATIC_CWES: tuple[tuple[str, frozenset[int]], ...] = (
    ("null-dereference", frozenset({476})),
    ("buffer", frozenset({119, 120, 121, 122, 124, 125, 126, 127, 131, 680, 787, 788, 805})),
    ("uninitialized", frozenset({457})),
    ("resource-leak", frozenset({401, 404, 772, 775})),
    ("format", frozenset({134})),
    ("randomness", frozenset({327, 330, 338})),
)


_SHARED_CATEGORIES = frozenset(
    {name for name, _numbers in _FROZEN_STATIC_CWES}
    | {name for name, _numbers in _CWE_CATEGORIES}
    | {name for name, _pattern in _KEYWORD_CATEGORIES}
)


def correlation_category(item: dict[str, Any]) -> str:
    """The category a finding correlates under, the same way for both engines.

    The review layer classifies static rows by six frozen rules so that static
    overlap group ids never move; here the full vocabulary applies to both
    engines, and CWE numbers are consulted BEFORE keyword rules.  Otherwise a
    flawfinder CWE-190 whose message says "integer overflow" lands in "buffer"
    via the static keyword table and never meets an LLM "integer-overflow".
    """
    declared = ""
    if item.get("engine") == "llm":
        raw = str(item.get("category", "")).strip().lower()
        declared = _CATEGORY_ALIASES.get(raw, raw)
        # A declared category that the static side can also produce is already
        # the meeting point, and it is the more accurate of the two: the alias
        # table exists to map a scanner's finer word onto the shared one.
        # Measured: llm-memory-safety reports `out-of-bounds` (-> buffer) with
        # CWE-129 on the same lines cppcheck reports CWE-788 (-> buffer).
        # Letting the CWE win there would split a correlation that the
        # declared name gets right.
        if declared in _SHARED_CATEGORIES:
            return declared
    value = f"{item.get('cwe', '')} {item.get('rule_id', '')} {item.get('message', '')}"
    match = re.search(r"CWE-?(\d+)", value, re.I)
    cwe = int(match.group(1)) if match else None
    if cwe is not None:
        for category, numbers in (*_FROZEN_STATIC_CWES, *_CWE_CATEGORIES):
            if cwe in numbers:
                # The shared CWE table wins over a declared name, for both
                # engines.  A scanner's vocabulary is finer than a static
                # tool's -- "error-path" where cppcheck says "memleak" -- and
                # correlating on the declared name alone kept two findings
                # that carry the SAME CWE on the same lines in two candidates,
                # one "llm-only" and one "static-only".  That does not just
                # lose a correlation: it inflates llm_only_confirmed, the one
                # metric the whole LLM layer is judged by.
                return category
    if declared:
        # Neither a shared category nor a shared CWE: the scanner's own word
        # stands, which is how state-machine, dead-code and the rest keep the
        # closed vocabulary that defines them.
        return declared
    for category, pattern in _LLM_KEYWORD_CATEGORIES:
        if re.search(pattern, value, re.I):
            return category
    return f"CWE-{cwe}" if cwe is not None else "unknown"

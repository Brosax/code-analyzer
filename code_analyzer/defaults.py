"""Constants that used to be settings.

v3 keeps nine settings (``settings.py``).  Everything else a request needs is a
property of the *kind* of endpoint it goes to, not a knob: the local GPU and a
third-party provider differ in how thinking is switched off, which field caps
the output, and how many requests may be in flight.  Measured values -- the
served window, the codec that works, the batch concurrency -- come from
``probe.json`` instead (``model/probe.py``).
"""
from __future__ import annotations

from typing import Any

# How each endpoint class is spoken to.  "local" is Ollama on the GPU host:
# reasoning_effort "none" is the only spelling its /v1 honours ("off" is HTTP
# 400, "low" still thinks -- measured 2026-09-03 and again 2026-09-22).
# "public" is an OpenAI-compatible third party such as b.ai's glm-5.3-flash,
# which always thinks, rejects "off", and caps output with
# max_completion_tokens; its thinking tokens count against that cap.
ENDPOINT_CLASSES: dict[str, dict[str, Any]] = {
    "local": {
        "reasoning": {"reasoning_effort": "none"},
        "max_tokens_field": "max_tokens",
        "chat_max_tokens": 1500,
        "lens_max_tokens": 2000,
        "max_concurrency": 8,
        "system_role": "system",
    },
    "public": {
        "reasoning": {"reasoning_effort": "low"},
        "max_tokens_field": "max_completion_tokens",
        "chat_max_tokens": 4000,
        "lens_max_tokens": 4000,
        "max_concurrency": 2,
        "system_role": "system",
    },
}

# A conversational turn that has produced nothing for this long is abandoned.
CHAT_TIMEOUT_SECONDS = 300.0
# A background request (extraction, lens, verify) may prefill a long prompt.
BATCH_TIMEOUT_SECONDS = 600.0
# Loading 17.7 GB of weights is not a failure; a probe that treats a cold
# load as "down" is what made /model's verdict flip with the host's state.
MODEL_LOAD_TIMEOUT_SECONDS = 180.0
# Background requests resume this long after the last interactive activity.
RESUME_BACKGROUND_AFTER_SECONDS = 30.0


def endpoint_class(kind: str) -> dict[str, Any]:
    try:
        return ENDPOINT_CLASSES[kind]
    except KeyError:
        raise ValueError(f"unknown endpoint class {kind!r}; expected one of {sorted(ENDPOINT_CLASSES)}") from None

"""Built-in LLM provider profiles.

A profile is a named bundle of ``endpoint`` / ``model`` / ``api_key_env``
defaults.  User-named profiles would need arbitrarily nested TOML tables, which
this strictly allow-listed configuration layer cannot express: ``_ALLOWED``
matches key sets by exact prefix and ``FIELD_REGISTRY`` must cover every schema
leaf.  Hence a fixed table plus an explicit-override rule (design doc 10.2).
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

PROFILES: dict[str, dict[str, str]] = {
    "gpu-host": {
        "endpoint": "https://gpu-host.internal:8000/v1",
        "model": "qwen3.6-27b",
        "api_key_env": "CODE_ANALYZER_LLM_API_KEY",
    },
    "openrouter": {
        "endpoint": "https://openrouter.ai/api/v1",
        "model": "stealth/ox-alpha",
        "api_key_env": "OPENROUTER_API_KEY",
    },
}

PROFILE_NAMES: tuple[str, ...] = tuple(PROFILES)
DEFAULT_PROFILE = "gpu-host"
PROFILE_KEYS: tuple[str, ...] = ("endpoint", "api_key_env", "model")

# Profiles that keep the scanned source on operator-controlled infrastructure.
LOCAL_PROFILES = frozenset({"gpu-host"})


def apply_profile(llm: dict[str, Any], sources: dict[str, str]) -> None:
    """Fill the profile-backed keys that no layer set explicitly.

    ``sources`` is the provenance map built while merging the configuration
    layers; it is the only way to tell a default apart from a value a file or
    the CLI deliberately set, and it is updated so the resolution is recorded.
    """
    name = llm.get("profile")
    profile = PROFILES.get(name) if isinstance(name, str) else None
    if profile is None:
        return  # validate_config reports the unknown profile name.
    for key in PROFILE_KEYS:
        path = f"llm.{key}"
        if sources.get(path, "default") != "default":
            continue
        llm[key] = profile[key]
        sources[path] = f"profile:{name}"


def is_local(profile: Any) -> bool:
    return str(profile or DEFAULT_PROFILE) in LOCAL_PROFILES


def third_party_warning(llm: Mapping[str, Any]) -> str | None:
    """The warning for a profile that sends scanned source off this machine."""
    name = str(llm.get("profile") or DEFAULT_PROFILE)
    if is_local(name):
        return None
    # Only the host is quoted: an endpoint may never carry userinfo, and this
    # message must not become a way for a credential to reach a terminal.
    host = _host(str(llm.get("endpoint") or PROFILES.get(name, {}).get("endpoint", "")))
    target = f" ({host})" if host else ""
    return (
        f"llm.profile '{name}' is a third-party cloud provider: the source code under "
        f"analysis leaves this machine, and is sent to the configured endpoint{target} and "
        "to the model providers behind it. The API key itself is never printed, exported "
        "or written to any artifact."
    )


def _host(endpoint: str) -> str:
    try:
        return urlsplit(endpoint).hostname or ""
    except ValueError:
        return ""

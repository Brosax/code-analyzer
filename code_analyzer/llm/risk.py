"""Risk tiering for scan units (design doc 5.5).

The tier only decides how much effort a unit gets, never whether it is
scanned: invariant 3 of the design doc forbids dropping code from the plan.
``min_tier`` is the floor that keeps that promise honest.

The signal tables are evaluated in tier order and the first row that matches
wins, so a module-scope remainder inside ``crypto/`` stays CRITICAL while the
same remainder in ordinary code falls to LOW.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import PurePosixPath
from typing import Any

from ..errors import UserError

RISK_TIERS: tuple[str, ...] = ("critical", "high", "medium", "low")
RISK_PROFILES: tuple[str, ...] = ("auto", *RISK_TIERS)

# Path components and symbol fragments that carry the signal.  Kept as plain
# tuples so the reasons emitted alongside a tier name the exact trigger.
_CRITICAL_PATH = (
    "bootloader", "boot", "crypto", "secure", "security", "ipc", "attest", "tls", "ssl",
    "keystore", "keys", "cert", "signature", "verify", "mpu", "trustzone", "psa",
)
_CRITICAL_SYMBOL = ("isr", "irq", "interrupt", "handler", "vector", "fault", "exception")
_HIGH_PATH = (
    "parse", "parser", "decode", "decoder", "codec", "proto", "protocol", "net", "network",
    "http", "tcp", "udp", "ip", "usb", "uart", "serial", "spi", "i2c", "can", "modbus",
    "packet", "frame", "message", "json", "xml", "asn1", "tlv", "dfu", "ota", "update",
    "firmware", "flash", "input", "command", "shell", "cli",
)
_HIGH_SYMBOL = (
    "parse", "parser", "decode", "decoder", "unpack", "deserialize", "recv", "receive", "read",
    "scan", "handle", "process", "validate", "check", "verify", "load", "import", "extract",
    "convert", "input", "packet", "frame", "message", "cmd", "command",
)
_LOW_PATH = ("led", "gpio", "config", "conf", "settings", "example", "demo", "test", "mock", "stub")
_LOW_SYMBOL = ("led", "gpio", "get", "is", "getter", "dump", "print", "log", "trace", "delay", "sleep")

_CAMEL = re.compile(r"[A-Z]+(?![a-z])|[A-Z][a-z]+|[a-z]+|\d+")
_LENGTH_PARAM = re.compile(r"\b(?:len|length|size|count|n|nbytes|num|sz|cb)\w*\b", re.IGNORECASE)
_OPAQUE_BUFFER = re.compile(r"\bvoid\s*\*|\b(?:unsigned\s+)?char\s*\*|\buint8_t\s*\*|\bu8\s*\*")


@dataclass(frozen=True)
class RiskProfile:
    """Resolved [llm] risk settings.  Overrides win; ``min_tier`` is a floor."""

    profile: str = "auto"
    min_tier: str = "low"
    overrides: tuple[tuple[str, str], ...] = ()

    def tier_for(self, unit: Mapping[str, Any]) -> tuple[str, tuple[str, ...]]:
        return classify(unit, profile=self)


def tier_rank(tier: str) -> int:
    """0 is the most severe tier; unknown tiers sort last."""
    try:
        return RISK_TIERS.index(str(tier).strip().lower())
    except ValueError:
        return len(RISK_TIERS)


def parse_overrides(values: Sequence[str]) -> tuple[tuple[str, str], ...]:
    """Parse the flat ``"glob=tier"`` list used by [llm].risk_overrides."""
    result: list[tuple[str, str]] = []
    for raw in values:
        text = str(raw).strip()
        if not text:
            continue
        pattern, separator, tier = text.rpartition("=")
        tier = tier.strip().lower()
        if not separator or not pattern.strip() or tier not in RISK_TIERS:
            raise UserError(
                f"invalid risk override '{raw}': expected \"<glob>=<tier>\" with tier in "
                f"{', '.join(RISK_TIERS)}"
            )
        result.append((pattern.strip(), tier))
    return tuple(result)


def profile_from_config(config: Mapping[str, Any] | None) -> RiskProfile:
    """Build a profile from a parsed configuration, tolerating an absent [llm]."""
    section = config.get("llm") if isinstance(config, Mapping) else None
    section = section if isinstance(section, Mapping) else {}
    profile = str(section.get("risk_profile", "auto")).strip().lower() or "auto"
    if profile not in RISK_PROFILES:
        raise UserError(f"unknown risk_profile '{profile}' (expected one of {', '.join(RISK_PROFILES)})")
    minimum = str(section.get("min_tier", "low")).strip().lower() or "low"
    if minimum not in RISK_TIERS:
        raise UserError(f"unknown min_tier '{minimum}' (expected one of {', '.join(RISK_TIERS)})")
    raw = section.get("risk_overrides", ())
    values = raw if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes)) else ()
    return RiskProfile(profile=profile, min_tier=minimum, overrides=parse_overrides(values))


def classify(unit: Mapping[str, Any], *, profile: RiskProfile | None = None) -> tuple[str, tuple[str, ...]]:
    """Return ``(tier, reasons)`` for one scan unit."""
    profile = profile or RiskProfile()
    path = str(unit.get("path", ""))
    name = str(unit.get("name", ""))
    kind = str(unit.get("kind", "function"))
    signature = str(unit.get("signature", ""))
    reasons: list[str] = []
    if profile.profile != "auto":
        tier = profile.profile
        reasons.append(f"risk_profile={profile.profile}")
    else:
        tier, reasons = _auto_tier(path, name, kind, signature, unit)
    override = _override(path, profile.overrides)
    if override is not None:
        tier = override[1]
        reasons = [*reasons, f"override:{override[0]}={override[1]}"]
    if tier_rank(tier) > tier_rank(profile.min_tier):
        tier = profile.min_tier
        reasons = [*reasons, f"min_tier={profile.min_tier}"]
    return tier, tuple(reasons)


def _auto_tier(
    path: str, name: str, kind: str, signature: str, unit: Mapping[str, Any]
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    parts = _fragments(path)
    words = _fragments(name)
    hits = [word for word in _CRITICAL_PATH if word in parts]
    if hits:
        reasons.append("path:" + ",".join(sorted(hits)))
        return "critical", reasons
    hits = [word for word in _CRITICAL_SYMBOL if word in words]
    if kind == "function" and hits:
        reasons.append("symbol:" + ",".join(sorted(hits)))
        return "critical", reasons
    if kind == "function" and _OPAQUE_BUFFER.search(signature) and _LENGTH_PARAM.search(_params(signature)):
        reasons.append("signature:opaque-buffer-with-length")
        return "critical", reasons
    hits = [word for word in _HIGH_PATH if word in parts]
    if hits:
        reasons.append("path:" + ",".join(sorted(hits)))
        return "high", reasons
    hits = [word for word in _HIGH_SYMBOL if word in words]
    if kind == "function" and hits:
        reasons.append("symbol:" + ",".join(sorted(hits)))
        return "high", reasons
    if kind != "function":
        reasons.append(f"kind:{kind}")
        return "low", reasons
    if unit.get("is_header"):
        reasons.append("header")
        return "low", reasons
    if unit.get("dead"):
        reasons.append("inactive-preprocessor-branch")
        return "low", reasons
    hits = [word for word in _LOW_PATH if word in parts]
    if hits:
        reasons.append("path:" + ",".join(sorted(hits)))
        return "low", reasons
    hits = [word for word in _LOW_SYMBOL if word in words]
    if hits:
        reasons.append("symbol:" + ",".join(sorted(hits)))
        return "low", reasons
    reasons.append("default")
    return "medium", reasons


def _fragments(text: str) -> set[str]:
    """Word fragments of a path or symbol, split on separators and camel case.

    Substring matching would tier ``enabled`` as LED code; fragments do not.
    """
    lowered = text.lower()
    words = {part for part in re.split(r"[^a-z0-9]+", lowered) if part}
    words |= {match.lower() for match in _CAMEL.findall(text)}
    return words | set(PurePosixPath(lowered).parts)


def _params(signature: str) -> str:
    start = signature.find("(")
    return signature[start:] if start >= 0 else ""


def _override(path: str, overrides: Sequence[tuple[str, str]]) -> tuple[str, str] | None:
    match: tuple[str, str] | None = None
    for pattern, tier in overrides:
        target = PurePosixPath(path)
        cleaned = pattern.rstrip("/")
        matched = (
            fnmatch(path, pattern)
            or fnmatch(target.name, pattern)
            or path == cleaned
            or path.startswith(cleaned + "/")
            or target.match(pattern)
        )
        if matched:
            match = (pattern, tier)
    return match

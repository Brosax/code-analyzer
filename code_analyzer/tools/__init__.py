"""Native analyzer adapters."""
from __future__ import annotations

from ..errors import UserError
from .adapter import Adapter, CompileDatabase, RunContext

# The single registry of supported analyzers, in canonical execution order.
TOOL_NAMES: tuple[str, ...] = ("cppcheck", "flawfinder", "splint")

# LLM scanners are producers, not native binaries: they have no executable to
# probe, no apt package, and no [tools.<name>] configuration section.
LLM_PRODUCERS: tuple[str, ...] = (
    "llm-memory-safety",
    "llm-security",
    "llm-firmware-concurrency",
    "llm-undefined-behavior",
    "llm-resource-error",
    "llm-logic",
)
PRODUCER_ORDER: tuple[str, ...] = TOOL_NAMES + LLM_PRODUCERS


def _registry() -> dict[str, Adapter]:
    # Imported inside the function so that importing ``TOOL_NAMES`` -- which
    # half the package does, including from modules the adapters themselves
    # reach -- never drags in the analyzer implementations.
    from . import cppcheck, flawfinder, splint

    declared = {module.ADAPTER.name: module.ADAPTER for module in (cppcheck, flawfinder, splint)}
    return {name: declared[name] for name in TOOL_NAMES}


def adapters() -> dict[str, Adapter]:
    """Every native adapter, keyed and ordered by ``TOOL_NAMES``."""
    global _ADAPTERS
    if _ADAPTERS is None:
        _ADAPTERS = _registry()
    return _ADAPTERS


def adapter(name: str) -> Adapter:
    """The adapter called ``name``.

    The only lookup.  An unknown name is a named error rather than a
    ``KeyError`` from a dictionary index buried outside a ``try``, and rather
    than the silent fallthrough that used to hand any unknown tool to splint.
    """
    try:
        return adapters()[name]
    except KeyError:
        raise UserError(
            f"unknown analyzer {name!r}: supported analyzers are {', '.join(TOOL_NAMES)}"
        ) from None


_ADAPTERS: dict[str, Adapter] | None = None

__all__ = [
    "Adapter",
    "CompileDatabase",
    "LLM_PRODUCERS",
    "PRODUCER_ORDER",
    "RunContext",
    "TOOL_NAMES",
    "adapter",
    "adapters",
]

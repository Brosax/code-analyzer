"""Native analyzer adapters."""

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

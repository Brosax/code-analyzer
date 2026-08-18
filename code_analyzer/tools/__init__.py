"""Native analyzer adapters."""

# The single registry of supported analyzers, in canonical execution order.
TOOL_NAMES: tuple[str, ...] = ("cppcheck", "flawfinder", "splint")

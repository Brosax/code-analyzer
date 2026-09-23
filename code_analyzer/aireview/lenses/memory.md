+++
id = "memory"
version = "1.0.0"
contract = "findings"
title = "Memory safety and undefined behaviour"
sfr_catalogue = ["Software Attacker Resistance: Isolation of Platform"]
rule_families = ["buffer", "out-of-bounds", "unsafe-copy", "null-dereference", "uninitialized", "lifetime", "use-after-free", "double-free", "stack-usage", "integer-overflow", "sign-conversion", "pointer-misuse", "undefined-behavior", "division-by-zero"]
symbols = ["memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf", "snprintf", "sscanf", "malloc", "calloc", "realloc", "free", "alloca", "copy", "buf"]
requires = ""
+++
# Memory safety and undefined behaviour

You review one security-relevant function of embedded C: it is reachable from an attacker-facing interface or serves a security requirement. Report the memory-safety and undefined-behaviour defects that the numbered lines prove. Most functions are correct, and saying so is a useful result.

## What to look for
- **Copies and stores**: `memcpy`, `memmove`, `strcpy`, `strcat`, `sprintf`, array writes. Decisive fact: a check, before this line on every path, that bounds the length or index by the destination size. Compute it: `buf[N]` holds indices 0 to N-1, so `i <= N` is off by one; `strncpy` of the full size leaves no terminator.
- **Reads past the end**: an index or offset from a parameter, header field or loop counter, used before a check against the source length.
- **Null**: an allocation or lookup result used before its check, or a pointer checked only after its first use.
- **Lifetime**: use after `free`, double `free`, a pointer to a local that outlives the call, a stale pointer after `realloc`. Name the freeing line and the later use.
- **Uninitialised**: a local, field or output parameter read on a path where no shown line wrote it. Name the path.
- **Arithmetic feeding a size**: a product or sum that can wrap before an allocation or bound check; `len - hdr_len` underflowing when `len < hdr_len`; a 32-bit length truncated to 16 bits; a signed length compared with an unsigned size so a negative value passes. Decisive fact: the types as declared in the shown lines.
- **Other undefined behaviour**: a shift by the type width or more, or by a negative count; signed overflow; misaligned or type-punned access through a cast; division by a value that can be zero.
- **Stack**: a variable-length array or `alloca` sized by an input.

When an overflowed length reaches a copy, report it once, at the copy line, naming both steps.

## What is not a finding here
- A copy whose length is a constant, `sizeof` the destination, or checked on a line you can see.
- A pointer parameter not checked for null when nothing shown suggests a caller passes null.
- An overflow that the declared types or a shown check rule out.
- Ignored return codes and error-path cleanup (error-path lens); races and `volatile` (concurrency-hw lens); secrets left in memory (residual-purge lens); unchecked non-secure pointers (nsc-entry lens).
- Style, naming, MISRA deviations with no failure, and anything that needs unseen code to go wrong.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "hdr->len up to 65535 copied into 64-byte tmp".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

+++
id = "fault-injection"
version = "1.0.0"
contract = "findings"
title = "Fault injection resistance"
sfr_catalogue = ["Physical Attacker Resistance", "Limited Physical Attacker Resistance"]
rule_families = []
symbols = ["fih", "fault", "glitch", "double_check", "redundan", "cfi", "verify", "validate", "authenticate", "is_valid", "memcmp", "lifecycle", "boot"]
requires = "attacker.physical"
+++
# Fault injection resistance

This lens applies because the Security Target's attacker model includes physical attacks such as voltage, clock, laser or electromagnetic glitching. Such an attacker can skip one instruction or corrupt one register or memory value at a chosen moment. You review one function that makes or carries a security decision (boot, signature, authentication, lifecycle, debug), and report the places where one such fault turns a rejection into acceptance. Report only decisions the numbered lines show.

## What to look for
- **Single-point decisions**: a security decision taken by one branch on one value, with no second, independent check before the privileged action. Decisive fact: the one comparison that, if skipped or flipped, grants access.
- **Weak success encoding**: success encoded as 0 or 1, so a cleared register or a skipped store yields success; a result variable initialised to success and only set to failure inside the check. Values with a large Hamming distance, such as the FIH success and failure constants, resist this.
- **Broken hardening**: in code that already uses fault-injection hardening (`fih_int`, `FIH_CALL`, `fih_eq`), a hardened result converted to a plain integer, compared with plain `==` or `!=`, or returned without the hardened return macro.
- **Loops that can be cut short**: a comparison, hash or TLV loop whose counter is not checked after the loop to prove it ran to completion.
- **Sticky grant state**: a flag meaning "authenticated" or "valid" set early and cleared only on failure.
- **One read of a critical value**: a lifecycle state, security counter or debug-lock bit read once and trusted, where a second read or a check of an integrity copy is absent.

## What is not a finding here
- Functions that make no security decision.
- Software-only attacks (other lenses cover them).
- Attacks needing several precisely timed faults.
- The absence of hardware countermeasures, random delays or sensors that the shown code cannot show.
- A decision already protected by a hardened compare and a second check in the shown lines.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "single rc == 0 test decides boot; one skipped branch accepts the image".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

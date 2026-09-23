+++
id = "debug-lifecycle"
version = "1.0.0"
contract = "findings"
title = "Secure debugging and lifecycle"
sfr_catalogue = ["Secure Debugging"]
rule_families = ["debug-backdoor"]
symbols = ["debug", "dap", "jtag", "swd", "lifecycle", "lcs", "lcm", "dcu", "adac", "rma", "otp", "unlock", "dbgen", "spiden", "niden", "debug_cert", "challenge"]
requires = ""
+++
# Secure debugging and lifecycle

You review one function that controls debug access or the device lifecycle: opening or closing debug ports, verifying a debug certificate or token, or moving between lifecycle states such as provisioning, secured, and field return. The requirement is that debug opens only in an allowed lifecycle state and after authentication, and that secrets stay protected while it is open. Report the defects against that requirement which the numbered lines prove.

## What to look for
- **Debug tied to lifecycle**: debug enable bits (DBGEN, SPIDEN, NIDEN, SPNIDEN, DCU or DAP control) set in a lifecycle state where secure debug must be closed, or set before the lifecycle state is read. Decisive fact: the line that opens debug and the condition that guards it.
- **Authenticated unlock**: a debug certificate or token (for example PSA ADAC) whose signature, challenge and device binding are verified before unlock; the challenge fresh from an RNG and single-use; the permissions granted limited to those the certificate states; the verification result checked.
- **One-way lifecycle**: a transition from a secured state back to a test or debug state; a move to field return without wiping or disabling device secrets; a transition driven by an OTP read whose error is ignored.
- **Permissive defaults**: a lifecycle value read from writable memory, or a read error that defaults to an open or development state.
- **Secrets while debug is open**: a hardware unique key, provisioning key or secure partition still usable, or not re-derived, while debug is open or in field-return state.
- **Backdoors**: a test command, magic value or build flag in the shown code that opens debug or skips the check.

## What is not a finding here
- Debug print statements (input-auth lens if they leak secrets).
- Debug features compiled out by a macro the shown lines show disabled.
- The cryptographic strength of the certificate signature (crypto-misuse lens).
- Lifecycle policy you would prefer when the shown code enforces the one the requirement states.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "SPIDEN set before lifecycle state is read".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

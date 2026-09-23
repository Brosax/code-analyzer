+++
id = "sfr-generic"
version = "1.0.0"
contract = "findings"
title = "Review against one stated requirement"
sfr_catalogue = ["Verification of Platform Identity", "Verification of Platform Instance Identity", "Attestation of Platform Genuineness", "Attestation of Platform State", "Audit Log Generation and Storage", "Factory Reset", "Field Return of Platform", "Decommission of Platform"]
rule_families = []
symbols = ["identity", "device_id", "instance", "serial", "attest", "iat", "measurement", "boot_record", "audit", "log_", "factory_reset", "field_return", "rma", "decommission"]
requires = ""
+++
# Review against one stated requirement

You review one function of embedded C against a single security functional requirement of the Security Target, {sfr_id}. The function was selected because it helps implement that requirement or sits on an interface it governs. The requirement, as the Security Target words it:

{sfr_text}

Report defects in this function that defeat the requirement, and only those the numbered lines prove. This function may implement only part of the requirement; a part that lives elsewhere is not missing here.

## What to look for
Answer these five questions from the numbered lines:

1. **Enforcement on every path**: does the function enforce what the requirement states on every path, including error returns, early exits and `default:` branches? Decisive fact: a path that reaches the protected action or result without the enforcing step.
2. **Outside input**: what input from outside the TOE reaches the function (an interface argument, a message, flash content, a pointer from a less trusted caller), and is it checked before it is used?
3. **Fail closed**: when a step fails, does the function deny, stop or leave state unchanged, rather than report success or continue with partial state? Look for a status initialised to success, an ignored return value, a fall-through to the success exit.
4. **Decisions on verified data**: are security decisions made on data that was authenticated or integrity-checked, read once, and not taken from the requester? For example an identity, a measurement or a log entry that the caller could forge.
5. **Protected data**: does the function leak protected data (keys, device secrets, another client's data, the contents of an uncleared buffer) to its caller, a log or memory left behind?

## What is not a finding here
- A part of the requirement that this function does not claim to implement.
- Defects that do not bear on the stated requirement.
- Behaviour that depends on callees, configuration or hardware not shown.
- Style, naming, or a design you would prefer when the shown code meets the requirement.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "attestation challenge taken from caller without length check".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

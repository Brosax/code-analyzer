+++
id = "secure-boot"
version = "1.0.0"
contract = "findings"
title = "Secure initialisation of the platform"
sfr_catalogue = ["Secure Initialization of Platform"]
rule_families = []
symbols = ["boot", "bl1", "bl2", "bootutil", "mcuboot", "image_validate", "verify_image", "img_hdr", "image_header", "image_hash", "tlv", "boot_record", "measure", "nv_counter", "security_cnt", "fih", "jump", "vtor"]
requires = ""
+++
# Secure initialisation of the platform

You review one function of a boot stage (ROM, BL1, BL2 or MCUboot, or early secure runtime). The requirement is that only an authentic, integrity-checked, non-rolled-back image runs, and that any failure stops the boot. Report the defects against that requirement which the numbered lines prove.

## What to look for
- **Header parsing**: header size, TLV offset and length, image size or load address read from flash and used without a check against the slot size or TLV area, or with `hdr_size + img_size` able to wrap. Decisive fact: the check and its arithmetic.
- **Coverage of the hash and signature**: a hash over a range that does not cover what will run (header, protected TLVs, the whole image), or over a length from an unverified field; a signature checked against a hash other than the one computed; the verification key chosen from the image without comparing it to the provisioned key hash.
- **Verify then use**: the image or header validated in one place and executed, copied or re-read from a place an attacker can change in between. Decisive fact: validation and use on different buffers, or a field read twice.
- **Fail closed**: every error from hash, signature, TLV walk, counter read or flash read must stop the boot or reject the image. Look for a result overwritten before its test, an error path that falls through to the jump, a missing signature TLV treated as success, a `default:` returning success, a configuration flag in the shown code that skips validation.
- **Anti-rollback**: the image's security counter compared with the stored counter before the boot decision, in the right direction and width; the stored counter advanced only after validation succeeds; a counter read failure treated as failure.
- **Measured boot**: the measurement recorded over the image that actually boots, before the jump; a failed record ignored when attestation relies on it.
- **Handover**: a jump to an entry point from the image not checked to lie inside the validated image; protection (MPU, SAU, debug, key access) not locked before the jump.

## What is not a finding here
- Missing redundant checks against glitching (fault-injection lens, used only when a physical attacker is in scope).
- Cryptographic primitive internals (crypto-misuse lens); installing or swapping an update (update-rollback lens).
- Code under a configuration macro that the shown lines show disabled.
- Style, or a hardening you would prefer when nothing shown fails.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "TLV walk error ignored; boot continues to jump".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

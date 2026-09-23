+++
id = "update-rollback"
version = "1.0.0"
contract = "findings"
title = "Secure update and anti-rollback"
sfr_catalogue = ["Secure Update of Platform"]
rule_families = ["firmware-update"]
symbols = ["update", "fwu", "firmware_update", "upgrade", "install", "swap", "revert", "rollback", "downgrade", "trailer", "image_ok", "copy_done", "scratch", "slot", "version", "security_cnt", "nv_counter", "confirm"]
requires = ""
+++
# Secure update and anti-rollback

You review one function of a firmware update path: receiving, staging, validating, installing, swapping, confirming or reverting an image. The requirement is that only an authentic, intact image of an allowed version is installed, and that no sequence of steps or power loss lets an older or unverified image run. Report the defects against that requirement which the numbered lines prove.

## What to look for
- **Authenticate before install**: the signature and hash of the new image validated before it is written to the active slot, marked pending or executed. Decisive fact: the order of the validate call and the write or mark call.
- **Same bytes**: the validated buffer and the installed bytes are the same, not re-read from an attacker-writable staging area after validation.
- **Version monotonicity**: the new version or security counter compared with the stored one in the right direction and width (`<` against `<=`, signed against unsigned, an 8-bit field wrapping in a semantic version compare); the compared value taken from the validated image; the stored counter advanced only after the new image is confirmed, and never lowered.
- **Downgrade paths**: a test, revert or recovery mode that installs an image without the version check, or reverts to an image the stored counter should now reject.
- **Swap and trailer state**: swap status, magic, `image_ok` or `copy_done` read without a check and trusted; `image_ok` set before the new image confirmed itself.
- **Power loss**: an erase, write and status sequence that, interrupted at any step, resumes into a half-copied or unverified image; status written before the data it describes.
- **Errors**: a flash write or erase result ignored so a failed install still marks the slot valid; a validation error that leaves the image pending.
- **Sizes**: image size against slot size, and offsets inside the update payload, bounded before use.

## What is not a finding here
- Boot-time validation of an installed image (secure-boot lens), unless this function is on the update path.
- Transport security of the download (input-auth lens).
- Missing features, such as no encryption of the image, unless the requirement shown demands them.
- Hypothetical power-loss states that the shown sequence cannot produce.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "security counter compared with <= so an equal-version image downgrades".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

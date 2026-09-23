+++
id = "residual-purge"
version = "1.0.0"
contract = "findings"
title = "Residual information purging"
sfr_catalogue = ["Residual Information Purging"]
rule_families = []
symbols = ["zeroize", "zeroise", "memset", "wipe", "scrub", "cleanse", "clear", "purge", "erase", "explicit_bzero", "memset_s", "secure_zero", "free", "destroy", "plaintext", "secret"]
requires = ""
+++
# Residual information purging

You review one function that handles secret data: keys, plaintext, passwords, derived material, or the working state of a cipher, hash or MAC. The requirement is that such data is removed from memory as soon as it is no longer needed, on every path. Report the defects against that requirement which the numbered lines prove. Name the secret for every finding and say where it came from.

## What to look for
- **Every exit path**: a buffer holding a secret cleared on the success path but not on an error return or a `goto` that jumps past the clear. Decisive fact: a return after the secret is written and before the clear.
- **A clear the compiler may remove**: a plain `memset` to zero on a local or stack buffer, or on memory about to be freed, as the last use of that buffer. It needs a clear the compiler must keep, such as `mbedtls_platform_zeroize`, `memset_s`, `explicit_bzero` or a volatile-pointer loop.
- **Wrong size**: a clear of `sizeof` a pointer instead of the buffer, or a length shorter than what was written.
- **Stack secrets**: a stack array holding a secret that is never cleared before return; a secret copied into a structure passed or returned by value.
- **Heap**: `free` of a buffer holding a secret without clearing it first; `realloc` of such a buffer, which can leave the old copy behind.
- **Crypto contexts**: a cipher, hash or MAC context holding key schedule or state not released with its free or abort function on an error path.
- **Reused buffers**: a shared or static work buffer that held one caller's secret, reused for another caller without clearing.

## What is not a finding here
- Buffers holding only public data: ciphertext, public keys, hashes of public data.
- A plain `memset` on a buffer that is read again afterwards; the compiler cannot remove it.
- A clear performed by a callee that the shown code or context identifies as a zeroize helper.
- Secrets in registers, caches or flash, which the shown code cannot prove anything about.
- Key export or ownership (key-isolation lens).

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "derived key in stack buffer tmp not cleared on the error return".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

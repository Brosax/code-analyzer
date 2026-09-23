+++
id = "crypto-misuse"
version = "1.0.0"
contract = "findings"
title = "Cryptographic misuse"
sfr_catalogue = ["Cryptographic Operation", "Cryptographic Random Number Generation"]
rule_families = ["crypto-misuse", "randomness"]
symbols = ["crypto", "aes", "sha2", "hmac", "cmac", "ecdsa", "rsa", "gcm", "ccm", "cipher", "nonce", "rng", "random", "drbg", "entropy", "mbedtls", "memcmp", "signature", "verify"]
requires = ""
+++
# Cryptographic misuse

You review one function of embedded C that calls, wraps or implements cryptography. Report the misuse the numbered lines prove: a result ignored, a secret compared in variable time, a nonce reused, a weak mode or size, randomness that fails silently. Judge how primitives are used, not their internal mathematics.

## What to look for
- **Variable-time comparison of a secret**: `memcmp`, `strcmp` or an early-exit loop over a MAC, tag, signature, password or token. Decisive fact: the compare line and that one operand is secret-derived. A helper that accumulates differences over the full length is fine.
- **Ignored result**: the return code of a verify, decrypt, MAC check, hash, key generation or RNG call not tested, or tested while the function carries on as if it succeeded; a verification result stored and never read.
- **Wrong success test**: the wrong sense or constant; a tag compared over a length taken from the input instead of the expected tag length; a zero-length tag or signature accepted.
- **IV and nonce**: a fixed, zero or constant nonce with CTR, GCM, CCM or ChaCha20 under one key; a nonce counter not advanced, or not persisted so it repeats after reset.
- **Weak mode or algorithm in a security decision**: ECB over more than one block; DES, 3DES, RC4, MD5 or SHA-1 for integrity or authenticity; CBC or CTR without integrity where integrity is required; RSA PKCS#1 v1.5 decryption with distinguishable errors.
- **Key size and parameters**: RSA below 2048 bits, curves below 256 bits, a key length or curve or hash identifier taken from input without checking it against an allowed set.
- **Randomness**: `rand`, `srand` or a time-seeded generator for keys, nonces, challenges or IVs; the status of a TRNG or DRBG call ignored, so an unfilled buffer is used as random; a health-test or reseed failure ignored.
- **Keys from constants**: a key or seed computed only from a constant or a public device identifier.

## What is not a finding here
- `memcmp` on public data: a key identifier, magic number, version or public key.
- A hash used as a checksum or lookup with no security decision on it.
- A timing side channel where no shown line compares, indexes or branches on secret data. Do not claim one otherwise.
- Where keys are stored or copied (key-isolation lens); wiping secrets (residual-purge lens); hardcoded credentials (input-auth lens).
- Algorithm choices you merely dislike when nothing shown puts them in security use.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "HMAC tag compared with memcmp; early exit leaks match length".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

+++
id = "key-isolation"
version = "1.0.0"
contract = "findings"
title = "Key isolation in the keystore"
sfr_catalogue = ["Cryptographic KeyStore"]
rule_families = []
symbols = ["keystore", "key_slot", "key_id", "key_handle", "builtin_key", "huk", "kmu", "derive", "kdf", "export_key", "import_key", "get_key", "key_policy", "key_attr", "owner", "key_buf"]
requires = ""
+++
# Key isolation in the keystore

You review one function of a keystore or key-management service: importing, generating, looking up, using, exporting, deriving or destroying keys. The requirement is that key material stays inside the keystore, that each caller reaches only its own keys, and that each key is used only as its policy allows. Report the defects against that requirement which the numbered lines prove.

## What to look for
- **Key bytes leaving**: key material copied into a caller-supplied buffer, an output vector, non-secure memory, a log or a response. Decisive fact: the destination of the copy, and whether the key's export permission is checked first.
- **Ownership**: a key id, handle or slot index from the caller used to find a key without checking that the caller owns it; the owner taken from the request instead of the caller identity the platform established; an index used before a range check.
- **Usage policy**: the key's permitted algorithm and usage (sign, decrypt, derive, export) not checked against the requested operation; the policy checked on one slot and a different slot used.
- **Builtin keys and the HUK**: a raw hardware unique key or builtin key returned or copied out; a derivation whose label or context comes from the caller without the caller's identity, so two partitions derive the same key; a key slot not locked after loading.
- **Destruction**: a destroyed key's slot still usable, or reused while still holding the old key; a destroy that frees the slot without clearing it.
- **Lengths**: a stored key length larger than its buffer, or an output buffer size not checked against the key length before writing.

## What is not a finding here
- Algorithm or key-size choices (crypto-misuse lens).
- Buffers cleared on every exit path in general (residual-purge lens); report here only a destroyed key that stays usable.
- Hardcoded keys in source (input-auth lens).
- Exporting a public key, or a key whose shown policy allows export.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "key_id from caller looked up without owner check".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

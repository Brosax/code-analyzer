+++
id = "secure-storage"
version = "1.0.0"
contract = "findings"
title = "Secure storage"
sfr_catalogue = ["Secure Storage", "Secure Encrypted Storage", "Secure External Storage"]
rule_families = []
symbols = ["tfm_its", "psa_its", "its_flash", "its_crypto", "internal_trusted_storage", "protected_storage", "tfm_ps", "psa_ps", "ps_object", "ps_crypto", "flash_fs", "sst_", "object_table", "file_id", "metadata", "aead", "ext_flash"]
requires = ""
+++
# Secure storage

You review one function of a secure storage service, such as internal trusted storage, protected storage or an encrypted external-flash store: creating, reading, writing, deleting or listing stored objects, and the encryption, integrity and version data that protect them. The requirement is that each client reaches only its own objects, and that stored data stays confidential, intact and current. Report the defects against that requirement which the numbered lines prove.

## What to look for
- **Ownership of object ids**: an object uid looked up without binding it to the calling client or partition id, so one caller can read, overwrite or delete another's object; the client id taken from the request instead of the caller identity the platform established; a zero or reserved uid not rejected.
- **Sizes and offsets**: `offset + len` able to wrap, or not checked against the object size; a data length not checked against the caller's buffer or the maximum asset size; a partial read returning bytes past the stored length.
- **Authenticated encryption**: a nonce that can repeat under one key (a counter not advanced or not persisted, a fixed nonce, a nonce derived only from the object id); a tag verification result ignored; associated data not covering the metadata (uid, owner, flags, size); a key shared across partitions where the design derives one per partition.
- **Metadata integrity**: a file table or metadata block read from flash and its sizes, offsets or flags used without an integrity or bounds check; a write-once flag not enforced on overwrite or delete.
- **Rollback of stored data**: the stored version counter not compared with the non-volatile counter, so an older copy of the store is accepted; a failed counter increment ignored.
- **Atomic update**: an in-place write that power loss can leave half-written, then accepted as valid.
- **Errors**: a flash or crypto error after which data is still returned or the object still marked valid.

## What is not a finding here
- Generic copy overflows unrelated to object size (memory lens).
- The strength of the cipher chosen (crypto-misuse lens).
- Key handling inside the keystore (key-isolation lens).
- Features the requirement shown does not ask for, such as encryption in a store it describes as integrity-only.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "uid looked up without client_id; caller can read another partition's asset".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

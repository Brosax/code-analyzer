"""The SESIP security functional requirement catalogue, as extraction and review anchors.

Names follow GlobalPlatform SESIP (GPT_SPE_150).  A Security Target picks and
refines a subset; the profile records the ST's own ids and wording, and uses
``catalogue`` to point back here.  ``keywords`` only ever make a *weak* link
between code and an SFR (shown, never used for ranking); ``families`` are the
finding categories whose defects directly defeat the requirement, a strong
link.  ``lens`` names the review lens that serves the requirement (M7).
"""
from __future__ import annotations

from typing import Any

CATALOGUE: tuple[dict[str, Any], ...] = (
    {"name": "Verification of Platform Identity", "keywords": ["identity", "device_id", "uid"],
     "families": [], "lens": "sfr-generic"},
    {"name": "Verification of Platform Instance Identity", "keywords": ["instance", "serial", "uid"],
     "families": [], "lens": "sfr-generic"},
    {"name": "Attestation of Platform Genuineness", "keywords": ["attest", "token", "iat"],
     "families": [], "lens": "sfr-generic"},
    {"name": "Attestation of Platform State", "keywords": ["attest", "measurement", "boot_record"],
     "families": [], "lens": "sfr-generic"},
    {"name": "Secure Initialization of Platform", "keywords": ["boot", "bl1", "bl2", "image_validate", "mcuboot"],
     "families": [], "lens": "secure-boot"},
    {"name": "Secure Update of Platform", "keywords": ["update", "fwu", "firmware_update", "rollback", "swap"],
     "families": [], "lens": "update-rollback"},
    {"name": "Secure Communication Support", "keywords": ["tls", "channel", "mbedtls_ssl"],
     "families": [], "lens": "input-auth"},
    {"name": "Secure Communication Enforcement", "keywords": ["tls", "channel"],
     "families": [], "lens": "input-auth"},
    {"name": "Secure Storage", "keywords": ["its", "internal_trusted_storage", "protected_storage", "ps_", "flash_fs"],
     "families": [], "lens": "secure-storage"},
    {"name": "Secure Encrypted Storage", "keywords": ["its_encryption", "ps_crypto", "aead"],
     "families": [], "lens": "secure-storage"},
    {"name": "Secure External Storage", "keywords": ["external_flash", "ext_flash"],
     "families": [], "lens": "secure-storage"},
    {"name": "Secure Debugging", "keywords": ["debug", "dap", "jtag", "swd", "lifecycle", "lcs"],
     "families": [], "lens": "debug-lifecycle"},
    {"name": "Cryptographic Operation", "keywords": ["crypto", "aes", "sha", "ecdsa", "rsa", "psa_crypto"],
     "families": ["crypto-misuse"], "lens": "crypto-misuse"},
    {"name": "Cryptographic Random Number Generation", "keywords": ["rng", "random", "trng", "drbg", "entropy"],
     "families": ["randomness"], "lens": "crypto-misuse"},
    {"name": "Cryptographic KeyStore", "keywords": ["key", "keystore", "huk", "kmu", "builtin_key"],
     "families": [], "lens": "key-isolation"},
    {"name": "Residual Information Purging", "keywords": ["zeroize", "memset", "wipe", "scrub", "clear"],
     "families": [], "lens": "residual-purge"},
    {"name": "Audit Log Generation and Storage", "keywords": ["audit", "log"],
     "families": [], "lens": "sfr-generic"},
    {"name": "Software Attacker Resistance: Isolation of Platform", "keywords": ["spm", "partition", "isolation",
                                                                              "mpu", "sau", "nsc", "veneer"],
     "families": ["buffer", "null-dereference", "use-after-free", "double-free", "integer-overflow",
                  "uninitialized"], "lens": "nsc-entry"},
    {"name": "Software Attacker Resistance: Isolation of Platform Parts", "keywords": ["partition", "isolation_level"],
     "families": [], "lens": "nsc-entry"},
    {"name": "Physical Attacker Resistance", "keywords": ["fih", "fault", "glitch", "double_check"],
     "families": [], "lens": "fault-injection"},
    {"name": "Limited Physical Attacker Resistance", "keywords": ["fih", "fault"],
     "families": [], "lens": "fault-injection"},
    {"name": "Factory Reset", "keywords": ["factory_reset", "reset"], "families": [], "lens": "sfr-generic"},
    {"name": "Field Return of Platform", "keywords": ["field_return", "rma"], "families": [], "lens": "sfr-generic"},
    {"name": "Decommission of Platform", "keywords": ["decommission"], "families": [], "lens": "sfr-generic"},
)

BY_NAME: dict[str, dict[str, Any]] = {entry["name"]: entry for entry in CATALOGUE}


def entry(name: str) -> dict[str, Any] | None:
    return BY_NAME.get(name)

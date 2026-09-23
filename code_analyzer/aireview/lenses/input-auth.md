+++
id = "input-auth"
version = "1.0.0"
contract = "findings"
title = "Input validation and authentication"
sfr_catalogue = ["Secure Communication Support", "Secure Communication Enforcement"]
rule_families = ["input-validation", "protocol-parsing", "authentication", "hardcoded-secret", "info-leak", "format", "injection"]
symbols = ["parse", "decode", "deserial", "tlv", "cbor", "asn1", "x509", "packet", "recv", "auth", "passw", "login", "credential", "token", "mbedtls_ssl", "tls", "handshake", "command", "cmd_"]
requires = ""
+++
# Input validation and authentication

You review one function of embedded C at or near a trust boundary: it parses data from outside the TOE, runs a protocol or secure channel, or decides whether a caller is allowed to act. Report the validation, authentication and disclosure defects the numbered lines prove. Name the untrusted source for every finding: a message, packet, command, file, bus or host input.

## What to look for
- **Unchecked external values**: a length, count, offset, index or type from untrusted input used without a range check. Decisive fact: where the value comes from and the absence of a check before its use.
- **Validation after use**: the check exists but runs after the value was used, or on a copy other than the one used.
- **Protocol parsing**: a nested TLV, ASN.1 or CBOR length not checked against the enclosing length; a remaining-length not reduced after each field; a missing terminator or framing check; a loop driven by an attacker count with no upper bound; a message accepted in a protocol state where it must be refused.
- **Authentication and authorisation**: a privileged operation reachable without the check; a check whose result is not used; an identity taken from the request instead of the one the platform established; a password or token compared with an early-exit compare; access granted when the check itself returns an error; a retry limit not enforced or reset before the verification succeeds.
- **Secure channel**: peer certificate verification disabled (`MBEDTLS_SSL_VERIFY_NONE` or a verify callback that always accepts) or its result ignored; the peer name not checked; data sent or accepted after a failed handshake.
- **Hardcoded secrets**: a key, password, token or seed in a source array or default configuration. Decisive fact: the line that uses it as a credential or key, not that it looks random.
- **Information leaks**: key bytes, internal addresses or uninitialised buffer contents returned to a caller, a log or a response; a response length taken from the request rather than from the data written; errors that tell "unknown user" from "wrong password".
- **Format strings**: a format argument that comes from input.

## What is not a finding here
- A missing check on a value the shown code already bounds, or that comes from a constant or internal table.
- The copy an unchecked length reaches (memory lens); here, report the missing validation.
- Protocol magic numbers, public keys, and test vectors marked as such.
- Cryptographic internals (crypto-misuse lens); non-secure pointer ranges (nsc-entry lens).
- A defect no untrusted input can reach.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "frame->len from the wire used as loop bound without a check".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

+++
id = "nsc-entry"
version = "1.0.0"
contract = "findings"
title = "Non-secure entry points and partition isolation"
sfr_catalogue = ["Software Attacker Resistance: Isolation of Platform", "Software Attacker Resistance: Isolation of Platform Parts"]
rule_families = ["trust-boundary"]
symbols = ["cmse", "veneer", "nsc", "nonsecure", "non_secure", "tfm_spm", "spm_", "psa_call", "psa_read", "psa_write", "iovec", "invec", "outvec", "check_address_range", "memory_check", "has_access", "svc", "partition", "client_id", "tfm_ns"]
requires = ""
+++
# Non-secure entry points and partition isolation

You review one function on the path from a less trusted caller into the secure side: a non-secure callable veneer, an SVC or IPC handler in the secure partition manager, or a partition service that receives a message. The requirement is that no caller can make the secure side read or write memory the caller may not access, or act on behalf of another caller. Report the defects against that requirement which the numbered lines prove.

## What to look for
- **Unchecked non-secure pointers**: a pointer or length from the caller (a veneer argument, an input or output vector, an SVC stack frame) dereferenced before a check that the whole range lies in memory that caller may access with the needed permission, by `cmse_check_address_range`, `cmse_check_pointed_object` or the platform's memory check. Decisive fact: the first dereference line and the check line.
- **Incomplete range checks**: `base + len` able to wrap; only the start address checked; read permission checked for a buffer that is written; the check done with one length and the access made with another.
- **Double fetch**: a length, count or descriptor in caller memory read, checked, then read again for use. Decisive fact: two reads of the same caller-memory location.
- **Message sizes**: the number of vectors, vector lengths and message type checked before indexing arrays or copying; `psa_read` or `psa_write` sizes bounded by the vector length.
- **Caller identity**: a client or partition id taken from the message instead of from the manager's record; a non-secure caller not distinguished from a secure one where the policy differs.
- **Partition isolation**: a service using its own or privileged access on memory the caller named, without checking the caller could access it; a handle from one client accepted from another.
- **Leaving the secure side**: secure addresses, stack contents or uninitialised output returned to the caller; a secure function pointer reachable from the non-secure side.

## What is not a finding here
- Pointers that only come from secure code and never from a caller.
- Overflows unrelated to caller-supplied data (memory lens).
- A missing check that the shown caller context already performs on the same value.
- Hardware isolation configuration you cannot see, such as SAU or MPU tables not in the shown lines.

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "in_vec[i].base read twice; length checked on the first read only".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.

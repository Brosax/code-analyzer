# Recorded LLM response envelopes

This repository otherwise checks in no fixtures — tests write the inputs they
need into `tmp_path` — and these six earn the exception because they are not
inputs a test can invent honestly. They are the shapes a real model actually
returns through the harness: a clean JSON report, one wrapped in a ```` ```json ````
fence, one behind a sentence of prose, one cut off at `max_tokens`, an empty
body from a provider that ended with `stopReason: "error"`, and one whose line
numbers point outside the scan unit. The lenient-parse / strict-validate rules
in `harness/schema.py` exist because of these cases, so pinning them as bytes
keeps that code honest; hand-written strings drift toward whatever the parser
already handles. Each envelope is tiny, is written in the repository's one
canonical JSON representation (a test asserts it), and was recorded against a
single unit: `parse_packet` in `src/parser.c`, spanning lines 100-140
(`fake_harness.FIXTURE_UNIT`) — the reference point that makes
`line-out-of-range.json` out of range.

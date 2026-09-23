# code-analyzer

A SESIP code evaluation, done in a browser on the evaluator's own machine.

1. The static analyzers (Cppcheck, Flawfinder, Splint) run first, over the whole tree, on the CPU.
2. Their findings are clustered into **one numbered vulnerability list** (`PV-0007`), graded by the evaluation's
   **profile** (the Security Target's SFRs, TOE modules and the AVA test plan's §7.4.1 levels and §7.4.2
   categories) — only where the mapping is provable; everything else is listed as *to verify*, never dropped.
3. An agent (a local model, `qwen3.8:27b` on the lab's GPU host) is a conversation beside the list: it answers
   questions from the evidence, proposes profile and build-context changes, and runs **targeted AI review** —
   a verdict on a listed entry, or a look at SFR-relevant code no tool flagged — whose every claim is checked
   against the code it was shown.
4. The deliverable is exported in English as xlsx / Markdown / CSV, with a redacted *shareable* variant.

Client source code only ever reaches the local GPU host the evaluation was pinned to. Nothing is installed,
nothing is built without a click, and a model's opinion never removes an entry or fails a build.

## Install

```bash
python3 -m pip install -e .          # Python 3.11+, no runtime dependencies
```

The analyzers are found on `PATH` (or at the paths in `settings.toml`); they are never installed for you.

| Analyzer | Minimum | Why |
|---|---|---|
| Cppcheck | **2.11** | `--check-level` and `--checkers-report` appear there; Ubuntu 20.04's 1.90 is refused |
| Flawfinder | **2.0.19** | `--sarif` appears there; Ubuntu 20.04's 2.0.10 is refused |
| Splint | 3.1.2 | the final release |

Neither needs root to replace: `pip install --user flawfinder`, and Cppcheck builds from source with
`cmake -DCMAKE_INSTALL_PREFIX=$HOME/.local`. Compatibility is decided by running each tool over a canary, not
by reading its `--help`. Optional: `pdftotext` (poppler) to read a PDF Security Target, `bwrap` (bubblewrap) to
let CMake produce a compilation database in a jail.

## Use it

```bash
code-analyzer
```

prints a one-time URL (`http://127.0.0.1:8765/login?token=…`); open it. Create an evaluation (a source tree,
*client* or *public*, a built-in profile), then work on the page:

- **对话** (left): say what you want in Chinese. The agent calls seven tools — `list`, `show`, `run_tools`,
  `build_context`, `profile_edit`, `review`, `export` — and answers from what they return. Reading and running
  the analyzers happen by themselves; anything that writes, spends GPU time, executes a project command or
  leaves the machine stops at an **approval card** you click (typed "批准" is never an approval).
- **清单** — the list: main partition and *to verify*, filters, dispositions with notes, AI verdicts, accepting
  suggested levels.
- **证据** — one entry: its findings, the source, the priority breakdown, the AI's grounded opinion.
- **档案** — the profile: pick a built-in, upload the ST / test plan (PDF or Word) and let the agent extract a
  draft (every item quoted from the document), edit, and **confirm** (only a person can). Also: pin the model
  host; allow the public model for a public evaluation.
- **覆盖** — triage conservation (every in-TOE cluster is in exactly one partition), the SFR × TOE-module
  coverage matrix, per-lens grounding failure rates, what was not reviewed and why, a review planner, and a
  version diff against an earlier evaluation (dispositions to reuse).
- **任务** — run the analyzers, watch and stop jobs, prepare a compilation database.

Every button works with the model off (`CODE_ANALYZER_NO_MODEL=1`); only the conversation and AI review need it.

## Headless

```bash
code-analyzer analyze SOURCE [--eval-dir DIR] [--profile rt700-tp-v1.1|generic-sesip|FILE.toml]
                             [--buildctx FILE.toml] [--tool cppcheck ...] [--compile-db FILE | --no-compile-db]
                             [--exclude GLOB ...] [--fail-on none|low|medium|high|critical]
code-analyzer rebuild EVAL_DIR      # rebuild the index and list from the ledger and evidence, offline
code-analyzer probe                 # maintainers: measure what the configured model can do (idle GPU)
```

`analyze` never opens a socket to a model. It prints the evaluation directory; the page opens the same
evaluation. Exit codes: `0` complete, `1` the `--fail-on` gate fired (native findings only), `2` usage error,
`10` partial (a tool or unit did not finish, the tree changed during the run, or part of it was unreadable),
`20` failed (no valid report), `130` interrupted (Ctrl+C or SIGTERM — the run's record says so).

## Settings

`~/.code-analyzer/settings.toml` (or `$CODE_ANALYZER_HOME/settings.toml`) — nine keys, nothing else:

```toml
port = 8765
data_root = "~/.code-analyzer/evaluations"

[local_model]
endpoint = "http://192.168.5.10:11434/v1"
name = "qwen3.8:27b"
review_name = ""        # optional second model on the same host, for AI review

[public_model]          # public / test code only, and only when an evaluator allows it per evaluation
endpoint = ""
name = ""
api_key_env = ""        # the environment variable's NAME; the key is never written anywhere

[analyzers]             # where the tools live on this host (default: PATH)
cppcheck = ""
flawfinder = ""
splint = ""
```

Changing `settings.toml` never moves an existing evaluation to another model host: a client evaluation reaches
only the host pinned when it was created, whose addresses must all be private (loopback, RFC 1918, link-local,
ULA). The public model is refused for client code before any socket opens, and nothing ever falls back to it.

## What an evaluation keeps

```
<data_root>/<evaluation>/
  evaluation.json        source, confidentiality, pinned model host
  ledger.jsonl           the truth: every call, decision, card, AI answer (fsynced, append-only)
  profile/  buildctx/    immutable versions (profile.vN.toml, buildctx.vN.toml)
  calls/Cnnnn-static/…   each analyzer run: native reports, manifest.json (never rewritten)
  model/                 every model exchange, byte for byte (request before it is sent)
  aireview/              the code index and the answer cache
  index.sqlite           derived: findings, clusters, the numbered list (rebuildable)
  exports/En/            what was delivered, with its leak check
```

The fingerprint of a finding, the clustering, the numbering (one-to-one across re-runs: shared findings, then
anchor, then "moved"), the grading and the partitions are deterministic; the ledger replays every analyst
decision and every grounded AI opinion onto a rebuilt index.

## AI review, briefly

The model never picks what to look at. T1 verifies listed entries through the `verify` lens; T2 looks at
functions the profile ties to an SFR (TSFI entry points, callees two calls down, names in the SFR lens's
vocabulary) through at most two of fifteen lenses (`code_analyzer/aireview/lenses/*.md`). Every answer is held
to a JSON schema whose SFR / level / category values are the profile's own, and **grounded**: the path, the
lines and a verbatim quote must be in the code shown, or the claim never reaches the list. A new AI finding
joins the *to verify* partition only after a second, separate look confirms it. The engine accounts for every
planned unit (reviewed, or unscheduled with a reason) and yields the GPU to the conversation at once.

## Develop

```bash
python3 -m pip install -e '.[dev]'
python -m pytest -q          # no test opens a socket to a model
ruff check code_analyzer tests
CODE_ANALYZER_LIVE_TOOLS=1 python -m pytest tests/test_live_tools.py   # with the real analyzers
```

Design and interfaces: [docs/v3-design.md](docs/v3-design.md) (Chinese), [docs/v3-web-api.md](docs/v3-web-api.md).

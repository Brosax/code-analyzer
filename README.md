# code-analyzer

`code-analyzer` is a Python 3.11+ command-line runner for evidence-first C/C++
static analysis on WSL. One invocation discovers and hashes source files, runs
Cppcheck, Flawfinder, and Splint — and, when enabled, LLM specialist scanners
that review the same code independently — retains their native reports,
writes a versioned JSON manifest, a non-authoritative normalized review, a
complete offline dashboard, and a path-redacted ZIP.

It does not install tools, invoke a build, or watch files. The evidence layer
(`review/summary.json`) never merges findings and never decides that a report
is a false positive: every producer's finding stays its own row with its native
severity retained; normalized severities are versioned derived metadata.

A separate, optional audit layer (`audit/assessment.json`) may group findings
from different producers that name the same lines, attach confidence labels to
those groups, and carry remediation hints. It is model-assisted opinion,
explicitly non-authoritative: it never alters or removes an evidence row, is
excluded from the quality gate, and cannot change the exit code.

## Install and check the host

```bash
python3 -m pip install -e .
code-analyzer doctor
code-analyzer doctor --json
```

Doctor reports missing executables or capabilities and prints Ubuntu 24.04 apt
guidance, but never runs installation commands.

The three analyzers are not interchangeable with any version of themselves —
the runner drives them through a fixed argv contract and rejects a build that
cannot honour it:

| Analyzer | Minimum | Why |
|---|---|---|
| Cppcheck | **2.11** | `--check-level` and `--checkers-report` do not exist before it; 1.90, still shipped by Ubuntu 20.04, is rejected |
| Flawfinder | **2.0.19** | `--sarif` was added there; 2.0.10, still shipped by Ubuntu 20.04, is rejected |
| Splint | 3.1.2 | The final release (2018); there is nothing newer to require |

Older distributions carry versions below these. Neither tool needs root to
replace: `uv tool install flawfinder` (or `pip install --user flawfinder`)
puts a current Flawfinder on `PATH`, and Cppcheck builds from its own source
with `cmake -DCMAKE_INSTALL_PREFIX=$HOME/.local`. Doctor decides compatibility
by running each tool over a canary rather than by reading its `--help`, so a
build that implements an option without advertising it is accepted — and said
to be, on the line beneath.

## Talking to it

Run `code-analyzer` with no arguments in an interactive terminal, or name the
tree explicitly:

```bash
code-analyzer
code-analyzer tui /path/to/project
code-analyzer tui /path/to/project --config ./review-config.toml
```

The interface is a conversation: one scrolling transcript and an input box.
There is no form and no mode. What you type is a block, what the tool answers
is a block, a scan is a block you can open, and every question it stops to ask
is a turn you answer in the same place. All of it stays scrollable.

```text
› ~/fw/tfm
  ↳ scan
● 对一个 C/C++ 源码树执行完整扫描
    在输出目录下新建一个报告目录；不修改源码树。
    开始吗？ [y/N]
› y
▼ 正在扫描 · llm-memory-safety copy.c · 85% · 已运行 03:32 · 静态 3/3 · LLM 1/2
```

**Say anything; the model reads it.** Two shapes resolve instantly and
offline, because both are unambiguous: a **slash command** and a **bare path
that exists**. Everything else is a sentence and goes to the model
automatically — no prefix. A slash command hands its tail to the very parser
`code-analyzer analyze` uses, so `/scan ~/fw --llm-jobs 4` accepts exactly what
the subcommand accepts and refuses `--llm-jobs 0` in the same words.

Three edges stay deterministic because routing them would be worse. A path
that does not exist is a typo, and the intent model has no filesystem, so it
cannot repair one — sending the commonest keyboard error to the most expensive
operation would be absurd. A directory holding a `manifest.json` has five
readings and four of them write, and the model would receive exactly what the
parser received. And `扫描~/fw` is one token — Chinese needs no space — so a
CJK check keeps it from dead-ending on "no such path".

**What the model may do with what it understood.** It proposes actions from a
catalogue generated from the registry, so a name it uses is a name that exists.
An action outside it is dropped by name; a setting is dropped unless
`validate_config` accepts it; `llm.profile`, `llm.endpoint` and `llm.api_key_env`
are refused outright, because all three pass validation while silently
repointing the session at a metered provider. Every drop says why.

A step whose action **writes nothing, spends nothing and blocks on nothing**
runs immediately — that is `doctor`, `preflight` and `config`, and the set is
computed from declared effects rather than asserted. Everything else confirms,
naming the files it is about to replace. A step that changes configuration
always waits to be ticked, whatever its action's policy. What runs is the very
command you could have typed, so the one place that confirms cannot be
bypassed. The model is given the catalogue, the current paths and the settings
that differ from default — never a finding, never analyzer output, never
source.

**A minute is a long time, so the wait is honest.** One round trip is 21–31
seconds measured. While it thinks you see elapsed seconds, which phase it is
in, and how long the *last* question took — a measurement, labelled as one.
There is no ETA, because nothing has measured this one. `Ctrl+C` abandons it
and says plainly that the request may still be running at the provider and its
answer will be dropped; the first tokens are genuinely uninterruptible and
pretending otherwise would be a lie. You can keep typing meanwhile — sentences
queue, slash commands never do, and `Esc` drops the queue.

When the provider is unreachable it says so once, names what still works, and
offers the command your sentence began with if it began with one. Three
sentences at a dead host cost one probe (6s), not three (90s). Only free text
needs a provider: every command, every alias, `/set`, `/config`, bare paths and
the whole CLI work with nothing reachable, and `CODE_ANALYZER_NO_MODEL=1`
turns the lane off for good.

**Configuration is part of the conversation.** `/config` lists what is set and
where it came from, `/config --all` includes the 59 advanced fields, and
`/set <path> <value>` reaches any of the 83 schema leaves — `build.overrides`
excepted, which is a table and says so rather than pretending. Values are
checked where you typed them, `Ctrl+S` writes the TOML snapshot.

**A run is a block.** Collapsed it is one live line — elapsed, percent, the
lane bars, which producers are running. `Enter` opens the whole diagram:
discovery fanning out to every analyzer and scanner and converging on review,
export and the report, plus the model's own transcript with its prompts (`F6`)
and its speed. Two speeds are reported and never conflated: while an answer is
arriving only its characters are known, so the rate is labelled *估算*; once
the provider reports its own `outputTokens` it becomes output tokens over
session seconds, labelled *测量*. When the run settles the block collapses to
one line with the exit code, the duration and the report directory, and the
history stays above it.

`code-analyzer <a sentence>` on the command line is refused, on a terminal or
off one: a headless run must never call a provider, and a provider outage must
never move an exit code. Naming a directory there prints the command it would
have run rather than running it — a scan is not a side effect.

`/pause`, `/resume`, `/skip`, `/jobs`, `/retry` and `/decide` steer a run while
it runs — the single letters that used to do this are now names you can
discover, complete and read back. Every one is journalled as a `control/*`
event. `F5` opens the log pane, `F4` filters it. `Ctrl+C` requests cooperative
cancellation; running process groups get the same bounded TERM/KILL cleanup as
the CLI, and an existing run directory is retained with an `interrupted`
manifest and exit code `130`.

The conversation is written to `~/.code-analyzer/sessions/<stamp>.jsonl` —
what you typed, how it was read, what you confirmed, which report came out.
Same status as `events.jsonl`: a progress log, not evidence, never in the
archive. `CODE_ANALYZER_NO_JOURNAL=1` turns it off.

Every action the conversation can perform, the CLI can too, from the same
registry: `doctor`, `llm-doctor`, `preflight`, `compile-db`, `analyze`,
`llm-resume`, `tools-resume`, `assess`, `rebuild-dashboard`, `recover-report`,
`serve`, `config`. `code-analyzer <something you said>` works too, though a
bare path off a terminal prints the command it would have run rather than
running it — a scan is not a side effect.


## Analyze

```bash
code-analyzer analyze /path/to/project
python3 -m code_analyzer analyze /path/to/project --no-compile-db
python3 run_code_analyzer.py analyze /path/to/project
code-analyzer analyze . --tool cppcheck --output-root /tmp/reports
code-analyzer analyze . --splint-scope build --splint-jobs 4
code-analyzer analyze . --fail-on high
code-analyzer analyze . --no-compile-db --build-assist propose      # ask before patching the build context
code-analyzer analyze . --no-compile-db --build-assist-yes          # headless: apply the pre-ticked patch
code-analyzer tools-resume /path/to/report-directory --tool splint  # finish a recorded patch later
```

Without a compile database Splint tends to die at the first `#include`. The
run ends its static lane with a build-context loop: it aggregates the failed
units' diagnosis, infers only what the tree proves (include roots, per-subtree
overrides, typed Splint options, the host's architecture macro when glibc's
`gnu/stubs.h` reached for a branch that is not installed, optional empty stub
headers that are never pre-ticked), asks the configured LLM endpoint to fill in what only reading the
tree can tell (a board, a define, which headers are external — every item
validated like hand-written TOML), tries the patch on a sample of failed
units, and puts the result to the operator: a checkbox dialog in the TUI, a
`[y/N]` prompt on a terminal, `--build-assist-yes` for unattended runs,
record-only otherwise. An applied patch re-runs only the failed units as a
second attempt into new unit directories; the first attempt is kept, marked
superseded, and its review rows stay tagged. Evidence lives under
`inputs/build-context/r<N>/` plus `suggested-config.toml`; the project's own
TOML and the scanned tree are never touched.

Scan progress is written to stderr in real time. In an interactive terminal, a
small spinner with elapsed time remains animated between progress events, so a
long scan is visibly active. Redirected output and CI logs remain plain text;
set `CODE_ANALYZER_NO_ANIMATION=1` to disable the spinner explicitly. Standard
output remains a single final run-directory path, so scripts can safely capture it. See the
[complete usage tutorial](docs/usage.md) for configuration, reports, progress,
and exit-code details.

## LLM scanners

The LLM layer is off by default: a scan that may take hours must never be a
side effect of `analyze .`. Enabled, six specialist scanners review every unit
independently of the native tools and of each other — memory safety, security,
firmware concurrency, undefined behaviour, resource and error handling, and a
closed set of four control-flow logic classes.

```bash
code-analyzer llm-doctor /path/to/project --llm-profile gpu-host
code-analyzer analyze /path/to/project --llm --llm-profile gpu-host
code-analyzer llm-resume /path/to/report-directory
code-analyzer assess /path/to/report-directory
```

Three built-in profiles supply `endpoint`, `model` and `api_key_env`, and
nothing else: `gpu-host` (the operator's GPU host, reached directly on the
local network without SSH port-forward), `gpu-host-uncensored` (the same box,
a model without the safety tuning — scanned source is exploit-shaped by
construction, and a refusal reaches the parser as an unparseable response),
and `openrouter` (third party: the source leaves this machine, and both the CLI
and `llm-doctor` say so).
Any other provider needs `--llm-endpoint` and `--llm-model`, not a new profile.

`llm-doctor` probes the provider before a long scan commits to it: it lists the
endpoint's models, checks that the configured one is among them *and* that the
reply comes back stamped with it, compares the served context window against
the configured one (a smaller window truncates prompts silently), times one
real request for a tokens-per-second figure, and estimates the full scan from
the run's own unit plan. Exit `20` when any of that fails, like `doctor`.

`llm-resume` finishes the units a run left `unscheduled` (token budget or
deadline) or `interrupted`, then re-derives the review. Unlike
`recover-report` it does invoke the scanner, and says so in the manifest. It
replays each unit's stored prompt rather than re-planning, so a resumed unit
scans the bytes its plan described.

`assess` runs the second layer over a finished run: one validator session per
correlated candidate, riskiest first, writing verdicts into
`audit/assessment.json`. The evidence layer is never touched. Exit `10` when
some candidates were left unvalidated by the cap or the budget.

To rebuild a missing or outdated offline dashboard without rerunning analyzers,
point the dedicated command at an unpacked report directory:

```bash
code-analyzer rebuild-dashboard /path/to/report-directory
```

If native reports already exist but an earlier review or export failed, rebuild
all derived artifacts without running analyzers or changing native evidence:

```bash
code-analyzer recover-report /path/to/report-directory
```

Reviews use schema v2 and retain valid findings when another report unit is
missing or corrupt. Findings and summary counts distinguish `build-aware` from
`source-only` evidence; the dashboard defaults to build-aware findings when
that layer is available. Recovery preserves the original run/tool status,
timestamps, and exit code, and writes a new timestamped shareable ZIP.

The command prints the unique private run directory. Exit codes are `0` for a
complete run, `10` for a partial run with at least one valid native report, `20`
when no requested/applicable tool produced a valid report, `2` for input or
configuration errors, and `130` for interruption. Findings do not affect the
exit code unless an explicit `--fail-on medium|high|critical` gate is used; a
completed run that hits the gate exits `1`. A missing compile database is
degraded analysis context, not a failure by itself. Auto mode searches common
in-tree and adjacent build directories, validates every candidate, and selects
the database with the best source-TU coverage. It never runs project commands.

To inspect the decision or explicitly prepare a database:

```bash
code-analyzer compile-db /path/to/project
code-analyzer compile-db /path/to/project --json
code-analyzer compile-db /path/to/project --method cmake --yes
code-analyzer compile-db /path/to/project --method command \
  --expected-db /path/to/project/compile_commands.json --yes \
  -- bear -- make -j8
```

Generation first displays the exact argv, cwd, expected output, and impact.
Without `--yes`, redirected/CI invocations only print guidance; an interactive
terminal asks for confirmation. CMake mode configures but does not build, and
custom commands always run as argv without a shell. The command never installs
tools or writes `.code-analyzer.toml`.

Configuration precedence is built-ins, `SOURCE/.code-analyzer.toml`, an
explicit `--config`, then typed CLI/TUI session overrides. Paths in TOML are relative to
that TOML file; CLI paths and the built-in output directory are relative to the
current working directory. Example:

```toml
config_schema_version = 2

[run]
output_root = "./reports"
profile = "exhaustive"
shareable_export = true

[source]
exclude = ["fixtures/broken/**"]

[build]
compile_database_mode = "auto"
c_standard = "c11"
cpp_standard = "c++20"
include = ["include"]
define = ["PRODUCT=1"]

[review]
enabled = true
fail_on = "none"
max_markdown_findings = 200

[tools.cppcheck]
timeout_seconds = 7200

[tools.flawfinder]
timeout_seconds = 1800

[tools.splint]
tu_timeout_seconds = 60
total_timeout_seconds = 14400
scope = "auto"
jobs = 1
heartbeat_seconds = 10
```

Schema v1 files remain readable and receive the v2 defaults in memory. Only
typed supported keys are accepted; arbitrary analyzer arguments are
intentionally unavailable. With a valid compile database, Splint `auto` means
`build`; otherwise it means `inventory`. Cppcheck still adds a fallback pass
for inventory files outside the database, while Flawfinder always scans the
inventory. The private report can contain source snippets
and business data. The shareable ZIP redacts machine paths, user paths, and host
identifiers, but users must still assess whether analyzer content itself may be
shared. A malformed non-core native artifact is omitted from the ZIP and
recorded in its redaction report and export manifest; this produces a `partial`
export instead of discarding every safe artifact.

## Tests

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest
CODE_ANALYZER_LIVE_TOOLS=1 python3 -m pytest -m live_tools
CODE_ANALYZER_LIVE_LLM=1 python3 -m pytest -m live_llm
```

The dashboard JavaScript syntax check additionally needs `node` on `PATH`;
without it that one test is skipped. The `live_tools` tests require both the
`-m live_tools` marker selection and `CODE_ANALYZER_LIVE_TOOLS=1`, so they
never run by accident. The `live_llm` tests are armed the same way and need a
reachable provider: they prove what a scripted fake cannot — that the endpoint
answers, that a real reply survives the finding schema, that the provider's own
token counters reach the ledger, that a second scan is served entirely from the
cache, and that a verdict never touches the evidence layer. Once armed they
fail rather than skip when the provider is unreachable, because a live run that
quietly skips is how a broken provider stays undetected. The `tfm_full` acceptance profile is manual, requires
`CODE_ANALYZER_TFM_FULL=1`, and is intentionally excluded from a normal test
run; see [docs/tfm_full.md](docs/tfm_full.md).

Lint with `python3 -m ruff check code_analyzer tests run_code_analyzer.py`.

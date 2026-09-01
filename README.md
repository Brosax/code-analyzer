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

## Full-screen configuration

Run `code-analyzer` with no arguments in an interactive terminal, or invoke the
interface explicitly:

```bash
code-analyzer
code-analyzer tui /path/to/project
code-analyzer tui /path/to/project --config ./review-config.toml
```

The UTF-8 Chinese TUI is a single-page basic scan interface for the source,
output, compile database, analyzer selection, shareable export, and fail gate.
The page adapts to terminal width — two balanced columns at 120 columns or
wider, a single column below that — and the action buttons stay pinned below
the form instead of scrolling away. `F1` shows the grading reference.
Advanced schema-v2 values remain available through TOML and the CLI; loaded
hidden values are preserved when the TUI runs or saves a full snapshot. `F5`
performs a read-only preflight, `F9` shows the run impact, and `Ctrl+S` saves the
validated snapshot. The interface never generates a compile database, invokes
CMake, or installs tools. It requires a TTY and at least 80×24 cells; a non-TTY
no-argument invocation prints help and exits `2`.

During a scan, `Ctrl+C` requests cooperative cancellation. Running process
groups receive the same bounded TERM/KILL cleanup as the CLI; an existing run
directory is retained with an `interrupted` manifest and exit code `130`.

## Analyze

```bash
code-analyzer analyze /path/to/project
python3 -m code_analyzer analyze /path/to/project --no-compile-db
python3 run_code_analyzer.py analyze /path/to/project
code-analyzer analyze . --tool cppcheck --output-root /tmp/reports
code-analyzer analyze . --splint-scope build --splint-jobs 4
code-analyzer analyze . --fail-on high
```

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

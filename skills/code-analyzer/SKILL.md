---
name: code-analyzer
description: Use when reviewing C/C++ code, investigating static-analysis, security, or defect findings, running Cppcheck, Flawfinder, Splint, or clang-tidy, triaging CWE results, or generating combined C/C++ analysis reports.
---

# Code Analyzer

## Overview

Use the bundled standard-library runner. It never installs or upgrades external analyzers.

```bash
python3 scripts/run_code_analyzer.py --project . --out code-analyzer-report
```

Cppcheck and Flawfinder are required. Missing required tools are `failed`; missing Splint or clang-tidy is `skipped`. clang-tidy runs only with a discovered or explicit `compile_commands.json`. A project `.clang-tidy` takes priority; otherwise the runner enables `clang-analyzer-*`, `bugprone-*`, `performance-*`, and `portability-*`.

## Workflow

1. Inspect C/C++ source roots, generated/vendor paths, build metadata, `.clang-tidy`, Cppcheck suppressions, and compile databases.
2. Run all analyzers unless the user requests a subset. The default order is `cppcheck,flawfinder,splint,clang-tidy`; use `--tool-jobs` only for explicit tool-level parallelism.
3. Read `latest/combined/summary.md`, then use the JSON and raw tool logs to confirm parser/configuration quality.
4. Prioritize critical/high findings and `overlap_groups`, but confirm every result against source. Overlap groups do not remove findings.
5. Report failed/timed-out/skipped tools and configuration gaps alongside the findings.

## Reports

Each run is atomically published under `runs/<run-id>`. `latest` plus root-level tool and `combined` links point to the newest run; older runs remain available. A repeated explicit `--run-id` is rejected unless `--overwrite` is supplied.

```text
code-analyzer-report/
  runs/<run-id>/
    cppcheck/       raw logs, summary.json, summary.md
    flawfinder/     one raw scan, summary.json, summary.md
    splint/         raw logs, summary.json, summary.md
    clang-tidy/     raw logs, summary.json, summary.md
    combined/       summary.json, summary.md, index.html
  latest -> runs/<run-id>
```

## Quick reference

| Need | Option or output |
|---|---|
| Check tool availability | `--doctor` |
| Choose analyzers | `--tools cppcheck,flawfinder,splint,clang-tidy` |
| Run analyzers concurrently | `--tool-jobs N` |
| Set per-tool timeout | `--timeout-seconds N` |
| Apply CI gate | `--fail-on none|tool-error|medium|high|critical` |
| Find current report | `latest/combined/summary.md` and `latest/combined/index.html` |

## Configuration example

```bash
python3 scripts/run_code_analyzer.py \
  --project . \
  --out code-analyzer-report \
  --compile-commands build/compile_commands.json \
  --clang-tidy-checks 'clang-analyzer-*,bugprone-*' \
  --timeout-seconds 1800 \
  --fail-on tool-error
```

- `--run-id ID` and `--overwrite`
- Existing Cppcheck, Flawfinder, and Splint configuration flags remain supported.

Install the same skill source for local hosts with:

```bash
python3 scripts/install_code_analyzer.py --hosts auto
```

The installer supports `--check`, `--uninstall`, `--copy`, and `--migrate-legacy`. It refuses to overwrite foreign files or incorrect links.

## Common mistakes

- Do not interpret missing headers or parse failures as clean analysis; inspect each tool status and raw logs.
- Do not expect clang-tidy to run without `compile_commands.json`; supply `--compile-commands` or generate the database through the project build.
- Do not use `--overwrite` unintentionally; omit it to preserve and protect named historical runs.
- Do not deduplicate `overlap_groups`; they identify related locations while retaining all analyzer evidence.
- Do not treat findings as confirmed defects without reviewing the source and build configuration.

## Reporting guidance

Lead with the run directory and `combined/index.html`, then severity counts, overlap areas, high-priority examples, and tool/configuration status. State that static-analysis results require source review before code changes.

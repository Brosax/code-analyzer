---
name: code-analyzer
description: Use when reviewing C/C++ code, investigating static-analysis, security, or defect findings, running Cppcheck, Flawfinder, or Splint, triaging CWE results, or generating combined C/C++ analysis reports.
---

# Code Analyzer

## Overview

Use the bundled standard-library runner. It never installs or upgrades external analyzers.

```bash
python3 scripts/run_code_analyzer.py --project . --out code-analyzer-report
```

Cppcheck and Flawfinder are required. Missing required tools are `failed`; missing Splint is `skipped`. All tools consume one filtered source manifest. A discovered or explicit `compile_commands.json` is filtered to that manifest before Cppcheck uses it.

By default, source discovery excludes version-control metadata, caches, `.tools`, `node_modules`, vendor/third-party trees, generated code, build outputs, and analyzer report directories. Refine discovery with repeated `--source-include GLOB` and `--source-exclude GLOB`; use `--no-default-excludes` only when excluded trees are intentionally in scope.

## Workflow

1. Inspect C/C++ source roots, generated/vendor paths, build metadata, Cppcheck suppressions, and compile databases. Confirm `combined/source-manifest.json` matches the intended scope.
2. Run all analyzers unless the user requests a subset. The default order is `cppcheck,flawfinder,splint`; use `--tool-jobs` only for explicit tool-level parallelism.
3. Open `latest/combined/index.html` for the complete offline dashboard, then use the JSON, tool diagnostics, and linked raw logs to confirm parser/configuration quality.
4. Prioritize critical/high findings and `overlap_groups`, but confirm every result against source. Overlap groups do not remove findings.
5. Report failed/timed-out/skipped tools and configuration gaps alongside the findings. Splint parse, include, and configuration diagnostics are not security findings; fatal diagnostics fail the Splint run.

## Reports

Each run is atomically published under `runs/<run-id>`. `latest` plus root-level tool and `combined` links point to the newest run; older runs remain available. A repeated explicit `--run-id` is rejected unless `--overwrite` is supplied.

```text
code-analyzer-report/
  runs/<run-id>/
    cppcheck/       raw logs, summary.json, summary.md
    flawfinder/     one raw scan, summary.json, summary.md
    splint/         raw logs, summary.json, summary.md
    combined/       source-manifest.json, summary.json, summary.md, index.html
  latest -> runs/<run-id>
```

## Quick reference

| Need | Option or output |
|---|---|
| Check tool availability | `--doctor` |
| Choose analyzers | `--tools cppcheck,flawfinder,splint` |
| Run analyzers concurrently | `--tool-jobs N` |
| Set per-tool timeout | `--timeout-seconds N` |
| Include source paths | repeated `--source-include GLOB` |
| Exclude source paths | repeated `--source-exclude GLOB` |
| Include normally excluded trees | `--no-default-excludes` |
| Bound Splint command size | `--splint-command-bytes N` |
| Apply CI gate | `--fail-on none|tool-error|medium|high|critical` |
| Limit Markdown detail | `--max-findings N` (HTML remains complete) |
| Find current report | `latest/combined/summary.md` and `latest/combined/index.html` |

## Configuration example

```bash
python3 scripts/run_code_analyzer.py \
  --project . \
  --out code-analyzer-report \
  --compile-commands build/compile_commands.json \
  --source-exclude 'fixtures/**' \
  --timeout-seconds 1800 \
  --fail-on tool-error
```

- `--run-id ID` and `--overwrite`
- `--patch` and `--suppressions-list` resolve relative paths from the project root.
- Splint automatically chunks large source lists under one overall timeout.
- Existing Cppcheck, Flawfinder, and Splint configuration flags remain supported.
- `combined/index.html` is a self-contained offline dashboard generated after all selected tools finish. It includes every normalized finding, diagnostics, overlap groups, scope, charts, filters, sorting, and pagination; raw analyzer logs are linked rather than embedded.

Install the same skill source for local hosts with:

```bash
python3 scripts/install_code_analyzer.py --hosts auto
```

The installer supports `--check`, `--uninstall`, `--copy`, and `--migrate-legacy`. It refuses to overwrite foreign files or incorrect links. Copy installs are content-hashed, so `--check` detects stale or damaged copies and the next install refreshes them. Multi-host installation and legacy migration roll back together on failure.

## Common mistakes

- Do not interpret missing headers or parse failures as clean analysis; inspect each tool status and raw logs.
- Do not assume a compile database is ignored; when discovered or supplied, Cppcheck analyzes a filtered copy. An explicitly missing database is a CLI error.
- Do not count Splint parser, include, or configuration diagnostics as vulnerabilities; use `diagnostics` and tool status.
- Do not bypass default exclusions casually; inspect `source-manifest.json` before expanding scope.
- Do not use `--overwrite` unintentionally; omit it to preserve and protect named historical runs.
- Do not deduplicate `overlap_groups`; they identify related locations while retaining all analyzer evidence.
- Do not treat findings as confirmed defects without reviewing the source and build configuration.

## Reporting guidance

Lead with the run directory and `combined/index.html`, then severity counts, overlap areas, high-priority examples, and tool/configuration status. State that static-analysis results require source review before code changes.

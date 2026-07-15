# Code Analyzer

Code Analyzer is a Codex plugin and standalone Python runner for C and C++ static analysis. It runs Cppcheck, Flawfinder, and Splint, normalizes their results, separates analyzer diagnostics from code findings, and publishes versioned Markdown, JSON, and HTML reports.

## Requirements

- Python 3.8 or newer; the runner uses only the standard library.
- Cppcheck and Flawfinder for the default required checks.
- Splint for the optional C analysis pass.

The plugin never installs or upgrades external analyzers.

## Quick start

Run directly from the skill directory:

```bash
python3 skills/code-analyzer/scripts/run_code_analyzer.py \
  --project /path/to/project \
  --out /path/to/project/code-analyzer-report
```

Check availability without running analyzers:

```bash
python3 skills/code-analyzer/scripts/run_code_analyzer.py --doctor
```

Install the shared skill for detected local agent hosts:

```bash
python3 skills/code-analyzer/scripts/install_code_analyzer.py --hosts auto
```

Use `--copy` where symbolic links are unsuitable. Copy installations include a content hash; `--check` reports damaged or stale copies, and rerunning the installer refreshes them. Multi-host installs and `--migrate-legacy` migrations are transactional.

## Analysis scope

All analyzers use one source manifest. Default discovery excludes `.tools`, version-control and cache directories, `node_modules`, vendor and third-party trees, generated code, build outputs, and report directories.

Use repeated filters when the defaults do not match a repository:

```bash
python3 skills/code-analyzer/scripts/run_code_analyzer.py \
  --project . \
  --source-include 'src/**' \
  --source-include 'include/**' \
  --source-exclude 'src/generated/**'
```

The exact scope is saved as `combined/source-manifest.json`. A discovered or explicit compilation database is filtered to the same scope before Cppcheck runs. Splint source lists are chunked to avoid operating-system command-length limits.

## Reports and exit status

Each completed run is published under `runs/<run-id>`. The `latest` and root-level analyzer links update atomically, while prior runs remain available. Existing flat report directories are preserved as a `runs/legacy-*` snapshot during the first new publication.

The combined report contains:

- Original findings with stable fingerprints and severity counts.
- Tool diagnostics, including Splint parse, include, and configuration failures.
- Cross-tool overlap groups based on semantic category and nearby source lines.
- An interactive HTML table with severity, tool, and text filters.

`--fail-on tool-error` is the default. Other gates are `none`, `medium`, `high`, and `critical`. CLI validation errors return 2, a failed gate returns 1, and cancellation returns 130.

## Development

Run the release checks and tests with:

```bash
python3 scripts/validate_release.py
python3 -m unittest discover -s tests -v
git diff --check
```

The canonical release repository is mirrored into the workspace plugin directory after validation. `scripts/validate_release.py --compare PATH` verifies that two distribution trees have identical content.

## License

Code Analyzer is available under the [MIT License](LICENSE).

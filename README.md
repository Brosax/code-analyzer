# Code Analyzer

Code Analyzer is a Codex plugin and standalone Python runner for C and C++ analysis. Its default path runs Cppcheck, Flawfinder, and Splint over one filtered source manifest. Version 0.6 adds an explicitly enabled, independent multi-round AI reviewer for OpenAI, local OpenAI-compatible servers, or a ledger produced by the skill host.

## Requirements

- Python 3.8 or newer; the runner uses only the standard library.
- Cppcheck and Flawfinder for the default required checks.
- Splint for the optional C analysis pass.
- An environment-only API key for OpenAI provider mode, or an explicitly configured compatible endpoint. Local compatible endpoints may run without a key.

The plugin never installs analyzers, modifies source, auto-discovers local AI services, or enables AI by default.

## Quick start

Run the unchanged default static suite:

```bash
python3 skills/code-analyzer/scripts/run_code_analyzer.py \
  --project /path/to/project \
  --out /path/to/project/code-analyzer-report
```

Check static tool availability with `--doctor`. Install the shared skill with `python3 skills/code-analyzer/scripts/install_code_analyzer.py --hosts auto`; copy installs include a content hash that covers scripts, references, and metadata.

## Optional AI review

AI must be explicitly included as the fourth tool:

```bash
export OPENAI_API_KEY='...'
python3 skills/code-analyzer/scripts/run_code_analyzer.py \
  --project /path/to/project \
  --tools cppcheck,flawfinder,splint,ai-review \
  --ai-provider openai \
  --ai-model gpt-5.6
```

For vLLM, llama.cpp server, LM Studio, or an Ollama OpenAI-compatible endpoint:

```bash
python3 skills/code-analyzer/scripts/run_code_analyzer.py \
  --project /path/to/project \
  --tools ai-review \
  --ai-provider openai-compatible \
  --ai-model local-model \
  --ai-base-url http://127.0.0.1:8000/v1
```

The default protocol uses four rounds and accepts 3–8. Round one presents every source-manifest range; intermediate rounds deepen defect-specific analysis; the penultimate round rereads relevant source and tries to disprove every candidate; the final round deduplicates and calibrates only verified candidates. Requests inherit the structured ledger, not an ever-growing conversation transcript. Source code and repository text are always marked as untrusted data.

OpenAI mode follows the official [Responses API structured-output format](https://developers.openai.com/api/docs/guides/structured-outputs) with a strict JSON schema.

Provider output is structured JSON. One JSON-only format repair is allowed; another parse failure makes the batch a tool error and leaves its first-round ranges uncovered. The runner independently validates every final file, inclusive line range, and exact evidence excerpt. It retains dismissed and inconclusive candidates but never promotes them to combined findings.

The skill host can follow `skills/code-analyzer/references/ai-review-protocol.md`, write the same schema `2.2` ledger, and import it with `--ai-ledger PATH`. Ledger mode is mutually exclusive with provider options.

Configuration precedence is CLI, `AI_REVIEW_*` environment variables, then provider defaults. OpenAI mode reads `AI_REVIEW_API_KEY` or `OPENAI_API_KEY`; a compatible endpoint receives only an explicitly set `AI_REVIEW_API_KEY`, preventing an ambient OpenAI key from leaking to a local server. Credentials are never serialized. Relevant options are:

- `--ai-provider openai|openai-compatible`
- `--ai-model MODEL`
- `--ai-base-url URL`
- `--ai-rounds N` (3–8; default 4)
- `--ai-context-tokens N`
- `--ai-timeout-seconds N`
- `--ai-ledger PATH`
- `--ai-fail-on none|medium|high|critical` (default `none`)

AI findings do not affect severity-based `--fail-on`; `--ai-fail-on` is independent. Provider failures, timeouts, malformed output, and partial coverage are still tool errors and can fail `--fail-on tool-error`.

## Scope and reports

All analyzers use one source manifest. Default discovery excludes version-control metadata, caches, `.tools`, `node_modules`, vendor/third-party trees, generated code, build outputs, and report directories. Use repeated `--source-include` and `--source-exclude` filters when needed. A discovered or explicit compilation database is filtered to the same scope before Cppcheck runs.

Each completed run is published under `runs/<run-id>`. `latest` and root-level analyzer links update atomically while prior runs remain available. The combined output includes:

- Original normalized static and verified AI findings with stable fingerprints.
- Schema `2.2` AI fields: candidate ID, category, confidence, exact evidence, impact, trigger, recommendation, and verification state.
- Tool diagnostics and explicit AI source coverage/uncovered ranges.
- Cross-tool overlap groups, including independently produced AI/static evidence.
- A self-contained offline HTML dashboard with full AI candidate detail.
- `ai-review/rounds/`, `ai-review/ledger.json`, `summary.json`, and `summary.md` when AI is selected.

`--max-findings` limits only Markdown; the dashboard keeps every normalized finding. CLI validation errors return 2, a failed gate returns 1, and cancellation returns 130.

## Development

```bash
python3 scripts/validate_release.py
python3 -m unittest discover -s tests -v
git diff --check
```

Tests use fake providers for deterministic round, coverage, timeout, repair, injection, evidence, and CI-gate assertions. Forward model evaluation can use the included Juliet workspace samples, but probabilistic model outputs are not fixed CI assertions.

The canonical release repository is mirrored into the workspace plugin and local marketplace trees after validation. `scripts/validate_release.py --compare PATH` verifies byte-identical distribution content.

## License

Code Analyzer is available under the [MIT License](LICENSE).

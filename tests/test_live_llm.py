"""Live provider tests: the one thing a scripted fake cannot prove.

Scheduling, budgets, parsing, redaction and offline re-derivation are already
pinned against ``tests/fake_harness.py`` -- deterministically, in CI, with no
model.  What no fake can answer is whether the configured endpoint, model and
prompt contract actually work *together*: that the provider answers at all,
that a real reply survives the finding schema, that the provider's own token
counters reach the ledger, and that a second run replays those answers instead
of paying for them again.

Opt-in twice, exactly like ``live_tools``: the ``live_llm`` marker selects the
module and CODE_ANALYZER_LIVE_LLM=1 arms it, so a bare ``pytest`` run never
reaches a GPU host.  Set CODE_ANALYZER_LIVE_LLM_PROFILE to probe a provider
other than the built-in default, and CODE_ANALYZER_LIVE_LLM_CONFIG to point at
a TOML file for whatever the profile cannot carry -- the served context window
above all, since a provider that serves a smaller window than ``[llm]
context_window`` declares truncates prompts silently and ``llm-doctor`` rightly
refuses the run.

    CODE_ANALYZER_LIVE_LLM=1 python3 -m pytest -m live_llm

These tests fail rather than skip when the endpoint is unreachable: an armed
live run that quietly skips is how a broken provider stays undetected.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from helpers import run_cli

from code_analyzer.config import load_config
from code_analyzer.harness.schema import FINDING_CATEGORIES
from code_analyzer.harness.verdict import VERDICTS
from code_analyzer.llm.doctor import probe_llm
from code_analyzer.llm.profiles import DEFAULT_PROFILE
from code_analyzer.tools import LLM_PRODUCERS

pytestmark = [
    pytest.mark.live_llm,
    pytest.mark.skipif(
        os.environ.get("CODE_ANALYZER_LIVE_LLM") != "1",
        reason="set CODE_ANALYZER_LIVE_LLM=1 for live provider tests",
    ),
]

SCANNER = "llm-memory-safety"
# One scanner over a two-function file: enough for a unit plan, a correlated
# candidate and a verdict, while a session that costs ~25s stays a test.
SCAN_TIMEOUT = 1800.0
ASSESS_TIMEOUT = 900.0


def _profile() -> str:
    return os.environ.get("CODE_ANALYZER_LIVE_LLM_PROFILE") or DEFAULT_PROFILE


def _config_path() -> Path | None:
    """The operator's provider settings, if this host needs any."""
    configured = os.environ.get("CODE_ANALYZER_LIVE_LLM_CONFIG")
    if not configured:
        return None
    path = Path(configured).expanduser()
    assert path.is_file(), f"CODE_ANALYZER_LIVE_LLM_CONFIG does not name a file: {path}"
    return path


def _config_argv() -> tuple[object, ...]:
    path = _config_path()
    return ("--config", path) if path is not None else ()


def _tree(root: Path) -> Path:
    source = root / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "frame.c").write_text(
        "#include <stdlib.h>\n"
        "#include <string.h>\n"
        "\n"
        "int copy_frame(char *out, const char *in, unsigned len)\n"
        "{\n"
        "    char scratch[16];\n"
        "    memcpy(scratch, in, len);\n"
        "    strcpy(out, scratch);\n"
        "    return (int)len;\n"
        "}\n"
        "\n"
        "void release(char *buffer)\n"
        "{\n"
        "    free(buffer);\n"
        "    free(buffer);\n"
        "}\n",
        encoding="utf-8",
    )
    return source


def _manifest(run_dir: Path) -> dict:
    return json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))


def _summary(run_dir: Path) -> dict:
    return json.loads((run_dir / "review" / "summary.json").read_text(encoding="utf-8"))


def _analyze(source: Path, output_root: Path) -> tuple[int, Path]:
    completed = run_cli(
        "analyze", source,
        *_config_argv(),
        "--output-root", output_root,
        "--no-compile-db",
        "--tool", "cppcheck",
        "--tool", "flawfinder",
        "--llm",
        "--llm-profile", _profile(),
        "--llm-scanner", SCANNER,
        "--llm-jobs", "2",
        timeout=SCAN_TIMEOUT,
    )
    assert completed.returncode in {0, 10}, completed.stderr
    return completed.returncode, Path(completed.stdout.strip())


@pytest.fixture(scope="module")
def live_scan(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """One real scan, shared: the provider is the expensive part of this file."""
    root = tmp_path_factory.mktemp("live-llm")
    source = _tree(root)
    output_root = root / "reports"
    exit_code, run_dir = _analyze(source, output_root)
    return {
        "source": source,
        "output_root": output_root,
        "run_dir": run_dir,
        "exit_code": exit_code,
        "manifest": _manifest(run_dir),
        "summary": _summary(run_dir),
    }


def test_the_provider_answers_the_doctor_probe(tmp_path: Path) -> None:
    source = _tree(tmp_path)
    config = load_config(source, _config_path(), {"llm": {"profile": _profile()}})

    result = probe_llm(config, source)

    assert result["runtime"]["available"], result["runtime"]
    assert result["models"]["reachable"], result["models"]["reason"]
    assert result["models"]["model_present"], result["models"]["reason"]
    # A served window smaller than the configured one truncates prompts in
    # silence, so the probe refuses the run: the fix is the operator's config,
    # which is what CODE_ANALYZER_LIVE_LLM_CONFIG is for.
    assert result["context_window"]["ok"], result["context_window"]["reason"]
    assert result["benchmark"]["ok"], result["benchmark"]["reason"]
    # The mis-route this command exists to catch: an endpoint that answers, but
    # with something other than what it was asked for.
    assert not result["benchmark"]["served_other_model"], result["benchmark"]
    assert (result["benchmark"]["tokens_per_second"] or 0) > 0
    # A rate plus the run's own unit plan is the whole point of the estimate.
    assert result["estimate"]["known"], result["estimate"].get("reason")
    assert result["ok"]


def test_the_scan_completes_and_the_provider_counts_reach_the_ledger(live_scan: dict) -> None:
    block = live_scan["manifest"]["llm"]

    assert block["status"] in {"completed", "partial"}, block
    assert block["scanners"][SCANNER]["status"] in {"completed", "partial"}
    counts = block["unit_counts"]
    assert counts["planned"] == counts["started"] + counts["unscheduled"]
    assert counts["completed"] >= 1, counts
    # Design appendix A #11 was verified by hand once, on 2026-08-24.  This is
    # that verification as a test: the provider's own counters, not ours.
    measured = block["budget"]["measured"]
    assert measured["requests"] >= 1, measured
    assert measured["prompt_tokens"] > 0 and measured["completion_tokens"] > 0, measured
    assert block["budget"]["prompt_tokens_spent"] > 0
    assert live_scan["summary"]["llm_coverage"]["functions"]["scanned"] >= 1


def test_a_real_reply_survives_the_schema_and_the_provenance_rules(live_scan: dict) -> None:
    summary = live_scan["summary"]
    findings = [item for item in summary["findings"] if item["engine"] == "llm"]
    if not findings:
        pytest.skip("the model reported nothing on this fixture; the ledger test still ran")

    for finding in findings:
        assert finding["producer"] in LLM_PRODUCERS
        assert finding["tool"] == SCANNER
        assert finding["evidence_class"] == "generated"
        # gate_includes_llm is off by default, and that default is the charter.
        assert finding["gate_eligible"] is False, finding
        # The closed category set is a contract on what the model may say, and
        # a real reply is the only thing that can break it.
        assert finding["category"] in FINDING_CATEGORIES, finding["category"]
        # A model writes prose, and a home path invented inside it would reach
        # the shareable ZIP: design 11.1 scrubs it at parse time.
        assert "/home/" not in finding["message"], finding["message"]
        assert finding["source_artifact"].startswith("llm/sessions/")
        # Provenance: which unit, which model, which skill revision.
        assert finding["unit_id"] and finding["model"] and finding["skill_version"]


def test_a_second_scan_is_served_entirely_from_the_cache(live_scan: dict) -> None:
    first = live_scan["manifest"]["llm"]
    before = (live_scan["run_dir"] / "review" / "summary.json").read_bytes()

    _exit_code, run_dir = _analyze(live_scan["source"], live_scan["output_root"])

    second = _manifest(run_dir)["llm"]
    assert second["cache"]["hits"] == first["cache"]["stores"] > 0, second["cache"]
    assert second["cache"]["misses"] == 0
    # A replayed unit costs the provider nothing: no request may have been made.
    assert second["budget"]["measured"]["requests"] == 0, second["budget"]["measured"]
    after = json.loads((run_dir / "review" / "summary.json").read_text(encoding="utf-8"))
    assert after["findings"] == json.loads(before)["findings"]


def test_the_validator_files_a_verdict_without_touching_the_evidence(live_scan: dict) -> None:
    run_dir = live_scan["run_dir"]
    candidates = json.loads((run_dir / "audit" / "assessment.json").read_text(encoding="utf-8"))
    if not candidates["candidates"]:
        pytest.skip("no correlated candidate on this fixture")
    evidence = (run_dir / "review" / "summary.json").read_bytes()

    completed = run_cli(
        "assess", run_dir,
        *_config_argv(),
        "--llm-profile", _profile(),
        "--max-candidates", "1",
        timeout=ASSESS_TIMEOUT,
    )

    assert completed.returncode in {0, 10}, completed.stderr
    assessment = json.loads((run_dir / "audit" / "assessment.json").read_text(encoding="utf-8"))
    validated = [item for item in assessment["candidates"] if isinstance(item.get("verdict"), dict)]
    assert validated, assessment["metrics"]
    for candidate in validated:
        assert candidate["verdict"]["label"] in VERDICTS
        assert candidate["verdict"]["skill_version"]
    # The audit layer is an opinion appended beside the evidence, never onto it.
    assert (run_dir / "review" / "summary.json").read_bytes() == evidence
    assert _manifest(run_dir)["audit"]["verdicts"] >= 1

"""End-to-end wiring of the LLM scanner path into the existing pipeline.

Every test here drives ``tests/fake_harness.py``: CI has no model and no
network, and the point of the exercise is the plumbing -- provenance,
coverage, budget accounting, the exit code, and offline re-derivation -- not
the model.  The fake is injected at the one seam ``llm/scan.py`` exposes for
it, so planning, prompting, evidence writing, parsing and reporting all run
for real.
"""
from __future__ import annotations

import copy
import json
import socket
from pathlib import Path
from typing import Any

import pytest
from fake_harness import FakeHarness, HarnessTimeout, response, timed_out
from helpers import executable

from code_analyzer.analysis import AnalysisRequest, run_analysis
from code_analyzer.cli import _overrides, parser
from code_analyzer.config import DEFAULTS, effective_toml, load_config, validate_config
from code_analyzer.dashboard import rebuild_dashboard
from code_analyzer.errors import UserError
from code_analyzer.harness.runtime import SECRET_TOKEN, HarnessRunFailed, RunOutcome
from code_analyzer.llm import scan
from code_analyzer.persist import json_bytes
from code_analyzer.recovery import recover_report
from code_analyzer.tools import TOOL_NAMES

SOURCE = """\
#include <string.h>

void parse_packet(unsigned char *dst, const unsigned char *src, unsigned int len)
{
    unsigned char header[8];
    memcpy(header, src, len);
    if (dst != 0) {
        memcpy(dst, header, sizeof(header));
    }
}
"""

# A model is free to invent a path that never existed on this machine; the
# export stage fails hard on one, so the parser has to scrub it (design 11.1).
HALLUCINATED = "/home/someone/project/parser.c"


def _finding(**overrides: Any) -> dict[str, Any]:
    return {
        "file": "parser.c",
        "line_range": [7, 9],
        "symbol": "parse_packet",
        "category": "null-dereference",
        "severity": "high",
        "confidence": 0.72,
        "cwe": "CWE-476",
        "message": f"dst is dereferenced before the null check in {HALLUCINATED}",
        "rule_id": "MEM-014",
        **overrides,
    }


def _report(*findings: dict[str, Any]) -> str:
    return json.dumps({"findings": list(findings) or [_finding()]})


class _Runtime:
    """A harness runtime bound to one (producer, unit), backed by the fake.

    ``llm/scan.py`` opens one runtime per unit, so the fake's per-unit
    scripting maps onto the production seam without reshaping either side.
    """

    def __init__(self, fake: FakeHarness, producer: str, unit_id: str, settings: dict[str, Any]) -> None:
        self.fake = fake
        self.producer = producer
        self.unit_id = unit_id
        self.settings = settings

    def __enter__(self) -> _Runtime:
        return self

    def __exit__(self, *_exception: object) -> None:
        return None

    def run(self, prompt: Any, *, session_id: str | None = None, on_event: Any = None) -> RunOutcome:
        try:
            result = self.fake.run(producer=self.producer, unit_id=self.unit_id, prompt=prompt)
        except HarnessTimeout as exc:
            raise HarnessRunFailed("timed_out", f"agent runtime timed out: {exc}") from exc
        except AssertionError:
            raise
        except Exception as exc:
            raise HarnessRunFailed("failed", f"agent runtime error: {type(exc).__name__}: {exc}") from exc
        if on_event is not None:
            for event in result.events:
                on_event(event)
        return RunOutcome(
            session_id=result.session_id,
            final_response=result.final_response,
            finish_reason=result.finish_reason,
            events=list(result.events),
            notifications=list(result.notifications),
            duration_seconds=0.0,
        )


class _CancelledRuntime:
    """The user-cancellation path, as ``HarnessRuntime.run`` reports it.

    A CancellationToken observed inside the SDK notifier surfaces as
    ``HarnessRunFailed("interrupted")`` with no provider outcome at all, which
    is exactly what distinguishes it from a provider-reported abort.
    """

    def __init__(self, settings: dict[str, Any]) -> None:
        self.settings = settings

    def __enter__(self) -> _CancelledRuntime:
        return self

    def __exit__(self, *_exception: object) -> None:
        return None

    def run(self, prompt: Any, *, session_id: str | None = None, on_event: Any = None) -> RunOutcome:
        raise HarnessRunFailed("interrupted", "run interrupted")


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeHarness:
    """A fake harness wired into the scan phase's runtime seam."""
    harness = FakeHarness()
    real = scan.run

    def patched(*args: Any, **kwargs: Any) -> dict[str, Any]:
        kwargs["open_runtime"] = lambda producer, unit_id, settings: _Runtime(
            harness, producer, unit_id, settings
        )
        return real(*args, **kwargs)

    monkeypatch.setattr(scan, "run", patched)
    return harness


@pytest.fixture
def closed_endpoint() -> str:
    """A URL nothing is listening on: offline re-derivation must not care."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"http://127.0.0.1:{port}/v1"


def _cppcheck(tmp_path: Path) -> Path:
    return executable(tmp_path / "fake-cppcheck", """
        import pathlib, sys
        if '--version' in sys.argv: print('Cppcheck 2.fake'); raise SystemExit()
        report = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--output-file=')))
        checkers = pathlib.Path(next(x.split('=', 1)[1] for x in sys.argv if x.startswith('--checkers-report=')))
        report.write_text('<?xml version="1.0"?><results version="2"><errors>'
            '<error id="nullPointer" severity="error" msg="Null pointer dereference" cwe="476">'
            '<location file="parser.c" line="8" column="9"/></error></errors></results>')
        checkers.write_text('checked\\n')
    """)


def _tree(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    source.mkdir(parents=True)
    (source / "parser.c").write_text(SOURCE, encoding="utf-8")
    return source


def _config(
    tmp_path: Path,
    endpoint: str,
    *,
    cppcheck: Path | None = None,
    export: bool = False,
    **llm: Any,
) -> dict[str, Any]:
    config = copy.deepcopy(DEFAULTS)
    config["run"]["output_root"] = str(tmp_path / "reports")
    config["run"]["shareable_export"] = export
    config["build"]["compile_database_mode"] = "disabled"
    for name in TOOL_NAMES:
        config["tools"][name]["enabled"] = name == "cppcheck" and cppcheck is not None
    if cppcheck is not None:
        config["tools"]["cppcheck"]["executable"] = str(cppcheck)
    config["llm"].update({
        "enabled": True, "endpoint": endpoint, "scanners": ["llm-memory-safety"], "jobs": 1,
        "heartbeat_seconds": 30.0, **llm,
    })
    return validate_config(config)


def _analyze(source: Path, config: dict[str, Any]) -> tuple[int, Path, dict[str, Any]]:
    events: list[Any] = []
    result = run_analysis(AnalysisRequest(source, config), events=events.append)
    assert result.report_directory is not None
    config["_events"] = events
    return result.exit_code, result.report_directory, result.manifest or {}


def _summary(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "review" / "summary.json").read_text(encoding="utf-8"))


# --- end to end -------------------------------------------------------------


def test_llm_findings_reach_the_review_with_full_provenance(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report()))
    config = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path), export=True)

    exit_code, run_dir, manifest = _analyze(source, config)

    assert exit_code == 0
    assert manifest["manifest_schema_version"] == 2
    assert "llm" not in manifest["tools"]
    assert manifest["llm"]["status"] == "completed"
    assert manifest["llm"]["endpoint"] == closed_endpoint
    assert set(manifest["llm"]["scanners"]) == {"llm-memory-safety"}
    assert (run_dir / "llm" / "index.json").is_file()
    assert list((run_dir / "llm" / "units").glob("*.json"))

    summary = _summary(run_dir)
    llm_findings = [item for item in summary["findings"] if item["engine"] == "llm"]
    assert llm_findings, "the LLM scanner produced no findings"
    item = llm_findings[0]
    assert item["tool"] == item["producer"] == "llm-memory-safety"
    assert item["evidence_class"] == "generated"
    assert item["gate_eligible"] is False
    assert item["severity"] == "high" and item["rank"] == 4
    assert item["canonical_path"] == "parser.c"
    assert item["line"] == "7" and item["line_range"] == [7, 9]
    assert item["category"] == "null-dereference"
    assert item["symbol"] == "parse_packet"
    assert item["confidence"] == 0.72
    assert item["model"] == config["llm"]["model"]
    assert item["skill_version"]
    assert item["unit_id"]
    assert item["source_artifact"].endswith("/findings.json")
    assert item["rationale_artifact"].endswith("/response.json")
    assert (run_dir / item["source_artifact"]).is_file()
    assert (run_dir / item["rationale_artifact"]).is_file()

    # Static findings keep every default they had before the engine axis.
    static = [entry for entry in summary["findings"] if entry["engine"] == "static"]
    assert static and all(
        entry["gate_eligible"] and entry["evidence_class"] == "native" for entry in static
    )
    assert summary["finding_counts_by_engine"] == {
        "total": len(summary["findings"]), "static": len(static), "llm": len(llm_findings),
    }
    assert summary["severity_counts_by_engine"]["llm"]["high"] == len(llm_findings)
    # overlap_groups stays native-only (design 6.1) even though a static and an
    # LLM finding sit three lines apart in the same category. Cross-engine
    # correlation belongs to the audit layer's own artifact.
    assert all(
        "llm-memory-safety" not in group["tools"] for group in summary["overlap_groups"]
    )
    assert manifest["export"]["status"] == "completed"


def test_review_carries_the_scanners_block_and_llm_coverage(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report()))
    config = _config(tmp_path, closed_endpoint)

    _exit_code, run_dir, manifest = _analyze(source, config)
    summary = _summary(run_dir)

    scanner = summary["scanners"]["llm-memory-safety"]
    tool = summary["tools"]["cppcheck"]
    assert set(tool) <= set(scanner), "scanners must stay structurally isomorphic to tools"
    assert scanner["status"] == "completed"
    assert scanner["requested"] is True
    assert scanner["version"] == config["llm"]["model"]
    assert scanner["total_findings"] >= 1
    assert scanner["unit_counts"]["planned"] == manifest["llm"]["planned_units"]

    coverage = summary["llm_coverage"]
    assert coverage["files"]["total"] == 1 and coverage["files"]["scanned"] == 1
    assert coverage["functions"]["total"] >= 1
    assert coverage["by_scanner"]["llm-memory-safety"]["units"] == manifest["llm"]["planned_units"]
    assert coverage["risk_tiers"] and coverage["unscanned_reasons"]["unscheduled"] == 0
    assert manifest["llm"]["coverage"] == coverage


def test_hallucinated_host_paths_are_scrubbed_at_parse_time(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding(
        message=r"length taken from C:\Users\victim\packet.h and /mnt/c/Users/victim/x.c",
        file=HALLUCINATED,
    ))))
    config = _config(tmp_path, closed_endpoint, export=True)

    exit_code, run_dir, manifest = _analyze(source, config)

    raw = (run_dir / "review" / "summary.json").read_text(encoding="utf-8")
    assert "/home/someone" not in raw
    assert "victim" not in raw
    assert "<HOME>" in raw
    assert exit_code == manifest["exit_code"]
    assert manifest["export"]["status"] == "completed"


# --- the exit code is never the model's to change ---------------------------


@pytest.mark.parametrize("outcome", ["timeout", "unavailable", "unparsable", "aborted"])
def test_a_broken_scanner_never_changes_the_exit_code(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str, outcome: str
) -> None:
    source = _tree(tmp_path)
    scripted = {
        "timeout": timed_out(),
        "unavailable": response("", finish_reason="error"),
        "unparsable": response("I could not analyse this unit.", finish_reason="completed"),
        # design 5.2 lists 'aborted' as an ordinary provider stopReason, not a
        # user Ctrl+C: it must not be able to cancel the run.
        "aborted": response("", finish_reason="aborted"),
    }[outcome]
    fake.script_default(scripted)
    cppcheck = _cppcheck(tmp_path)

    control_config = _config(tmp_path / "control", closed_endpoint, cppcheck=cppcheck)
    control_config["llm"]["enabled"] = False
    control_code, control_dir, control_manifest = _analyze(_tree(tmp_path / "control"), control_config)

    exit_code, run_dir, manifest = _analyze(source, _config(tmp_path, closed_endpoint, cppcheck=cppcheck))

    assert control_code == 0 and control_manifest["llm"]["status"] == "not_requested"
    assert exit_code == control_code
    assert manifest["status"] == control_manifest["status"]
    assert manifest["llm"]["status"] in {"failed", "timed_out", "partial"}
    # The review is the deliverable: a scanner problem must never discard it.
    assert (run_dir / "review" / "summary.json").is_file()
    assert manifest["review"]["status"] == "completed"
    summary = _summary(run_dir)
    # An unusable scanner report must not mark the derived review partial:
    # that is what turns a complete run into exit code 10.
    assert summary["report_integrity"]["status"] == "complete"
    assert not any(item["engine"] == "llm" for item in summary["findings"])
    assert any(item["category"].startswith("llm-") for item in summary["diagnostics"])
    static = [item for item in summary["findings"] if item["engine"] == "static"]
    control_static = [item for item in _summary(control_dir)["findings"] if item["engine"] == "static"]
    assert static and len(static) == len(control_static)


def test_a_user_cancellation_still_interrupts_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, closed_endpoint: str
) -> None:
    """The other half of the abort fix: a real cancel must still exit 130."""
    source = _tree(tmp_path)
    real = scan.run

    def patched(*args: Any, **kwargs: Any) -> dict[str, Any]:
        kwargs["open_runtime"] = lambda _producer, _unit, settings: _CancelledRuntime(settings)
        return real(*args, **kwargs)

    monkeypatch.setattr(scan, "run", patched)

    exit_code, _run_dir, manifest = _analyze(
        source, _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path))
    )

    assert exit_code == 130
    assert manifest["status"] == "interrupted"
    assert manifest["llm"]["status"] == "interrupted"


def test_a_hallucinated_critical_cannot_trip_the_quality_gate(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding(severity="critical"))))
    config = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path))
    config["review"]["fail_on"] = "critical"

    exit_code, run_dir, manifest = _analyze(source, config)

    summary = _summary(run_dir)
    assert any(item["severity"] == "critical" and item["engine"] == "llm" for item in summary["findings"])
    assert manifest["gate"]["triggered"] is False
    assert exit_code == 0


# --- the credential is nobody's to leak -------------------------------------

# A value long enough to be a real key, so the length guard does not hide a
# regression.
SECRET = "sk-test-6f1c9b2ad4e84457bb3a00112233445566"
KEY_ENV = "CODE_ANALYZER_TEST_KEY"


class _LeakingRuntime:
    """A provider error whose text quotes the Authorization header it sent.

    This is how the credential actually escapes: not because anyone persists
    it deliberately, but because the SDK formats its own request context into
    an exception and the phase records that as the unit's reason.
    """

    def __init__(self, settings: dict[str, Any]) -> None:
        self.settings = settings

    def __enter__(self) -> _LeakingRuntime:
        return self

    def __exit__(self, *_exception: object) -> None:
        return None

    def run(self, prompt: Any, *, session_id: str | None = None, on_event: Any = None) -> RunOutcome:
        raise HarnessRunFailed(
            "failed", f"401 Unauthorized for {{'Authorization': 'Bearer {SECRET}'}}"
        )


def test_a_provider_error_quoting_the_api_key_does_not_reach_manifest_or_review(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, closed_endpoint: str
) -> None:
    monkeypatch.setenv(KEY_ENV, SECRET)
    source = _tree(tmp_path)
    real = scan.run

    def patched(*args: Any, **kwargs: Any) -> dict[str, Any]:
        kwargs["open_runtime"] = lambda _producer, _unit, settings: _LeakingRuntime(settings)
        return real(*args, **kwargs)

    monkeypatch.setattr(scan, "run", patched)
    config = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path), api_key_env=KEY_ENV)

    exit_code, run_dir, manifest = _analyze(source, config)

    manifest_text = (run_dir / "manifest.json").read_text(encoding="utf-8")
    review_text = (run_dir / "review" / "summary.json").read_text(encoding="utf-8")
    assert SECRET not in manifest_text
    assert SECRET not in review_text
    # The reason itself must survive, redacted: asserting only on absence
    # would also pass on a run that recorded nothing at all.
    assert "401 Unauthorized" in manifest_text
    assert SECRET_TOKEN in manifest_text
    assert manifest["llm"]["status"] == "failed"
    assert exit_code == 0


def test_a_model_echoing_the_api_key_does_not_reach_the_review_or_its_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake: FakeHarness, closed_endpoint: str
) -> None:
    """The other direction: whatever the model says is evidence, and evidence
    is what rebuild-dashboard and recover-report re-derive the review from."""
    monkeypatch.setenv(KEY_ENV, SECRET)
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding(
        message=f"the request authorised with {SECRET} overflows dst",
    ))))
    config = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path), api_key_env=KEY_ENV)

    exit_code, run_dir, _manifest = _analyze(source, config)

    evidence = list((run_dir / "llm").rglob("findings.json"))
    assert evidence
    for path in evidence:
        assert SECRET not in path.read_text(encoding="utf-8")
    review_text = (run_dir / "review" / "summary.json").read_text(encoding="utf-8")
    assert SECRET not in review_text
    assert SECRET_TOKEN in review_text
    assert exit_code == 0


# --- budget -----------------------------------------------------------------


def test_an_exhausted_token_budget_records_unscheduled_units(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report()))
    config = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path), total_prompt_tokens=1)

    exit_code, run_dir, manifest = _analyze(source, config)

    counts = manifest["llm"]["unit_counts"]
    assert counts["planned"] == counts["started"] + counts["unscheduled"]
    assert counts["unscheduled"] == counts["planned"] > 0
    assert fake.calls == [], "a unit that cannot be afforded must never be dispatched"
    reasons = {
        unit["reason"] for unit in manifest["llm"]["scanners"]["llm-memory-safety"]["units"]
    }
    assert reasons == {"prompt token budget exhausted"}
    assert manifest["llm"]["coverage"]["unscanned_reasons"]["unscheduled"] == counts["planned"]
    assert exit_code == 0


def test_an_exhausted_wall_clock_budget_records_unscheduled_units(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report()))
    config = _config(tmp_path, closed_endpoint, total_timeout_seconds=0.001)

    _exit_code, _run_dir, manifest = _analyze(source, config)

    counts = manifest["llm"]["unit_counts"]
    assert counts["planned"] == counts["started"] + counts["unscheduled"]
    assert counts["unscheduled"] >= 1
    assert "total budget exhausted" in {
        unit["reason"] for unit in manifest["llm"]["scanners"]["llm-memory-safety"]["units"]
    }


# --- offline re-derivation --------------------------------------------------


def test_rebuild_and_recover_work_offline_against_a_closed_endpoint(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report()))
    _exit_code, run_dir, _manifest = _analyze(
        source, _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path), export=True)
    )
    before = _summary(run_dir)
    calls = len(fake.calls)

    dashboard = rebuild_dashboard(run_dir)
    assert dashboard.is_file()
    index = rebuild_dashboard(run_dir)
    assert index.read_bytes() == dashboard.read_bytes()

    recovered = recover_report(run_dir)
    assert recovered.is_file()
    after = _summary(run_dir)

    assert len(fake.calls) == calls, "offline re-derivation must not call the model"
    assert [item["fingerprint"] for item in after["findings"]] == [
        item["fingerprint"] for item in before["findings"]
    ]
    assert after["llm_coverage"] == before["llm_coverage"]
    assert after["scanners"] == before["scanners"]
    # The endpoint recorded in the run is a closed port; nothing reached it.
    config_text = (run_dir / "inputs" / "effective-config.toml").read_text(encoding="utf-8")
    assert closed_endpoint in config_text


def test_a_second_run_answers_from_the_cache_without_the_model(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report()))
    config = _config(tmp_path, closed_endpoint)
    _first_code, first_dir, first_manifest = _analyze(source, config)
    assert first_manifest["llm"]["cache"]["stores"] == len(fake.calls) > 0

    # The script stays in place: a cache miss would quietly succeed, so the
    # assertion below is on the calls the fake actually received.
    fake.calls.clear()
    _second_code, second_dir, second_manifest = _analyze(source, _config(tmp_path, closed_endpoint))

    assert fake.calls == []
    assert second_manifest["llm"]["cache"]["hits"] == first_manifest["llm"]["cache"]["stores"]
    assert second_dir != first_dir
    assert _summary(second_dir)["findings"] == _summary(first_dir)["findings"]
    # A hit is materialised into the new run: every run stays self-contained.
    unit = second_manifest["llm"]["scanners"]["llm-memory-safety"]["units"][0]
    meta = json.loads((second_dir / "llm" / "sessions" / "llm-memory-safety" / unit["id"] / "meta.json").read_text(encoding="utf-8"))
    assert meta["cache"]["hit"] is True and meta["cache"]["key"]

    # Design 8.4: volatile values live in meta.json alone.  A replay therefore
    # has to reproduce the whole review byte for byte, not merely its findings.
    assert "seconds_remaining" not in second_manifest["llm"]["budget"]
    assert second_manifest["llm"]["budget"] == first_manifest["llm"]["budget"]
    first, second = _summary(first_dir), _summary(second_dir)
    assert first["run"].keys() == second["run"].keys()
    assert json_bytes(_stable(second)) == json_bytes(_stable(first))


# The identity of a run, and the session metadata whose digest carries the
# duration and the cache provenance of that run, are the only keys a replay is
# allowed to change.  meta.json is written by harness/session.py.
VOLATILE_RUN_KEYS = ("id", "started_at", "completed_at")


def _stable(summary: dict[str, Any]) -> dict[str, Any]:
    summary = copy.deepcopy(summary)
    summary["run"] = {
        key: value for key, value in summary["run"].items() if key not in VOLATILE_RUN_KEYS
    }
    for scanner in summary["scanners"].values():
        for unit in scanner["units"]:
            unit["artifacts"] = [
                item for item in unit["artifacts"] if not item["path"].endswith("/meta.json")
            ]
    return summary


def _rules(run_dir: Path) -> set[str]:
    return {item["rule_id"] for item in _summary(run_dir)["findings"] if item["engine"] == "llm"}


def _prompt_digests(run_dir: Path) -> set[str]:
    return {
        json.loads(path.read_text(encoding="utf-8"))["prompt_sha256"]
        for path in sorted((run_dir / "llm" / "sessions").rglob("request.json"))
    }


def test_the_cache_key_covers_the_rendered_prompt(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding(rule_id="MEM-LOW"))))
    _low_code, low_dir, low_manifest = _analyze(
        source, _config(tmp_path, closed_endpoint, risk_profile="low")
    )
    low_prompts = [call.request["prompt"] for call in fake.calls]
    assert low_manifest["llm"]["cache"]["stores"] == len(low_prompts) > 0

    # The tier drives TIER_BUDGETS and therefore the rendered prompt, so a
    # re-tiered unit is a different scan: replaying the cheaper one would hand
    # the operator low-context findings under a CRITICAL banner.
    fake.calls.clear()
    fake.script_default(response(_report(_finding(rule_id="MEM-CRITICAL"))))
    _high_code, high_dir, high_manifest = _analyze(
        source, _config(tmp_path, closed_endpoint, risk_profile="critical")
    )
    high_prompts = [call.request["prompt"] for call in fake.calls]

    assert high_manifest["llm"]["cache"]["hits"] == 0
    assert high_prompts and high_prompts != low_prompts
    assert _rules(low_dir) == {"MEM-LOW"} and _rules(high_dir) == {"MEM-CRITICAL"}
    assert _prompt_digests(low_dir).isdisjoint(_prompt_digests(high_dir))

    # An unchanged prompt still hits, and serves the answer that prompt
    # produced rather than whatever the model would say today.
    fake.calls.clear()
    fake.script_default(response(_report(_finding(rule_id="MEM-NEVER-CALLED"))))
    _repeat_code, repeat_dir, repeat_manifest = _analyze(
        source, _config(tmp_path, closed_endpoint, risk_profile="critical")
    )
    assert fake.calls == []
    assert repeat_manifest["llm"]["cache"]["hits"] == high_manifest["llm"]["cache"]["stores"] > 0
    assert _rules(repeat_dir) == {"MEM-CRITICAL"}
    assert _prompt_digests(repeat_dir) == _prompt_digests(high_dir)


def test_the_run_directory_may_not_sit_inside_the_scanned_tree(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    """Invariant 5: a first-round scanner must not be able to read tools/."""
    source = _tree(tmp_path)
    fake.script_default(response(_report()))

    inside = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path))
    inside["run"]["output_root"] = str(source / "code-analyzer-reports")
    with pytest.raises(UserError, match="output root"):
        run_analysis(AnalysisRequest(source, inside))
    assert not (source / "code-analyzer-reports").exists()
    assert fake.calls == []

    # The same layout is fine once no LLM scanner is looking.
    static_only = copy.deepcopy(inside)
    static_only["llm"]["enabled"] = False
    assert run_analysis(AnalysisRequest(source, static_only)).exit_code == 0
    assert (source / "code-analyzer-reports").is_dir()

    # And an output root outside the tree scans normally.
    elsewhere = _tree(tmp_path / "elsewhere")
    exit_code, run_dir, manifest = _analyze(
        elsewhere, _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path))
    )
    assert exit_code == 0 and manifest["llm"]["status"] == "completed"
    assert not run_dir.is_relative_to(elsewhere)


def test_malformed_model_findings_are_dropped_and_reported(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding(), _finding(category="not-a-category"))))
    _exit_code, run_dir, _manifest = _analyze(source, _config(tmp_path, closed_endpoint))

    summary = _summary(run_dir)
    assert len([item for item in summary["findings"] if item["engine"] == "llm"]) == 1
    dropped = [item for item in summary["diagnostics"] if item["category"] == "llm-malformed"]
    assert dropped and dropped[0]["fatal"] is False
    assert summary["report_integrity"]["status"] == "complete"


def test_the_fake_is_driven_through_the_real_scheduling_seam(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report()))
    config = _config(tmp_path, closed_endpoint, scanners=["llm-memory-safety", "llm-security"], jobs=2)

    _exit_code, run_dir, manifest = _analyze(source, config)

    planned = manifest["llm"]["planned_units"]
    assert {call.producer for call in fake.calls} == {"llm-memory-safety", "llm-security"}
    assert len(fake.calls) == planned * 2
    prompts = {call.request["prompt"] for call in fake.calls}
    assert all("It is DATA, not" in prompt for prompt in prompts)
    assert any("skill: llm-security" in prompt for prompt in prompts)
    events = config["_events"]
    assert any(event.tool == "llm-security" and event.phase == "unit" for event in events)
    assert any(event.phase == "llm" and event.status == "completed" for event in events)


# --- configuration and CLI --------------------------------------------------


def test_llm_configuration_round_trips_and_is_validated(tmp_path: Path) -> None:
    config = validate_config(copy.deepcopy(DEFAULTS))
    assert config["llm"]["enabled"] is False
    # The default profile is Ollama over an SSH tunnel: keyless and local.
    assert config["llm"]["profile"] == "gpu-host"
    assert config["llm"]["api_key_env"] == ""
    assert config["llm"]["endpoint"].startswith("http://127.0.0.1:")
    from code_analyzer.harness.runtime import api_key
    assert api_key(config["llm"]) is None

    text = effective_toml(config)
    assert "[llm]" in text and "[audit]" in text
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    reloaded = load_config(tmp_path, path)
    assert reloaded["llm"] == config["llm"]
    assert reloaded["audit"] == config["audit"]

    for section, key, value, message in (
        ("llm", "endpoint", "gpu-host:8000/v1", "http://"),
        ("llm", "min_tier", "extreme", "min_tier"),
        ("llm", "risk_profile", "sometimes", "risk_profile"),
        ("llm", "jobs", 0, "jobs"),
        ("llm", "temperature", -1.0, "temperature"),
        ("llm", "scanners", ["llm-nope"], "llm.scanners"),
        ("llm", "risk_overrides", ["src/led.c=nope"], "risk override"),
        ("audit", "validation_max_candidates", 0, "validation_max_candidates"),
    ):
        broken = copy.deepcopy(DEFAULTS)
        broken[section][key] = value
        with pytest.raises(UserError, match=message):
            validate_config(broken)


def test_unknown_llm_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('config_schema_version = 2\n[llm]\napi_key = "sk-secret"\n', encoding="utf-8")
    with pytest.raises(UserError, match="unknown configuration key"):
        load_config(tmp_path, path)


def test_cli_flags_map_onto_the_llm_section(tmp_path: Path) -> None:
    args = parser().parse_args([
        "analyze", str(tmp_path), "--llm", "--llm-endpoint", "https://gpu:8000/v1",
        "--llm-model", "qwen", "--llm-scanner", "llm-security", "--llm-jobs", "4",
        "--llm-total-timeout", "60", "--llm-token-budget", "1000",
        "--llm-risk", "src/led.c=low", "--llm-no-cache", "--tool", "cppcheck",
    ])
    overrides = _overrides(args)

    assert overrides["llm"] == {
        "enabled": True, "endpoint": "https://gpu:8000/v1", "model": "qwen",
        "scanners": ["llm-security"], "jobs": 4, "total_timeout_seconds": 60.0,
        "total_prompt_tokens": 1000, "risk_overrides": ["src/led.c=low"], "cache": False,
    }
    assert overrides["tools"]["cppcheck"]["enabled"] is True
    assert _overrides(parser().parse_args(["analyze", str(tmp_path), "--no-llm"]))["llm"] == {
        "enabled": False
    }
    assert "llm" not in _overrides(parser().parse_args(["analyze", str(tmp_path)]))

def test_a_provider_stopped_unit_is_never_written_to_the_cache(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    """A transient abort must not be baked into every later run of the prompt.

    ``_provider_stop`` demotes an aborted unit to ``partial`` so it cannot
    cancel the phase, which also walked it straight through the store gate.
    Caching a truncated unit is the "operator believes they ran a full scan"
    hazard the prompt-keyed cache exists to prevent.
    """
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding()), finish_reason="aborted"))
    _code, _run_dir, aborted = _analyze(source, _config(tmp_path, closed_endpoint))
    assert aborted["llm"]["cache"]["stores"] == 0

    # A healthy provider on the same tree must really call the model again
    # rather than replay the truncated unit.
    fake.calls.clear()
    fake.script_default(response(_report(_finding()), finish_reason="completed"))
    _code2, _dir2, healthy = _analyze(source, _config(tmp_path, closed_endpoint))
    assert healthy["llm"]["cache"]["hits"] == 0
    assert len(fake.calls) > 0
    assert healthy["llm"]["cache"]["stores"] == len(fake.calls)


def test_a_provider_stop_leaves_the_evidence_and_the_manifest_telling_one_story(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    """meta.json is written before the scanner can reclassify a provider stop.

    An offline auditor reads the per-unit evidence, not the manifest, so the two
    must not use the same status vocabulary to say different things.
    """
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding()), finish_reason="aborted"))
    _code, run_dir, manifest = _analyze(source, _config(tmp_path, closed_endpoint))

    unit = manifest["llm"]["scanners"]["llm-memory-safety"]["units"][0]
    assert unit["status"] in {"partial", "failed"}
    meta_path = run_dir / "llm" / "sessions" / "llm-memory-safety" / unit["id"] / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["status"] == unit["status"]
    assert meta["status"] != "interrupted"


def test_progress_stays_monotone_when_the_llm_phase_runs(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str
) -> None:
    """tests/test_runtime_output.py pins monotone progress, but only static-only.

    With [llm] enabled the phase ended at 0.84 and the stability rescan then
    re-announced 0.8, so every LLM run walked the progress bar backwards while
    the pinned test stayed green.
    """
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding())))
    config = _config(tmp_path, closed_endpoint)
    _analyze(source, config)
    values = [event.progress for event in config["_events"] if event.progress is not None]
    assert values and values == sorted(values)
    # The regression was specifically the LLM phase's end being followed by a
    # lower stability value; make sure both events are present in the sample.
    phases = [event.phase for event in config["_events"] if event.progress is not None]
    assert "llm" in phases and "stability" in phases

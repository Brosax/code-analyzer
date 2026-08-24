"""``llm-resume``: finish a scan the budget or the clock cut short.

The property under test is not "it scans again" but *what it refuses to do*:
it replays the run's own rendered prompts rather than re-planning against
today's source, it says so when a skill has changed underneath, and it re-derives
the review from the enlarged evidence without touching the verdicts an assess
already paid for.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fake_harness import FakeHarness, response
from test_llm_pipeline import (  # noqa: F401  (fixtures)
    _analyze,
    _config,
    _cppcheck,
    _finding,
    _report,
    _Runtime,
    _tree,
    closed_endpoint,
    fake,
)

from code_analyzer.errors import UserError
from code_analyzer.llm.resume import RESUMABLE, run_resume
from code_analyzer.llm.skills import load_skill

SCANNER = "llm-memory-safety"


def _manifest(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))


def _units(run_dir: Path, scanner: str = SCANNER) -> list[dict[str, Any]]:
    return _manifest(run_dir)["llm"]["scanners"][scanner]["units"]


def _starved(tmp_path: Path, harness: FakeHarness, endpoint: str) -> tuple[Path, dict[str, Any]]:
    """A finished run whose units were all left unscheduled by the budget."""
    source = _tree(tmp_path)
    harness.script_default(response(_report(_finding())))
    config = _config(tmp_path, endpoint, cppcheck=_cppcheck(tmp_path), cache=False, total_prompt_tokens=1)
    exit_code, run_dir, _manifest_value = _analyze(source, config)
    assert exit_code == 0
    assert {unit["status"] for unit in _units(run_dir)} == {"unscheduled"}
    assert harness.calls == []
    return run_dir, config


def _resume(run_dir: Path, config: dict[str, Any], harness: FakeHarness, **overrides: Any) -> dict[str, Any]:
    settings = {**config, "llm": {**config["llm"], "total_prompt_tokens": 2_000_000, **overrides}}
    return run_resume(
        run_dir, settings,
        open_runtime=lambda producer, unit_id, active: _Runtime(harness, producer, unit_id, active),
    )


def test_resume_scans_the_starved_units_and_rederives_the_review(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    run_dir, config = _starved(tmp_path, fake, closed_endpoint)
    before = json.loads((run_dir / "review" / "summary.json").read_text(encoding="utf-8"))
    assert [item for item in before["findings"] if item.get("engine") == "llm"] == []

    block = _resume(run_dir, config, fake)

    assert block["exit_code"] == 0 and block["resumed"] > 0
    assert {unit["status"] for unit in _units(run_dir)} == {"completed"}
    assert fake.calls, "resume must actually dispatch the units it reports as resumed"
    # The review is derived again from the enlarged evidence, not left stale.
    after = json.loads((run_dir / "review" / "summary.json").read_text(encoding="utf-8"))
    assert [item for item in after["findings"] if item.get("engine") == "llm"]
    assert after["total_findings"] > before["total_findings"]
    manifest = _manifest(run_dir)
    assert manifest["review"]["findings"] == after["total_findings"]
    # Unlike recover-report, this command *did* invoke an analyzer and says so.
    assert manifest["llm"]["resume"] == {
        **manifest["llm"]["resume"], "runs": 1, "analyzers_invoked": True,
    }
    assert (run_dir / "review" / "summary.sarif").is_file()
    assert (run_dir / "audit" / "assessment.json").is_file()


def test_resume_replays_the_stored_prompt_instead_of_re_planning(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    """The unit ids belong to the original plan, so the code must too.

    Re-planning against today's source would scan different bytes under the
    same unit id and file them as one run's evidence.
    """
    run_dir, config = _starved(tmp_path, fake, closed_endpoint)
    source = Path(_manifest(run_dir)["source"])
    stored = sorted((run_dir / "llm" / "units").glob("*.json"))
    assert stored
    payload = json.loads(stored[0].read_text(encoding="utf-8"))
    original = json.dumps(payload["prompt"], sort_keys=True)

    # Rewrite the tree entirely: every planned unit is now stale source.
    for path in source.rglob("*.c"):
        path.write_text("int replaced(void) { return 0; }\n", encoding="utf-8")

    _resume(run_dir, config, fake)

    assert json.loads(stored[0].read_text(encoding="utf-8"))["prompt"] == json.loads(original)
    sent = "\n".join(str(call) for call in fake.calls)
    assert "replaced" not in sent, "resume must not send code the plan never described"


def test_resume_reports_a_scanner_that_changed_under_the_run(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str, monkeypatch: pytest.MonkeyPatch  # noqa: F811
) -> None:
    run_dir, config = _starved(tmp_path, fake, closed_endpoint)
    manifest = _manifest(run_dir)
    manifest["llm"]["scanners"][SCANNER]["skill_version"] = "0.0.1"
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    messages: list[str] = []

    run_resume(
        run_dir, {**config, "llm": {**config["llm"], "total_prompt_tokens": 2_000_000}},
        progress=messages.append,
        open_runtime=lambda producer, unit_id, active: _Runtime(fake, producer, unit_id, active),
    )

    drift = [text for text in messages if "0.0.1" in text]
    assert drift and "resumed units are scanned by the newer scanner" in drift[0]
    # Every unit carries the version that actually scanned it.
    block = _manifest(run_dir)["llm"]["scanners"][SCANNER]
    assert {unit["skill_version"] for unit in block["units"]} == {load_skill(SCANNER).skill_version}
    # One version scanned everything here, so the block states it plainly.
    assert block["skill_version"] == load_skill(SCANNER).skill_version
    assert "skill_versions" not in block


def test_a_block_spanning_two_scanner_versions_names_both(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    """A resumed run can hold units scanned by two different scanners.

    Stamping the block with whichever ran last would claim the new version for
    units the old one produced, and their own records would contradict it.
    """
    run_dir, config = _starved(tmp_path, fake, closed_endpoint)
    manifest = _manifest(run_dir)
    units = manifest["llm"]["scanners"][SCANNER]["units"]
    # One unit already scanned, by an older scanner than the one on disk.
    units[0].update({"status": "completed", "valid_report": True, "skill_version": "0.9.0", "skill_sha256": "a" * 64})
    manifest["llm"]["scanners"][SCANNER].update({"skill_version": "0.9.0", "skill_sha256": "a" * 64})
    (run_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    _resume(run_dir, config, fake)

    block = _manifest(run_dir)["llm"]["scanners"][SCANNER]
    assert block["skill_version"] == "0.9.0", "the block must not adopt the newer version wholesale"
    assert [item["skill_version"] for item in block["skill_versions"]] == ["0.9.0", load_skill(SCANNER).skill_version]


def test_resume_leaves_a_finished_run_untouched(
    tmp_path: Path, fake: FakeHarness, closed_endpoint: str  # noqa: F811
) -> None:
    source = _tree(tmp_path)
    fake.script_default(response(_report(_finding())))
    config = _config(tmp_path, closed_endpoint, cppcheck=_cppcheck(tmp_path), cache=False)
    _exit_code, run_dir, _manifest_value = _analyze(source, config)
    assert not [unit for unit in _units(run_dir) if unit["status"] in RESUMABLE]
    before = (run_dir / "manifest.json").read_bytes()
    calls = len(fake.calls)

    block = _resume(run_dir, config, fake)

    assert block["exit_code"] == 0 and block["resumed"] == 0
    assert len(fake.calls) == calls, "nothing to resume must dispatch nothing"
    assert (run_dir / "manifest.json").read_bytes() == before


def test_resume_refuses_a_run_that_has_no_llm_phase(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text(json.dumps({"manifest_schema_version": 2, "source": str(tmp_path)}))
    with pytest.raises(UserError, match="no LLM phase to resume"):
        run_resume(run_dir, {"llm": {}, "run": {}, "review": {}})

from __future__ import annotations

import copy
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .audit import assessment_summary, build_assessment
from .config import DEFAULTS, load_config, validate_config
from .errors import UserError
from .html_report import render
from .persist import json_bytes, manifest_structure_problem
from .review import REVIEW_SCHEMA_VERSION, build_review, markdown_report
from .sanitize import ExportError, export_shareable
from .sarif import build_sarif
from .tools.common import artifact_index


def recover_report(report_directory: Path) -> Path:
    """Rebuild every derived report artifact without invoking an analyzer."""
    report_directory = report_directory.expanduser().resolve()
    if not report_directory.is_dir():
        raise UserError(f"report directory is not a directory: {report_directory}")
    manifest_path = report_directory / "manifest.json"
    manifest = _read_object(manifest_path, "manifest")
    _validate_manifest(manifest, manifest_path)
    inventory_path = report_directory / "inputs" / "source-inventory.json"
    inventory_document = _read_object(inventory_path, "source inventory")
    inventory = inventory_document.get("files")
    if not isinstance(inventory, list) or not all(
        isinstance(item, dict) and isinstance(item.get("path"), str) for item in inventory
    ):
        raise UserError(f"invalid source inventory in {inventory_path}: files must contain path objects")

    original_state = {
        key: copy.deepcopy(manifest.get(key))
        for key in ("status", "exit_code", "started_at", "finished_at", "tools")
    }
    source = Path(str(inventory_document.get("source") or manifest.get("source") or "."))
    try:
        review = build_review(source, report_directory, manifest, inventory)
    except Exception as exc:
        raise UserError(f"cannot recover review from {report_directory}: {exc}") from exc

    config = _recovery_config(report_directory, source)
    max_findings = int(config["review"]["max_markdown_findings"])
    review_json = json_bytes(review)
    review_markdown = markdown_report(review, max_findings).encode("utf-8")
    assessment = build_assessment(review)
    assessment_json = json_bytes(assessment)
    sarif_json = json_bytes(build_sarif(review, manifest))
    recovered = copy.deepcopy(manifest)
    recovered["review"] = {
        **recovered.get("review", {}),
        "enabled": True,
        "status": "partial" if review.get("report_integrity", {}).get("status") == "partial" else "completed",
        "schema_version": REVIEW_SCHEMA_VERSION,
        "summary": "review/summary.json",
        "error": None,
        "findings": review["total_findings"],
        "diagnostics": review["total_diagnostics"],
    }
    recovery_time = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    filename_time = recovery_time.replace("-", "").replace(":", "").replace(".", "")
    archive_name = f"{manifest['run_id']}-recovery-{filename_time}-shareable.zip"
    recovered["recovery"] = {
        "performed_at": recovery_time,
        "mode": "offline",
        "analyzers_invoked": False,
        "source_inventory": "inputs/source-inventory.json",
        "native_artifacts_modified": False,
        "derived_artifacts": [],
    }

    archive: Path | None = None
    try:
        archive = export_shareable(
            report_directory,
            recovered,
            config,
            [inventory_path, report_directory / "inputs" / "effective-config.toml"],
            review_override=review,
            archive_name=archive_name,
        )
        # Export metadata describes the recovered archive, while scan outcome
        # and tool execution records remain byte-for-byte equivalent values.
        for key, value in original_state.items():
            recovered[key] = value
        artifacts = artifact_index(report_directory)
        artifacts = _replace_artifact(artifacts, "review/summary.json", review_json)
        artifacts = _replace_artifact(artifacts, "review/summary.md", review_markdown)
        artifacts = _replace_artifact(artifacts, "audit/assessment.json", assessment_json)
        artifacts = _replace_artifact(artifacts, "review/summary.sarif", sarif_json)
        recovered["audit"] = {**assessment_summary(assessment), "error": None}
        render_manifest = copy.deepcopy(recovered)
        render_manifest["artifacts"] = [item for item in artifacts if item.get("path") != "index.html"]
        index_bytes = render(render_manifest, review, assessment).encode("utf-8")
        artifacts = _replace_artifact(artifacts, "index.html", index_bytes)
        recovered["artifacts"] = artifacts
        recovered["recovery"]["derived_artifacts"] = [
            item for item in artifacts
            if item.get("path") in {
                "review/summary.json", "review/summary.md", "review/summary.sarif", "audit/assessment.json", "index.html",
                archive.relative_to(report_directory).as_posix(),
            }
        ]
        manifest_bytes = json_bytes(recovered)
        _replace_transaction(report_directory, {
            report_directory / "review" / "summary.json": review_json,
            report_directory / "review" / "summary.md": review_markdown,
            report_directory / "audit" / "assessment.json": assessment_json,
            report_directory / "review" / "summary.sarif": sarif_json,
            report_directory / "index.html": index_bytes,
            manifest_path: manifest_bytes,
        })
    except (ExportError, OSError, ValueError, TypeError) as exc:
        if archive is not None:
            archive.unlink(missing_ok=True)
        raise UserError(f"cannot recover report in {report_directory}: {exc}") from exc
    return report_directory / "index.html"


def _recovery_config(report_directory: Path, source: Path) -> dict[str, Any]:
    path = report_directory / "inputs" / "effective-config.toml"
    if path.is_file():
        try:
            return load_config(source, path)
        except UserError:
            pass
    config = copy.deepcopy(DEFAULTS)
    config["run"]["shareable_export"] = True
    return validate_config(config)


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise UserError(f"missing {label}: {path}") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise UserError(f"invalid {label} in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise UserError(f"invalid {label} in {path}: expected a JSON object")
    return value


def _validate_manifest(manifest: dict[str, Any], path: Path) -> None:
    problem = manifest_structure_problem(manifest)
    if problem is not None:
        raise UserError(f"invalid manifest in {path}: {problem}")
    if not isinstance(manifest.get("run_id"), str) or not manifest["run_id"]:
        raise UserError(f"invalid manifest in {path}: run_id is required")


def _replace_artifact(artifacts: list[dict[str, Any]], relative: str, data: bytes) -> list[dict[str, Any]]:
    replacement = {"path": relative, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    result = [item for item in artifacts if item.get("path") != relative]
    result.append(replacement)
    return sorted(result, key=lambda item: str(item.get("path", "")))


def _replace_transaction(report_directory: Path, replacements: dict[Path, bytes]) -> None:
    token = uuid.uuid4().hex
    temporary: dict[Path, Path] = {}
    previous: dict[Path, bytes | None] = {}
    committed: list[Path] = []
    try:
        for target, data in replacements.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            previous[target] = target.read_bytes() if target.exists() else None
            temp = target.parent / f".recover-{target.name}-{token}.tmp"
            with temp.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            temporary[target] = temp
        for target, temp in temporary.items():
            temp.replace(target)
            committed.append(target)
    except OSError:
        for target in reversed(committed):
            old = previous[target]
            if old is None:
                target.unlink(missing_ok=True)
            else:
                rollback = target.parent / f".recover-{target.name}-{token}.rollback"
                with rollback.open("xb") as stream:
                    stream.write(old)
                    stream.flush()
                    os.fsync(stream.fileno())
                rollback.replace(target)
        raise
    finally:
        for temp in temporary.values():
            temp.unlink(missing_ok=True)
        for path in report_directory.rglob(f".recover-*-{token}.rollback"):
            path.unlink(missing_ok=True)

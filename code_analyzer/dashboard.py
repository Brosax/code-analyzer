from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

from .audit import load_assessment
from .errors import UserError
from .html_report import render
from .persist import json_bytes, manifest_structure_problem
from .report_presentation import (
    load_run_summary,
    safe_relative_path,
    standalone_summary_markdown,
)


def rebuild_dashboard(report_directory: Path) -> Path:
    """Rebuild one dashboard from its persisted structured report data."""
    report_directory = report_directory.expanduser().resolve()
    if not report_directory.is_dir():
        raise UserError(f"report directory is not a directory: {report_directory}")

    manifest_path = report_directory / "manifest.json"
    manifest = _read_object(manifest_path, "manifest")
    problem = manifest_structure_problem(manifest)
    if problem is not None:
        raise UserError(f"invalid manifest in {manifest_path}: {problem}")
    artifacts = manifest["artifacts"]

    review_path = report_directory / "review" / "summary.json"
    review = _read_object(review_path, "review summary") if review_path.exists() else None
    if review is not None and review.get("review_schema_version") not in {1, 2, 3}:
        raise UserError(
            f"invalid review summary in {review_path}: unsupported or missing review schema version"
        )
    if review is not None:
        _validate_review(review, review_path)

    index_path = report_directory / "index.html"
    if index_path.exists() and not index_path.is_file():
        raise UserError(f"dashboard path is not a file: {index_path}")

    try:
        # Do not embed index.html's previous digest in index.html itself.  A
        # self-digest has no finite stable representation, and retaining the
        # old value would make every rebuild produce different bytes.
        render_manifest = dict(manifest)
        render_manifest["artifacts"] = [
            item for item in artifacts if item.get("path") != "index.html"
            and safe_relative_path(item.get("path"))
            and (report_directory / item["path"]).is_file()
        ]
        assessment = load_assessment(report_directory)
        run_summary = load_run_summary(report_directory, manifest, review, assessment)
        index_bytes = render(render_manifest, review, assessment, run_summary=run_summary).encode("utf-8")
        updated_manifest = dict(manifest)
        updated_manifest["artifacts"] = _updated_artifacts(artifacts, index_bytes)
        manifest_bytes = json_bytes(updated_manifest)
    except (TypeError, ValueError) as exc:
        raise UserError(f"cannot rebuild dashboard from {report_directory}: {exc}") from exc

    try:
        old_index = index_path.read_bytes() if index_path.exists() else None
    except OSError as exc:
        raise UserError(f"cannot read existing dashboard {index_path}: {exc}") from exc
    token = uuid.uuid4().hex
    index_temporary = report_directory / f".index.html.{token}.tmp"
    manifest_temporary = report_directory / f".manifest.json.{token}.tmp"
    rollback_temporary = report_directory / f".index.html.{token}.rollback"
    try:
        _write_durable(index_temporary, index_bytes)
        _write_durable(manifest_temporary, manifest_bytes)
        index_temporary.replace(index_path)
        try:
            manifest_temporary.replace(manifest_path)
        except OSError:
            if old_index is None:
                index_path.unlink(missing_ok=True)
            else:
                _write_durable(rollback_temporary, old_index)
                rollback_temporary.replace(index_path)
            raise
    except OSError as exc:
        raise UserError(f"cannot replace dashboard in {report_directory}: {exc}") from exc
    finally:
        index_temporary.unlink(missing_ok=True)
        manifest_temporary.unlink(missing_ok=True)
        rollback_temporary.unlink(missing_ok=True)
    return index_path


def write_report_markdown(
    run_dir: Path, manifest: dict[str, Any], review: dict[str, Any] | None,
    assessment: dict[str, Any] | None, run_summary: dict[str, Any], max_findings: int = 200,
) -> None:
    """Refresh reading artifacts only; the review JSON remains untouched."""
    from .review import markdown_report

    if review is not None:
        path = run_dir / "review" / "summary.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown_report(review, max_findings, manifest=manifest,
                                       assessment=assessment, run_summary=run_summary), encoding="utf-8")
    path = run_dir / "audit" / "summary.md"
    if path.exists() or run_summary.get("status") == "available":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(standalone_summary_markdown(run_summary, manifest), encoding="utf-8")


def refresh_reports(run_dir: Path, max_findings: int | None = None) -> Path:
    """Post-assess/summary/resume refresh; rebuild-dashboard itself remains HTML-only."""
    import tomllib

    from .tools.common import artifact_index

    manifest = _read_object(run_dir / "manifest.json", "manifest")
    # Optional summaries may have just been written and are not in the old
    # manifest yet. Link against the files present for this refresh.
    manifest["artifacts"] = artifact_index(run_dir)
    path = run_dir / "review" / "summary.json"
    review = _read_object(path, "review summary") if path.exists() else None
    assessment = load_assessment(run_dir)
    run_summary = load_run_summary(run_dir, manifest, review, assessment)
    if max_findings is None:
        try:
            config = tomllib.loads((run_dir / "inputs" / "effective-config.toml").read_text(encoding="utf-8"))
            max_findings = max(0, int(config.get("review", {}).get("max_markdown_findings", 200)))
        except (OSError, ValueError):
            max_findings = 200
    write_report_markdown(run_dir, manifest, review, assessment, run_summary, max_findings)
    manifest["artifacts"] = artifact_index(run_dir)
    (run_dir / "manifest.json").write_bytes(json_bytes(manifest))
    return rebuild_dashboard(run_dir)


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


def _validate_review(review: dict[str, Any], path: Path) -> None:
    for key in ("tools", "source_manifest"):
        if not isinstance(review.get(key), dict):
            raise UserError(f"invalid review summary in {path}: {key} must be an object")
    if not all(isinstance(item, dict) for item in review["tools"].values()):
        raise UserError(f"invalid review summary in {path}: tools must contain objects")
    scanners = review.get("scanners")
    if scanners is not None and (
        not isinstance(scanners, dict) or not all(isinstance(item, dict) for item in scanners.values())
    ):
        raise UserError(f"invalid review summary in {path}: scanners must contain objects")
    for key in ("findings", "diagnostics", "overlap_groups"):
        value = review.get(key)
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise UserError(f"invalid review summary in {path}: {key} must be a list of objects")
    files = review["source_manifest"].get("files")
    if not isinstance(files, list) or not all(isinstance(item, str) for item in files):
        raise UserError(f"invalid review summary in {path}: source_manifest.files must be a list of strings")


def _updated_artifacts(artifacts: list[dict[str, Any]], index_bytes: bytes) -> list[dict[str, Any]]:
    index_artifact = {
        "path": "index.html",
        "size": len(index_bytes),
        "sha256": hashlib.sha256(index_bytes).hexdigest(),
    }
    result: list[dict[str, Any]] = []
    replaced = False
    for item in artifacts:
        if item.get("path") == "index.html":
            if not replaced:
                result.append(index_artifact)
                replaced = True
        else:
            result.append(item)
    if not replaced:
        result.append(index_artifact)
    return result


def _write_durable(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())

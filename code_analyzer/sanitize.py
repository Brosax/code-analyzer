from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import socket
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Callable

from .audit import load_assessment
from .config import effective_toml
from .events import EVENTS_FILE
from .html_report import render
from .persist import manifest_structure_problem, write_json
from .review import markdown_report

# Rendered scan units and session logs quote the analyzed source verbatim, so
# they stay out of a shareable archive unless the operator asks for them.
# findings.json is the one file the review parser reads, so it is always
# exported and recover-report keeps working on an unpacked ZIP (design 11.3).
SESSION_EXCERPT_REASON = "contains source excerpts"
# llm/index.json is the symbol table: every typedef, struct, enum, macro and
# global verbatim, plus every function signature in the analyzed tree.  Nothing
# downstream reads it -- the review parser reads findings.json and coverage is
# already in the manifest -- so it is withheld whole rather than stripped.
SYMBOL_TABLE_REASON = "contains the analyzed source symbol table (verbatim definitions and signatures)"
_SESSION_EXPORTED: tuple[str, ...] = ("findings.json",)
# A finding's `evidence` is the offending source, copied verbatim by the model.
# findings.json is exported because it is the report the review is re-derived
# from, so the excerpt is withheld inside it instead of withholding the file.
EXCERPT_FIELDS: tuple[str, ...] = ("evidence",)
EXCERPT_WITHHELD = "withheld: contains source excerpts; set [llm] export_sessions = true to include"
_SYMBOL_TABLE = "llm/index.json"
# The run-level event log is progress, not evidence: it carries host paths
# and raw analyzer output lines, and is still being appended to after the
# archive is sealed.  The manifest and native reports are the record.
EVENT_LOG_REASON = "progress log, not evidence: contains host paths and analyzer output lines"

# A credential is redacted as a literal value, not by pattern: the harness
# formats arbitrary SDK exception text into unit reasons, and a pydantic
# ValidationError echoes its input_value, so the key can arrive in any shape.
SECRET_TOKEN = "<SECRET>"
_MIN_SECRET_CHARS = 8


class ExportError(Exception):
    pass


class Redactor:
    def __init__(self, values: list[tuple[str, str]], *, secrets: Iterable[str] = ()):
        unique: dict[str, str] = {}
        for value, token in values:
            if value and len(value) > 2:
                unique[value] = token
                windows = _windows_form(value)
                if windows:
                    unique[windows] = token
        self.mapping = sorted(unique.items(), key=lambda pair: (-len(pair[0]), pair[0]))
        # A value too short to be a credential would rewrite unrelated text.
        self.secrets = sorted(
            {value for value in secrets if value and len(value) >= _MIN_SECRET_CHARS},
            key=lambda value: (-len(value), value),
        )
        self.counts: dict[str, int] = {
            "prefix": 0, "secret_value": 0,
            "linux_home_pattern": 0, "windows_user_pattern": 0, "unc_pattern": 0,
        }

    def text(self, value: str) -> str:
        for secret in self.secrets:
            found = value.count(secret)
            if found:
                value = value.replace(secret, SECRET_TOKEN)
                self.counts["secret_value"] += found
        for original, token in self.mapping:
            found = value.count(original)
            if found:
                value = value.replace(original, token)
                self.counts["prefix"] += found
        lowered = value.lower()
        patterns = []
        if "/home/" in lowered:
            patterns.append((r"/home/[^/\s\"'<>]+", "<HOME>", "linux_home_pattern"))
        if "/mnt/" in lowered and "/users/" in lowered:
            patterns.append((r"/mnt/[A-Za-z]/(?:[^/\s\"'<>]+/)*Users/[^/\s\"'<>]+", "<HOME>", "linux_home_pattern"))
        if "users\\" in lowered:
            patterns.append((r"[A-Za-z]:\\+(?:[^\\\r\n\"'<>]+\\+)*Users\\+[^\\\r\n\"'<>]+", "<HOME>", "windows_user_pattern"))
        if "\\\\" in value:
            patterns.append((
                r"(?<!\\)\\{2,4}[A-Za-z0-9][A-Za-z0-9._-]+\\{1,2}[A-Za-z0-9$_. -]{2,}(?:\\{1,2}[^\\\r\n\"'<>]+)*",
                "<HOST>", "unc_pattern",
            ))
        for pattern, token, name in patterns:
            value, count = re.subn(pattern, token, value, flags=re.IGNORECASE)
            self.counts[name] += count
        return value

    def json_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.json_value(item) for item in value]
        if isinstance(value, dict):
            return {self.text(str(key)): self.json_value(item) for key, item in value.items()}
        return value

    def leaks(self, text: str) -> list[str]:
        leaks = ["secret_value" for secret in self.secrets if secret in text]
        leaks.extend("dynamic_prefix" for original, _ in self.mapping if original in text)
        lowered = text.lower()
        generic = []
        if "/home/" in lowered:
            generic.append(r"/home/[^/\s\"'<>]+")
        if "/mnt/" in lowered and "/users/" in lowered:
            generic.append(r"/mnt/[A-Za-z]/[^\s\"'<>]*/Users/[^/\s\"'<>]+")
        if "users\\" in lowered:
            generic.append(r"[A-Za-z]:\\+[^\r\n]*\\+Users\\+")
        if "\\\\" in text:
            generic.append(
                r"(?<!\\)\\{2,4}[A-Za-z0-9][A-Za-z0-9._-]+\\{1,2}[A-Za-z0-9$_. -]{2,}(?:\\{1,2}[^\\\r\n\"'<>]+)*"
            )
        if generic:
            leaks.extend("sensitive_path_pattern" for pattern in generic if re.search(pattern, text, re.IGNORECASE))
        return leaks


def export_shareable(
    run_dir: Path,
    manifest: dict[str, Any],
    config: dict[str, Any],
    sensitive_paths: list[Path],
    *,
    cancelled: Callable[[], bool] | None = None,
    review_override: dict[str, Any] | None = None,
    archive_name: str | None = None,
) -> Path:
    _check_cancelled(cancelled)
    _validate_core_manifest(run_dir, manifest)
    values = [
        (str(manifest.get("source", "")), "<SRC>"),
        (str(manifest.get("output_root", "")), "<OUT>"),
        (str(run_dir.resolve()), "<OUT>"),
        (str(Path.cwd().resolve()), "<HOST>"),
        (str(Path.home().resolve()), "<HOME>"),
        (socket.gethostname(), "<HOST>"),
    ]
    values.extend((str(path.resolve()), "<HOST>") for path in sensitive_paths if path)
    redactor = Redactor(values, secrets=_configured_secrets(config))
    exports = run_dir / "exports"
    exports.mkdir(parents=True, exist_ok=True)
    archive_name = archive_name or f"{manifest['run_id']}-shareable.zip"
    if Path(archive_name).name != archive_name or not archive_name.endswith(".zip"):
        raise ExportError("unsafe shareable archive name")
    destination = exports / archive_name
    if destination.exists():
        raise ExportError(f"shareable archive already exists: {destination.name}")
    temp_zip = exports / f".{archive_name}.{os.getpid()}.tmp"
    report_entries: list[dict[str, Any]] = []
    omitted_entries: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="code-analyzer-export-") as temp_name:
        staging = Path(temp_name)
        safe_review = review_override
        review_path = run_dir / "review" / "summary.json"
        if safe_review is None and review_path.is_file():
            try:
                safe_review = json.loads(review_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise ExportError(f"invalid core review summary: {exc}") from exc
        if safe_review is None and manifest.get("review", {}).get("enabled"):
            raise ExportError("missing core review summary")
        export_sessions = bool(config.get("llm", {}).get("export_sessions", False))
        if safe_review is not None:
            _validate_core_review(safe_review)
            safe_review = redactor.json_value(safe_review)
            if not export_sessions:
                safe_review = withhold_excerpts(safe_review)
        for source, omission in _export_files(run_dir, export_sessions=export_sessions):
            _check_cancelled(cancelled)
            relative = source.relative_to(run_dir)
            if relative.as_posix() in {
                "manifest.json", "index.html", "inputs/effective-config.toml",
                "review/summary.json", "review/summary.md",
            }:
                continue
            safe_name = redactor.text(relative.as_posix())
            if omission is not None:
                omitted_entries.append(_excluded_entry(source, safe_name, omission))
                continue
            target: Path | None = None
            digest: str | None = None
            source_size: int | None = None
            try:
                source_bytes = source.read_bytes()
                source_size = len(source_bytes)
                digest = hashlib.sha256(source_bytes).hexdigest()
                if redactor.leaks(safe_name) or safe_name.startswith("/") or ".." in Path(safe_name).parts:
                    raise ExportError("unsafe archive entry name")
                target = staging / safe_name
                target.parent.mkdir(parents=True, exist_ok=True)
                kind = _sanitize_file(source, target, redactor, relative=relative, export_sessions=export_sessions)
            except (ExportError, OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
                if target is not None:
                    target.unlink(missing_ok=True)
                omitted_entries.append({
                    "artifact_sha256": digest,
                    "size": source_size,
                    "entry": safe_name, "status": "omitted",
                    "reason": redactor.text(str(exc)),
                })
                continue
            report_entries.append({"artifact_sha256": digest, "size": len(source_bytes), "entry": safe_name, "format": kind, "validated": True})
        # Withholding source excerpts is policy, not failure: it must not
        # degrade the run status and with it somebody's exit code.
        export_status = "partial" if any(
            entry["status"] == "omitted" for entry in omitted_entries
        ) else "completed"
        manifest["export"].update({
            "status": export_status, "archive": f"exports/{archive_name}", "error": None,
            "omitted_artifacts": omitted_entries,
        })
        safe_manifest = redactor.json_value(manifest)
        _write_json(staging / "manifest.json", safe_manifest)
        if safe_review is not None:
            _write_json(staging / "review" / "summary.json", safe_review)
            (staging / "review" / "summary.md").write_text(
                markdown_report(safe_review, int(config["review"]["max_markdown_findings"])), encoding="utf-8"
            )
        # Core HTML is regenerated exclusively from validated structured data.
        safe_assessment = load_assessment(run_dir)
        if safe_assessment is not None:
            safe_assessment = redactor.json_value(safe_assessment)
        (staging / "index.html").write_text(render(safe_manifest, safe_review, safe_assessment), encoding="utf-8")
        safe_config = redactor.json_value(config)
        target_config = staging / "inputs" / "effective-config.toml"
        target_config.parent.mkdir(parents=True, exist_ok=True)
        target_config.write_text(effective_toml(safe_config), encoding="utf-8")
        redaction_report = {
            "status": export_status, "rules": redactor.counts,
            "artifacts": report_entries, "omitted_artifacts": omitted_entries,
        }
        _write_json(staging / "redaction-report.json", redaction_report)
        _check_cancelled(cancelled)
        _validate_tree(staging, redactor)
        try:
            with zipfile.ZipFile(temp_zip, "w", compression=zipfile.ZIP_DEFLATED, strict_timestamps=False) as archive:
                for path in sorted(staging.rglob("*")):
                    _check_cancelled(cancelled)
                    if path.is_file():
                        archive.write(path, path.relative_to(staging).as_posix())
            with zipfile.ZipFile(temp_zip) as archive:
                if archive.testzip() is not None:
                    raise ExportError("ZIP CRC validation failed")
            try:
                os.link(temp_zip, destination)
            except OSError:
                # Hardlinks are unavailable on some target filesystems
                # (notably WSL DrvFs mounts); fall back to an atomic rename.
                os.replace(temp_zip, destination)
            else:
                temp_zip.unlink()
        except Exception:
            temp_zip.unlink(missing_ok=True)
            raise
    return destination


def _validate_core_manifest(run_dir: Path, manifest: dict[str, Any]) -> None:
    problem = manifest_structure_problem(manifest)
    if problem is not None:
        raise ExportError(f"invalid core manifest: {problem}")
    try:
        persisted = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExportError(f"invalid core manifest: {exc}") from exc
    if not isinstance(persisted, dict) or persisted.get("manifest_schema_version") != 2:
        raise ExportError("invalid persisted core manifest schema")
    if persisted.get("run_id") != manifest.get("run_id"):
        raise ExportError("core manifest run identifier mismatch")


def _validate_core_review(review: dict[str, Any]) -> None:
    if not isinstance(review, dict) or review.get("review_schema_version") not in {1, 2, 3}:
        raise ExportError("invalid core review schema")
    for key in ("tools", "source_manifest"):
        if not isinstance(review.get(key), dict):
            raise ExportError(f"invalid core review: {key} must be an object")
    # Schema 3 adds the isomorphic sibling of tools; older reviews have none.
    if "scanners" in review and (
        not isinstance(review["scanners"], dict)
        or not all(isinstance(item, dict) for item in review["scanners"].values())
    ):
        raise ExportError("invalid core review: scanners must be an object of objects")
    for key in ("findings", "diagnostics", "overlap_groups"):
        if not isinstance(review.get(key), list) or not all(isinstance(item, dict) for item in review[key]):
            raise ExportError(f"invalid core review: {key} must be an array of objects")
    files = review["source_manifest"].get("files")
    if not isinstance(files, list) or not all(isinstance(item, str) for item in files):
        raise ExportError("invalid core review: source_manifest.files must be an array of strings")


def _check_cancelled(cancelled: Callable[[], bool] | None) -> None:
    if cancelled is not None and cancelled():
        raise ExportError("run interrupted")


def _configured_secrets(config: dict[str, Any]) -> list[str]:
    """The credential values that must not appear anywhere in an archive.

    The key itself lives only in the environment; this resolves it so the
    exported text can be checked against the value rather than a shape.
    """
    llm = config.get("llm")
    name = str(llm.get("api_key_env", "") or "").strip() if isinstance(llm, dict) else ""
    return [os.environ.get(name, "")] if name else []


def _quotes_source(relative: Path) -> str | None:
    """Why an artifact reproduces the analyzed source, or ``None`` if it does not."""
    parts = relative.parts
    if parts[:2] == ("llm", "sessions"):
        excerpt = len(parts) > 3 and parts[-1] not in _SESSION_EXPORTED
        return SESSION_EXCERPT_REASON if excerpt else None
    if parts[:2] == ("llm", "units"):
        return SESSION_EXCERPT_REASON
    # The runtime's own JSONL session log: every tool result, so every file
    # the model read, verbatim.  The bwrap launcher script is host layout.
    if parts[:2] == ("llm", "dsh-sessions") or relative.as_posix() == "llm/runtime-sandbox.sh":
        return SESSION_EXCERPT_REASON
    if relative.as_posix() == _SYMBOL_TABLE:
        return SYMBOL_TABLE_REASON
    return None


def withhold_excerpts(value: Any) -> Any:
    """Replace source excerpts in every finding of a findings/review document."""
    if not isinstance(value, dict):
        return value
    findings = value.get("findings")
    if not isinstance(findings, list):
        return value
    stripped = []
    for item in findings:
        if isinstance(item, dict) and any(item.get(field) for field in EXCERPT_FIELDS):
            item = {**item, **{field: EXCERPT_WITHHELD for field in EXCERPT_FIELDS if item.get(field)}}
        stripped.append(item)
    return {**value, "findings": stripped}


def _is_session_findings(relative: Path) -> bool:
    parts = relative.parts
    return parts[:2] == ("llm", "sessions") and parts[-1] in _SESSION_EXPORTED


def _export_files(run_dir: Path, *, export_sessions: bool = False):
    """Yield every archive candidate as ``(path, omission reason or None)``.

    A reason marks a deliberate policy exclusion: the file is reported in the
    redaction report instead of being shipped. Paths that never belonged in an
    archive at all are simply not yielded.
    """
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(run_dir)
        if relative.parts[0] == "exports" or relative.as_posix() == "inputs/sanitizer-map.private.json":
            continue
        if "build" in relative.parts or "tmp" in relative.parts:
            continue
        if relative.as_posix() == EVENTS_FILE:
            yield path, EVENT_LOG_REASON
            continue
        reason = None if export_sessions else _quotes_source(relative)
        if reason is not None:
            yield path, reason
            continue
        yield path, None


def _excluded_entry(source: Path, entry: str, reason: str) -> dict[str, Any]:
    """Report a file withheld by policy, not by a sanitizer failure."""
    try:
        payload = source.read_bytes()
    except OSError:
        return {"artifact_sha256": None, "size": None, "entry": entry, "status": "excluded", "reason": reason}
    return {
        "artifact_sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload),
        "entry": entry, "status": "excluded", "reason": reason,
    }


def _sanitize_file(
    source: Path, target: Path, redactor: Redactor, *, relative: Path | None = None, export_sessions: bool = True
) -> str:
    suffix = source.suffix.lower()
    if suffix == ".xml":
        try:
            with source.open("r", encoding="utf-8", newline="") as input_stream, target.open(
                "w", encoding="utf-8", newline=""
            ) as output_stream:
                for line in input_stream:
                    safe = redactor.text(line)
                    # Redaction tokens are data, never XML markup.
                    for token in ("SRC", "OUT", "HOME", "HOST", "SECRET"):
                        safe = safe.replace(f"<{token}>", f"&lt;{token}&gt;")
                    output_stream.write(safe)
            _validate_xml_stream(target)
        except (OSError, UnicodeError, ET.ParseError) as exc:
            raise ExportError(f"cannot sanitize XML {source}: {exc}") from exc
        return "xml"
    if suffix in {".json", ".sarif"}:
        try:
            value = json.loads(source.read_text(encoding="utf-8"))
            value = redactor.json_value(value)
            if relative is not None and not export_sessions and _is_session_findings(relative):
                value = withhold_excerpts(value)
            _write_json(target, value)
            checked = json.loads(target.read_text(encoding="utf-8"))
            if suffix == ".sarif" and (not isinstance(checked, dict) or checked.get("version") != "2.1.0"):
                raise ExportError(f"invalid SARIF after sanitization: {source}")
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ExportError(f"cannot sanitize JSON {source}: {exc}") from exc
        return "sarif" if suffix == ".sarif" else "json"
    if suffix == ".csv":
        try:
            with source.open("r", encoding="utf-8", newline="") as stream:
                rows = list(csv.reader(stream, strict=True))
            if not rows or not any(any(cell.strip() for cell in row) for row in rows):
                raise ExportError(f"invalid empty CSV: {source}")
            width = len(rows[0])
            if width < 2 or any(len(row) != width for row in rows):
                raise ExportError(f"invalid or truncated CSV: {source}")
            with target.open("w", encoding="utf-8", newline="") as stream:
                csv.writer(stream).writerows([[redactor.text(cell) for cell in row] for row in rows])
            with target.open("r", encoding="utf-8", newline="") as stream:
                list(csv.reader(stream, strict=True))
        except (OSError, UnicodeError, csv.Error) as exc:
            raise ExportError(f"cannot sanitize CSV {source}: {exc}") from exc
        return "csv"
    try:
        text = source.read_text(encoding="utf-8", errors="strict")
        target.write_text(redactor.text(text), encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ExportError(f"cannot safely decode text artifact {source}: {exc}") from exc
    return "text"


def _validate_tree(staging: Path, redactor: Redactor) -> None:
    for path in staging.rglob("*"):
        if not path.is_file():
            continue
        name = path.relative_to(staging).as_posix()
        try:
            text = path.read_text(encoding="utf-8", errors="strict")
        except UnicodeError as exc:
            raise ExportError(f"non-UTF-8 export entry {name}: {exc}") from exc
        leaks = redactor.leaks(name)
        suffix = path.suffix.lower()
        if suffix in {".json", ".sarif"}:
            value = json.loads(text)
            leaks.extend(_json_leaks(value, redactor))
            if suffix == ".sarif" and (not isinstance(value, dict) or value.get("version") != "2.1.0"):
                raise ExportError(f"invalid SARIF export entry {name}")
        elif suffix == ".html":
            match = re.search(
                r'<script id="report-data" type="application/json">(.*?)</script>', text, re.DOTALL
            )
            if not match:
                raise ExportError(f"generated dashboard lacks structured report data: {name}")
            leaks.extend(_json_leaks(json.loads(match.group(1)), redactor))
            leaks.extend(redactor.leaks(text[:match.start()] + text[match.end():]))
        else:
            leaks.extend(redactor.leaks(text))
        if leaks:
            raise ExportError(f"sensitive path remains in export entry {name}")
        if suffix == ".csv":
            list(csv.reader(io.StringIO(text), strict=True))


def _json_leaks(value: Any, redactor: Redactor) -> list[str]:
    if isinstance(value, str):
        return redactor.leaks(value)
    if isinstance(value, list):
        return [leak for item in value for leak in _json_leaks(item, redactor)]
    if isinstance(value, dict):
        return [
            leak
            for key, item in value.items()
            for leak in redactor.leaks(str(key)) + _json_leaks(item, redactor)
        ]
    return []


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, value)


def _validate_xml_stream(path: Path) -> None:
    for _event, element in ET.iterparse(path, events=("end",)):
        element.clear()


def _windows_form(value: str) -> str | None:
    match = re.match(r"^/mnt/([A-Za-z])/(.*)$", value)
    if match:
        return match.group(1).upper() + ":\\" + match.group(2).replace("/", "\\")
    return None

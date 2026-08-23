from __future__ import annotations

import codecs
import hashlib
from pathlib import Path
from typing import Any

from ..events import EVENTS_FILE


def utf8_validation(path: Path, chunk_size: int = 1024 * 1024) -> tuple[bool, dict[str, Any] | None]:
    """Validate UTF-8 without loading a potentially large source file in memory."""
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    offset = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(chunk_size):
                pending = decoder.getstate()[0]
                try:
                    decoder.decode(chunk, final=False)
                except UnicodeDecodeError as exc:
                    return False, {
                        "byte_offset": offset - len(pending) + exc.start,
                        "reason": str(exc),
                    }
                offset += len(chunk)
            try:
                pending = decoder.getstate()[0]
                decoder.decode(b"", final=True)
            except UnicodeDecodeError as exc:
                return False, {
                    "byte_offset": offset - len(pending) + exc.start,
                    "reason": str(exc),
                }
    except OSError as exc:
        return False, {"byte_offset": None, "reason": str(exc)}
    return True, None


def unit_outcome(
    process: Any, valid: bool, succeeded: bool, reason: str | None, failure_reason: str
) -> tuple[str, str | None]:
    """Shared per-unit status ladder for every analyzer adapter."""
    if process.interrupted:
        return "interrupted", reason
    if process.timed_out:
        return ("partial" if valid else "timed_out"), reason
    if succeeded:
        return "completed", reason
    return ("partial" if valid else "failed"), (reason or failure_reason)


def artifact(path: Path, run_dir: Path, chunk_size: int = 1024 * 1024) -> dict:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_size):
            digest.update(chunk)
            size += len(chunk)
    return {
        "path": path.relative_to(run_dir).as_posix(),
        "size": size,
        "sha256": digest.hexdigest(),
    }


def artifact_index(
    run_dir: Path, cache: dict[str, tuple[int, int, dict[str, Any]]] | None = None
) -> list[dict[str, Any]]:
    """Index evidence files under a report directory.

    Skips the manifest and writer temporaries (both the runner's and the
    recovery command's), the run-level event log (still being appended to
    after the final index is taken, so its hash could never be verified) and
    the per-unit analyzer scratch directories (cppcheck ``build/``, splint
    ``tmp/``), which are caches, not evidence.  The optional cache avoids
    re-hashing files whose size and mtime are unchanged between successive
    index rebuilds within one run.
    """
    result = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name in {"manifest.json", ".manifest.json.tmp"} or path.name.startswith(".recover-"):
            continue
        relative = path.relative_to(run_dir)
        if relative.as_posix() == EVENTS_FILE:
            continue
        parts = relative.parts
        if len(parts) >= 5 and parts[0] == "tools" and parts[3] in {"build", "tmp"}:
            continue
        if cache is None:
            result.append(artifact(path, run_dir))
            continue
        key = relative.as_posix()
        stat = path.stat()
        cached = cache.get(key)
        if cached is not None and cached[0] == stat.st_size and cached[1] == stat.st_mtime_ns:
            result.append(cached[2])
            continue
        item = artifact(path, run_dir)
        cache[key] = (stat.st_size, stat.st_mtime_ns, item)
        result.append(item)
    return result


def attach_artifacts(unit: dict, directory: Path, run_dir: Path) -> None:
    unit["artifacts"] = [artifact(path, run_dir) for path in sorted(directory.iterdir()) if path.is_file()]

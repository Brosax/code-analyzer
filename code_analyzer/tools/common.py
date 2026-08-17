from __future__ import annotations

import hashlib
import codecs
from pathlib import Path
from typing import Any


def valid_utf8(path: Path) -> bool:
    return utf8_validation(path)[0]


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


def artifact(path: Path, run_dir: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": path.relative_to(run_dir).as_posix(),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def attach_artifacts(unit: dict, directory: Path, run_dir: Path) -> None:
    unit["artifacts"] = [artifact(path, run_dir) for path in sorted(directory.iterdir()) if path.is_file()]

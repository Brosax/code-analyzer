"""The code a lens is shown: functions, their lines, and a static call graph.

Built once per source inventory with the proven approximate parser
(llm/index.py) and cached under ``aireview/`` as a slim JSON (functions and
calls only).  The call graph is "static approximation": names resolved against
the repository's own definitions, no function pointers, no macros that expand
to calls -- good enough to rank relevance, never used as proof.
"""
from __future__ import annotations

import hashlib
import json
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..evidence.workspace import Workspace, _atomic
from ..llm.index import build_index
from ..persist import json_bytes

INDEX_VERSION = 1
MAX_SOURCE_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class Function:
    path: str
    name: str
    line_start: int
    line_end: int
    signature: str
    calls: tuple[str, ...]

    @property
    def key(self) -> str:
        return f"{self.path}::{self.name}"

    @property
    def lines(self) -> int:
        return self.line_end - self.line_start + 1


class CodeIndex:
    def __init__(self, source: Path, data: dict[str, Any]) -> None:
        self.source = source
        self.by_path: dict[str, list[Function]] = {}
        self.by_name: dict[str, list[Function]] = {}
        for path, functions in sorted(data["files"].items()):
            items = [Function(path, f["name"], int(f["line_start"]), int(f["line_end"]), f.get("signature", ""),
                              tuple(f.get("calls", ()))) for f in functions]
            self.by_path[path] = sorted(items, key=lambda f: (f.line_start, f.line_end))
            for function in items:
                self.by_name.setdefault(function.name, []).append(function)
        self._lines: dict[str, list[str]] = {}

    # -- building ---------------------------------------------------------------------------------
    @classmethod
    def for_run(cls, workspace: Workspace, run_dir: Path, *,
                cancelled: Callable[[], bool] = lambda: False) -> CodeIndex:
        inventory_path = run_dir / "inputs" / "source-inventory.json"
        raw = inventory_path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()[:20]
        cache = workspace.root / "aireview" / f"code-index-v{INDEX_VERSION}-{digest}.json"
        if cache.is_file():
            return cls(workspace.source, json.loads(cache.read_text(encoding="utf-8")))
        inventory = [item for item in json.loads(raw).get("files") or [] if isinstance(item, dict)]
        full = build_index(workspace.source, inventory, cancelled=cancelled)
        slim = {"version": INDEX_VERSION, "files": {}}
        for path, record in full["files"].items():
            functions = [{"name": f["name"], "line_start": f["line_start"], "line_end": f["line_end"],
                          "signature": f.get("signature", "")[:300],
                          "calls": sorted(set(f.get("calls", ())))}
                         for f in record.get("functions", ()) if not f.get("dead")]
            if functions:
                slim["files"][path] = functions
        cache.parent.mkdir(parents=True, exist_ok=True)
        _atomic(cache, json_bytes(slim))
        return cls(workspace.source, slim)

    # -- lookup -----------------------------------------------------------------------------------
    def functions(self) -> Iterator[Function]:
        for path in sorted(self.by_path):
            yield from self.by_path[path]

    def function_at(self, path: str, line: int) -> Function | None:
        """The innermost function whose lines contain ``line``."""
        best = None
        for function in self.by_path.get(path, ()):
            if function.line_start <= line <= function.line_end:
                if best is None or function.lines < best.lines:
                    best = function
        return best

    def named(self, name: str) -> list[Function]:
        return list(self.by_name.get(name, ()))

    def callers(self, function: Function) -> list[Function]:
        return sorted((f for f in self.functions() if function.name in f.calls), key=lambda f: f.key)

    def callees(self, function: Function) -> list[Function]:
        out = []
        for name in function.calls:
            candidates = self.by_name.get(name, ())
            same = [f for f in candidates if f.path == function.path]
            out.extend(same[:1] or list(candidates)[:1])
        return out

    def distances(self, roots: list[Function], depth: int) -> dict[str, int]:
        """Call-graph distance (callees direction) from any root, up to ``depth``."""
        seen: dict[str, int] = {}
        queue: deque[tuple[Function, int]] = deque((root, 0) for root in roots)
        while queue:
            function, distance = queue.popleft()
            if function.key in seen and seen[function.key] <= distance:
                continue
            seen[function.key] = distance
            if distance < depth:
                queue.extend((callee, distance + 1) for callee in self.callees(function))
        return seen

    # -- text -------------------------------------------------------------------------------------
    def text_lines(self, path: str) -> list[str]:
        if path not in self._lines:
            root = self.source.resolve()
            target = (root / path).resolve()
            if not target.is_relative_to(root) or not target.is_file():
                self._lines[path] = []
            else:
                data = target.read_bytes()[:MAX_SOURCE_BYTES]
                self._lines[path] = data.decode("utf-8", "replace").splitlines()
        return self._lines[path]

    def lines(self, path: str, start: int, end: int) -> dict[int, str]:
        text = self.text_lines(path)
        start, end = max(1, start), min(len(text), end)
        return {n: text[n - 1] for n in range(start, end + 1)}

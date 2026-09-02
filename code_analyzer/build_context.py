"""Diagnose why Splint (and Cppcheck's fallback pass) could not preprocess, propose a fix, prove it, apply it.

The last real run had 1394 of 1588 Splint units die at their first
``#include``: the headers existed in the tree, the analyzer was never told
where.  This module turns the per-unit diagnosis the adapters already record
(``unit["diagnosis"]``: missing headers, ``#error`` directives, parse errors)
into a *patch* -- include directories, per-path overrides, defines, typed
Splint options, empty stub headers for names the tree does not carry -- that
is validated through the same ``validate_config`` every TOML goes through,
proved on a handful of failed units, and only then offered to the operator.

Everything it decides is evidence: ``inputs/build-context/r<N>/`` holds the
diagnosis, the patch, the probe and the decision, and the manifest records
the round.  It never edits ``.code-analyzer.toml``, never writes into the
scanned tree (stubs live under the run directory), and never runs a build.
"""
from __future__ import annotations

import copy
import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .config import ASSIST_MODES, SPLINT_MODES, effective_toml, validate_config
from .errors import UserError
from .includes import IncludeIndex, candidate_dirs, include_index
from .persist import write_json
from .tools.common import effective_units

# The closed vocabulary of a patch: what a proposal may ask for, whether it
# was inferred by code, proposed by a model, or typed by the operator.
OPS: tuple[str, ...] = (
    "add_include", "add_system_include", "add_define", "add_undefine", "set_standard",
    "add_override", "set_splint_option", "add_stub_header",
)
C_STANDARDS: tuple[str, ...] = ("c89", "c99", "c11", "c17", "gnu89", "gnu99", "gnu11", "gnu17")
# Typed Splint options a patch may set, and the values they accept.
SPLINT_OPTIONS: dict[str, tuple[Any, ...]] = {
    "mode": SPLINT_MODES,
    "report_reserved_names": (True, False),
    "try_to_recover": (True, False),
    "skip_system_headers": (True, False),
}
# A multi-platform tree can prove a hundred include roots; the dialog shows
# the ones that carry the most units, stubs counted separately.
MAX_ITEMS = 64
MAX_STUBS = 16
MAX_FILES_PER_HEADER = 200
_DEFINE = re.compile(r"^[A-Za-z_]\w*(\([A-Za-z_,\s]*\))?(=.{0,200})?$")
_ORIGINS = ("deterministic", "llm", "operator")
EVIDENCE_DIR = ("inputs", "build-context")
AUTHORITY = "non-authoritative-configuration-proposal"


@dataclass(frozen=True)
class MissingHeader:
    name: str
    units: int
    files: tuple[str, ...]
    candidates: tuple[str, ...]
    kind: str  # unambiguous | ambiguous | external


@dataclass(frozen=True)
class BuildDiagnosis:
    tool: str
    units_total: int
    units_failed: int
    units_analysis_reached: int
    missing_headers: tuple[MissingHeader, ...]
    error_directives: tuple[str, ...]
    parse_errors: int
    reserved_name_warnings: int
    csv_recovered_rows: int
    classes: dict[str, int]
    failed_unit_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["missing_headers"] = [asdict(item) for item in self.missing_headers]
        return value

    @property
    def counts(self) -> dict[str, int]:
        kinds = {"unambiguous": 0, "ambiguous": 0, "external": 0}
        for item in self.missing_headers:
            kinds[item.kind] = kinds.get(item.kind, 0) + 1
        return {
            "units_total": self.units_total, "units_failed": self.units_failed,
            "units_analysis_reached": self.units_analysis_reached, "missing_headers": len(self.missing_headers),
            **kinds, "error_directives": len(self.error_directives), "parse_errors": self.parse_errors,
            "reserved_name_warnings": self.reserved_name_warnings,
        }


@dataclass(frozen=True)
class PatchItem:
    op: str
    value: Any
    origin: str = "deterministic"
    evidence: str = ""
    units_affected: int = 0
    match: str | None = None
    rationale: str = ""
    # Ticked when the dialog opens.  Stubs never are: they make a unit
    # preprocess by hiding an interface, and the operator should say so.
    preselected: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def label(self) -> str:
        if self.op == "add_include":
            return f"-I {self.value or '.'}"
        if self.op == "add_system_include":
            return f"-isystem {self.value or '.'}"
        if self.op == "add_define":
            return f"-D {self.value}"
        if self.op == "add_undefine":
            return f"-U {self.value}"
        if self.op == "set_standard":
            return f"c_standard = {self.value}"
        if self.op == "add_override":
            include = ", ".join(self.value.get("include") or []) or "-"
            return f"override {self.match} -> -I {include}"
        if self.op == "set_splint_option":
            name, value = self.value
            return f"splint {name} = {str(value).lower()}"
        if self.op == "add_stub_header":
            return f"stub {self.value}"
        return f"{self.op} {self.value}"


@dataclass
class ConfigPatch:
    round: int
    items: list[PatchItem] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"schema_version": 1, "authority": AUTHORITY, "round": self.round, "items": [item.as_dict() for item in self.items]}

    def apply(self, config: dict[str, Any], run_dir: Path, source: Path, selected: Sequence[int] | None = None) -> dict[str, Any]:
        """A new, validated config with the selected items applied; the input is untouched."""
        patched = copy.deepcopy({key: value for key, value in config.items() if not key.startswith("_")})
        build = patched["build"]
        stubs: list[str] = []
        chosen = list(range(len(self.items))) if selected is None else [index for index in selected if 0 <= index < len(self.items)]
        for index in chosen:
            item = self.items[index]
            if item.op == "add_include":
                _append_unique(build["include"], str((source / item.value).resolve()))
            elif item.op == "add_system_include":
                _append_unique(build["system_include"], str((source / item.value).resolve()))
            elif item.op == "add_define":
                _append_unique(build["define"], str(item.value))
            elif item.op == "add_undefine":
                _append_unique(build["undefine"], str(item.value))
            elif item.op == "set_standard":
                build["c_standard"] = str(item.value)
            elif item.op == "add_override":
                override = {"match": str(item.match)}
                for key in ("include", "system_include"):
                    values = [str((source / entry).resolve()) for entry in item.value.get(key) or []]
                    if values:
                        override[key] = values
                for key in ("define", "undefine"):
                    values = [str(entry) for entry in item.value.get(key) or []]
                    if values:
                        override[key] = values
                build["overrides"].append(override)
            elif item.op == "set_splint_option":
                name, value = item.value
                patched["tools"]["splint"][name] = value
            elif item.op == "add_stub_header":
                stubs.append(str(item.value))
        if stubs:
            # Last on the search path, so a real header always wins over a stub.
            _append_unique(build["include"], str(stub_directory(run_dir, self.round).resolve()))
        validate_config(patched)
        for key, value in config.items():
            if key.startswith("_"):
                patched[key] = copy.deepcopy(value)
        return patched

    def selected_stubs(self, selected: Sequence[int] | None = None) -> list[str]:
        chosen = list(range(len(self.items))) if selected is None else list(selected)
        return [str(self.items[index].value) for index in chosen if 0 <= index < len(self.items) and self.items[index].op == "add_stub_header"]


def _append_unique(values: list[Any], value: Any) -> None:
    if value not in values:
        values.append(value)


# --- diagnosis ------------------------------------------------------------------


def diagnose_units(record: Mapping[str, Any], inventory: Sequence[Mapping[str, Any]], *, tool: str = "splint") -> BuildDiagnosis:
    """Aggregate the failed units' recorded diagnosis; never re-opens a stdout.raw."""
    index = include_index(inventory)
    units = effective_units(record.get("units") or [])
    headers: dict[str, dict[str, Any]] = {}
    directives: dict[str, None] = {}
    classes: dict[str, int] = {}
    failed_ids: list[str] = []
    parse_errors = reserved = recovered = reached = 0
    for unit in units:
        if unit.get("analysis_reached"):
            reached += 1
        diagnosis = unit.get("diagnosis") if isinstance(unit.get("diagnosis"), dict) else {}
        cls = unit.get("failure_class") or diagnosis.get("category")
        if unit.get("status") == "completed" or not cls:
            continue
        classes[str(cls)] = classes.get(str(cls), 0) + 1
        if cls in {"include", "configuration", "parsing", "csv"}:
            failed_ids.append(str(unit["id"]))
        files = [str(item) for item in unit.get("input_files") or []]
        for name in diagnosis.get("missing_includes") or unit.get("missing_includes") or []:
            entry = headers.setdefault(str(name), {"units": 0, "files": []})
            entry["units"] += 1
            if len(entry["files"]) < MAX_FILES_PER_HEADER:
                entry["files"].extend(files)
        for text in diagnosis.get("error_directives") or []:
            directives.setdefault(str(text)[:200], None)
        parse_errors += int(diagnosis.get("parse_errors") or 0)
        reserved += int(diagnosis.get("reserved_name_warnings") or 0)
        recovered += int(diagnosis.get("csv_recovered_rows") or unit.get("csv_recovered_rows") or 0)
    missing = []
    for name, entry in sorted(headers.items(), key=lambda kv: (-kv[1]["units"], kv[0])):
        candidates = tuple(candidate_dirs(name, index))
        kind = "external" if not candidates else ("unambiguous" if len(candidates) == 1 else "ambiguous")
        missing.append(MissingHeader(name, entry["units"], tuple(entry["files"]), candidates, kind))
    return BuildDiagnosis(
        tool=tool, units_total=len(units), units_failed=len(failed_ids), units_analysis_reached=reached,
        missing_headers=tuple(missing), error_directives=tuple(directives)[:20], parse_errors=parse_errors,
        reserved_name_warnings=reserved, csv_recovered_rows=recovered, classes=classes,
        failed_unit_ids=tuple(failed_ids),
    )


# --- inference --------------------------------------------------------------------


def infer_patch(
    diagnosis: BuildDiagnosis, config: Mapping[str, Any], *, source: Path, round: int = 1,
) -> ConfigPatch:
    """The patch code can stand behind: include roots the tree proves, nothing guessed.

    Rules, in order: an unambiguous header names its directory (merged per
    directory, ranked by units); an ambiguous header is resolved per TU
    group by the candidate nearest to the failing file (an override); when
    reserved-name noise is the only failure class the Splint switch is
    offered; a header the tree does not carry becomes a stub only when the
    configuration allows stubs, and it is never pre-ticked.  ``#error``
    directives are reported, never turned into a define: a macro's value is
    the operator's knowledge.
    """
    build = config["build"]
    known = {str(Path(item).resolve()) for item in list(build.get("include") or []) + list(build.get("system_include") or [])}
    items: list[PatchItem] = []
    roots: dict[str, dict[str, Any]] = {}
    for header in diagnosis.missing_headers:
        if header.kind != "unambiguous":
            continue
        root = header.candidates[0]
        if str((source / root).resolve()) in known:
            continue
        entry = roots.setdefault(root, {"units": 0, "headers": []})
        entry["units"] += header.units
        entry["headers"].append(header.name)
    for root, entry in sorted(roots.items(), key=lambda kv: (-kv[1]["units"], kv[0])):
        shown = ", ".join(entry["headers"][:4]) + (f", …(+{len(entry['headers']) - 4})" if len(entry["headers"]) > 4 else "")
        items.append(PatchItem(
            "add_include", root, "deterministic", f"satisfies {entry['units']} unit(s): {shown}", entry["units"],
        ))
    overrides: dict[str, dict[str, Any]] = {}
    for header in diagnosis.missing_headers:
        if header.kind != "ambiguous":
            continue
        for file in header.files:
            candidate, prefix = _nearest_candidate(file, header.candidates)
            if candidate is None or not prefix:
                continue
            entry = overrides.setdefault(prefix, {"include": [], "units": 0, "headers": set()})
            if candidate not in entry["include"]:
                entry["include"].append(candidate)
            entry["units"] += 1
            entry["headers"].add(header.name)
    for prefix, entry in sorted(overrides.items(), key=lambda kv: (-kv[1]["units"], kv[0])):
        if len(entry["include"]) > 3:
            # Several boards share the prefix: no single include set is right.
            continue
        items.append(PatchItem(
            "add_override", {"include": entry["include"]}, "deterministic",
            f"{entry['units']} unit(s) under {prefix}/ need {', '.join(sorted(entry['headers'])[:3])}",
            entry["units"], match=f"{prefix}/**",
        ))
    only_reserved = (
        diagnosis.reserved_name_warnings and not diagnosis.missing_headers
        and not diagnosis.error_directives and not diagnosis.parse_errors
    )
    if only_reserved and config["tools"]["splint"].get("report_reserved_names", True):
        items.append(PatchItem(
            "set_splint_option", ("report_reserved_names", False), "deterministic",
            f"{diagnosis.reserved_name_warnings} reserved-name warning(s) are the only failure class", 0,
        ))
    if build.get("stub_headers", True):
        for header in diagnosis.missing_headers:
            if header.kind == "external" and len([item for item in items if item.op == "add_stub_header"]) < MAX_STUBS:
                items.append(PatchItem(
                    "add_stub_header", header.name, "deterministic",
                    f"{header.units} unit(s); the tree carries no {header.name}", header.units, preselected=False,
                ))
    return ConfigPatch(round, items[:MAX_ITEMS])


def _nearest_candidate(file: str, candidates: Sequence[str]) -> tuple[str | None, str]:
    """The candidate directory sharing the longest path prefix with the failing file."""
    directory = file.rsplit("/", 1)[0] if "/" in file else ""
    best: tuple[int, str, str] | None = None
    for candidate in candidates:
        prefix = _common_prefix(directory, candidate)
        depth = prefix.count("/") + 1 if prefix else 0
        if depth and (best is None or depth > best[0]):
            best = (depth, candidate, prefix)
    if best is None:
        return None, ""
    return best[1], best[2]


def _common_prefix(left: str, right: str) -> str:
    parts = []
    for a, b in zip(left.split("/"), right.split("/"), strict=False):
        if a != b or not a:
            break
        parts.append(a)
    return "/".join(parts)


# --- validation (the gate every item passes, whoever wrote it) ----------------------


def validate_patch(
    items: Sequence[Mapping[str, Any]], *, diagnosis: BuildDiagnosis, source: Path, index: IncludeIndex,
    inventory: Sequence[Mapping[str, Any]], origin: str = "llm",
) -> tuple[list[PatchItem], list[str]]:
    """Lenient in, strict out: keep what validates, name what was dropped."""
    kept: list[PatchItem] = []
    problems: list[str] = []
    directories = {""} | {path.rsplit("/", 1)[0] for path in index.by_path if "/" in path}
    external = {header.name for header in diagnosis.missing_headers if header.kind == "external"}
    for position, raw in enumerate(items):
        where = f"item[{position}]"
        if not isinstance(raw, Mapping):
            problems.append(f"{where}: not an object")
            continue
        op = str(raw.get("op") or "")
        rationale = str(raw.get("rationale") or "")[:300]
        try:
            if op in {"add_include", "add_system_include"}:
                path = _tree_dir(str(raw.get("path") or raw.get("value") or ""), directories)
                kept.append(PatchItem(op, path, origin, rationale[:120] or "proposed", 0, rationale=rationale))
            elif op in {"add_define", "add_undefine"}:
                value = str(raw.get("value") or "")
                if not _DEFINE.match(value):
                    raise ValueError(f"define {value!r} is not NAME, NAME=VALUE or NAME(args)")
                kept.append(PatchItem(op, value, origin, rationale[:120] or "proposed", 0, rationale=rationale))
            elif op == "set_standard":
                value = str(raw.get("value") or "")
                if value not in C_STANDARDS:
                    raise ValueError(f"standard {value!r} is not one of {', '.join(C_STANDARDS)}")
                kept.append(PatchItem(op, value, origin, rationale[:120] or "proposed", 0, rationale=rationale))
            elif op == "add_override":
                match = str(raw.get("match") or "")
                if not match or not any(_glob_match(path, match) for path in index.by_path):
                    raise ValueError(f"override match {match!r} names no file in the tree")
                value = {
                    key: [_tree_dir(str(entry), directories) for entry in raw.get(key) or []]
                    for key in ("include", "system_include")
                }
                value = {key: entries for key, entries in value.items() if entries}
                for key in ("define", "undefine"):
                    entries = [str(entry) for entry in raw.get(key) or []]
                    for entry in entries:
                        if not _DEFINE.match(entry):
                            raise ValueError(f"define {entry!r} is not NAME, NAME=VALUE or NAME(args)")
                    if entries:
                        value[key] = entries
                if not value:
                    raise ValueError("override carries nothing")
                kept.append(PatchItem(op, value, origin, rationale[:120] or "proposed", 0, match=match, rationale=rationale))
            elif op == "set_splint_option":
                name = str(raw.get("name") or "")
                if name not in SPLINT_OPTIONS:
                    raise ValueError(f"splint option {name!r} is not typed")
                value = raw.get("value")
                if value not in SPLINT_OPTIONS[name] or isinstance(value, bool) != isinstance(SPLINT_OPTIONS[name][0], bool):
                    raise ValueError(f"splint option {name} does not accept {value!r}")
                kept.append(PatchItem(op, (name, value), origin, rationale[:120] or "proposed", 0, rationale=rationale))
            elif op == "add_stub_header":
                name = str(raw.get("name") or raw.get("value") or "")
                if name not in external:
                    raise ValueError(f"stub {name!r} is not a header the tree lacks")
                if sum(1 for item in kept if item.op == "add_stub_header") >= MAX_STUBS:
                    raise ValueError("too many stubs")
                kept.append(PatchItem(op, name, origin, rationale[:120] or rationale[:120] or "proposed", 0, rationale=rationale, preselected=False))
            else:
                raise ValueError(f"unknown op {op!r}")
        except ValueError as exc:
            problems.append(f"{where}: {exc}")
        if len(kept) >= MAX_ITEMS:
            problems.append(f"item[{position + 1}:]: dropped past {MAX_ITEMS} items")
            break
    return kept, problems


def _tree_dir(value: str, directories: set[str]) -> str:
    normalized = "/".join(part for part in value.replace("\\", "/").split("/") if part not in ("", "."))
    if ".." in normalized.split("/") or value.startswith("/"):
        raise ValueError(f"path {value!r} is not tree-relative")
    if normalized not in directories:
        raise ValueError(f"path {value!r} is not a directory in the tree")
    return normalized


def _glob_match(path: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatchcase(path, pattern)


# --- the probe ----------------------------------------------------------------------


def select_probe_files(diagnosis: BuildDiagnosis, record: Mapping[str, Any], limit: int) -> list[str]:
    """Failed units the patch can be expected to fix, so the probe measures the patch.

    A unit whose recorded misses are all headers the tree carries unambiguously
    comes first; one that also needs an ambiguous header next; one that needs
    a header the tree lacks last -- only a stub could rescue it, and the
    operator has not chosen one yet.
    """
    kinds = {header.name: header.kind for header in diagnosis.missing_headers}
    by_id = {str(unit.get("id")): unit for unit in record.get("units") or []}
    scored: list[tuple[tuple[bool, bool, int], str]] = []
    seen: set[str] = set()
    for unit_id in diagnosis.failed_unit_ids:
        unit = by_id.get(unit_id) or {}
        files = unit.get("input_files") or []
        if len(files) != 1 or files[0] in seen:
            continue
        seen.add(files[0])
        diag = unit.get("diagnosis") if isinstance(unit.get("diagnosis"), dict) else {}
        missing = [str(name) for name in diag.get("missing_includes") or unit.get("missing_includes") or []]
        if not missing:
            continue
        present = {kinds.get(name, "external") for name in missing}
        scored.append((("external" in present, "ambiguous" in present, len(missing)), str(files[0])))
    scored.sort()
    return [file for _score, file in scored[:limit]]


def probe_patch(
    executable: str, source: Path, run_dir: Path, patched: Mapping[str, Any], files: Sequence[str], *,
    round: int, per_file_timeout: float = 10.0, cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run Splint over a few failed units with the patch, into the round's probe directory.

    Nothing under ``tools/`` is touched: the probe is a rehearsal, and its
    only output is a count of units that now reach ``Finished checking``.
    """
    from .process import run_process
    from .tools import splint

    root = run_dir.joinpath(*EVIDENCE_DIR) / f"r{round}" / "probe"
    root.mkdir(parents=True, exist_ok=True)
    options = splint.option_flags(patched["tools"]["splint"])
    grace = float(patched["run"]["termination_grace_seconds"])
    results = []
    reached = 0
    for relative in files:
        if cancelled is not None and cancelled():
            break
        safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in relative.replace("/", "__"))[:80]
        directory = root / safe
        directory.mkdir(parents=True, exist_ok=True)
        tmp = directory / "tmp"
        tmp.mkdir(exist_ok=True)
        report = directory / "report.csv"
        argv = splint.unit_argv(executable, options, splint.build_flags(patched["build"], relative), tmp, report, relative)
        process = run_process(argv, source, directory / "stdout.raw", directory / "stderr.raw", per_file_timeout, grace)
        text = "\n".join(_read(directory / "stdout.raw") + "\n" + _read(directory / "stderr.raw") for _ in (0,)).lower()
        finished = "finished checking" in text and "cannot continue" not in text
        rows = []
        try:
            rows = splint.splint_rows(report.read_text(encoding="utf-8"))[0] if report.is_file() else []
        except (OSError, UnicodeError):
            rows = []
        diagnosis = splint.diagnose(text, rows)
        results.append({
            "file": relative, "reached": finished, "exit_code": process.exit_code,
            "missing_includes": diagnosis["missing_includes"][:8], "duration_seconds": process.duration_seconds,
        })
        reached += int(finished)
    return {"sampled": len(results), "reached_before": 0, "reached_after": reached, "per_file": results}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# --- evidence -------------------------------------------------------------------------


def stub_directory(run_dir: Path, round: int) -> Path:
    return run_dir.joinpath(*EVIDENCE_DIR) / f"r{round}" / "stubs"


def write_stubs(run_dir: Path, round: int, names: Sequence[str], *, run_id: str) -> Path:
    """Empty, include-guarded headers for names the tree lacks; code-generated, never model text."""
    root = stub_directory(run_dir, round)
    for name in names:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        guard = "CODE_ANALYZER_STUB_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper()
        target.write_text(
            f"/* Stub written by code-analyzer (run {run_id}, build-context round {round}).\n"
            f"   The scanned tree carries no {name}; this empty header lets the\n"
            f"   analyzer preprocess the units that include it.  It declares nothing. */\n"
            f"#ifndef {guard}\n#define {guard}\n#endif\n",
            encoding="utf-8",
        )
    return root


def write_round(run_dir: Path, round: int, **documents: Any) -> Path:
    """One JSON file per document under ``inputs/build-context/r<N>/``; ``meta`` carries the clock."""
    root = run_dir.joinpath(*EVIDENCE_DIR) / f"r{round}"
    root.mkdir(parents=True, exist_ok=True)
    for name, value in documents.items():
        if value is None:
            continue
        if name == "applied_config":
            (root / "applied-config.toml").write_text(str(value), encoding="utf-8")
        else:
            write_json(root / f"{name.replace('_', '-')}.json", value)
    write_json(root / "meta.json", {"round": round, "written_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    return root


def suggested_toml(config: Mapping[str, Any], patched: Mapping[str, Any], source: Path) -> str:
    """The ``[build]`` / ``[tools.splint]`` lines an operator could paste into their own TOML."""
    lines = ["# Suggested by code-analyzer's build-context loop; paths are relative to the source tree.", "[build]"]
    for key in ("include", "system_include", "define", "undefine"):
        values = [_relative(item, source) if key.endswith("include") else item for item in patched["build"].get(key) or []]
        if values != [_relative(item, source) if key.endswith("include") else item for item in config["build"].get(key) or []]:
            lines.append(f"{key} = [{', '.join(json.dumps(v, ensure_ascii=False) for v in values)}]")
    if patched["build"].get("c_standard") != config["build"].get("c_standard") and patched["build"].get("c_standard"):
        lines.append(f"c_standard = {json.dumps(patched['build']['c_standard'])}")
    for override in patched["build"].get("overrides") or []:
        if override in (config["build"].get("overrides") or []):
            continue
        lines.append("[[build.overrides]]")
        for key, value in override.items():
            if key.endswith("include"):
                value = [_relative(item, source) for item in value]
            lines.append(f"{key} = {json.dumps(value, ensure_ascii=False)}")
    splint_lines = [
        f"{key} = {json.dumps(patched['tools']['splint'][key])}"
        for key in SPLINT_OPTIONS if patched["tools"]["splint"].get(key) != config["tools"]["splint"].get(key)
    ]
    if splint_lines:
        lines.append("[tools.splint]")
        lines.extend(splint_lines)
    return "\n".join(lines) + "\n"


def _relative(value: str, source: Path) -> str:
    try:
        return Path(value).resolve().relative_to(source.resolve()).as_posix() or "."
    except ValueError:
        return str(value)


def manifest_block(assist: str, status: str, rounds: Sequence[Mapping[str, Any]], *, reason: str | None = None) -> dict[str, Any]:
    if assist not in ASSIST_MODES:
        raise UserError(f"build.assist must be one of {', '.join(ASSIST_MODES)}")
    return {
        "assist": assist, "status": status, "authority": AUTHORITY, "reason": reason,
        "rounds": list(rounds), "evidence": "/".join(EVIDENCE_DIR),
        "suggested_config": "suggested-config.toml" if any(r.get("applied") for r in rounds) else None,
    }


def applied_config_toml(patched: Mapping[str, Any]) -> str:
    return effective_toml(dict(patched))


def relative_to_run(path: Path, run_dir: Path) -> str:
    try:
        return path.relative_to(run_dir).as_posix()
    except ValueError:
        return os.fspath(path)

"""Helpers shared by the CLI-driving test modules."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).parents[1]


def run_cli(
    *args: object,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> subprocess.CompletedProcess[str]:
    runtime = {**os.environ, "PYTHONPATH": str(ROOT), **(env or {})}
    return subprocess.run(
        [sys.executable, "-S", "-m", "code_analyzer", *(str(item) for item in args)],
        cwd=cwd or ROOT, env=runtime, text=True, capture_output=True, timeout=timeout,
    )


def executable(path: Path, body: str) -> Path:
    path.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body), encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


# Sections and keys of the pre-v3 configuration that the analysis configuration no longer has.  Tests written
# against the old loader pass them; they are dropped here rather than rewritten in every test.
_RETIRED = {"review", "llm", "audit"}
_RETIRED_RUN = {"profile", "shareable_export", "events_file", "log_level"}


def load_config(source: Path, explicit: Path | None = None, cli: dict | None = None) -> dict:
    """The analysis configuration a test run uses: defaults, then an explicit TOML, then overrides."""
    import copy
    import tomllib

    from code_analyzer.config import DEFAULTS, validate_config

    config = copy.deepcopy(DEFAULTS)
    config["run"]["output_root"] = str(Path(source).parent / "code-analyzer-runs")
    layers = []
    if explicit is not None:
        layer = tomllib.loads(Path(explicit).read_text(encoding="utf-8"))
        _absolutise(layer.get("build", {}), Path(explicit).parent)   # paths in a file are relative to the file
        layers.append(layer)
    if cli:
        layers.append(cli)
    for layer in layers:
        for section, values in layer.items():
            if section in _RETIRED or not isinstance(values, dict):
                continue
            if section == "run":
                values = {k: v for k, v in values.items() if k not in _RETIRED_RUN}
            if section == "tools":
                for tool, settings in values.items():
                    config["tools"][tool].update(settings)
            else:
                config[section].update(values)
    return validate_config(config)


def run_static(source: Path, config: dict, *, cancellation=None):
    """One static call, the way ``analyze`` makes it; returns (exit code, run directory)."""
    from code_analyzer.evidence import static_run

    return static_run.run(Path(source), config, lambda _line: None, cancellation=cancellation)


def _absolutise(build: dict, base: Path) -> None:
    def fix(items):
        return [str((base / item).resolve()) if isinstance(item, str) and not Path(item).is_absolute() else item
                for item in items]
    for key in ("include", "system_include"):
        if isinstance(build.get(key), list):
            build[key] = fix(build[key])
    if isinstance(build.get("compile_database"), str) and not Path(build["compile_database"]).is_absolute():
        build["compile_database"] = str((base / build["compile_database"]).resolve())
    for override in build.get("overrides") or []:
        for key in ("include", "system_include"):
            if isinstance(override, dict) and isinstance(override.get(key), list):
                override[key] = fix(override[key])


def run_analyze(source: Path, *args: object, env: dict[str, str] | None = None,
                timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
    """``code-analyzer analyze`` with the old runner's arguments translated.

    ``--config C`` becomes a build context (its [build] and [tools] tables), ``--output-root O`` becomes the
    evaluation directory ``O/evaluation``; stdout is replaced by the run directory of the call the command
    made, which is what the old command printed and what these tests inspect.
    """
    import json as _json
    import tomllib

    rest: list[object] = []
    eval_dir: Path | None = None
    items = list(args)
    index = 0
    while index < len(items):
        item = str(items[index])
        if item == "--config":
            data = tomllib.loads(Path(items[index + 1]).read_text(encoding="utf-8"))
            _absolutise(data.get("build", {}), Path(items[index + 1]).parent)
            buildctx = Path(items[index + 1]).with_suffix(".buildctx.toml")
            lines = []
            for section in ("build", "tools"):
                for key, value in data.get(section, {}).items():
                    if section == "tools":
                        lines.append(f"[tools.{key}]")
                        lines += [f"{k} = {_json.dumps(v)}" for k, v in value.items()]
                    else:
                        lines.insert(0, f"{key} = {_json.dumps(value)}")
            if any(not line.startswith("[") for line in lines[:1]) and data.get("build"):
                lines.insert(0, "[build]")
            buildctx.write_text("\n".join(lines) + "\n", encoding="utf-8")
            rest += ["--buildctx", buildctx]
            index += 2
        elif item == "--output-root":
            eval_dir = Path(items[index + 1]) / "evaluation"
            rest += ["--eval-dir", eval_dir]
            index += 2
        else:
            rest.append(items[index])
            index += 1
    completed = run_cli("analyze", source, *rest, env=env, timeout=timeout)
    evaluation = Path(completed.stdout.strip()) if completed.stdout.strip() else eval_dir
    if evaluation is not None and (evaluation / "ledger.jsonl").is_file():
        calls = [_json.loads(line) for line in (evaluation / "ledger.jsonl").read_text().splitlines()
                 if '"call_finished"' in line]
        if calls and calls[-1].get("run_dir"):
            completed.stdout = str(evaluation / calls[-1]["run_dir"]) + "\n"
    return completed

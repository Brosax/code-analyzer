from __future__ import annotations

import locale
import os
import re
import shutil
import subprocess
import sys
import tempfile
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from . import __version__


REQUIRED = {
    "cppcheck": ["--xml-version", "--output-file", "--project", "--file-list", "--check-level", "--check-library", "--checkers-report", "--cppcheck-build-dir"],
    "flawfinder": ["--sarif", "--minlevel", "--columns", "--neverignore"],
}


def probe_all(config: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"analyzer_version": __version__, "python": _python_probe(), "platform": _platform_probe(), "tools": {}}
    for name in ("cppcheck", "flawfinder", "splint"):
        result["tools"][name] = probe_tool(name, config["tools"][name]["executable"])
    result["ok"] = result["python"]["ok"] and all(
        not config["tools"][name]["enabled"] or result["tools"][name]["status"] == "compatible"
        for name in result["tools"]
    )
    return result


def probe_tool(name: str, executable: str) -> dict[str, Any]:
    resolved = shutil.which(executable)
    if not resolved:
        return {"status": "missing", "executable": executable, "version": None, "missing_capabilities": [], "guidance": _guidance(name)}
    try:
        if name == "splint":
            version_text = _capture([resolved, "-help", "version"])
            match = re.search(r"^Splint\s+([0-9][^\s]*)", version_text, re.MULTILINE)
            topics = {topic: _capture([resolved, "-help", topic]) for topic in ("nof", "csv", "tmpdir", "modes", "ITS4")}
            missing = [topic for topic, text in topics.items() if not text.strip()]
            version = match.group(1) if match else None
        else:
            version_text = _capture([resolved, "--version"])
            help_text = _capture([resolved, "--help"])
            missing = [flag for flag in REQUIRED[name] if flag not in help_text]
            version = version_text.strip().splitlines()[0] if version_text.strip() else None
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "incompatible", "executable": resolved, "version": None, "missing_capabilities": [str(exc)], "guidance": _guidance(name)}
    canary_ok, canary_reason = verify_canary(name, resolved)
    # Help text is advisory: distro builds and wrappers occasionally implement
    # an option without listing it.  The isolated canary is the final capability
    # check and records how compatibility was established.
    status = "compatible" if canary_ok else "incompatible"
    return {
        "status": status,
        "executable": resolved,
        "version": version,
        "missing_capabilities": [] if canary_ok else (missing or [canary_reason or "canary failed"]),
        "help_missing_capabilities": missing,
        "verification": "canary" if canary_ok else "failed",
        "canary": {"ok": canary_ok, "reason": canary_reason},
        "guidance": None if status == "compatible" else _guidance(name),
    }


def verify_canary(name: str, executable: str) -> tuple[bool, str | None]:
    try:
        with tempfile.TemporaryDirectory(prefix=f"code-analyzer-{name}-canary-") as temporary:
            root = Path(temporary)
            source = root / "canary.c"
            source.write_text("int main(void) { int value; return value; }\n", encoding="utf-8")
            if name == "cppcheck":
                report, checkers, files, build = root / "report.xml", root / "checkers.txt", root / "files.txt", root / "build"
                files.write_text("canary.c\n", encoding="utf-8")
                build.mkdir()
                argv = [
                    executable, "--xml", "--xml-version=2", f"--output-file={report}",
                    f"--checkers-report={checkers}", f"--cppcheck-build-dir={build}",
                    "--check-level=exhaustive", "--check-library", f"--file-list={files}", "--quiet",
                ]
                completed = subprocess.run(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, shell=False)
                valid = completed.returncode in {0, 1} and report.is_file() and ET.parse(report).getroot().tag == "results"
            elif name == "flawfinder":
                argv = [executable, "--sarif", "--minlevel=0", "--columns", "--neverignore", "--omittime", "--quiet", "--", "canary.c"]
                completed = subprocess.run(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, shell=False)
                data = json.loads(completed.stdout.decode("utf-8", errors="strict"))
                valid = completed.returncode in {0, 1} and data.get("version") == "2.1.0"
            else:
                report, tmp = root / "report.csv", root / "tmp"
                tmp.mkdir()
                argv = [executable, "+nof", "-tmpdir", str(tmp), "+csvoverwrite", "+csv", str(report), "./canary.c"]
                completed = subprocess.run(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, shell=False)
                output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace").lower()
                valid = completed.returncode in {0, 1} and report.is_file() and report.stat().st_size > 0 and "finished checking" in output
            return (True, None) if valid else (False, f"minimal {name} canary did not produce a valid native report")
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, ET.ParseError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def _capture(argv: list[str]) -> str:
    env = {**os.environ, "LC_ALL": "C.UTF-8", "LANG": "C.UTF-8"}
    completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, env=env, shell=False)
    return (completed.stdout + completed.stderr).decode("utf-8", errors="replace")


def _python_probe() -> dict[str, Any]:
    command = subprocess.run([sys.executable, "-m", "code_analyzer", "--version"], capture_output=True, text=True, timeout=10)
    return {"ok": sys.version_info >= (3, 11) and command.returncode == 0, "executable": sys.executable, "version": sys.version.split()[0], "module_version": command.stdout.strip()}


def _platform_probe() -> dict[str, Any]:
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8").strip()
    except OSError:
        release = ""
    os_release = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip('"')
    except OSError:
        pass
    aliases = {item.lower() for item in locale.locale_alias}
    has_c_utf8 = any(item in aliases for item in {"c.utf8", "c_utf8", "c.utf-8"})
    try:
        output = subprocess.run(["locale", "-a"], capture_output=True, text=True, timeout=5).stdout.lower()
        has_c_utf8 |= "c.utf8" in output or "c.utf-8" in output
    except (OSError, subprocess.TimeoutExpired):
        pass
    return {"wsl": "microsoft" in release.lower(), "kernel_release": release, "ubuntu": os_release.get("ID") == "ubuntu", "os_release": os_release.get("PRETTY_NAME"), "c_utf8": has_c_utf8}


def _guidance(name: str) -> str:
    packages = {"cppcheck": "cppcheck", "flawfinder": "flawfinder", "splint": "splint"}
    return f"Ubuntu 24.04: sudo apt update && sudo apt install {packages[name]} (not run automatically)"

from __future__ import annotations

import json
import locale
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from . import __version__
from .tools import TOOL_NAMES, adapter


def probe_all(config: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"analyzer_version": __version__, "python": _python_probe(), "platform": _platform_probe(), "tools": {}}
    for name in TOOL_NAMES:
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
    declared = adapter(name)
    try:
        version = declared.reported_version(_capture(declared.version_argv(resolved)))
        if declared.help_topics:
            topics = {topic: _capture([resolved, "-help", topic]) for topic in declared.help_topics}
            missing = [topic for topic, text in topics.items() if not text.strip()]
        else:
            help_text = _capture([resolved, "--help"])
            missing = [flag for flag in declared.required_capabilities if flag not in help_text]
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
    """Run the tool over a minimal source file and check its native report.

    Help text is advisory -- distro builds and wrappers implement options they
    do not list -- so this is the capability check that decides.  Each adapter
    owns the argv and the report check for its own tool; this function owns
    the isolation and the failure vocabulary they share.
    """
    try:
        with tempfile.TemporaryDirectory(prefix=f"code-analyzer-{name}-canary-") as temporary:
            root = Path(temporary)
            (root / "canary.c").write_text("int main(void) { int value; return value; }\n", encoding="utf-8")
            valid, reason = adapter(name).canary(executable, root)
            if valid:
                return True, None
            return False, reason or f"minimal {name} canary did not produce a valid native report"
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
    return f"Ubuntu 24.04: sudo apt update && sudo apt install {adapter(name).apt_package} (not run automatically)"

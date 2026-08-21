"""Cordis configuration: packaged skills, a tool allow-list, a filesystem scope.

The plain remote-endpoint case needs no file here at all, because base_url and
api_key are top-level SDK configuration.  What that cannot express is the
security boundary of design section 11.4: scanned source is untrusted input, so
the audited repository must not be able to supply the instructions that scan it,
the scanner must not be able to reach a shell, and its filesystem reach must be
bounded to the scanned tree and read-only.

Verification status against the pinned deepseek-harness-runtime-bin==0.1.1rc1,
read out of the plugin sources embedded in the bundled runtime binary:

* VERIFIED -- the package names and config keys under ``packages``:
  ``@deepseek-ai/dsh-skill-filesystem`` takes ``{customSkillDirs,
  includeDefaultRoots, ...}`` and ranks project roots (100/200) ABOVE the custom
  root (300), so ``includeDefaultRoots: false`` is what actually keeps a scanned
  repository from shipping the instructions that scan it;
  ``@deepseek-ai/dsh-sandbox-policy`` takes ``{mode, workspaceRoot}`` with mode
  in read-only | workspace-write | danger-full-access; ``@deepseek-ai/dsh-fs-sandbox``
  is the ``ctx.fs`` backend that enforces that mode.
* NOT VERIFIED, and left visible rather than silently assumed: (a) that this
  document's top-level encoding is the one the runtime's loader accepts -- the
  bundled default config is a plugin LIST, so the ``skills`` / ``tools`` /
  ``filesystem`` sections here are this project's vocabulary and only the
  ``packages`` entries are in upstream shape; (b) that ANY upstream package
  confines READS to a root.  ``dsh-fs-sandbox`` fences mutations only ("Reads
  pass through untouched: every mode permits reading") and ``dsh-fs-local``
  documents its own cwd as "a resolution default, NOT a containment boundary".
  ``filesystem.enforcement`` records that split inside the evidence file itself.

Design appendix A4 requires every one of these key names to be re-checked on an
SDK bump; ``enforcement`` is where a re-check writes its answer.
"""
from __future__ import annotations

import os
import threading
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ..errors import UserError
from ..persist import json_bytes


def endpoint_url(settings: dict[str, Any]) -> str:
    """The endpoint with any userinfo removed, safe to persist as evidence."""
    value = str(settings.get("endpoint", "") or "").strip()
    if not value:
        return ""
    try:
        split = urlsplit(value)
    except ValueError:
        return ""
    if not (split.username or split.password):
        return value
    host = split.hostname or ""
    if split.port:
        host = f"{host}:{split.port}"
    return urlunsplit(split._replace(netloc=host))


SKILL_PACKAGE = "code_analyzer"
SKILL_RESOURCE = "skills"
CORDIS_FILENAME = "cordis.json"
PROVIDER_ID = "code-analyzer-endpoint"
PROVIDER_PACKAGE = "@deepseek-ai/dsh-llm-pi-ai"
SKILL_FILESYSTEM_PACKAGE = "@deepseek-ai/dsh-skill-filesystem"
SANDBOX_POLICY_PACKAGE = "@deepseek-ai/dsh-sandbox-policy"
FS_SANDBOX_PACKAGE = "@deepseek-ai/dsh-fs-sandbox"

# The filesystem scope of design 11.4 defence #3, as a document section.  A
# working directory is not a sandbox, so the scope is stated -- root, mode and
# who enforces which half -- and HarnessRuntime refuses to launch a scanner
# whose document does not carry it.
FILESYSTEM_KEY = "filesystem"
READ_ONLY = "read-only"
ROOT_CONFINED = "root"
UNENFORCED_UPSTREAM = "unenforced-upstream"

# A scanner reads files and navigates symbols. It is never granted command
# execution: a comment in the audited source is a prompt-injection vector, and
# an allow-list (unlike a deny-list) also excludes tools added upstream later.
SCANNER_TOOL_ALLOWLIST: tuple[str, ...] = ("fs", "lsp")
FORBIDDEN_TOOLS: frozenset[str] = frozenset({"shell", "bash", "exec", "process", "terminal", "command"})

# Skill roots the scanned repository controls. Disabled for the whole scan so
# that audited code cannot override the scanner instructions examining it.
PROJECT_SKILL_ROOTS: tuple[str, ...] = (".dsh/skills", ".agents/skills")

_FILESYSTEM_PACKAGES = frozenset({FS_SANDBOX_PACKAGE, SANDBOX_POLICY_PACKAGE})


def skill_directory() -> Path:
    """Locate the packaged scanner skills as a real directory.

    Skill discovery scans project-relative roots, and the scanned firmware
    repository is not this package, so the packaged root has to be injected by
    absolute path.
    """
    resource = resources.files(SKILL_PACKAGE).joinpath(SKILL_RESOURCE)
    try:
        path = Path(os.fspath(resource))
    except TypeError as exc:
        raise UserError(
            "packaged scanner skills are not available as real files; install code-analyzer as a normal "
            "package rather than from a zip import, or set [llm] enabled = false"
        ) from exc
    if not path.is_dir():
        raise UserError(f"packaged scanner skills are missing from this installation: {path}")
    return path


def cordis_document(
    settings: dict[str, Any],
    *,
    skill_dir: Path,
    source_root: Path | None = None,
    tools: tuple[str, ...] = SCANNER_TOOL_ALLOWLIST,
    provider_routing: bool = False,
) -> dict[str, Any]:
    """Build the cordis document for one scan."""
    allowed = tuple(dict.fromkeys(str(name).strip() for name in tools if str(name).strip()))
    if not allowed:
        raise UserError("scanner tool allow-list must not be empty")
    granted = sorted(name for name in allowed if name.lower() in FORBIDDEN_TOOLS)
    if granted:
        raise UserError(
            f"scanner tool allow-list must not grant {', '.join(granted)}: the scanned source is untrusted input"
        )
    document: dict[str, Any] = {
        "skills": {
            "customSkillDirs": [str(skill_dir)],
            "projectSkillsEnabled": False,
            "userSkillsEnabled": False,
            "disabledSkillRoots": list(PROJECT_SKILL_ROOTS),
        },
        "tools": {"allow": list(allowed)},
        "packages": [_skill_package(skill_dir)],
    }
    if provider_routing:
        document["packages"].append(_provider_package(settings))
    if source_root is not None:
        document = confined(document, source_root)
    return document


def filesystem_scope(root: Path) -> dict[str, Any]:
    """The agent's declared filesystem reach: this tree, read-only.

    ``enforcement`` is part of the declaration on purpose.  The read-only half
    is carried by a package the pinned runtime really has; no upstream package
    confines reads to a root, and an evidence file that hid that difference
    would be claiming a control nobody applies.
    """
    resolved = Path(root).resolve()
    if not resolved.is_dir():
        raise UserError(
            f"the scanned tree {resolved} is not a directory, so the scanner's filesystem scope "
            f"cannot be bounded"
        )
    return {
        "root": str(resolved),
        "mode": READ_ONLY,
        "confinement": ROOT_CONFINED,
        "enforcement": {"mode": SANDBOX_POLICY_PACKAGE, "confinement": UNENFORCED_UPSTREAM},
    }


def confined(document: dict[str, Any], root: Path) -> dict[str, Any]:
    """Return ``document`` with the filesystem scope of ``root`` declared.

    The scanned tree is known to whoever launches an agent over it, not to
    whoever drafts the document, so this completes a draft rather than
    rejecting it -- but a document already bound to a different tree is a
    conflict, not a draft, and is refused.
    """
    scope = filesystem_scope(root)
    existing = document.get(FILESYSTEM_KEY)
    if isinstance(existing, dict) and str(existing.get("root", "")) not in ("", scope["root"]):
        raise UserError(
            f"the cordis document confines the scanner to {existing['root']}, which is not the tree "
            f"being scanned ({scope['root']})"
        )
    kept = [
        item
        for item in document.get("packages", [])
        if not (isinstance(item, dict) and item.get("name") in _FILESYSTEM_PACKAGES)
    ]
    return {**document, FILESYSTEM_KEY: scope, "packages": [*_filesystem_packages(scope), *kept]}


def write_cordis_config(directory: Path, document: dict[str, Any], name: str = CORDIS_FILENAME) -> Path:
    """Write the document through the one canonical JSON encoder.

    JSON is a subset of YAML, so a hand-written YAML emitter (and the quoting
    bugs that come with one) buys nothing, and the file stays byte-stable
    evidence like every other artifact.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    # Replaced, never truncated in place: a scanner process may be booting on
    # this exact path in another thread while a second scan unit completes it.
    temporary = directory / f".{name}.{os.getpid()}.{threading.get_ident()}.tmp"
    temporary.write_bytes(json_bytes(document))
    temporary.replace(path)
    return path


def _skill_package(skill_dir: Path) -> dict[str, Any]:
    return {
        "id": "skills",
        "name": SKILL_FILESYSTEM_PACKAGE,
        # Project roots outrank the custom root, so injecting the packaged
        # directory is not enough on its own: the default roots have to go.
        "config": {"customSkillDirs": [str(skill_dir)], "includeDefaultRoots": False},
    }


def _filesystem_packages(scope: dict[str, Any]) -> list[dict[str, Any]]:
    root = str(scope["root"])
    return [
        {"id": "fs", "name": FS_SANDBOX_PACKAGE, "config": {"cwd": root}},
        {
            "id": "sandbox-policy",
            "name": SANDBOX_POLICY_PACKAGE,
            "config": {"mode": scope["mode"], "workspaceRoot": root},
        },
    ]


def _provider_package(settings: dict[str, Any]) -> dict[str, Any]:
    model = str(settings.get("model", "") or "").strip()
    endpoint = str(settings.get("endpoint", "") or "").strip()
    if not model or not endpoint:
        raise UserError("[llm] model and endpoint must be set to route through a custom provider")
    entry: dict[str, Any] = {"id": model}
    if settings.get("context_window"):
        entry["contextWindow"] = int(settings["context_window"])
    if settings.get("max_completion_tokens"):
        entry["maxTokens"] = int(settings["max_completion_tokens"])
    provider: dict[str, Any] = {
        "displayName": "code-analyzer endpoint",
        "api": "openai-completions",
        "baseURL": endpoint_url(settings),
        "models": [entry],
    }
    key_env = str(settings.get("api_key_env", "") or "").strip()
    if key_env:
        # Only the variable name. The secret itself never reaches a config file.
        provider["apiKeyEnv"] = key_env
    return {"id": "llm", "name": PROVIDER_PACKAGE, "config": {"providers": {PROVIDER_ID: provider}}}

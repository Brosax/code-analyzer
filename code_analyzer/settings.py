"""The ten settings, and where the program keeps its own state.

``~/.code-analyzer/settings.toml`` (or ``$CODE_ANALYZER_HOME/settings.toml``)
is the whole operator-facing configuration.  An unknown key is an error rather
than a silently ignored typo: with only ten keys, every one of them matters.

    port = 8765
    data_root = "~/.code-analyzer/evaluations"
    web_url = ""                # optional: where a reverse proxy on this host publishes the page,
                                # e.g. "http://192.168.5.34:8787/code-analyzer/"

    [local_model]
    endpoint = "http://192.168.5.10:11434/v1"
    name = "qwen3.8:27b"
    review_name = ""            # optional second model on the same pinned host

    [public_model]              # public/test code only; never client code
    endpoint = ""
    name = ""
    api_key_env = ""            # the variable's NAME; the key never lives here

    [analyzers]                 # path overrides; default: found on PATH
    cppcheck = ""
    flawfinder = ""
    splint = ""
"""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import UserError

HOME_ENV = "CODE_ANALYZER_HOME"
SETTINGS_FILE = "settings.toml"
ANALYZERS = ("cppcheck", "flawfinder", "splint")

DEFAULT_LOCAL_ENDPOINT = "http://192.168.5.10:11434/v1"
DEFAULT_LOCAL_MODEL = "qwen3.8:27b"
DEFAULT_PORT = 8765


def home() -> Path:
    """Where the program keeps settings, probe results and evaluations."""
    override = os.environ.get(HOME_ENV, "").strip()
    return Path(override).expanduser() if override else Path.home() / ".code-analyzer"


@dataclass(frozen=True)
class Settings:
    local_endpoint: str = DEFAULT_LOCAL_ENDPOINT
    local_model: str = DEFAULT_LOCAL_MODEL
    local_review_model: str = ""
    public_endpoint: str = ""
    public_model: str = ""
    public_api_key_env: str = ""
    data_root: Path = field(default_factory=lambda: home() / "evaluations")
    port: int = DEFAULT_PORT
    web_url: str = ""
    analyzers: dict[str, str] = field(default_factory=dict)

    @property
    def review_model(self) -> str:
        return self.local_review_model or self.local_model

    @property
    def has_public_model(self) -> bool:
        return bool(self.public_endpoint and self.public_model)


_SCHEMA: dict[str, Any] = {
    "port": int,
    "data_root": str,
    "web_url": str,
    "local_model": {"endpoint": str, "name": str, "review_name": str},
    "public_model": {"endpoint": str, "name": str, "api_key_env": str},
    "analyzers": {name: str for name in ANALYZERS},
}


def load_settings(path: Path | None = None) -> Settings:
    """Read the settings file; a missing file means every default."""
    target = path or home() / SETTINGS_FILE
    if not target.exists():
        return Settings()
    try:
        raw = tomllib.loads(target.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise UserError(f"{target}: cannot read settings: {error}") from error
    _check(raw, _SCHEMA, str(target))
    local = raw.get("local_model", {})
    public = raw.get("public_model", {})
    port = raw.get("port", DEFAULT_PORT)
    if not 1 <= port <= 65535:
        raise UserError(f"{target}: port must be between 1 and 65535, got {port}")
    data_root = raw.get("data_root")
    return Settings(
        local_endpoint=local.get("endpoint", DEFAULT_LOCAL_ENDPOINT).strip(),
        local_model=local.get("name", DEFAULT_LOCAL_MODEL).strip(),
        local_review_model=local.get("review_name", "").strip(),
        public_endpoint=public.get("endpoint", "").strip(),
        public_model=public.get("name", "").strip(),
        public_api_key_env=public.get("api_key_env", "").strip(),
        data_root=Path(data_root).expanduser() if data_root else home() / "evaluations",
        port=port,
        web_url=_web_url(raw.get("web_url", ""), str(target)),
        analyzers={name: value.strip() for name, value in raw.get("analyzers", {}).items() if value.strip()},
    )


def _web_url(value: str, where: str) -> str:
    """The page's address behind a reverse proxy: its host is the one Host header accepted besides loopback.

    Normalised to what a browser sends -- no default port, a path ending in ``/`` -- so the Host
    and Origin checks can compare strings.
    """
    value = value.strip()
    if not value:
        return ""
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.query or parts.fragment:
        raise UserError(f"{where}: web_url must be a plain http(s) URL such as "
                        f"http://192.168.5.34:8787/code-analyzer/, got {value!r}")
    try:
        port = parts.port
    except ValueError:
        raise UserError(f"{where}: web_url has an invalid port: {value!r}") from None
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    netloc = host if port in (None, {"http": 80, "https": 443}[parts.scheme]) else f"{host}:{port}"
    path = parts.path if parts.path.endswith("/") else parts.path + "/"
    return f"{parts.scheme}://{netloc}{path}"


def _check(value: dict[str, Any], schema: dict[str, Any], where: str) -> None:
    for key, item in value.items():
        if key not in schema:
            raise UserError(f"{where}: unknown setting {key!r}; known: {', '.join(sorted(schema))}")
        expected = schema[key]
        if isinstance(expected, dict):
            if not isinstance(item, dict):
                raise UserError(f"{where}: [{key}] must be a table")
            _check(item, expected, f"{where} [{key}]")
        elif not isinstance(item, expected) or isinstance(item, bool):
            raise UserError(f"{where}: {key} must be {expected.__name__}, got {type(item).__name__}")

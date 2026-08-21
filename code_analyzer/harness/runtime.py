"""Lifecycle wrapper around the deepseek-harness SDK.

Upstream is a release candidate that promises compatibility-breaking changes,
so ``deepseek_harness`` is imported here and nowhere else, and only at call
time: ``analyze`` must keep working when the optional extra or its bundled
runtime binary is absent.
"""
from __future__ import annotations

import json
import math
import os
import time
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from ..errors import UserError
from .cordis import confined, write_cordis_config

SDK_MODULE = "deepseek_harness"
DEFAULT_PROVIDER = "deepseek-official"
INSTALL_HINT = (
    "install the agent runtime with `pip install deepseek-harness-sdk`, or set [llm] enabled = false "
    "to scan with the native analyzers only"
)

# SDK finish reasons mapped onto the per-unit status ladder shared with every
# native adapter (see tools/common.py unit_outcome).
FINISH_REASON_STATUS: dict[str, str] = {
    "completed": "completed",
    "complete": "completed",
    "stop": "completed",
    "end_turn": "completed",
    "max-tokens": "partial",
    "max_tokens": "partial",
    "length": "partial",
    "aborted": "interrupted",
    "cancelled": "interrupted",
    "canceled": "interrupted",
    "timeout": "timed_out",
    "timed_out": "timed_out",
    "error": "failed",
    "refusal": "failed",
}

# Design 5.4 puts four gates on an agent loop.  Two of them have no home in the
# pinned SDK -- ``DeepSeekHarnessConfig`` carries no step or turn field and
# ``run()`` takes only input/session_id/on_notification (design appendix A3) --
# so they are counted here, off the session event stream, and the only lever a
# caller has over a loop already in flight is the notification callback it
# drives.  The event names are the runtime's own: ``turn/start`` opens a model
# round trip, ``tool/call`` dispatches one tool.
STEP_EVENTS: frozenset[str] = frozenset({"tool/call"})
TURN_EVENTS: frozenset[str] = frozenset({"turn/start"})


class HarnessUnavailable(UserError):
    """The SDK or its runtime binary cannot be used on this machine."""


class HarnessRunFailed(Exception):
    """One invocation failed; ``outcome`` is a per-unit status word."""

    def __init__(self, outcome: str, reason: str) -> None:
        super().__init__(reason)
        self.outcome = outcome
        self.reason = reason


class _Cancelled(Exception):
    """Internal signal raised out of the SDK notification callback."""


class _CeilingReached(Exception):
    """Internal signal: a budget gate this project enforces itself has tripped."""


@dataclass(frozen=True)
class RunOutcome:
    """One completed invocation, reduced to plain JSON-safe data."""

    session_id: str
    final_response: str
    finish_reason: str
    events: list[dict[str, Any]]
    notifications: list[dict[str, Any]]
    duration_seconds: float


def harness_available() -> bool:
    try:
        _sdk()
    except HarnessUnavailable:
        return False
    return True


def sdk_version() -> str:
    return str(getattr(_sdk(), "__version__", "") or "unknown")


def api_key(settings: dict[str, Any]) -> str | None:
    """Read the credential from the environment named by ``api_key_env``.

    A key written into configuration would reach inputs/effective-config.toml
    and from there every shared export.
    """
    name = str(settings.get("api_key_env", "") or "").strip()
    if not name:
        return None
    value = os.environ.get(name, "")
    if not value:
        raise UserError(f"environment variable {name}, named by [llm] api_key_env, is unset or empty")
    return value


# The literal the export sanitizer also writes, so a value reads the same
# whether it was redacted here or on the way into a shareable archive.
SECRET_TOKEN = "<SECRET>"
# Below this length a value is not a credential, and replacing it would
# corrupt unrelated text.
_MIN_SECRET_CHARS = 8


def credential_value(settings: dict[str, Any]) -> str:
    """The resolved credential, or "" when it is unset or too short to be one.

    Unlike ``api_key`` this never raises: redaction has to work on a run that
    already failed because the variable was missing.
    """
    name = str(settings.get("api_key_env", "") or "").strip()
    value = os.environ.get(name, "") if name else ""
    return value if len(value) >= _MIN_SECRET_CHARS else ""


def redact_credential(value: Any, settings: dict[str, Any]) -> Any:
    """Replace the credential wherever it occurs in a JSON-shaped value.

    A provider error body, or a pydantic ValidationError echoing its
    input_value, carries the Authorization header into a unit reason, and from
    there into manifest.json and review/summary.json -- neither of which may
    ever hold a credential.  Matching the resolved value rather than a
    key-shaped pattern is what makes that reliable, since the SDK is free to
    format the header into any shape it likes.
    """
    secret = credential_value(settings)
    return _replace_secret(value, secret) if secret else value


def _replace_secret(value: Any, secret: str) -> Any:
    if isinstance(value, str):
        return value.replace(secret, SECRET_TOKEN)
    if isinstance(value, dict):
        return {key: _replace_secret(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_secret(item, secret) for item in value]
    return value


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


def request_description(settings: dict[str, Any]) -> dict[str, Any]:
    """The credential-free endpoint description recorded in request.json."""
    return {
        "provider": str(settings.get("provider") or DEFAULT_PROVIDER),
        "model": required(settings, "model"),
        "base_url": endpoint_url(settings),
    }


def required(settings: dict[str, Any], key: str) -> str:
    value = str(settings.get(key, "") or "").strip()
    if not value:
        raise UserError(f"[llm] {key} must be set before LLM scanning can run")
    return value


def finish_status(finish_reason: str, valid_report: bool) -> str:
    """Map an SDK finish reason and report validity onto a unit status."""
    state = FINISH_REASON_STATUS.get(str(finish_reason or "").strip().lower(), "failed")
    if state in {"completed", "partial"}:
        return state if valid_report else "failed"
    return state


class HarnessRuntime:
    """One agent runtime, owned for the duration of an LLM scan phase."""

    def __init__(
        self,
        settings: dict[str, Any],
        *,
        cwd: Path,
        session_root: Path | None = None,
        cordis_path: Path | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self.settings = settings
        self.cwd = Path(cwd)
        self.session_root = Path(session_root) if session_root is not None else None
        self.cordis_path = Path(cordis_path) if cordis_path is not None else None
        self.cancelled = cancelled
        self._harness: Any = None

    def __enter__(self) -> HarnessRuntime:
        try:
            self.start()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, *_exception: object) -> None:
        self.close()

    @property
    def started(self) -> bool:
        return self._harness is not None

    def start(self) -> None:
        if self._harness is not None:
            return
        module = _sdk()
        self.confine()
        try:
            config = module.DeepSeekHarnessConfig(**self.config_arguments())
        except UserError:
            raise
        except TypeError as exc:
            raise HarnessUnavailable(
                f"the installed {SDK_MODULE} rejects this configuration ({exc}); pin the SDK version "
                f"recorded in pyproject.toml"
            ) from exc
        harness = module.DeepSeekHarness(config)
        try:
            harness.start()
        except FileNotFoundError as exc:
            raise HarnessUnavailable(f"the deepseek-harness runtime binary is missing ({exc}); {INSTALL_HINT}") from exc
        except Exception as exc:
            # A half-started child must not outlive this call even though the
            # SDK never handed the object back to us.
            _close_quietly(harness)
            raise HarnessRunFailed("failed", f"cannot start the agent runtime: {type(exc).__name__}: {exc}") from exc
        self._harness = harness

    def config_arguments(self) -> dict[str, Any]:
        """Build DeepSeekHarnessConfig keyword arguments from the [llm] section."""
        settings = self.settings
        arguments: dict[str, Any] = {
            "provider": str(settings.get("provider") or DEFAULT_PROVIDER),
            "model": required(settings, "model"),
            # Path resolution only: upstream documents this cwd as "a resolution
            # default, NOT a containment boundary".  The agent's reach is bounded
            # by the cordis filesystem scope confine() insists on (design 11.4).
            "cwd": str(self.cwd),
            "runtime_cwd": str(self.cwd),
            "api_key": api_key(settings),
        }
        endpoint = endpoint_url(settings)
        if endpoint:
            arguments["base_url"] = endpoint
        if settings.get("max_completion_tokens"):
            arguments["max_tokens"] = int(settings["max_completion_tokens"])
        if settings.get("request_timeout_seconds"):
            arguments["request_timeout_seconds"] = float(settings["request_timeout_seconds"])
        if settings.get("shutdown_timeout_seconds"):
            arguments["shutdown_timeout_seconds"] = float(settings["shutdown_timeout_seconds"])
        if self.session_root is not None:
            arguments["session_root"] = str(self.session_root)
        if self.cordis_path is not None:
            arguments["cordis"] = str(self.cordis_path)
        return arguments

    def confine(self) -> None:
        """Refuse to launch a scanner whose filesystem reach is not declared.

        Design 11.4 defence #3 is a property of the cordis document, and the
        tree being scanned is known here rather than where that document was
        drafted, so the wrapper completes the document it was handed and
        persists exactly what it launches with.  With no document at all there
        is nowhere to state the boundary, and an unbounded agent over untrusted
        source is not launched.
        """
        if self.cordis_path is None:
            raise HarnessUnavailable(
                "no cordis document is configured, so the scanner's filesystem scope cannot be "
                "declared; the scanned source is untrusted input and an unconfined agent will not "
                "be launched (design 11.4)"
            )
        try:
            document = json.loads(self.cordis_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise HarnessUnavailable(
                f"the cordis document {self.cordis_path} cannot be read ({exc}), so the scanner's "
                f"filesystem scope cannot be declared"
            ) from exc
        if not isinstance(document, dict):
            raise HarnessUnavailable(
                f"the cordis document {self.cordis_path} is not a JSON object, so the scanner's "
                f"filesystem scope cannot be declared"
            )
        try:
            complete = confined(document, self.cwd)
        except UserError as exc:
            raise HarnessUnavailable(str(exc)) from exc
        if complete != document:
            write_cordis_config(self.cordis_path.parent, complete, self.cordis_path.name)

    def run(
        self,
        prompt: str | list[dict[str, Any]],
        *,
        session_id: str | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> RunOutcome:
        self.check_cancelled()
        if self._harness is None:
            self.start()
        started = time.monotonic()
        ceiling = _Ceiling(
            _positive_int(self.settings, "max_steps"), _positive_int(self.settings, "max_turns")
        )
        try:
            result = self._harness.run(
                prompt, session_id=session_id, on_notification=self._notifier(on_event, ceiling)
            )
        except _Cancelled as exc:
            raise HarnessRunFailed("interrupted", "run interrupted") from exc
        except _CeilingReached as exc:
            # "failed", not "partial": the ladder reserves partial for a report
            # that arrived and was cut short (see finish_status), and a unit
            # stopped at a ceiling has produced no report at all.  It also keeps
            # a truncated unit out of the cross-run cache.
            raise HarnessRunFailed("failed", str(exc)) from exc
        except Exception as exc:
            if isinstance(exc, TimeoutError) or "timeout" in type(exc).__name__.lower():
                raise HarnessRunFailed("timed_out", f"agent runtime timed out: {exc}") from exc
            raise HarnessRunFailed("failed", f"agent runtime error: {type(exc).__name__}: {exc}") from exc
        duration = time.monotonic() - started
        self.check_cancelled()
        return RunOutcome(
            session_id=str(getattr(result, "session_id", "") or ""),
            final_response=str(getattr(result, "final_response", "") or ""),
            finish_reason=str(getattr(result, "finish_reason", "") or ""),
            events=[as_json_object(item) for item in getattr(result, "events", None) or []],
            notifications=[as_json_object(item) for item in getattr(result, "notifications", None) or []],
            duration_seconds=duration,
        )

    def close(self) -> None:
        harness, self._harness = self._harness, None
        if harness is not None:
            _close_quietly(harness)

    def check_cancelled(self) -> None:
        if self.cancelled is not None and self.cancelled():
            raise HarnessRunFailed("interrupted", "run interrupted")

    def _notifier(
        self, on_event: Callable[[dict[str, Any]], None] | None, ceiling: _Ceiling
    ) -> Callable[[Any], None]:
        def notify(notification: Any) -> None:
            if self.cancelled is not None and self.cancelled():
                # The SDK exposes no cancel handle, so aborting its callback is
                # the only way to stop an agent loop already in flight; close()
                # reclaims the child whether or not the SDK re-raises this.
                raise _Cancelled
            plain = as_json_object(notification)
            exceeded = ceiling.observe(_event_type(plain))
            if on_event is not None:
                try:
                    on_event(plain)
                except Exception:
                    # Live display is best-effort. Native evidence must never
                    # depend on a UI/event callback behaving correctly.
                    pass
            if exceeded is not None:
                raise _CeilingReached(exceeded)

        return notify


class _Ceiling:
    """The step and turn gates of design 5.4, counted on this side of the SDK."""

    def __init__(self, steps: int | None, turns: int | None) -> None:
        self.steps = steps
        self.turns = turns
        self.step_count = 0
        self.turn_count = 0

    def observe(self, kind: str) -> str | None:
        """Count one session event; return why the loop must stop, or None."""
        if kind in STEP_EVENTS:
            self.step_count += 1
            if self.steps is not None and self.step_count > self.steps:
                return f"agent step ceiling of {self.steps} reached"
        if kind in TURN_EVENTS:
            self.turn_count += 1
            if self.turns is not None and self.turn_count > self.turns:
                return f"model turn ceiling of {self.turns} reached"
        return None


def _event_type(notification: dict[str, Any]) -> str:
    """The session event type one notification carries, or an empty string.

    A ``session.event`` notification wraps the event under ``payload.event``;
    anything already reduced to an event is read directly.
    """
    payload = notification.get("payload")
    event = payload.get("event") if isinstance(payload, dict) else None
    if isinstance(event, dict):
        return str(event.get("type", "") or "")
    return str(notification.get("type", "") or "")


def _positive_int(settings: dict[str, Any], key: str) -> int | None:
    value = settings.get(key)
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def as_json_object(value: Any) -> dict[str, Any]:
    """Reduce one SDK event or notification to a plain JSON object."""
    plain = as_json_data(value)
    return plain if isinstance(plain, dict) else {"value": plain}


def as_json_data(value: Any) -> Any:
    """Reduce arbitrary SDK data to JSON-serialisable, order-stable values."""
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, dict):
        return {str(key): as_json_data(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [as_json_data(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(str(item) for item in value)
    for name in ("model_dump", "dict", "_asdict"):
        method = getattr(value, name, None)
        if callable(method):
            try:
                converted = method()
            except Exception:
                continue
            if isinstance(converted, dict):
                return as_json_data(converted)
    if is_dataclass(value) and not isinstance(value, type):
        return as_json_data(asdict(value))
    attributes = getattr(value, "__dict__", None)
    if isinstance(attributes, dict):
        return {str(key): as_json_data(item) for key, item in attributes.items() if not str(key).startswith("_")}
    return str(value)


def _sdk() -> Any:
    try:
        import deepseek_harness
    except ImportError as exc:
        raise HarnessUnavailable(f"{SDK_MODULE} is not importable ({exc}); {INSTALL_HINT}") from exc
    missing = [name for name in ("DeepSeekHarness", "DeepSeekHarnessConfig") if not hasattr(deepseek_harness, name)]
    if missing:
        raise HarnessUnavailable(
            f"the installed {SDK_MODULE} does not provide {', '.join(missing)}; it is incompatible with this "
            f"release of code-analyzer"
        )
    return deepseek_harness


def _close_quietly(harness: Any) -> None:
    try:
        harness.close()
    except Exception:
        # Teardown is best-effort: a failing close() must not mask the error
        # that caused it.
        pass

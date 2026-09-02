"""``llm-doctor``: is this endpoint able to run the scan, and how long will it take?

The native ``doctor`` answers the same question for the three analyzers: it
runs each one over a canary and reports what it found rather than what the
help text promises.  This is that command for the provider.

Three failures it exists to make explicit, all of them observed in practice:

* the endpoint answers but serves a *different* model than the configured one,
  so a scan silently runs against whatever was loaded;
* the endpoint serves the right model on CPU, where one unit takes minutes and
  a full scan takes longer than anybody will wait;
* the served context window is smaller than the units the scan will send, so
  prompts are truncated silently and the scanner reviews chopped code.

Nothing here prints the credential, and nothing here writes into a run
directory: it is a probe, not a phase.
"""
from __future__ import annotations

import json
import socket
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..errors import UserError
from ..harness.runtime import (
    api_key,
    endpoint_context_length,
    endpoint_url,
    harness_available,
    sdk_version,
)
from .profiles import third_party_warning

BENCHMARK_PROMPT = "Reply with the single word: ready."
BENCHMARK_MAX_TOKENS = 32
# A unit's reply is short by construction (one JSON report), so completion time
# dominates only when the model is slow; the per-request latency the benchmark
# measures carries the rest.
ESTIMATED_COMPLETION_TOKENS = 220


# Listing models is cheap.  Generating is not: a model that has to load, or a
# host already busy with a scan, legitimately takes minutes to answer the first
# request -- which is exactly the condition this command is meant to measure
# rather than time out on.
LIST_TIMEOUT = 15.0


def probe_llm(config: dict[str, Any], source: Path | None = None, *, timeout: float = 300.0) -> dict[str, Any]:
    """Probe the configured provider and estimate a full scan of ``source``."""
    settings = config["llm"]
    base = endpoint_url(settings).rstrip("/")
    model = str(settings.get("model", "") or "")
    result: dict[str, Any] = {
        "endpoint": base,
        "model": model,
        "profile": settings.get("profile"),
        "runtime": {"available": harness_available(), "sdk_version": _sdk_version()},
        "third_party_warning": third_party_warning(settings),
        "scanners": list(settings.get("scanners") or []),
    }
    try:
        # Read once, so an unset variable is one clear error rather than three.
        key = api_key(settings)
    except UserError as exc:
        result["credential"] = {"ok": False, "reason": str(exc)}
        key = None
    else:
        result["credential"] = {"ok": True, "reason": None, "source": settings.get("api_key_env") or "none (keyless)"}

    result["models"] = _models(base, key, model, timeout=min(timeout, LIST_TIMEOUT))
    result["context_window"] = _context(settings, config)
    result["benchmark"] = _benchmark(base, key, model, timeout=timeout)
    result["estimate"] = _estimate(config, source, result["benchmark"])
    result["ok"] = bool(
        result["runtime"]["available"]
        and result["credential"]["ok"]
        and result["models"]["reachable"]
        and result["models"]["model_present"]
        and result["benchmark"]["ok"]
        and not result["benchmark"].get("served_other_model")
        and result["context_window"]["ok"]
    )
    return result


def endpoint_reachable(settings: dict[str, Any], *, timeout: float = 15.0) -> tuple[bool, str | None]:
    """Is the endpoint answering and serving the configured model?  ``(ok, reason)``.

    The cheap half of :func:`probe_llm` -- a model listing, no generation --
    so a scan can refuse a dead endpoint in seconds instead of discovering it
    one unit at a time.
    """
    base = endpoint_url(settings).rstrip("/")
    model = str(settings.get("model", "") or "")
    try:
        key = api_key(settings)
    except UserError as exc:
        return False, str(exc)
    models = _models(base, key, model, timeout=timeout)
    if not models["reachable"] or not models["model_present"]:
        return False, str(models["reason"] or "the endpoint did not answer")
    return True, None


def _sdk_version() -> str | None:
    """The runtime version, or None when there is no runtime.

    A missing SDK is precisely one of the things this command reports, so
    asking for its version must not be what stops the command from running.
    """
    try:
        return sdk_version()
    except UserError:
        return None


def _models(base: str, key: str | None, model: str, *, timeout: float) -> dict[str, Any]:
    """List the endpoint's models and say whether the configured one is there.

    An endpoint that answers but does not serve the configured model is the
    quiet failure this command exists for: the scan would run against whatever
    the server decided to load and report it as the configured model.
    """
    payload, error = _request(f"{base}/models", None, key, timeout=timeout)
    if payload is None:
        return {"reachable": False, "model_present": False, "available": [], "reason": error}
    names = sorted(
        str(item.get("id", "")) for item in payload.get("data") or []
        if isinstance(item, dict) and item.get("id")
    )
    present = _serves(names, model)
    return {
        "reachable": True,
        "model_present": present,
        "available": names,
        "reason": None if present else (
            f"the endpoint does not serve {model!r}; it serves: {', '.join(names) or '(nothing)'}"
        ),
    }


def _serves(names: list[str], model: str) -> bool:
    """Is ``model`` among ``names``, allowing for the implicit ``:latest`` tag?"""
    if not model:
        return False
    if model in names or f"{model}:latest" in names:
        return True
    return any(name.split(":", 1)[0] == model for name in names)


def _context(settings: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """Compare the window the endpoint will really serve with the configured one."""
    configured = int(settings.get("context_window") or 0)
    served = endpoint_context_length(settings)
    if served is None:
        # Not every server can be asked.  Unknown is not a failure: the scan
        # proceeds on the configured window, as it always has.
        return {"ok": True, "configured": configured, "served": None, "reason": "the endpoint does not report its served window"}
    if served < configured:
        return {
            "ok": False, "configured": configured, "served": served,
            "reason": (
                f"the endpoint serves {served} tokens but [llm] context_window is {configured}: "
                "prompts past the served window are truncated silently"
            ),
        }
    return {"ok": True, "configured": configured, "served": served, "reason": None}


def _benchmark(base: str, key: str | None, model: str, *, timeout: float) -> dict[str, Any]:
    """One real completion, timed: the only honest source of tokens per second."""
    body = {
        "model": model,
        "messages": [{"role": "user", "content": BENCHMARK_PROMPT}],
        "max_tokens": BENCHMARK_MAX_TOKENS,
        "temperature": 0,
        "stream": False,
    }
    started = time.monotonic()
    payload, error = _request(f"{base}/chat/completions", body, key, timeout=timeout)
    elapsed = time.monotonic() - started
    if payload is None:
        return {"ok": False, "reason": error, "latency_seconds": round(elapsed, 3), "tokens_per_second": None}
    served = str(payload.get("model") or "") or None
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    completion = usage.get("completion_tokens")
    completion = completion if isinstance(completion, int) and completion > 0 else None
    return {
        "ok": True,
        "reason": None,
        "latency_seconds": round(elapsed, 3),
        "completion_tokens": completion,
        "prompt_tokens": usage.get("prompt_tokens"),
        "tokens_per_second": round(completion / elapsed, 2) if completion and elapsed > 0 else None,
        "served_model": served,
        # The endpoint naming a different model than it was asked for is the
        # mis-route this command exists to catch, and it is not an opinion:
        # the answer came back stamped with what actually produced it.
        "served_other_model": bool(served and model and not _serves([served], model)),
    }


def _estimate(config: dict[str, Any], source: Path | None, benchmark: dict[str, Any]) -> dict[str, Any]:
    """Wall clock for a full scan of ``source``, from the measured rate.

    The unit plan is the same deterministic plan the scan itself would build,
    so the unit count is exact; only the seconds per unit are extrapolated, and
    they are reported as what they are.
    """
    if source is None:
        return {"known": False, "reason": "no source tree given"}
    if not benchmark.get("ok"):
        return {"known": False, "reason": "the endpoint did not answer the benchmark"}
    try:
        from ..inventory import discover
        from .units import build_plan

        # ``output_root`` only tells discovery which directory to keep out of
        # the inventory; this probe writes nothing, so a temporary one is right.
        with tempfile.TemporaryDirectory(prefix="code-analyzer-llm-doctor-") as temporary:
            inventory = discover(source, config, Path(temporary))
        plan = build_plan(source, inventory, config=config)
    except (OSError, UserError, ValueError) as exc:
        return {"known": False, "reason": f"the source tree could not be planned: {exc}"}
    units = len(plan.get("units") or [])
    scanners = max(1, len(config["llm"].get("scanners") or []))
    jobs = max(1, int(config["llm"].get("jobs") or 1))
    rate = benchmark.get("tokens_per_second")
    latency = float(benchmark.get("latency_seconds") or 0.0)
    generation = ESTIMATED_COMPLETION_TOKENS / rate if rate else 0.0
    # The benchmark's own latency covers queueing, prompt evaluation and the
    # runtime's overhead for a request that generated almost nothing.
    per_session = max(latency, generation)
    sessions = units * scanners
    return {
        "known": True,
        "units": units,
        "scanners": scanners,
        "jobs": jobs,
        "sessions": sessions,
        "seconds_per_session": round(per_session, 2),
        "wall_clock_seconds": round(sessions * per_session / jobs, 1),
        "basis": (
            f"{sessions} sessions ({units} units x {scanners} scanners) at "
            f"~{per_session:.1f}s each, {jobs} at a time; extrapolated from one measured request"
        ),
    }


def _request(
    url: str, body: dict[str, Any] | None, key: str | None, *, timeout: float
) -> tuple[dict[str, Any] | None, str | None]:
    """One JSON request.  Returns ``(payload, None)`` or ``(None, reason)``.

    The credential travels in the header and never into the returned reason:
    this output is printed, and a probe must not be the thing that leaks a key.
    """
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code} from {url}"
    except (TimeoutError, socket.timeout):
        # Reachable but too slow to answer: on a shared or CPU-bound host this
        # is the diagnosis, not a connection problem, and saying "unreachable"
        # would send the operator to look at the wrong thing.
        return None, f"{url} did not answer within {timeout:g}s"
    except (OSError, urllib.error.URLError) as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, (TimeoutError, socket.timeout)):
            return None, f"{url} did not answer within {timeout:g}s"
        return None, f"{url} is unreachable: {reason}"
    except ValueError as exc:
        return None, f"{url} did not answer with JSON: {exc}"
    return (payload, None) if isinstance(payload, dict) else (None, f"{url} answered with {type(payload).__name__}, not an object")

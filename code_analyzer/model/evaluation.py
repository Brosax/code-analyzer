"""The only way evaluation content reaches a model: the pinned host, egress-checked, recorded.

``pin_local`` runs when an evaluation is created: it resolves the configured
local model host and pins it into evaluation.json (egress.py).  ``client_for``
builds the client every later request uses -- the endpoint from settings, the
policy from the evaluation (confidentiality, pin, allow_public_model), and a
recorder writing every exchange under ``model/``.  If settings.toml has since
been pointed elsewhere, the first request is blocked with a message to re-pin
on the profile page; settings never move an existing evaluation.
"""
from __future__ import annotations

from typing import Any

from ..errors import UserError
from ..evidence.workspace import Workspace
from ..settings import Settings
from .client import Endpoint, ModelClient, ModelError
from .egress import EgressBlocked, EgressPolicy, Pin, bound, pin_endpoint
from .record import Recorder


def local_endpoint(settings: Settings, *, review: bool = False, tool_mode: str = "native") -> Endpoint:
    return Endpoint(settings.local_endpoint, settings.review_model if review else settings.local_model,
                    tool_mode=tool_mode)


def pin_local(settings: Settings) -> dict[str, Any] | None:
    """Pin the local model host, or None when it cannot be resolved right now (re-pin later)."""
    try:
        return pin_endpoint(local_endpoint(settings)).to_json()
    except ModelError:
        return None


def public_endpoint(settings: Settings) -> Endpoint:
    if not settings.has_public_model:
        raise UserError("no public model is configured ([public_model] in settings.toml)")
    return Endpoint(settings.public_endpoint, settings.public_model, kind="public",
                    api_key_env=settings.public_api_key_env)


def public_allowed(workspace: Workspace, settings: Settings) -> tuple[bool, str]:
    """Whether this evaluation may use the third-party model, and if not, why."""
    evaluation = workspace.evaluation
    if evaluation["confidentiality"] != "public":
        return False, "client code only ever goes to the local GPU"
    if not settings.has_public_model:
        return False, "no public model is configured ([public_model] in settings.toml)"
    if not evaluation.get("allow_public_model"):
        return False, "the evaluator has not allowed the public model for this evaluation"
    return True, ""


def client_for(workspace: Workspace, settings: Settings, *, review: bool = False,
               tool_mode: str = "native", channel: str = "local") -> ModelClient:
    """``channel`` "public" is for batch jobs a human chose it for, on a public evaluation that allows it.
    The conversation never asks for it; nothing falls back to it."""
    evaluation = workspace.evaluation
    if channel == "public":
        allowed, reason = public_allowed(workspace, settings)
        if not allowed:
            raise EgressBlocked(reason)
        endpoint = public_endpoint(settings)
    elif channel == "local":
        if not evaluation.get("model_pin"):
            raise UserError("this evaluation has no pinned model host yet; pin one on the profile page")
        endpoint = local_endpoint(settings, review=review, tool_mode=tool_mode)
    else:
        raise UserError(f"unknown model channel {channel!r}")
    pin = Pin.from_json(evaluation["model_pin"]) if evaluation.get("model_pin") else None
    policy = EgressPolicy(evaluation["confidentiality"], pin,
                          allow_public_model=bool(evaluation.get("allow_public_model")))
    return ModelClient(endpoint, egress=bound(policy), recorder=Recorder(workspace.root / "model"))

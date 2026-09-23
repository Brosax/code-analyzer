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
from .egress import EgressPolicy, Pin, bound, pin_endpoint
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


def client_for(workspace: Workspace, settings: Settings, *, review: bool = False,
               tool_mode: str = "native") -> ModelClient:
    evaluation = workspace.evaluation
    if not evaluation.get("model_pin"):
        raise UserError("this evaluation has no pinned model host yet; pin one on the profile page")
    policy = EgressPolicy(evaluation["confidentiality"], Pin.from_json(evaluation["model_pin"]),
                          allow_public_model=bool(evaluation.get("allow_public_model")))
    return ModelClient(local_endpoint(settings, review=review, tool_mode=tool_mode), egress=bound(policy),
                       recorder=Recorder(workspace.root / "model"))

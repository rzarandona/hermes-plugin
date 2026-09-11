from __future__ import annotations

from enum import Enum


class RootCause(str, Enum):
    AGENT_BEHAVIOR = "agent behavior"
    POLICY = "policy"
    WORKFLOW = "workflow"
    RESOURCE = "resource"
    DEPENDENCY = "dependency"
    OWNER_WAIT = "owner wait"
    INFRASTRUCTURE = "infrastructure"


def require_root_cause(value: str) -> RootCause:
    try:
        return RootCause(value)
    except ValueError as exc:
        raise ValueError("ROOT_CAUSE_INVALID") from exc

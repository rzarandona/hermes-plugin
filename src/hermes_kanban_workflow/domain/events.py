from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, cast

from pydantic import Field, field_validator

from .commands import _freeze_json
from .identity import CorrelationEnvelope, FrozenModel


class WorkflowEvent(FrozenModel):
    event_id: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    event_type: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    command_id: str = Field(min_length=1)
    payload: Mapping[str, Any]
    correlation: CorrelationEnvelope
    occurred_at: datetime

    @field_validator("payload", mode="after")
    @classmethod
    def freeze_payload(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], _freeze_json(value))

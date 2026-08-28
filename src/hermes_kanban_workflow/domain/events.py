from __future__ import annotations

from datetime import datetime
from typing import Any

from .identity import FrozenModel


class WorkflowEvent(FrozenModel):
    event_id: str
    sequence: int
    event_type: str
    target_id: str
    command_id: str
    payload: dict[str, Any]
    occurred_at: datetime


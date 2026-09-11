from __future__ import annotations

import json
from hashlib import sha256

from pydantic import Field

from hermes_kanban_workflow.domain.commands import _thaw_json
from hermes_kanban_workflow.domain.events import WorkflowEvent
from hermes_kanban_workflow.domain.identity import FrozenModel


class CommandReceipt(FrozenModel):
    event: WorkflowEvent
    command_digest: str = Field(min_length=64, max_length=64)

    @property
    def event_id(self) -> str:
        """Compatibility access for callers that previously received WorkflowEvent."""
        return self.event.event_id

    def canonical_bytes(self) -> bytes:
        event = self.event.model_dump(mode="python", exclude={"payload", "correlation"})
        event["occurred_at"] = self.event.occurred_at.isoformat()
        event["payload"] = _thaw_json(self.event.payload)
        event["correlation"] = self.event.correlation.model_dump(mode="json")
        return json.dumps(
            {"command_digest": self.command_digest, "event": event},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_canonical_bytes(cls, value: bytes) -> CommandReceipt:
        return cls.model_validate_json(value)

from __future__ import annotations

from datetime import datetime
from typing import Any

from hermes_kanban_workflow.domain.identity import FrozenModel


class SignedPolicy(FrozenModel):
    policy_id: str
    scope: str
    issued_at: datetime
    expires_at: datetime
    rules: dict[str, Any]
    signature: str
    trust_epoch: int = 1

    def is_usable(self, now: datetime, scope: str) -> bool:
        return bool(self.signature) and self.issued_at <= now < self.expires_at and self.scope == scope


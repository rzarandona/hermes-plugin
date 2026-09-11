from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from hermes_kanban_workflow.policy.model import VerifiedPolicy


@dataclass(frozen=True, slots=True)
class RecoveryBudget:
    limit: int
    used: int = 0

    @property
    def remaining(self) -> int:
        return self.limit - self.used

    @classmethod
    def from_policy(
        cls, policy: VerifiedPolicy | None, *, now: datetime
    ) -> RecoveryBudget:
        limit = 1
        if (
            policy is not None
            and policy.is_usable(now)
            and policy.document.rules.get("max_automatic_recoveries") == 0
        ):
            limit = 0
        return cls(limit)

    def consume(self) -> RecoveryBudget:
        if self.remaining <= 0:
            raise PermissionError("RECOVERY_BUDGET_EXHAUSTED")
        return RecoveryBudget(self.limit, self.used + 1)

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import cast

from hermes_kanban_workflow.policy.model import VerifiedPolicy


class PriorityClass(IntEnum):
    SAFETY_CONTAINMENT = 1
    OWNER_ROLLBACK = 2
    EMERGENCY = 3
    SCHEDULED_PRODUCTION = 4
    VERIFICATION = 5
    ROUTINE = 6


@dataclass(frozen=True, slots=True)
class PrecedenceModel:
    ranks: dict[PriorityClass, int]
    dependency_edges: frozenset[tuple[str, str]] = frozenset()
    signed_policy_digest: str | None = None

    @classmethod
    def default(cls) -> PrecedenceModel:
        return cls({priority: int(priority) for priority in PriorityClass})

    @classmethod
    def from_verified_policy(cls, policy: VerifiedPolicy) -> PrecedenceModel:
        scheduler = policy.document.rules.get("scheduler", {})
        if not isinstance(scheduler, dict):
            raise TypeError("SCHEDULER_POLICY_INVALID")
        raw_edges = scheduler.get("dependency_edges", [])
        if not isinstance(raw_edges, list):
            raise TypeError("DEPENDENCY_EDGES_INVALID")
        edges: set[tuple[str, str]] = set()
        for raw in raw_edges:
            if (
                not isinstance(raw, list)
                or len(raw) != 2
                or not all(isinstance(item, str) and item for item in raw)
            ):
                raise ValueError("DEPENDENCY_EDGES_INVALID")
            before, after = cast(list[str], raw)
            if before == after:
                raise ValueError("DEPENDENCY_EDGE_CYCLE")
            edges.add((before, after))
        return cls(
            {priority: int(priority) for priority in PriorityClass},
            frozenset(edges),
            policy.digest,
        )

    def rank(self, priority: PriorityClass) -> int:
        return self.ranks[priority]

    def precedes(self, left: str, right: str) -> bool:
        return (left, right) in self.dependency_edges

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from uuid import uuid4


class RecoveryClass(IntEnum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3


@dataclass(frozen=True)
class RecoveryPolicy:
    allowlisted_r1: frozenset[str]

    def can_automate(self, recovery_class: RecoveryClass, command: str) -> bool:
        return recovery_class == RecoveryClass.R0 or (
            recovery_class == RecoveryClass.R1 and command in self.allowlisted_r1
        )


@dataclass(frozen=True)
class HoldRecord:
    hold_id: str
    project_id: str
    members: tuple[str, ...]
    reason: str


class HoldRegistry:
    def __init__(self) -> None:
        self._holds: dict[str, HoldRecord] = {}

    def create(self, project_id: str, members: tuple[str, ...], reason: str) -> HoldRecord:
        record = HoldRecord(str(uuid4()), project_id, tuple(dict.fromkeys(members)), reason)
        self._holds[record.hold_id] = record
        return record

    def resume_candidates(self, hold_id: str, eligible: tuple[str, ...]) -> tuple[str, ...]:
        record = self._holds[hold_id]
        allowed = set(eligible)
        return tuple(member for member in record.members if member in allowed)


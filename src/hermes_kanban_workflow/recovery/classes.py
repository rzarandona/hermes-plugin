from __future__ import annotations

from enum import IntEnum

from hermes_kanban_workflow.domain.identity import FrozenModel


class RecoveryClass(IntEnum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3


class RecoveryClassification(FrozenModel):
    command_name: str
    recovery_class: RecoveryClass
    known: bool


class RecoveryClassifier:
    def __init__(self, registry: dict[str, RecoveryClass]) -> None:
        self._registry = dict(registry)

    def classify(self, command_name: str) -> RecoveryClassification:
        known = command_name in self._registry
        return RecoveryClassification(
            command_name=command_name,
            recovery_class=self._registry.get(command_name, RecoveryClass.R3),
            known=known,
        )

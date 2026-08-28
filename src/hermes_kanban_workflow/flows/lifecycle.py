from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Flow(IntEnum):
    INTAKE = 1
    EXECUTION = 2
    RELEASE = 3
    OPERATIONS = 4


@dataclass(frozen=True)
class LifecycleRecord:
    work_id: str
    flow: Flow
    evidence: tuple[str, ...]


class LifecycleEngine:
    def start(self, work_id: str) -> LifecycleRecord:
        return LifecycleRecord(work_id, Flow.INTAKE, ())

    def advance(self, current: LifecycleRecord, target: Flow, *, evidence: str) -> LifecycleRecord:
        if target.value != current.flow.value + 1 or not evidence:
            raise ValueError("FLOW_TRANSITION_DENIED")
        return LifecycleRecord(current.work_id, target, current.evidence + (evidence,))


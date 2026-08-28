from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum


class EffectState(StrEnum):
    INTENT_RECORDED = "intent-recorded"
    DISPATCHED = "dispatched"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    UNKNOWN = "unknown"
    MANUAL_ESCALATION = "manual-escalation"


@dataclass(frozen=True)
class EffectRecord:
    effect_id: str
    provider: str
    state: EffectState
    receipt: str | None = None


class EffectStateMachine:
    def __init__(self) -> None:
        self._records: dict[str, EffectRecord] = {}

    def create_intent(self, effect_id: str, provider: str) -> EffectRecord:
        if effect_id in self._records:
            raise ValueError("EFFECT_ALREADY_EXISTS")
        record = EffectRecord(effect_id, provider, EffectState.INTENT_RECORDED)
        self._records[effect_id] = record
        return record

    def mark_unknown(self, effect_id: str, receipt: str) -> EffectRecord:
        record = replace(self._records[effect_id], state=EffectState.UNKNOWN, receipt=receipt)
        self._records[effect_id] = record
        return record

    def retry(self, effect_id: str) -> EffectRecord:
        record = self._records[effect_id]
        if record.state == EffectState.UNKNOWN:
            raise RuntimeError("EFFECT_RECONCILIATION_REQUIRED")
        return record

    def reconcile(self, effect_id: str, confirmed: bool, receipt: str) -> EffectRecord:
        record = replace(self._records[effect_id], state=EffectState.CONFIRMED if confirmed else EffectState.MANUAL_ESCALATION, receipt=receipt)
        self._records[effect_id] = record
        return record


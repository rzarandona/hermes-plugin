from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
import json
from typing import Any

from pydantic import Field

from .identity import AuthorityEpoch, CorrelationEnvelope, FrozenModel


class EffectClass(StrEnum):
    NO_EXTERNAL_EFFECT = "none"
    IDEMPOTENT_EXTERNAL_EFFECT = "idempotent"
    REVERSIBLE_EXTERNAL_EFFECT = "reversible"
    IRREVERSIBLE_EXTERNAL_EFFECT = "irreversible"
    UNKNOWN = "unknown"


class CommandEnvelope(FrozenModel):
    command_id: str
    idempotency_key: str
    actor_id: str
    target_id: str
    command_type: str
    effect_class: EffectClass
    authority_epoch: AuthorityEpoch
    policy_digest: str
    issued_at: datetime
    expires_at: datetime
    payload: dict[str, Any] = Field(default_factory=dict)
    correlation: CorrelationEnvelope

    @property
    def payload_digest(self) -> str:
        return sha256(json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def is_current(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(timezone.utc)) < self.expires_at


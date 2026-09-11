from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class ProviderReceipt:
    receipt_id: str
    operation_id: str
    idempotency_key: str
    outcome: Literal["accepted", "rejected", "unknown"]
    provider_reference: str
    effect_executed: bool = False
    production_proof: bool = False

    def __post_init__(self) -> None:
        if not all(
            (
                self.receipt_id,
                self.operation_id,
                self.idempotency_key,
                self.provider_reference,
            )
        ):
            raise ValueError("PROVIDER_RECEIPT_BINDINGS_REQUIRED")
        if self.effect_executed or self.production_proof:
            raise ValueError("REPOSITORY_FIXTURE_CANNOT_CLAIM_EXTERNAL_PROOF")

    @property
    def digest(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True, slots=True)
class ReadbackReceipt:
    receipt_id: str
    operation_id: str
    status: Literal["applied", "absent", "contradictory", "unknown"]
    authority: str
    evidence_reference: str
    effect_executed: bool = False
    production_proof: bool = False

    def __post_init__(self) -> None:
        if not all(
            (self.receipt_id, self.operation_id, self.authority, self.evidence_reference)
        ):
            raise ValueError("READBACK_RECEIPT_BINDINGS_REQUIRED")
        if self.effect_executed or self.production_proof:
            raise ValueError("REPOSITORY_FIXTURE_CANNOT_CLAIM_EXTERNAL_PROOF")

    @property
    def digest(self) -> str:
        return _digest(asdict(self))


def _digest(value: dict[str, object]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()

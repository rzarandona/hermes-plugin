from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True, slots=True)
class EffectCommand:
    operation_id: str
    action: str
    artifact_id: str
    environment: str
    binding_digest: str

    @property
    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "action": self.action,
                "artifact_id": self.artifact_id,
                "binding_digest": self.binding_digest,
                "environment": self.environment,
                "operation_id": self.operation_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class ReconciliationReceipt:
    operation_id: str
    command_digest: str
    reconciler_subject_id: str
    status: str
    evidence_ref: str
    authentication_tag: bytes
    repository_fixture: bool

    @property
    def production_proof(self) -> bool:
        return not self.repository_fixture


class AuthenticatedReconciliationBoundary:
    """Guarded adapter; it performs no deployment and delegates reconciliation."""

    def __init__(
        self,
        *,
        reconcile: Callable[[EffectCommand], ReconciliationReceipt],
        verify: Callable[[ReconciliationReceipt, EffectCommand], bool],
    ) -> None:
        self._reconcile = reconcile
        self._verify = verify

    def execute(self, command: EffectCommand) -> ReconciliationReceipt:
        receipt = self._reconcile(command)
        if (
            not self._verify(receipt, command)
            or receipt.operation_id != command.operation_id
            or receipt.command_digest != command.digest
        ):
            raise PermissionError("AUTHENTIC_EFFECT_RECONCILIATION_REQUIRED")
        return receipt

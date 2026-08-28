from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256


@dataclass(frozen=True)
class ActivationEvidence:
    stage: int
    predecessor_digest: str | None
    passed: bool


@dataclass(frozen=True)
class ActivationDecision:
    stage: int
    owner_id: str
    package_digest: str
    policy_digest: str
    host_digest: str


@dataclass(frozen=True)
class ActivationReceipt:
    stage: int
    receipt_digest: str


class ActivationChain:
    def __init__(self, package_digest: str, policy_digest: str, host_digest: str) -> None:
        self._package = package_digest
        self._policy = policy_digest
        self._host = host_digest
        self._current: ActivationReceipt | None = None

    def advance(self, evidence: ActivationEvidence, decision: ActivationDecision) -> ActivationReceipt:
        expected_stage = 1 if self._current is None else self._current.stage + 1
        predecessor = None if self._current is None else self._current.receipt_digest
        exact = (
            1 <= evidence.stage <= 10
            and evidence.stage == expected_stage == decision.stage
            and evidence.predecessor_digest == predecessor
            and evidence.passed
            and bool(decision.owner_id)
            and decision.package_digest == self._package
            and decision.policy_digest == self._policy
            and decision.host_digest == self._host
        )
        if not exact:
            raise PermissionError("ACTIVATION_STAGE_SKIP_DENIED")
        digest = sha256(
            f"{evidence.stage}:{predecessor}:{self._package}:{self._policy}:{self._host}:{decision.owner_id}".encode()
        ).hexdigest()
        self._current = ActivationReceipt(evidence.stage, digest)
        return self._current

    def rollback(self, stage: int) -> None:
        if stage < 0 or (self._current and stage >= self._current.stage):
            raise ValueError("ACTIVATION_ROLLBACK_DENIED")
        self._current = None if stage == 0 else ActivationReceipt(stage, "rollback-reentry-required")


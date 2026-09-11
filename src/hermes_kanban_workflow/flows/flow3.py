from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from hermes_kanban_workflow.adapters.artifact_store import (
    SignedArtifact,
    SigningAdapter,
    SigningRootClass,
)
from hermes_kanban_workflow.adapters.effects import EffectCommand


class RolloutStrategy(StrEnum):
    PROGRESSIVE = "progressive"
    ATOMIC = "atomic"


class HealthGateKind(StrEnum):
    TELEMETRY = "telemetry"
    CRITICAL_JOURNEY = "critical_journey"
    DATA_INTEGRITY = "data_integrity"
    DEPENDENCY = "dependency"


class HealthStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class HealthGate:
    kind: HealthGateKind
    status: HealthStatus
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class RolloutEvaluation:
    paused: bool
    reason: str
    gates: tuple[HealthGate, ...]


def select_rollout_strategy(
    *,
    supports_progressive: bool,
    requested: RolloutStrategy | None,
    atomic_unavailability_evidence: str | None = None,
) -> RolloutStrategy:
    if supports_progressive and requested is None:
        return RolloutStrategy.PROGRESSIVE
    strategy = requested or RolloutStrategy.ATOMIC
    if strategy is RolloutStrategy.ATOMIC and not atomic_unavailability_evidence:
        raise PermissionError("ATOMIC_TECHNICAL_UNAVAILABILITY_EVIDENCE_REQUIRED")
    return strategy


def evaluate_rollout(gates: tuple[HealthGate, ...]) -> RolloutEvaluation:
    if not gates:
        return RolloutEvaluation(True, "TYPED_HEALTH_GATES_REQUIRED", gates)
    if any(gate.status is HealthStatus.FAIL for gate in gates):
        return RolloutEvaluation(True, "HEALTH_GATE_FAILED_AUTOMATIC_PAUSE", gates)
    return RolloutEvaluation(False, "HEALTH_GATES_PASSED", gates)


@dataclass(frozen=True, slots=True)
class ReleaseBinding:
    artifact_id: str
    environment: str
    configuration_version: str
    policy_version: str
    strategy: RolloutStrategy
    valid_from: datetime
    valid_until: datetime
    rollback_contract: str
    emergency: bool = False

    @property
    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "artifact_id": self.artifact_id,
                "configuration_version": self.configuration_version,
                "emergency": self.emergency,
                "environment": self.environment,
                "policy_version": self.policy_version,
                "rollback_contract": self.rollback_contract,
                "strategy": self.strategy.value,
                "valid_from": self.valid_from.isoformat(),
                "valid_until": self.valid_until.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class OwnerApproval:
    approval_id: str
    owner_subject_id: str
    binding_digest: str
    decided_at: datetime
    signature: bytes

    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "approval_id": self.approval_id,
                "binding_digest": self.binding_digest,
                "decided_at": self.decided_at.isoformat(),
                "owner_subject_id": self.owner_subject_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class OwnerApprovalRegistry:
    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        owner_by_environment: dict[str, str],
    ) -> None:
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()
        self._owner_by_environment = dict(owner_by_environment)
        self._issued: dict[str, OwnerApproval] = {}
        self._consumed: set[str] = set()

    def issue(
        self,
        *,
        owner_subject_id: str,
        binding: ReleaseBinding,
        decided_at: datetime,
    ) -> OwnerApproval:
        if self._owner_by_environment.get(binding.environment) != owner_subject_id:
            raise PermissionError("PRODUCTION_OWNER_REGISTRY_MISMATCH")
        unsigned = OwnerApproval(
            approval_id=str(uuid4()),
            owner_subject_id=owner_subject_id,
            binding_digest=binding.digest,
            decided_at=decided_at,
            signature=b"",
        )
        approval = OwnerApproval(
            approval_id=unsigned.approval_id,
            owner_subject_id=unsigned.owner_subject_id,
            binding_digest=unsigned.binding_digest,
            decided_at=unsigned.decided_at,
            signature=self._private_key.sign(unsigned.signed_bytes()),
        )
        self._issued[approval.approval_id] = approval
        return approval

    def consume(
        self,
        approval: OwnerApproval,
        *,
        binding: ReleaseBinding,
        now: datetime,
    ) -> OwnerApproval:
        issued = self._issued.get(approval.approval_id)
        if issued != approval:
            raise PermissionError("AUTHENTIC_OWNER_APPROVAL_REQUIRED")
        try:
            self._public_key.verify(approval.signature, approval.signed_bytes())
        except InvalidSignature as exc:
            raise PermissionError("AUTHENTIC_OWNER_APPROVAL_REQUIRED") from exc
        if approval.approval_id in self._consumed:
            raise PermissionError("OWNER_APPROVAL_ALREADY_USED")
        if approval.binding_digest != binding.digest:
            raise PermissionError("OWNER_APPROVAL_BINDING_MISMATCH")
        if not binding.valid_from <= now < binding.valid_until:
            raise PermissionError("OWNER_APPROVAL_EXPIRED")
        self._consumed.add(approval.approval_id)
        return approval


@dataclass(frozen=True, slots=True)
class ObjectiveObservation:
    objective: str
    value: int
    evidence_ref: str
    authentication_tag: bytes


@dataclass(frozen=True, slots=True)
class RollbackAuthorization:
    authorization_id: str
    artifact_id: str
    rollback_contract: str
    objective: str
    threshold: int
    reversible: bool
    collateral_risk_bounded: bool
    expires_at: datetime
    signature: bytes

    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "artifact_id": self.artifact_id,
                "authorization_id": self.authorization_id,
                "collateral_risk_bounded": self.collateral_risk_bounded,
                "expires_at": self.expires_at.isoformat(),
                "objective": self.objective,
                "reversible": self.reversible,
                "rollback_contract": self.rollback_contract,
                "threshold": self.threshold,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class RollbackPolicyRegistry:
    def __init__(self, *, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._issued: dict[str, RollbackAuthorization] = {}

    def issue(
        self,
        *,
        artifact_id: str,
        rollback_contract: str,
        objective: str,
        threshold: int,
        reversible: bool,
        collateral_risk_bounded: bool,
        expires_at: datetime,
    ) -> RollbackAuthorization:
        unsigned = RollbackAuthorization(
            str(uuid4()),
            artifact_id,
            rollback_contract,
            objective,
            threshold,
            reversible,
            collateral_risk_bounded,
            expires_at,
            b"",
        )
        authorization = RollbackAuthorization(
            unsigned.authorization_id,
            unsigned.artifact_id,
            unsigned.rollback_contract,
            unsigned.objective,
            unsigned.threshold,
            unsigned.reversible,
            unsigned.collateral_risk_bounded,
            unsigned.expires_at,
            self._private_key.sign(unsigned.signed_bytes()),
        )
        self._issued[authorization.authorization_id] = authorization
        return authorization

    def verify(self, authorization: RollbackAuthorization) -> bool:
        if self._issued.get(authorization.authorization_id) != authorization:
            return False
        try:
            self._public_key.verify(authorization.signature, authorization.signed_bytes())
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True)
class RollbackDecision:
    artifact_id: str
    rollback_contract: str
    automatic: bool
    authorization_id: str | None
    owner_approval_id: str | None


def decide_rollback(
    *,
    artifact_id: str,
    rollback_contract: str,
    authorization: RollbackAuthorization | None,
    authorization_registry: RollbackPolicyRegistry,
    observation: ObjectiveObservation,
    verify_observation: Callable[[ObjectiveObservation], bool],
    now: datetime,
    owner_approval: OwnerApproval | None = None,
    owner_registry: OwnerApprovalRegistry | None = None,
    release_binding: ReleaseBinding | None = None,
) -> RollbackDecision:
    if (
        authorization is not None
        and authorization_registry.verify(authorization)
        and authorization.artifact_id == artifact_id
        and authorization.rollback_contract == rollback_contract
        and now < authorization.expires_at
        and authorization.reversible
        and authorization.collateral_risk_bounded
        and observation.objective == authorization.objective
        and observation.value >= authorization.threshold
        and verify_observation(observation)
    ):
        return RollbackDecision(
            artifact_id,
            rollback_contract,
            True,
            authorization.authorization_id,
            None,
        )
    if owner_approval is None or owner_registry is None or release_binding is None:
        raise PermissionError("FRESH_EXACT_OWNER_ROLLBACK_APPROVAL_REQUIRED")
    if (
        release_binding.artifact_id != artifact_id
        or release_binding.rollback_contract != rollback_contract
    ):
        raise PermissionError("OWNER_ROLLBACK_BINDING_MISMATCH")
    owner_registry.consume(owner_approval, binding=release_binding, now=now)
    return RollbackDecision(
        artifact_id,
        rollback_contract,
        False,
        None,
        owner_approval.approval_id,
    )


def _compute_durable_evidence_digest(evidence: tuple[str, ...]) -> str:
    encoded = json.dumps(evidence, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


def durable_evidence_digest(evidence: tuple[str, ...]) -> str:
    return _compute_durable_evidence_digest(evidence)


@dataclass(frozen=True, slots=True)
class ProductionVerification:
    verification_id: str
    artifact_id: str
    verifier_subject_id: str
    evidence_ref: str
    verified_at: datetime
    signature: bytes

    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "artifact_id": self.artifact_id,
                "evidence_ref": self.evidence_ref,
                "verification_id": self.verification_id,
                "verified_at": self.verified_at.isoformat(),
                "verifier_subject_id": self.verifier_subject_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class ProductionVerificationRegistry:
    def __init__(self, *, private_key: Ed25519PrivateKey, deployment_actor: str) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._deployment_actor = deployment_actor
        self._issued: dict[str, ProductionVerification] = {}

    def issue(
        self,
        *,
        artifact_id: str,
        verifier_subject_id: str,
        evidence_ref: str,
        verified_at: datetime,
    ) -> ProductionVerification:
        if verifier_subject_id == self._deployment_actor:
            raise PermissionError("INDEPENDENT_PRODUCTION_VERIFIER_REQUIRED")
        unsigned = ProductionVerification(
            str(uuid4()), artifact_id, verifier_subject_id, evidence_ref, verified_at, b""
        )
        receipt = ProductionVerification(
            unsigned.verification_id,
            unsigned.artifact_id,
            unsigned.verifier_subject_id,
            unsigned.evidence_ref,
            unsigned.verified_at,
            self._private_key.sign(unsigned.signed_bytes()),
        )
        self._issued[receipt.verification_id] = receipt
        return receipt

    def verify(self, receipt: ProductionVerification, *, artifact_id: str) -> bool:
        if self._issued.get(receipt.verification_id) != receipt or receipt.artifact_id != artifact_id:
            return False
        try:
            self._public_key.verify(receipt.signature, receipt.signed_bytes())
        except InvalidSignature:
            return False
        return receipt.verifier_subject_id != self._deployment_actor


@dataclass(frozen=True, slots=True)
class RollbackReadinessReceipt:
    artifact_id: str
    contract: str
    evidence_ref: str
    authentication_tag: bytes


@dataclass(frozen=True, slots=True)
class OperationalOwnerAcceptance:
    acceptance_id: str
    service_id: str
    artifact_id: str
    owner_subject_id: str
    evidence_digest: str
    accepted_at: datetime
    signature: bytes

    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "acceptance_id": self.acceptance_id,
                "accepted_at": self.accepted_at.isoformat(),
                "artifact_id": self.artifact_id,
                "evidence_digest": self.evidence_digest,
                "owner_subject_id": self.owner_subject_id,
                "service_id": self.service_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class OperationalOwnerAcceptanceRegistry:
    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        owner_by_service: dict[str, str],
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._owner_by_service = dict(owner_by_service)
        self._issued: dict[str, OperationalOwnerAcceptance] = {}
        self._consumed: set[str] = set()

    def issue(
        self,
        *,
        service_id: str,
        artifact_id: str,
        owner_subject_id: str,
        evidence_digest: str,
        accepted_at: datetime,
    ) -> OperationalOwnerAcceptance:
        if self._owner_by_service.get(service_id) != owner_subject_id:
            raise PermissionError("OPERATIONAL_OWNER_REGISTRY_MISMATCH")
        unsigned = OperationalOwnerAcceptance(
            str(uuid4()),
            service_id,
            artifact_id,
            owner_subject_id,
            evidence_digest,
            accepted_at,
            b"",
        )
        acceptance = OperationalOwnerAcceptance(
            unsigned.acceptance_id,
            unsigned.service_id,
            unsigned.artifact_id,
            unsigned.owner_subject_id,
            unsigned.evidence_digest,
            unsigned.accepted_at,
            self._private_key.sign(unsigned.signed_bytes()),
        )
        self._issued[acceptance.acceptance_id] = acceptance
        return acceptance

    def consume(
        self,
        acceptance: OperationalOwnerAcceptance,
        *,
        service_id: str,
        artifact_id: str,
        evidence_digest: str,
    ) -> OperationalOwnerAcceptance:
        if self._issued.get(acceptance.acceptance_id) != acceptance:
            raise PermissionError("EXPLICIT_OPERATIONAL_OWNER_ACCEPTANCE_REQUIRED")
        try:
            self._public_key.verify(acceptance.signature, acceptance.signed_bytes())
        except InvalidSignature as exc:
            raise PermissionError("EXPLICIT_OPERATIONAL_OWNER_ACCEPTANCE_REQUIRED") from exc
        if acceptance.acceptance_id in self._consumed:
            raise PermissionError("OPERATIONAL_OWNER_ACCEPTANCE_ALREADY_USED")
        if (
            acceptance.service_id != service_id
            or acceptance.artifact_id != artifact_id
            or acceptance.evidence_digest != evidence_digest
            or self._owner_by_service.get(service_id) != acceptance.owner_subject_id
        ):
            raise PermissionError("OPERATIONAL_OWNER_ACCEPTANCE_BINDING_MISMATCH")
        self._consumed.add(acceptance.acceptance_id)
        return acceptance


@dataclass(frozen=True, slots=True)
class OperationalHandoff:
    service_id: str
    artifact_id: str
    closed: bool
    production_verification_id: str
    operational_owner_subject_id: str
    durable_evidence_digest: str


def closeout_release(
    *,
    service_id: str,
    artifact_id: str,
    verification: ProductionVerification,
    verification_registry: ProductionVerificationRegistry,
    rollback_readiness: RollbackReadinessReceipt,
    verify_rollback_readiness: Callable[[RollbackReadinessReceipt], bool],
    durable_evidence: tuple[str, ...],
    durable_evidence_digest: str,
    operational_acceptance: OperationalOwnerAcceptance | None,
    operational_owner_registry: OperationalOwnerAcceptanceRegistry,
) -> OperationalHandoff:
    if not verification_registry.verify(verification, artifact_id=artifact_id):
        raise PermissionError("INDEPENDENT_PRODUCTION_VERIFICATION_REQUIRED")
    if (
        rollback_readiness.artifact_id != artifact_id
        or not verify_rollback_readiness(rollback_readiness)
    ):
        raise PermissionError("ROLLBACK_READINESS_RECHECK_REQUIRED")
    computed_digest = _compute_durable_evidence_digest(durable_evidence)
    if not durable_evidence or durable_evidence_digest != computed_digest:
        raise PermissionError("DURABLE_CLOSEOUT_EVIDENCE_REQUIRED")
    if operational_acceptance is None:
        raise PermissionError("EXPLICIT_OPERATIONAL_OWNER_ACCEPTANCE_REQUIRED")
    acceptance = operational_owner_registry.consume(
        operational_acceptance,
        service_id=service_id,
        artifact_id=artifact_id,
        evidence_digest=computed_digest,
    )
    return OperationalHandoff(
        service_id,
        artifact_id,
        True,
        verification.verification_id,
        acceptance.owner_subject_id,
        computed_digest,
    )


@dataclass(frozen=True, slots=True)
class PromotionCommand:
    operation_id: str
    artifact_id: str
    environment: str
    binding_digest: str
    strategy: RolloutStrategy
    emergency: bool
    owner_approval_id: str
    release_lease_ref: str
    health_gates: tuple[HealthGate, ...]
    rollback_readiness_ref: str
    repository_fixture: bool

    @property
    def production_proof(self) -> bool:
        return not self.repository_fixture

    def as_effect_command(self) -> EffectCommand:
        if self.environment == "production" and self.repository_fixture:
            raise PermissionError("PRODUCTION_PROOF_REQUIRED")
        return EffectCommand(
            self.operation_id,
            "promote",
            self.artifact_id,
            self.environment,
            self.binding_digest,
        )


def create_promotion_command(
    *,
    artifact: SignedArtifact,
    signer: SigningAdapter,
    binding: ReleaseBinding,
    approval: OwnerApproval,
    owner_registry: OwnerApprovalRegistry,
    release_lease_ref: str,
    verify_release_lease: Callable[[str, ReleaseBinding], bool],
    health_gates: tuple[HealthGate, ...],
    verify_health_gate: Callable[[HealthGate], bool],
    atomic_unavailability_evidence: str | None,
    rollback_readiness: RollbackReadinessReceipt,
    verify_rollback_readiness: Callable[[RollbackReadinessReceipt], bool],
    now: datetime,
) -> PromotionCommand:
    signature = artifact.signature
    if artifact.artifact_id != artifact.recompute_identity() or binding.artifact_id != artifact.artifact_id:
        raise PermissionError("ARTIFACT_IDENTITY_BINDING_MISMATCH")
    if (
        not signer.verify(signature)
        or signature.signed_digest != artifact.material.material_digest
        or signature.environment != binding.environment
    ):
        raise PermissionError("ARTIFACT_SIGNATURE_INVALID")
    if binding.environment == "production" and (
        signature.root_class is not SigningRootClass.PRODUCTION_HARDWARE_MANAGED
        or not signature.non_exportable
        or not signature.hardware_backed
        or signature.capability_id is None
    ):
        raise PermissionError("PRODUCTION_HARDWARE_SIGNING_REQUIREMENTS_NOT_MET")
    selected = select_rollout_strategy(
        supports_progressive=binding.strategy is RolloutStrategy.PROGRESSIVE,
        requested=binding.strategy,
        atomic_unavailability_evidence=atomic_unavailability_evidence,
    )
    rollout = evaluate_rollout(health_gates)
    if not all(verify_health_gate(gate) for gate in health_gates):
        raise PermissionError("AUTHENTIC_HEALTH_GATE_EVIDENCE_REQUIRED")
    if rollout.paused:
        raise PermissionError(rollout.reason)
    if not verify_release_lease(release_lease_ref, binding):
        raise PermissionError("AUTHENTIC_RELEASE_LEASE_REQUIRED")
    if (
        rollback_readiness.artifact_id != artifact.artifact_id
        or rollback_readiness.contract != binding.rollback_contract
        or not verify_rollback_readiness(rollback_readiness)
    ):
        raise PermissionError("ROLLBACK_READINESS_REQUIRED")
    owner_registry.consume(approval, binding=binding, now=now)
    return PromotionCommand(
        str(uuid4()),
        artifact.artifact_id,
        binding.environment,
        binding.digest,
        selected,
        binding.emergency,
        approval.approval_id,
        release_lease_ref,
        health_gates,
        rollback_readiness.evidence_ref,
        not signature.production_proof,
    )

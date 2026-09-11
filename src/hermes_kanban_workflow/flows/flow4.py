from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass(frozen=True, slots=True)
class ServiceIndicator:
    name: str
    kind: str
    target: int


@dataclass(frozen=True, slots=True)
class ObjectiveSet:
    service_id: str
    version: str
    indicators: tuple[ServiceIndicator, ...]
    error_budget: int
    exclusions: tuple[str, ...]
    criticality: str
    review_triggers: tuple[str, ...]

    @property
    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "criticality": self.criticality,
                "error_budget": self.error_budget,
                "exclusions": self.exclusions,
                "indicators": [
                    {"kind": item.kind, "name": item.name, "target": item.target}
                    for item in self.indicators
                ],
                "review_triggers": self.review_triggers,
                "service_id": self.service_id,
                "version": self.version,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class ObjectiveApproval:
    approval_id: str
    objective_digest: str
    owner_subject_id: str
    decided_at: datetime
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "approval_id": self.approval_id,
                "decided_at": self.decided_at.isoformat(),
                "objective_digest": self.objective_digest,
                "owner_subject_id": self.owner_subject_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class ObjectiveSetRegistry:
    def __init__(
        self, *, private_key: Ed25519PrivateKey, owner_by_service: dict[str, str]
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._owner_by_service = dict(owner_by_service)
        self._issued: dict[str, ObjectiveApproval] = {}

    def approve(
        self, objective: ObjectiveSet, *, owner_subject_id: str, decided_at: datetime
    ) -> ObjectiveApproval:
        complete = all(
            (
                objective.service_id,
                objective.version,
                objective.indicators,
                objective.error_budget > 0,
                objective.criticality,
                objective.review_triggers,
            )
        ) and all(
            indicator.name and indicator.kind and indicator.target > 0
            for indicator in objective.indicators
        )
        if not complete:
            raise ValueError("COMPLETE_SERVICE_OBJECTIVE_SET_REQUIRED")
        if self._owner_by_service.get(objective.service_id) != owner_subject_id:
            raise PermissionError("SERVICE_OWNER_REQUIRED")
        unsigned = ObjectiveApproval(
            str(uuid4()), objective.digest, owner_subject_id, decided_at, b""
        )
        approval = ObjectiveApproval(
            unsigned.approval_id,
            unsigned.objective_digest,
            unsigned.owner_subject_id,
            unsigned.decided_at,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._issued[approval.approval_id] = approval
        return approval

    def verify(self, approval: ObjectiveApproval, *, objective: ObjectiveSet) -> bool:
        if self._issued.get(approval.approval_id) != approval:
            return False
        if approval.objective_digest != objective.digest:
            return False
        try:
            self._public_key.verify(approval.signature, approval.signed_bytes)
        except InvalidSignature:
            return False
        return self._owner_by_service.get(objective.service_id) == approval.owner_subject_id


class HealthSignalKind(StrEnum):
    TELEMETRY = "telemetry"
    CRITICAL_JOURNEY = "critical_journey"
    DATA_INTEGRITY = "data_integrity"
    DEPENDENCY = "dependency"
    SUPPORT = "support"


@dataclass(frozen=True, slots=True)
class HealthEvidence:
    evidence_id: str
    service_id: str
    kind: HealthSignalKind
    healthy: bool
    evidence_ref: str
    source_subject_id: str
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "evidence_id": self.evidence_id,
                "evidence_ref": self.evidence_ref,
                "healthy": self.healthy,
                "kind": self.kind.value,
                "service_id": self.service_id,
                "source_subject_id": self.source_subject_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class HealthEvidenceAuthority:
    def __init__(self, *, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._issued: dict[str, HealthEvidence] = {}

    def issue(
        self,
        *,
        service_id: str,
        kind: HealthSignalKind,
        healthy: bool,
        evidence_ref: str,
        source_subject_id: str | None = None,
    ) -> HealthEvidence:
        unsigned = HealthEvidence(
            str(uuid4()),
            service_id,
            kind,
            healthy,
            evidence_ref,
            source_subject_id or f"independent:{kind.value}",
            b"",
        )
        receipt = HealthEvidence(
            unsigned.evidence_id,
            unsigned.service_id,
            unsigned.kind,
            unsigned.healthy,
            unsigned.evidence_ref,
            unsigned.source_subject_id,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._issued[receipt.evidence_id] = receipt
        return receipt

    def verify(self, evidence: HealthEvidence) -> bool:
        if self._issued.get(evidence.evidence_id) != evidence:
            return False
        try:
            self._public_key.verify(evidence.signature, evidence.signed_bytes)
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True)
class HealthAssessment:
    service_id: str
    healthy: bool
    signal_kinds: frozenset[HealthSignalKind]
    evidence_ids: tuple[str, ...]


def assess_service_health(
    service_id: str,
    signals: tuple[HealthEvidence, ...],
    *,
    verifier: HealthEvidenceAuthority,
) -> HealthAssessment:
    required = frozenset(HealthSignalKind)
    if not signals or any(
        signal.service_id != service_id or not verifier.verify(signal) for signal in signals
    ):
        raise PermissionError("AUTHENTIC_INDEPENDENT_HEALTH_EVIDENCE_REQUIRED")
    kinds = frozenset(signal.kind for signal in signals)
    if kinds != required or len({signal.source_subject_id for signal in signals}) < len(required):
        raise PermissionError("MULTI_SIGNAL_HEALTH_EVIDENCE_REQUIRED")
    return HealthAssessment(
        service_id,
        all(signal.healthy for signal in signals),
        kinds,
        tuple(signal.evidence_id for signal in signals),
    )


@dataclass(frozen=True, slots=True)
class ActionableAlert:
    alert_id: str
    dedupe_key: str
    alert_type: str
    owner_subject_id: str
    evidence_ref: str
    severity: str
    runbook_ref: str
    acknowledgement_lease_seconds: int
    routing_policy: str
    false_positive_target_ppm: int
    actionable: bool
    noisy: bool


@dataclass(frozen=True, slots=True)
class PageReceipt:
    alert_id: str
    dedupe_key: str
    paged: bool
    owner_subject_id: str


class AlertRouter:
    def __init__(self) -> None:
        self._pages: dict[str, tuple[ActionableAlert, PageReceipt]] = {}

    @property
    def page_count(self) -> int:
        return len(self._pages)

    def page(self, alert: ActionableAlert) -> PageReceipt:
        existing = self._pages.get(alert.dedupe_key)
        if existing is not None:
            if existing[0] != alert:
                raise PermissionError("ALERT_DEDUPE_MISMATCH")
            return existing[1]
        complete = all(
            (
                alert.alert_id,
                alert.dedupe_key,
                alert.alert_type,
                alert.owner_subject_id,
                alert.evidence_ref,
                alert.severity,
                alert.runbook_ref,
                alert.routing_policy,
            )
        )
        if (
            not complete
            or not alert.actionable
            or alert.noisy
            or alert.acknowledgement_lease_seconds <= 0
            or alert.false_positive_target_ppm < 0
        ):
            raise PermissionError("ACTIONABLE_OWNED_ALERT_REQUIRED")
        receipt = PageReceipt(alert.alert_id, alert.dedupe_key, True, alert.owner_subject_id)
        self._pages[alert.dedupe_key] = (alert, receipt)
        return receipt


class ChangeDimension(StrEnum):
    OPERATIONAL_CONFIGURATION = "operational_configuration"
    CONTAINMENT = "containment"
    MAINTENANCE = "maintenance"
    SCALING = "scaling"
    RESTORATION = "restoration"
    RETIREMENT = "retirement"
    BEHAVIOR = "behavior"
    SCOPE = "scope"
    ENTITLEMENT = "entitlement"
    SAFETY = "safety"
    DATA = "data"
    SCHEMA = "schema"
    ARCHITECTURE = "architecture"
    UX = "ux"
    POLICY = "policy"


_MATERIAL_DIMENSIONS = frozenset(
    {
        ChangeDimension.BEHAVIOR,
        ChangeDimension.SCOPE,
        ChangeDimension.ENTITLEMENT,
        ChangeDimension.SAFETY,
        ChangeDimension.DATA,
        ChangeDimension.SCHEMA,
        ChangeDimension.ARCHITECTURE,
        ChangeDimension.UX,
        ChangeDimension.POLICY,
    }
)


@dataclass(frozen=True, slots=True)
class OperationalCapability:
    capability_id: str
    name: str
    service_id: str
    scope: str
    preclassified: bool
    narrow: bool
    reversible: bool
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "capability_id": self.capability_id,
                "name": self.name,
                "narrow": self.narrow,
                "preclassified": self.preclassified,
                "reversible": self.reversible,
                "scope": self.scope,
                "service_id": self.service_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class OperationalCapabilityAuthority:
    def __init__(self, *, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._issued: dict[str, OperationalCapability] = {}

    def issue(
        self, *, name: str, service_id: str, scope: str
    ) -> OperationalCapability:
        unsigned = OperationalCapability(
            str(uuid4()), name, service_id, scope, True, True, True, b""
        )
        capability = OperationalCapability(
            unsigned.capability_id,
            unsigned.name,
            unsigned.service_id,
            unsigned.scope,
            unsigned.preclassified,
            unsigned.narrow,
            unsigned.reversible,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._issued[capability.capability_id] = capability
        return capability

    def verify(self, capability: OperationalCapability) -> bool:
        if self._issued.get(capability.capability_id) != capability:
            return False
        try:
            self._public_key.verify(capability.signature, capability.signed_bytes)
        except InvalidSignature:
            return False
        return capability.preclassified and capability.narrow and capability.reversible


@dataclass(frozen=True, slots=True)
class OperationalRequest:
    request_id: str
    name: str
    service_id: str
    scope: str
    reversible: bool
    change_dimensions: tuple[ChangeDimension, ...]
    capability: OperationalCapability | None


@dataclass(frozen=True, slots=True)
class OperationalAuthorizationReceipt:
    request_id: str
    route: str
    flow2_after_authorization: bool
    effect_executed: bool
    capability_id: str | None


class OperationalBoundary:
    def __init__(self, *, capability_authority: OperationalCapabilityAuthority) -> None:
        self._capability_authority = capability_authority

    def authorize(self, request: OperationalRequest) -> OperationalAuthorizationReceipt:
        if any(item in _MATERIAL_DIMENSIONS for item in request.change_dimensions):
            return OperationalAuthorizationReceipt(request.request_id, "flow1", True, False, None)
        if ChangeDimension.RETIREMENT in request.change_dimensions:
            raise PermissionError("OWNER_RETIREMENT_APPROVAL_REQUIRED")
        capability = request.capability
        if (
            capability is None
            or not self._capability_authority.verify(capability)
            or capability.name != request.name
            or capability.service_id != request.service_id
            or capability.scope != request.scope
            or not request.reversible
        ):
            raise PermissionError("SIGNED_EXACT_OPERATIONAL_CAPABILITY_REQUIRED")
        return OperationalAuthorizationReceipt(
            request.request_id, "flow4", False, False, capability.capability_id
        )

    def reconcile_as_authorization(
        self, request: OperationalRequest, *, evidence_ref: str
    ) -> OperationalAuthorizationReceipt:
        del request, evidence_ref
        raise PermissionError("RECONCILIATION_CANNOT_AUTHORIZE")


@dataclass(frozen=True, slots=True)
class BackupReceipt:
    backup_id: str
    service_id: str
    encrypted: bool
    provenance_ref: str
    sensitivity_tier: str
    access_review_ref: str
    job_succeeded: bool
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "access_review_ref": self.access_review_ref,
                "backup_id": self.backup_id,
                "encrypted": self.encrypted,
                "job_succeeded": self.job_succeeded,
                "provenance_ref": self.provenance_ref,
                "sensitivity_tier": self.sensitivity_tier,
                "service_id": self.service_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class BackupAuthority:
    def __init__(self, *, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._issued: dict[str, BackupReceipt] = {}

    def issue(
        self,
        *,
        backup_id: str,
        service_id: str,
        encrypted: bool,
        provenance_ref: str,
        sensitivity_tier: str,
        access_review_ref: str,
        job_succeeded: bool,
    ) -> BackupReceipt:
        unsigned = BackupReceipt(
            backup_id,
            service_id,
            encrypted,
            provenance_ref,
            sensitivity_tier,
            access_review_ref,
            job_succeeded,
            b"",
        )
        receipt = BackupReceipt(
            unsigned.backup_id,
            unsigned.service_id,
            unsigned.encrypted,
            unsigned.provenance_ref,
            unsigned.sensitivity_tier,
            unsigned.access_review_ref,
            unsigned.job_succeeded,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._issued[receipt.backup_id] = receipt
        return receipt

    def verify(self, receipt: BackupReceipt) -> bool:
        if self._issued.get(receipt.backup_id) != receipt:
            return False
        try:
            self._public_key.verify(receipt.signature, receipt.signed_bytes)
        except InvalidSignature:
            return False
        return all(
            (
                receipt.encrypted,
                receipt.provenance_ref,
                receipt.sensitivity_tier,
                receipt.access_review_ref,
            )
        )


@dataclass(frozen=True, slots=True)
class RestorationDrillProof:
    drill_id: str
    backup_id: str
    verifier_subject_id: str
    rto_met: bool
    rpo_met: bool
    integrity_verified: bool
    key_access_verified: bool
    service_usable: bool
    evidence_ref: str
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "backup_id": self.backup_id,
                "drill_id": self.drill_id,
                "evidence_ref": self.evidence_ref,
                "integrity_verified": self.integrity_verified,
                "key_access_verified": self.key_access_verified,
                "rpo_met": self.rpo_met,
                "rto_met": self.rto_met,
                "service_usable": self.service_usable,
                "verifier_subject_id": self.verifier_subject_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class RestorationDrillAuthority:
    def __init__(
        self, *, private_key: Ed25519PrivateKey, backup_actor: str
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._backup_actor = backup_actor
        self._issued: dict[str, RestorationDrillProof] = {}

    def issue(
        self,
        *,
        drill_id: str,
        backup_id: str,
        verifier_subject_id: str,
        rto_met: bool,
        rpo_met: bool,
        integrity_verified: bool,
        key_access_verified: bool,
        service_usable: bool,
        evidence_ref: str,
    ) -> RestorationDrillProof:
        if verifier_subject_id == self._backup_actor:
            raise PermissionError("INDEPENDENT_RESTORATION_DRILL_REQUIRED")
        unsigned = RestorationDrillProof(
            drill_id,
            backup_id,
            verifier_subject_id,
            rto_met,
            rpo_met,
            integrity_verified,
            key_access_verified,
            service_usable,
            evidence_ref,
            b"",
        )
        proof = RestorationDrillProof(
            unsigned.drill_id,
            unsigned.backup_id,
            unsigned.verifier_subject_id,
            unsigned.rto_met,
            unsigned.rpo_met,
            unsigned.integrity_verified,
            unsigned.key_access_verified,
            unsigned.service_usable,
            unsigned.evidence_ref,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._issued[proof.drill_id] = proof
        return proof

    def verify(self, proof: RestorationDrillProof, *, backup_id: str) -> bool:
        if self._issued.get(proof.drill_id) != proof or proof.backup_id != backup_id:
            return False
        try:
            self._public_key.verify(proof.signature, proof.signed_bytes)
        except InvalidSignature:
            return False
        return proof.verifier_subject_id != self._backup_actor and all(
            (
                proof.rto_met,
                proof.rpo_met,
                proof.integrity_verified,
                proof.key_access_verified,
                proof.service_usable,
                proof.evidence_ref,
            )
        )


@dataclass(frozen=True, slots=True)
class RestorationAssessment:
    backup_id: str
    recoverable: bool


def evaluate_restoration(
    backup: BackupReceipt,
    *,
    backup_authority: BackupAuthority,
    drill: RestorationDrillProof | None,
    drill_authority: RestorationDrillAuthority | None = None,
) -> RestorationAssessment:
    if not backup_authority.verify(backup):
        raise PermissionError("AUTHENTIC_COMPLIANT_BACKUP_REQUIRED")
    if (
        drill is None
        or drill_authority is None
        or not drill_authority.verify(drill, backup_id=backup.backup_id)
    ):
        raise PermissionError("INDEPENDENT_RESTORATION_DRILL_REQUIRED")
    return RestorationAssessment(backup.backup_id, True)


class LegalHoldState(StrEnum):
    CLEAR = "clear"
    BLOCKED = "blocked"


class RevocationState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class RetirementSpec:
    service_id: str
    environment_ids: tuple[str, ...]
    plan_version: str
    resource_ids: tuple[str, ...]
    consumer_inventory_hash: str
    obligation_inventory_hash: str
    data_disposition_plan_hash: str
    credential_revocation_plan_hash: str
    dependency_removal_plan_hash: str
    legal_hold_state: LegalHoldState
    approved_from: int
    approved_until: int
    rollback_or_recovery_contract_id: str
    policy_version: str
    owner_decision_id: str
    authority_epoch: int
    revocation_state: RevocationState

    @property
    def canonical_bytes(self) -> bytes:
        return json.dumps(
            {
                "approved_from": self.approved_from,
                "approved_until": self.approved_until,
                "authority_epoch": self.authority_epoch,
                "consumer_inventory_hash": self.consumer_inventory_hash,
                "credential_revocation_plan_hash": self.credential_revocation_plan_hash,
                "data_disposition_plan_hash": self.data_disposition_plan_hash,
                "dependency_removal_plan_hash": self.dependency_removal_plan_hash,
                "environment_ids": self.environment_ids,
                "legal_hold_state": self.legal_hold_state.value,
                "obligation_inventory_hash": self.obligation_inventory_hash,
                "owner_decision_id": self.owner_decision_id,
                "plan_version": self.plan_version,
                "policy_version": self.policy_version,
                "resource_ids": self.resource_ids,
                "revocation_state": self.revocation_state.value,
                "rollback_or_recovery_contract_id": self.rollback_or_recovery_contract_id,
                "service_id": self.service_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class RetirementApproval:
    approval_id: str
    spec_digest: str
    owner_subject_id: str
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "approval_id": self.approval_id,
                "owner_subject_id": self.owner_subject_id,
                "spec_digest": self.spec_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class RetirementApprovalAuthority:
    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        owner_by_service: dict[str, str],
        current_authority_epoch: int,
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._owner_by_service = dict(owner_by_service)
        self._current_authority_epoch = current_authority_epoch
        self._issued: dict[str, RetirementApproval] = {}
        self._consumed: set[str] = set()

    def issue(self, spec: RetirementSpec, *, owner_subject_id: str) -> RetirementApproval:
        if self._owner_by_service.get(spec.service_id) != owner_subject_id:
            raise PermissionError("RETIREMENT_OWNER_REQUIRED")
        unsigned = RetirementApproval(str(uuid4()), spec.digest, owner_subject_id, b"")
        approval = RetirementApproval(
            unsigned.approval_id,
            unsigned.spec_digest,
            unsigned.owner_subject_id,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._issued[approval.approval_id] = approval
        return approval

    def consume(
        self, approval: RetirementApproval, *, spec: RetirementSpec, control_time: int
    ) -> None:
        if self._issued.get(approval.approval_id) != approval:
            raise PermissionError("AUTHENTIC_RETIREMENT_APPROVAL_REQUIRED")
        try:
            self._public_key.verify(approval.signature, approval.signed_bytes)
        except InvalidSignature as exc:
            raise PermissionError("AUTHENTIC_RETIREMENT_APPROVAL_REQUIRED") from exc
        if approval.approval_id in self._consumed:
            raise PermissionError("RETIREMENT_APPROVAL_ALREADY_USED")
        if approval.spec_digest != spec.digest:
            raise PermissionError("RETIREMENT_APPROVAL_BINDING_MISMATCH")
        if (
            spec.authority_epoch != self._current_authority_epoch
            or not spec.approved_from <= control_time < spec.approved_until
            or spec.revocation_state is not RevocationState.ACTIVE
        ):
            raise PermissionError("RETIREMENT_APPROVAL_NOT_CURRENT")
        self._consumed.add(approval.approval_id)


@dataclass(frozen=True, slots=True)
class RetirementEvidence:
    evidence_id: str
    service_id: str
    spec_digest: str
    stop_use: bool
    consumers_migrated: bool
    consumers_notified: bool
    data_exported_or_disposed: bool
    dependencies_removed: bool
    credentials_revoked: bool
    access_revoked: bool
    traffic_drained: bool
    exact_resources_decommissioned: bool
    independent_absence_verified: bool
    unresolved_items: tuple[str, ...]
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "access_revoked": self.access_revoked,
                "consumers_migrated": self.consumers_migrated,
                "consumers_notified": self.consumers_notified,
                "credentials_revoked": self.credentials_revoked,
                "data_exported_or_disposed": self.data_exported_or_disposed,
                "dependencies_removed": self.dependencies_removed,
                "evidence_id": self.evidence_id,
                "exact_resources_decommissioned": self.exact_resources_decommissioned,
                "independent_absence_verified": self.independent_absence_verified,
                "service_id": self.service_id,
                "spec_digest": self.spec_digest,
                "stop_use": self.stop_use,
                "traffic_drained": self.traffic_drained,
                "unresolved_items": self.unresolved_items,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class RetirementEvidenceAuthority:
    def __init__(self, *, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._issued: dict[str, RetirementEvidence] = {}

    def issue(
        self,
        *,
        service_id: str,
        spec_digest: str,
        stop_use: bool,
        consumers_migrated: bool,
        consumers_notified: bool,
        data_exported_or_disposed: bool,
        dependencies_removed: bool,
        credentials_revoked: bool,
        access_revoked: bool,
        traffic_drained: bool,
        exact_resources_decommissioned: bool,
        independent_absence_verified: bool,
        unresolved_items: tuple[str, ...],
    ) -> RetirementEvidence:
        unsigned = RetirementEvidence(
            str(uuid4()),
            service_id,
            spec_digest,
            stop_use,
            consumers_migrated,
            consumers_notified,
            data_exported_or_disposed,
            dependencies_removed,
            credentials_revoked,
            access_revoked,
            traffic_drained,
            exact_resources_decommissioned,
            independent_absence_verified,
            unresolved_items,
            b"",
        )
        evidence = RetirementEvidence(
            unsigned.evidence_id,
            unsigned.service_id,
            unsigned.spec_digest,
            unsigned.stop_use,
            unsigned.consumers_migrated,
            unsigned.consumers_notified,
            unsigned.data_exported_or_disposed,
            unsigned.dependencies_removed,
            unsigned.credentials_revoked,
            unsigned.access_revoked,
            unsigned.traffic_drained,
            unsigned.exact_resources_decommissioned,
            unsigned.independent_absence_verified,
            unsigned.unresolved_items,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._issued[evidence.evidence_id] = evidence
        return evidence

    def verify(self, evidence: RetirementEvidence) -> bool:
        if self._issued.get(evidence.evidence_id) != evidence:
            return False
        try:
            self._public_key.verify(evidence.signature, evidence.signed_bytes)
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True)
class RetirementState:
    service_id: str
    spec_digest: str
    open: bool
    effect_executed: bool
    unresolved_items: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RetainedRecord:
    record_id: str
    key_escrow_reference: str
    recovery_authority_metadata: str
    access_evidence_ref: str

    def __post_init__(self) -> None:
        text = (
            f"{self.key_escrow_reference}\n{self.recovery_authority_metadata}\n"
            f"{self.access_evidence_ref}"
        ).lower()
        prohibited = (
            "raw-key:",
            "private_key",
            "begin private key",
            "api_key=",
            "password=",
            "secret=",
            "super-secret",
        )
        if any(marker in text for marker in prohibited):
            raise ValueError("RAW_SECRET_IN_RETAINED_RECORD")


class RetirementLifecycle:
    def __init__(
        self,
        *,
        approval_authority: RetirementApprovalAuthority,
        evidence_authority: RetirementEvidenceAuthority | None = None,
    ) -> None:
        self._approval_authority = approval_authority
        self._evidence_authority = evidence_authority
        self._states: dict[str, RetirementState] = {}

    def begin(
        self,
        spec: RetirementSpec,
        *,
        approval: RetirementApproval,
        control_time: int,
    ) -> RetirementState:
        if spec.legal_hold_state is LegalHoldState.BLOCKED:
            raise PermissionError("LEGAL_HOLD_VETO")
        self._approval_authority.consume(approval, spec=spec, control_time=control_time)
        state = RetirementState(spec.service_id, spec.digest, True, False)
        self._states[spec.service_id] = state
        return state

    def assess(self, proof: RetirementEvidence) -> RetirementState:
        current = self._states.get(proof.service_id)
        if (
            current is None
            or self._evidence_authority is None
            or not self._evidence_authority.verify(proof)
            or proof.spec_digest != current.spec_digest
        ):
            raise PermissionError("AUTHENTIC_EXACT_RETIREMENT_EVIDENCE_REQUIRED")
        complete = all(
            (
                proof.stop_use,
                proof.consumers_migrated,
                proof.consumers_notified,
                proof.data_exported_or_disposed,
                proof.dependencies_removed,
                proof.credentials_revoked,
                proof.access_revoked,
                proof.traffic_drained,
                proof.exact_resources_decommissioned,
                proof.independent_absence_verified,
            )
        )
        state = replace(
            current,
            open=not complete or bool(proof.unresolved_items),
            unresolved_items=proof.unresolved_items,
        )
        self._states[proof.service_id] = state
        return state

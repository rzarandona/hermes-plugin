from __future__ import annotations

import json
from dataclasses import dataclass, replace
from enum import StrEnum
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class ViolationKind(StrEnum):
    INVARIANT = "invariant"
    OBJECTIVE = "objective"
    USER_IMPACT = "user_impact"
    SECURITY = "security"
    DEPENDENCY = "dependency"


class IncidentRole(StrEnum):
    INCIDENT_COMMANDER = "incident_commander"
    RESPONDER = "responder"
    PM = "pm"
    SECRETARY = "secretary"
    OWNER = "owner"


@dataclass(frozen=True, slots=True)
class SeverityFacts:
    impact: int
    scope: int
    safety: int
    integrity: int
    security: int
    duration: int
    reversibility: int
    uncertain: bool

    @property
    def values(self) -> tuple[int, ...]:
        return (
            self.impact,
            self.scope,
            self.safety,
            self.integrity,
            self.security,
            self.duration,
            self.reversibility,
        )


@dataclass(frozen=True, slots=True)
class SeverityAssessment:
    assessment_id: str
    facts: SeverityFacts
    severity: str
    policy_version: str
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "assessment_id": self.assessment_id,
                "facts": {
                    "duration": self.facts.duration,
                    "impact": self.facts.impact,
                    "integrity": self.facts.integrity,
                    "reversibility": self.facts.reversibility,
                    "safety": self.facts.safety,
                    "scope": self.facts.scope,
                    "security": self.facts.security,
                    "uncertain": self.facts.uncertain,
                },
                "policy_version": self.policy_version,
                "severity": self.severity,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class SeverityPolicyAuthority:
    def __init__(
        self, *, private_key: Ed25519PrivateKey, policy_version: str = "severity-v1"
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._policy_version = policy_version
        self._issued: dict[str, SeverityAssessment] = {}

    def assess(self, facts: SeverityFacts) -> SeverityAssessment:
        if any(value < 0 or value > 3 for value in facts.values):
            raise ValueError("SEVERITY_FACT_OUT_OF_RANGE")
        score = sum(facts.values)
        rank = 1 if score >= 15 else 2 if score >= 9 else 3 if score >= 5 else 4
        if facts.uncertain:
            rank = max(1, rank - 1)
        unsigned = SeverityAssessment(
            str(uuid4()), facts, f"sev{rank}", self._policy_version, b""
        )
        receipt = SeverityAssessment(
            unsigned.assessment_id,
            unsigned.facts,
            unsigned.severity,
            unsigned.policy_version,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._issued[receipt.assessment_id] = receipt
        return receipt

    def verify(self, assessment: SeverityAssessment) -> bool:
        if self._issued.get(assessment.assessment_id) != assessment:
            return False
        try:
            self._public_key.verify(assessment.signature, assessment.signed_bytes)
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True)
class ViolationReceipt:
    violation_id: str
    dedupe_key: str
    service_id: str
    kind: ViolationKind
    evidence_ref: str
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "dedupe_key": self.dedupe_key,
                "evidence_ref": self.evidence_ref,
                "kind": self.kind.value,
                "service_id": self.service_id,
                "violation_id": self.violation_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class ViolationAuthority:
    def __init__(self, *, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._issued: dict[str, ViolationReceipt] = {}

    def issue(
        self,
        *,
        dedupe_key: str,
        service_id: str,
        kind: ViolationKind,
        evidence_ref: str,
    ) -> ViolationReceipt:
        unsigned = ViolationReceipt(
            str(uuid4()), dedupe_key, service_id, kind, evidence_ref, b""
        )
        receipt = ViolationReceipt(
            unsigned.violation_id,
            unsigned.dedupe_key,
            unsigned.service_id,
            unsigned.kind,
            unsigned.evidence_ref,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._issued[receipt.violation_id] = receipt
        return receipt

    def verify(self, violation: ViolationReceipt) -> bool:
        if self._issued.get(violation.violation_id) != violation:
            return False
        try:
            self._public_key.verify(violation.signature, violation.signed_bytes)
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True)
class IncidentRoles:
    incident_commander: str
    responders: tuple[str, ...]
    pm: str
    secretary: str


@dataclass(frozen=True, slots=True)
class IncidentCommand:
    command_id: str
    name: str
    scope: str
    actor_subject_id: str
    actor_role: IncidentRole
    owner_reserved: bool = False
    owner_subscribed: bool = False
    critical_attention: bool = False


@dataclass(frozen=True, slots=True)
class IncidentCommandReceipt:
    incident_id: str
    command_id: str
    recorded: bool
    effect_executed: bool


@dataclass(frozen=True, slots=True)
class ClosureProof:
    incident_id: str
    verifier_subject_id: str
    restoration_evidence_ref: str
    objective_readback_ref: str
    integrity_evidence_ref: str
    residual_risk_owner: str
    follow_up_ref: str
    explicit_close: bool
    signature: bytes = b""

    @property
    def signed_bytes(self) -> bytes:
        return json.dumps(
            {
                "explicit_close": self.explicit_close,
                "follow_up_ref": self.follow_up_ref,
                "incident_id": self.incident_id,
                "integrity_evidence_ref": self.integrity_evidence_ref,
                "objective_readback_ref": self.objective_readback_ref,
                "residual_risk_owner": self.residual_risk_owner,
                "restoration_evidence_ref": self.restoration_evidence_ref,
                "verifier_subject_id": self.verifier_subject_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


class ClosureAuthority:
    def __init__(self, *, private_key: Ed25519PrivateKey, forbidden_actor: str) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._forbidden_actor = forbidden_actor
        self._issued: dict[str, ClosureProof] = {}

    def issue(self, proof: ClosureProof) -> ClosureProof:
        if proof.verifier_subject_id == self._forbidden_actor:
            raise PermissionError("INDEPENDENT_RESTORATION_VERIFIER_REQUIRED")
        complete = all(
            (
                proof.incident_id,
                proof.verifier_subject_id,
                proof.restoration_evidence_ref,
                proof.objective_readback_ref,
                proof.integrity_evidence_ref,
                proof.residual_risk_owner,
                proof.follow_up_ref,
                proof.explicit_close,
            )
        )
        if not complete:
            raise PermissionError("COMPLETE_INCIDENT_CLOSURE_PROOF_REQUIRED")
        issued = replace(proof, signature=self._private_key.sign(proof.signed_bytes))
        self._issued[issued.incident_id] = issued
        return issued

    def verify(self, proof: ClosureProof) -> bool:
        if self._issued.get(proof.incident_id) != proof:
            return False
        try:
            self._public_key.verify(proof.signature, proof.signed_bytes)
        except InvalidSignature:
            return False
        return proof.verifier_subject_id != self._forbidden_actor


@dataclass(frozen=True, slots=True)
class ProblemRecord:
    problem_id: str
    service_id: str
    incident_ids: tuple[str, ...]
    reason: str
    product_change_route: str


@dataclass(frozen=True, slots=True)
class OperationalIncident:
    incident_id: str
    service_id: str
    dedupe_key: str
    violation_id: str
    severity: str
    roles: IncidentRoles
    open: bool = True


class IncidentStore:
    def __init__(
        self,
        *,
        severity_authority: SeverityPolicyAuthority,
        violation_authority: ViolationAuthority,
        closure_authority: ClosureAuthority | None = None,
    ) -> None:
        self._severity_authority = severity_authority
        self._violation_authority = violation_authority
        self._closure_authority = closure_authority
        self._incidents: dict[str, OperationalIncident] = {}
        self._problem_records: list[ProblemRecord] = []
        self._incident_ids_by_service: dict[str, list[str]] = {}

    @property
    def problem_records(self) -> tuple[ProblemRecord, ...]:
        return tuple(self._problem_records)

    def open(
        self,
        violation: ViolationReceipt,
        *,
        assessment: SeverityAssessment,
        roles: IncidentRoles,
    ) -> OperationalIncident:
        if not self._violation_authority.verify(violation):
            raise PermissionError("VERIFIED_VIOLATION_REQUIRED")
        if not self._severity_authority.verify(assessment):
            raise PermissionError("SIGNED_SEVERITY_ASSESSMENT_REQUIRED")
        if not all((roles.incident_commander, roles.responders, roles.pm, roles.secretary)):
            raise PermissionError("NAMED_INCIDENT_ROLES_REQUIRED")
        existing = self._incidents.get(violation.dedupe_key)
        if existing is not None:
            return existing
        incident = OperationalIncident(
            str(uuid4()),
            violation.service_id,
            violation.dedupe_key,
            violation.violation_id,
            assessment.severity,
            roles,
        )
        self._incidents[violation.dedupe_key] = incident
        history = self._incident_ids_by_service.setdefault(incident.service_id, [])
        history.append(incident.incident_id)
        if incident.severity == "sev1":
            self._problem_records.append(
                ProblemRecord(
                    str(uuid4()),
                    incident.service_id,
                    (incident.incident_id,),
                    "severe_incident",
                    "flow1_then_flow2_after_authorization",
                )
            )
        elif len(history) == 2:
            self._problem_records.append(
                ProblemRecord(
                    str(uuid4()),
                    incident.service_id,
                    tuple(history),
                    "repeated_incident",
                    "flow1_then_flow2_after_authorization",
                )
            )
        return incident

    def record_command(
        self, incident_id: str, command: IncidentCommand
    ) -> IncidentCommandReceipt:
        incident = next(
            (item for item in self._incidents.values() if item.incident_id == incident_id), None
        )
        if incident is None or not incident.open:
            raise PermissionError("OPEN_INCIDENT_REQUIRED")
        if not command.name or not command.scope:
            raise PermissionError("NAMED_SCOPED_COMMAND_REQUIRED")
        role_matches = {
            IncidentRole.INCIDENT_COMMANDER: command.actor_subject_id
            == incident.roles.incident_commander,
            IncidentRole.RESPONDER: command.actor_subject_id in incident.roles.responders,
            IncidentRole.PM: command.actor_subject_id == incident.roles.pm,
            IncidentRole.SECRETARY: command.actor_subject_id == incident.roles.secretary,
            IncidentRole.OWNER: command.owner_reserved
            or command.owner_subscribed
            or command.critical_attention,
        }
        if not role_matches[command.actor_role]:
            raise PermissionError("INCIDENT_COMMAND_SCOPE_DENIED")
        return IncidentCommandReceipt(incident_id, command.command_id, True, False)

    def close(self, incident_id: str, proof: ClosureProof) -> OperationalIncident:
        incident = next(
            (item for item in self._incidents.values() if item.incident_id == incident_id), None
        )
        if incident is None or self._closure_authority is None:
            raise PermissionError("OPEN_INCIDENT_AND_CLOSURE_AUTHORITY_REQUIRED")
        if proof.incident_id != incident_id or not self._closure_authority.verify(proof):
            raise PermissionError("AUTHENTIC_COMPLETE_CLOSURE_PROOF_REQUIRED")
        closed = replace(incident, open=False)
        self._incidents[incident.dedupe_key] = closed
        return closed

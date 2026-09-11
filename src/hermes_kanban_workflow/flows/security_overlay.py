from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from hashlib import sha256
from threading import Lock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_ALLOWED_ORIGIN_FLOWS = frozenset({"flow1", "flow2", "flow3", "flow4"})
_LEAST_DISCLOSURE_ROUTE = ("security-authority", "incident-lead", "evidence-custodian")


def _bound_digest(*values: str) -> str:
    return sha256(json.dumps(values, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class OriginatingRecord:
    flow_id: str
    record_type: str
    record_id: str
    evidence_digest: str

    def __post_init__(self) -> None:
        if self.flow_id not in _ALLOWED_ORIGIN_FLOWS:
            raise ValueError("SECURITY_OVERLAY_REQUIRES_FLOW1_TO_FLOW4_ORIGIN")
        if not self.record_type or not self.record_id:
            raise ValueError("EXACT_ORIGINATING_RECORD_REQUIRED")
        if len(self.evidence_digest) != 64:
            raise ValueError("PRESERVED_EVIDENCE_DIGEST_REQUIRED")
        try:
            int(self.evidence_digest, 16)
        except ValueError as exc:
            raise ValueError("PRESERVED_EVIDENCE_DIGEST_REQUIRED") from exc

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.flow_id, self.record_type, self.record_id)


@dataclass(frozen=True, slots=True)
class SecurityCase:
    case_id: str
    origin: OriginatingRecord
    preserved_evidence_digest: str
    routing: tuple[str, ...]
    is_overlay: bool
    security_authority_granted: bool


@dataclass(frozen=True, slots=True)
class SecurityContractTerms:
    contract_id: str
    policy_version: str
    authority_epoch: int
    effective_from: datetime
    expires_at: datetime
    security_authority: str
    incident_lead: str
    deputy: str
    evidence_custodian: str
    technical_pm: str
    product_secretary_route: str
    read_commands: tuple[str, ...]
    containment_commands: tuple[str, ...]
    investigation_commands: tuple[str, ...]
    recovery_commands: tuple[str, ...]
    disclosure_commands: tuple[str, ...]
    scopes: tuple[str, ...]
    evidence_access: tuple[tuple[str, tuple[str, ...]], ...]
    communication_approvers: tuple[str, ...]
    independent_closure_verifier: str
    residual_risk_owner: str
    handback_recipient: str
    handback_acceptance_required: bool

    @property
    def canonical_bytes(self) -> bytes:
        body = asdict(self)
        body["effective_from"] = self.effective_from.isoformat()
        body["expires_at"] = self.expires_at.isoformat()
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True, slots=True)
class SignedSecurityContract:
    terms: SecurityContractTerms
    signer_key_id: str
    production_authority: bool
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        return self.terms.canonical_bytes + b"\x00" + self.signer_key_id.encode() + b"\x00fixture"


@dataclass(frozen=True, slots=True)
class SecurityCapability:
    capability_id: str
    contract_id: str
    case_id: str
    subject_id: str
    command: str
    scope: str
    evidence_class: str
    expires_at: datetime
    authority_epoch: int
    nonce: str
    production_authority: bool
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        body = {
            "authority_epoch": self.authority_epoch,
            "capability_id": self.capability_id,
            "case_id": self.case_id,
            "command": self.command,
            "contract_id": self.contract_id,
            "evidence_class": self.evidence_class,
            "expires_at": self.expires_at.isoformat(),
            "nonce": self.nonce,
            "production_authority": self.production_authority,
            "scope": self.scope,
            "subject_id": self.subject_id,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True, slots=True)
class SecurityCommandRequest:
    case_id: str
    subject_id: str
    command: str
    scope: str
    evidence_class: str


@dataclass(frozen=True, slots=True)
class SecurityCommandReceipt:
    capability_id: str
    case_id: str
    command: str
    subject_id: str
    effect_executed: bool
    production_authority: bool


@dataclass(frozen=True, slots=True)
class ContainmentPlan:
    plan_id: str
    contract_id: str
    case_id: str
    command: str
    scope: str
    owner_visibility_route: str
    expires_at: datetime
    permanent_remediation_request: str
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        body = {
            "case_id": self.case_id,
            "command": self.command,
            "contract_id": self.contract_id,
            "expires_at": self.expires_at.isoformat(),
            "owner_visibility_route": self.owner_visibility_route,
            "permanent_remediation_request": self.permanent_remediation_request,
            "plan_id": self.plan_id,
            "scope": self.scope,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True, slots=True)
class ContainmentReceipt:
    plan_id: str
    case_id: str
    expires_at: datetime
    owner_visibility_route: str
    permanent_remediation_request: str
    lasting_change_authorized: bool
    effect_executed: bool


@dataclass(frozen=True, slots=True)
class CommunicationApproval:
    approval_id: str
    contract_id: str
    case_id: str
    approver_subject_id: str
    subject_id: str
    command: str
    route: str
    evidence_class: str
    expires_at: datetime
    nonce: str
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        body = {
            "approval_id": self.approval_id,
            "approver_subject_id": self.approver_subject_id,
            "case_id": self.case_id,
            "command": self.command,
            "contract_id": self.contract_id,
            "evidence_class": self.evidence_class,
            "expires_at": self.expires_at.isoformat(),
            "nonce": self.nonce,
            "route": self.route,
            "subject_id": self.subject_id,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class SecurityPolicyAuthority:
    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        policy_version: str,
        authority_epoch: int,
        signer_key_id: str = "fixture-security-policy-key",
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._policy_version = policy_version
        self._authority_epoch = authority_epoch
        self._signer_key_id = signer_key_id
        self._issued: dict[str, SignedSecurityContract] = {}
        self._capabilities: dict[str, SecurityCapability] = {}
        self._nonce_ids: dict[str, str] = {}
        self._used_capabilities: set[str] = set()
        self._containment_plans: dict[str, ContainmentPlan] = {}
        self._communication_approvals: dict[str, CommunicationApproval] = {}
        self._revoked_epochs: set[int] = set()
        self._capability_lock = Lock()

    def sign_contract(
        self, terms: SecurityContractTerms, *, now: datetime
    ) -> SignedSecurityContract:
        if not self._complete(terms) or not terms.effective_from <= now < terms.expires_at:
            raise PermissionError("COMPLETE_ACTIVE_SECURITY_CONTRACT_REQUIRED")
        if (
            terms.policy_version != self._policy_version
            or terms.authority_epoch != self._authority_epoch
        ):
            raise PermissionError("SECURITY_POLICY_BINDING_MISMATCH")
        unsigned = SignedSecurityContract(terms, self._signer_key_id, False, b"")
        contract = SignedSecurityContract(
            terms, self._signer_key_id, False, self._private_key.sign(unsigned.signed_bytes)
        )
        self._issued[terms.contract_id] = contract
        return contract

    def verify_contract(self, contract: SignedSecurityContract, *, now: datetime) -> bool:
        if self._issued.get(contract.terms.contract_id) != contract:
            return False
        terms = contract.terms
        if (
            not self._complete(terms)
            or terms.policy_version != self._policy_version
            or terms.authority_epoch != self._authority_epoch
            or terms.authority_epoch in self._revoked_epochs
            or not terms.effective_from <= now < terms.expires_at
            or contract.signer_key_id != self._signer_key_id
            or contract.production_authority
        ):
            return False
        try:
            self._public_key.verify(contract.signature, contract.signed_bytes)
        except InvalidSignature:
            return False
        return True

    def issue_capability(
        self,
        *,
        contract: SignedSecurityContract,
        case: SecurityCase,
        subject_id: str,
        command: str,
        scope: str,
        evidence_class: str,
        expires_at: datetime,
        nonce: str,
        now: datetime,
    ) -> SecurityCapability:
        if not self.verify_contract(contract, now=now):
            raise PermissionError("VERIFIED_SECURITY_CONTRACT_REQUIRED")
        terms = contract.terms
        security_subjects = {
            terms.security_authority,
            terms.incident_lead,
            terms.deputy,
            terms.evidence_custodian,
        }
        commands = {
            *terms.read_commands,
            *terms.containment_commands,
            *terms.investigation_commands,
            *terms.recovery_commands,
            *terms.disclosure_commands,
        }
        evidence_rules = dict(terms.evidence_access)
        if subject_id not in security_subjects:
            raise PermissionError("SECURITY_SUBJECT_NOT_AUTHORIZED")
        if command not in commands or scope not in terms.scopes:
            raise PermissionError("COMMAND_OR_SCOPE_NOT_ALLOWLISTED")
        if subject_id not in evidence_rules.get(evidence_class, ()):
            raise PermissionError("EVIDENCE_ACCESS_NOT_AUTHORIZED")
        if not nonce or not now < expires_at <= terms.expires_at:
            raise PermissionError("FRESH_BOUNDED_SECURITY_CAPABILITY_REQUIRED")
        capability_id = sha256(
            "\x00".join(
                (
                    terms.contract_id,
                    case.case_id,
                    subject_id,
                    command,
                    scope,
                    evidence_class,
                    expires_at.isoformat(),
                    str(terms.authority_epoch),
                    nonce,
                )
            ).encode()
        ).hexdigest()
        unsigned = SecurityCapability(
            capability_id,
            terms.contract_id,
            case.case_id,
            subject_id,
            command,
            scope,
            evidence_class,
            expires_at,
            terms.authority_epoch,
            nonce,
            False,
            b"",
        )
        capability = SecurityCapability(
            unsigned.capability_id,
            unsigned.contract_id,
            unsigned.case_id,
            unsigned.subject_id,
            unsigned.command,
            unsigned.scope,
            unsigned.evidence_class,
            unsigned.expires_at,
            unsigned.authority_epoch,
            unsigned.nonce,
            unsigned.production_authority,
            self._private_key.sign(unsigned.signed_bytes),
        )
        with self._capability_lock:
            existing_id = self._nonce_ids.get(nonce)
            if existing_id is not None and existing_id != capability_id:
                raise PermissionError("SECURITY_CAPABILITY_NONCE_REUSE")
            self._nonce_ids[nonce] = capability_id
            self._capabilities[capability_id] = capability
        return capability

    def authorize_command(
        self,
        request: SecurityCommandRequest,
        *,
        capability: SecurityCapability,
        now: datetime,
        communication_approval: CommunicationApproval | None = None,
    ) -> SecurityCommandReceipt:
        contract = self._issued.get(capability.contract_id)
        if contract is None:
            raise PermissionError("VERIFIED_SECURITY_CONTRACT_REQUIRED")
        if (
            capability.command in contract.terms.disclosure_commands
            and (
                communication_approval is None
                or not self._verify_communication_approval(
                    communication_approval, request=request, capability=capability, now=now
                )
            )
        ):
            raise PermissionError("COMMUNICATION_APPROVAL_REQUIRED")
        with self._capability_lock:
            if capability.capability_id in self._used_capabilities:
                raise PermissionError("SECURITY_CAPABILITY_ALREADY_USED")
            if self._capabilities.get(capability.capability_id) != capability:
                raise PermissionError("AUTHENTIC_SECURITY_CAPABILITY_REQUIRED")
            exact = (
                capability.case_id == request.case_id
                and capability.subject_id == request.subject_id
                and capability.command == request.command
                and capability.scope == request.scope
                and capability.evidence_class == request.evidence_class
                and capability.authority_epoch == self._authority_epoch
                and capability.authority_epoch not in self._revoked_epochs
                and now < capability.expires_at
                and not capability.production_authority
            )
            if not exact:
                raise PermissionError("SECURITY_CAPABILITY_BINDING_MISMATCH")
            try:
                self._public_key.verify(capability.signature, capability.signed_bytes)
            except InvalidSignature as exc:
                raise PermissionError("AUTHENTIC_SECURITY_CAPABILITY_REQUIRED") from exc
            self._used_capabilities.add(capability.capability_id)
        return SecurityCommandReceipt(
            capability.capability_id,
            request.case_id,
            request.command,
            request.subject_id,
            False,
            False,
        )

    def issue_communication_approval(
        self,
        *,
        contract: SignedSecurityContract,
        case: SecurityCase,
        approver_subject_id: str,
        subject_id: str,
        command: str,
        route: str,
        evidence_class: str,
        expires_at: datetime,
        nonce: str,
        now: datetime,
    ) -> CommunicationApproval:
        if not self.verify_contract(contract, now=now):
            raise PermissionError("VERIFIED_SECURITY_CONTRACT_REQUIRED")
        terms = contract.terms
        if (
            approver_subject_id not in terms.communication_approvers
            or command not in terms.disclosure_commands
            or route != terms.product_secretary_route
            or evidence_class not in dict(terms.evidence_access)
            or not nonce
            or not now < expires_at <= terms.expires_at
        ):
            raise PermissionError("EXACT_COMMUNICATION_APPROVAL_REQUIRED")
        approval_id = _bound_digest(
            terms.contract_id,
            case.case_id,
            approver_subject_id,
            subject_id,
            command,
            route,
            evidence_class,
            expires_at.isoformat(),
            nonce,
        )
        unsigned = CommunicationApproval(
            approval_id,
            terms.contract_id,
            case.case_id,
            approver_subject_id,
            subject_id,
            command,
            route,
            evidence_class,
            expires_at,
            nonce,
            b"",
        )
        approval = CommunicationApproval(
            unsigned.approval_id,
            unsigned.contract_id,
            unsigned.case_id,
            unsigned.approver_subject_id,
            unsigned.subject_id,
            unsigned.command,
            unsigned.route,
            unsigned.evidence_class,
            unsigned.expires_at,
            unsigned.nonce,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._communication_approvals[approval_id] = approval
        return approval

    def _verify_communication_approval(
        self,
        approval: CommunicationApproval,
        *,
        request: SecurityCommandRequest,
        capability: SecurityCapability,
        now: datetime,
    ) -> bool:
        contract = self._issued.get(capability.contract_id)
        if contract is None or self._communication_approvals.get(approval.approval_id) != approval:
            return False
        exact = (
            approval.contract_id == capability.contract_id
            and approval.case_id == request.case_id
            and approval.subject_id == request.subject_id
            and approval.command == request.command
            and approval.evidence_class == request.evidence_class
            and approval.route == contract.terms.product_secretary_route
            and approval.approver_subject_id in contract.terms.communication_approvers
            and now < approval.expires_at <= capability.expires_at
        )
        if not exact:
            return False
        try:
            self._public_key.verify(approval.signature, approval.signed_bytes)
        except InvalidSignature:
            return False
        return True

    def issue_containment_plan(
        self,
        *,
        contract: SignedSecurityContract,
        case: SecurityCase,
        command: str,
        scope: str,
        owner_visibility_route: str,
        expires_at: datetime,
        permanent_remediation_request: str,
        now: datetime,
    ) -> ContainmentPlan:
        if not self.verify_contract(contract, now=now):
            raise PermissionError("VERIFIED_SECURITY_CONTRACT_REQUIRED")
        terms = contract.terms
        if (
            command not in terms.containment_commands
            or scope not in terms.scopes
            or owner_visibility_route != terms.technical_pm
            or not now < expires_at <= terms.expires_at
            or not permanent_remediation_request.startswith("flow1:delivery-request:")
        ):
            raise PermissionError("BOUNDED_VISIBLE_CONTAINMENT_PLAN_REQUIRED")
        plan_id = _bound_digest(
            terms.contract_id,
            case.case_id,
            command,
            scope,
            owner_visibility_route,
            expires_at.isoformat(),
            permanent_remediation_request,
        )
        unsigned = ContainmentPlan(
            plan_id,
            terms.contract_id,
            case.case_id,
            command,
            scope,
            owner_visibility_route,
            expires_at,
            permanent_remediation_request,
            b"",
        )
        plan = ContainmentPlan(
            unsigned.plan_id,
            unsigned.contract_id,
            unsigned.case_id,
            unsigned.command,
            unsigned.scope,
            unsigned.owner_visibility_route,
            unsigned.expires_at,
            unsigned.permanent_remediation_request,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._containment_plans[plan_id] = plan
        return plan

    def authorize_containment(
        self, *, capability: SecurityCapability, plan: ContainmentPlan, now: datetime
    ) -> ContainmentReceipt:
        if self._containment_plans.get(plan.plan_id) != plan:
            raise PermissionError("AUTHENTIC_CONTAINMENT_PLAN_REQUIRED")
        exact = (
            plan.contract_id == capability.contract_id
            and plan.case_id == capability.case_id
            and plan.command == capability.command
            and plan.scope == capability.scope
            and now < plan.expires_at <= capability.expires_at
            and bool(plan.owner_visibility_route)
            and plan.permanent_remediation_request.startswith("flow1:delivery-request:")
        )
        if not exact:
            raise PermissionError("CONTAINMENT_BINDING_MISMATCH")
        try:
            self._public_key.verify(plan.signature, plan.signed_bytes)
        except InvalidSignature as exc:
            raise PermissionError("AUTHENTIC_CONTAINMENT_PLAN_REQUIRED") from exc
        self.authorize_command(
            SecurityCommandRequest(
                plan.case_id,
                capability.subject_id,
                plan.command,
                plan.scope,
                capability.evidence_class,
            ),
            capability=capability,
            now=now,
        )
        return ContainmentReceipt(
            plan.plan_id,
            plan.case_id,
            plan.expires_at,
            plan.owner_visibility_route,
            plan.permanent_remediation_request,
            False,
            False,
        )

    def revoke_epoch(self, epoch: int) -> None:
        self._revoked_epochs.add(epoch)

    @staticmethod
    def _complete(terms: SecurityContractTerms) -> bool:
        scalar_values = (
            terms.contract_id,
            terms.policy_version,
            terms.security_authority,
            terms.incident_lead,
            terms.deputy,
            terms.evidence_custodian,
            terms.technical_pm,
            terms.product_secretary_route,
            terms.independent_closure_verifier,
            terms.residual_risk_owner,
            terms.handback_recipient,
        )
        command_sets = (
            terms.read_commands,
            terms.containment_commands,
            terms.investigation_commands,
            terms.recovery_commands,
            terms.disclosure_commands,
        )
        return (
            all(scalar_values)
            and terms.authority_epoch > 0
            and terms.effective_from < terms.expires_at
            and all(items and all(items) for items in command_sets)
            and bool(terms.scopes)
            and all(terms.scopes)
            and bool(terms.evidence_access)
            and all(label and subjects and all(subjects) for label, subjects in terms.evidence_access)
            and bool(terms.communication_approvers)
            and all(terms.communication_approvers)
            and terms.handback_acceptance_required
        )


@dataclass(frozen=True, slots=True)
class ClosureProof:
    proof_id: str
    case_id: str
    verifier_subject_id: str
    containment_verified: bool
    restoration_verified: bool
    preserved_evidence_digest: str
    residual_risk_owner: str
    lasting_change_request: str
    production_authority: bool
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        body = {
            "case_id": self.case_id,
            "containment_verified": self.containment_verified,
            "lasting_change_request": self.lasting_change_request,
            "preserved_evidence_digest": self.preserved_evidence_digest,
            "production_authority": self.production_authority,
            "proof_id": self.proof_id,
            "residual_risk_owner": self.residual_risk_owner,
            "restoration_verified": self.restoration_verified,
            "verifier_subject_id": self.verifier_subject_id,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class IndependentClosureAuthority:
    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        verifier_subject_id: str,
        verify_containment: Callable[[SecurityCase, str], bool] | None = None,
        verify_restoration: Callable[[SecurityCase, str], bool] | None = None,
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self.verifier_subject_id = verifier_subject_id
        self._proofs: dict[str, ClosureProof] = {}
        self._verify_containment = verify_containment
        self._verify_restoration = verify_restoration

    def verify_closure(
        self,
        *,
        case: SecurityCase,
        containment_verified: bool,
        restoration_verified: bool,
        preserved_evidence_digest: str,
        residual_risk_owner: str,
        lasting_change_request: str,
        containment_evidence_ref: str = "",
        restoration_evidence_ref: str = "",
    ) -> ClosureProof:
        if (
            self._verify_containment is None
            or self._verify_restoration is None
            or not containment_evidence_ref
            or not restoration_evidence_ref
        ):
            raise PermissionError("INDEPENDENT_CLOSURE_EVIDENCE_REQUIRED")
        containment_verified = containment_verified and self._verify_containment(
            case, containment_evidence_ref
        )
        restoration_verified = restoration_verified and self._verify_restoration(
            case, restoration_evidence_ref
        )
        proof_id = _bound_digest(
            case.case_id,
            self.verifier_subject_id,
            containment_evidence_ref,
            restoration_evidence_ref,
            preserved_evidence_digest,
            residual_risk_owner,
            lasting_change_request,
        )
        unsigned = ClosureProof(
            proof_id,
            case.case_id,
            self.verifier_subject_id,
            containment_verified,
            restoration_verified,
            preserved_evidence_digest,
            residual_risk_owner,
            lasting_change_request,
            False,
            b"",
        )
        proof = ClosureProof(
            unsigned.proof_id,
            unsigned.case_id,
            unsigned.verifier_subject_id,
            unsigned.containment_verified,
            unsigned.restoration_verified,
            unsigned.preserved_evidence_digest,
            unsigned.residual_risk_owner,
            unsigned.lasting_change_request,
            unsigned.production_authority,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._proofs[proof_id] = proof
        return proof

    def verify(self, proof: ClosureProof) -> bool:
        if self._proofs.get(proof.proof_id) != proof or proof.production_authority:
            return False
        try:
            self._public_key.verify(proof.signature, proof.signed_bytes)
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True)
class HandbackStatement:
    case_id: str
    operational_state: str
    restrictions: tuple[str, ...]
    monitoring: tuple[str, ...]
    open_problems: tuple[str, ...]
    follow_up: tuple[str, ...]
    authority_resuming: str

    @property
    def digest(self) -> str:
        body = asdict(self)
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        return sha256(canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class HandbackAcceptance:
    acceptance_id: str
    handback_digest: str
    recipient_id: str
    accepted_at: datetime
    signature: bytes

    @property
    def signed_bytes(self) -> bytes:
        body = {
            "acceptance_id": self.acceptance_id,
            "accepted_at": self.accepted_at.isoformat(),
            "handback_digest": self.handback_digest,
            "recipient_id": self.recipient_id,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class HandbackAcceptanceAuthority:
    def __init__(
        self, *, private_key: Ed25519PrivateKey, registered_recipient: str
    ) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self.registered_recipient = registered_recipient
        self._acceptances: dict[str, HandbackAcceptance] = {}

    def accept(
        self, handback: HandbackStatement, *, recipient_id: str, now: datetime
    ) -> HandbackAcceptance:
        if recipient_id != self.registered_recipient:
            raise PermissionError("REGISTERED_HANDBACK_RECIPIENT_REQUIRED")
        acceptance_id = sha256(
            f"{handback.digest}\x00{recipient_id}\x00{now.isoformat()}".encode()
        ).hexdigest()
        unsigned = HandbackAcceptance(acceptance_id, handback.digest, recipient_id, now, b"")
        acceptance = HandbackAcceptance(
            unsigned.acceptance_id,
            unsigned.handback_digest,
            unsigned.recipient_id,
            unsigned.accepted_at,
            self._private_key.sign(unsigned.signed_bytes),
        )
        self._acceptances[acceptance_id] = acceptance
        return acceptance

    def verify(self, acceptance: HandbackAcceptance, handback: HandbackStatement) -> bool:
        if (
            self._acceptances.get(acceptance.acceptance_id) != acceptance
            or acceptance.handback_digest != handback.digest
            or acceptance.recipient_id != self.registered_recipient
        ):
            return False
        try:
            self._public_key.verify(acceptance.signature, acceptance.signed_bytes)
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True)
class ClosedSecurityCase:
    case_id: str
    proof_id: str
    handback: HandbackStatement
    acceptance_id: str
    closed_explicitly: bool


class SecurityCaseStore:
    def __init__(self, *, before_create: Callable[[], None] | None = None) -> None:
        self._lock = Lock()
        self._cases: dict[tuple[str, str, str], SecurityCase] = {}
        self._closed: dict[str, ClosedSecurityCase] = {}
        self._before_create = before_create

    @property
    def case_count(self) -> int:
        with self._lock:
            return len(self._cases)

    def open_case(self, origin: OriginatingRecord) -> SecurityCase:
        if self._before_create is not None:
            self._before_create()
        with self._lock:
            existing = self._cases.get(origin.identity)
            if existing is not None:
                if existing.origin != origin:
                    raise PermissionError("ORIGINATING_RECORD_BINDING_MISMATCH")
                return existing
            case_id = sha256("\x00".join((*origin.identity, origin.evidence_digest)).encode()).hexdigest()
            case = SecurityCase(
                case_id=case_id,
                origin=origin,
                preserved_evidence_digest=origin.evidence_digest,
                routing=_LEAST_DISCLOSURE_ROUTE,
                is_overlay=True,
                security_authority_granted=False,
            )
            self._cases[origin.identity] = case
            return case

    def close_case(
        self,
        *,
        case: SecurityCase,
        contract: SignedSecurityContract,
        policy_authority: SecurityPolicyAuthority,
        closure_proof: ClosureProof,
        closure_authority: IndependentClosureAuthority,
        handback: HandbackStatement,
        acceptance: HandbackAcceptance | None,
        acceptance_authority: HandbackAcceptanceAuthority,
        now: datetime,
    ) -> ClosedSecurityCase:
        terms = contract.terms
        known_case = self._cases.get(case.origin.identity)
        complete_handback = (
            handback.case_id == case.case_id
            and bool(handback.operational_state)
            and bool(handback.restrictions)
            and all(handback.restrictions)
            and bool(handback.monitoring)
            and all(handback.monitoring)
            and bool(handback.open_problems)
            and all(handback.open_problems)
            and bool(handback.follow_up)
            and all(handback.follow_up)
            and handback.authority_resuming == terms.handback_recipient
        )
        exact_proof = (
            closure_proof.case_id == case.case_id
            and closure_proof.verifier_subject_id == terms.independent_closure_verifier
            and closure_proof.containment_verified
            and closure_proof.restoration_verified
            and closure_proof.preserved_evidence_digest == case.preserved_evidence_digest
            and closure_proof.residual_risk_owner == terms.residual_risk_owner
            and closure_proof.lasting_change_request.startswith("flow1:delivery-request:")
            and closure_proof.lasting_change_request in handback.follow_up
        )
        if (
            known_case != case
            or not policy_authority.verify_contract(contract, now=now)
            or not closure_authority.verify(closure_proof)
            or not exact_proof
            or not complete_handback
            or acceptance is None
            or acceptance_authority.registered_recipient != terms.handback_recipient
            or not acceptance_authority.verify(acceptance, handback)
        ):
            raise PermissionError("VERIFIED_EXPLICIT_SECURITY_CLOSE_REQUIRED")
        closed = ClosedSecurityCase(
            case.case_id,
            closure_proof.proof_id,
            handback,
            acceptance.acceptance_id,
            True,
        )
        with self._lock:
            existing = self._closed.get(case.case_id)
            if existing is not None:
                if existing != closed:
                    raise PermissionError("SECURITY_CASE_ALREADY_CLOSED_WITH_DIFFERENT_HAND_BACK")
                return existing
            self._closed[case.case_id] = closed
        return closed

    def is_closed(self, case_id: str) -> bool:
        with self._lock:
            return case_id in self._closed

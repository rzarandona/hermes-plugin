from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.flows.security_overlay import (
    CommunicationApproval,
    HandbackAcceptance,
    HandbackAcceptanceAuthority,
    HandbackStatement,
    IndependentClosureAuthority,
    OriginatingRecord,
    SecurityCapability,
    SecurityCaseStore,
    SecurityCommandRequest,
    SecurityContractTerms,
    SecurityPolicyAuthority,
    SignedSecurityContract,
)

NOW = datetime(2026, 8, 29, 12, tzinfo=UTC)


def complete_terms() -> SecurityContractTerms:
    return SecurityContractTerms(
        contract_id="security-contract-1",
        policy_version="security-policy-v7",
        authority_epoch=7,
        effective_from=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=2),
        security_authority="security-authority-1",
        incident_lead="incident-lead-1",
        deputy="deputy-1",
        evidence_custodian="custodian-1",
        technical_pm="technical-pm-1",
        product_secretary_route="product-secretary:security",
        read_commands=("read_case",),
        containment_commands=("isolate_workload",),
        investigation_commands=("inspect_audit_log",),
        recovery_commands=("restore_workload",),
        disclosure_commands=("notify_owner",),
        scopes=("service:checkout",),
        evidence_access=(
            ("restricted", ("security-authority-1", "incident-lead-1", "custodian-1")),
        ),
        communication_approvers=("security-authority-1",),
        independent_closure_verifier="closure-verifier-1",
        residual_risk_owner="risk-owner-1",
        handback_recipient="ops-owner-1",
        handback_acceptance_required=True,
    )


def authority() -> SecurityPolicyAuthority:
    return SecurityPolicyAuthority(
        private_key=Ed25519PrivateKey.generate(),
        policy_version="security-policy-v7",
        authority_epoch=7,
    )


def test_disclosure_without_authority_issued_communication_approval_denies() -> None:
    policy = authority()
    contract = policy.sign_contract(complete_terms(), now=NOW)
    case = SecurityCaseStore().open_case(
        OriginatingRecord("flow2", "finding", "security-finding", "f" * 64)
    )
    capability = policy.issue_capability(
        contract=contract,
        case=case,
        subject_id="security-authority-1",
        command="notify_owner",
        scope="service:checkout",
        evidence_class="restricted",
        expires_at=NOW + timedelta(minutes=10),
        nonce="disclosure-without-approval",
        now=NOW,
    )
    request = SecurityCommandRequest(
        case.case_id,
        "security-authority-1",
        "notify_owner",
        "service:checkout",
        "restricted",
    )

    with pytest.raises(PermissionError, match="COMMUNICATION_APPROVAL_REQUIRED"):
        policy.authorize_command(request, capability=capability, now=NOW)


@pytest.mark.parametrize(
    "terms",
    (
        replace(complete_terms(), policy_version="wrong-policy"),
        replace(complete_terms(), authority_epoch=6),
        replace(
            complete_terms(),
            effective_from=NOW - timedelta(hours=2),
            expires_at=NOW,
        ),
    ),
)
def test_wrong_policy_epoch_or_stale_contract_denies(terms: SecurityContractTerms) -> None:
    with pytest.raises(PermissionError):
        authority().sign_contract(terms, now=NOW)


def test_revoked_authority_epoch_invalidates_signed_contract() -> None:
    policy = authority()
    contract = policy.sign_contract(complete_terms(), now=NOW)

    policy.revoke_epoch(7)

    assert policy.verify_contract(contract, now=NOW) is False


def test_revoked_epoch_invalidates_already_issued_capability() -> None:
    policy = authority()
    contract = policy.sign_contract(complete_terms(), now=NOW)
    case = SecurityCaseStore().open_case(OriginatingRecord("flow2", "finding", "revoked", "7" * 64))
    capability = policy.issue_capability(
        contract=contract,
        case=case,
        subject_id="incident-lead-1",
        command="inspect_audit_log",
        scope="service:checkout",
        evidence_class="restricted",
        expires_at=NOW + timedelta(minutes=5),
        nonce="revoked-capability",
        now=NOW,
    )
    policy.revoke_epoch(7)

    with pytest.raises(PermissionError, match="SECURITY_CAPABILITY_BINDING_MISMATCH"):
        policy.authorize_command(
            SecurityCommandRequest(
                case.case_id,
                "incident-lead-1",
                "inspect_audit_log",
                "service:checkout",
                "restricted",
            ),
            capability=capability,
            now=NOW,
        )


def test_unauthorized_evidence_class_denies_before_capability_issue() -> None:
    policy = authority()
    contract = policy.sign_contract(complete_terms(), now=NOW)
    case = SecurityCaseStore().open_case(OriginatingRecord("flow3", "release", "evidence", "8" * 64))

    with pytest.raises(PermissionError, match="EVIDENCE_ACCESS_NOT_AUTHORIZED"):
        policy.issue_capability(
            contract=contract,
            case=case,
            subject_id="incident-lead-1",
            command="inspect_audit_log",
            scope="service:checkout",
            evidence_class="secret",
            expires_at=NOW + timedelta(minutes=5),
            nonce="unauthorized-evidence",
            now=NOW,
        )


@pytest.mark.parametrize(
    ("mutation", "value"),
    (
        ("expires_at", NOW + timedelta(hours=1)),
        ("owner_visibility_route", "hidden-route"),
        ("permanent_remediation_request", "flow4:lasting-change"),
        ("signature", b"forged"),
    ),
)
def test_forged_containment_metadata_never_authorizes_lasting_change(
    mutation: str, value: object
) -> None:
    policy = authority()
    contract = policy.sign_contract(complete_terms(), now=NOW)
    case = SecurityCaseStore().open_case(OriginatingRecord("flow4", "incident", "contain", "a" * 64))
    capability = policy.issue_capability(
        contract=contract,
        case=case,
        subject_id="security-authority-1",
        command="isolate_workload",
        scope="service:checkout",
        evidence_class="restricted",
        expires_at=NOW + timedelta(minutes=20),
        nonce=f"contain-{mutation}",
        now=NOW,
    )
    plan = policy.issue_containment_plan(
        contract=contract,
        case=case,
        command="isolate_workload",
        scope="service:checkout",
        owner_visibility_route="technical-pm-1",
        expires_at=NOW + timedelta(minutes=10),
        permanent_remediation_request="flow1:delivery-request:contain-fix",
        now=NOW,
    )

    with pytest.raises(PermissionError, match="AUTHENTIC_CONTAINMENT_PLAN_REQUIRED"):
        policy.authorize_containment(capability=capability, plan=replace(plan, **{mutation: value}), now=NOW)


@pytest.mark.parametrize(
    ("containment", "restoration", "evidence", "risk_owner", "change_request"),
    (
        (False, True, "b" * 64, "risk-owner-1", "flow1:delivery-request:fix-close"),
        (True, False, "b" * 64, "risk-owner-1", "flow1:delivery-request:fix-close"),
        (True, True, "c" * 64, "risk-owner-1", "flow1:delivery-request:fix-close"),
        (True, True, "b" * 64, "wrong-owner", "flow1:delivery-request:fix-close"),
        (True, True, "b" * 64, "risk-owner-1", "flow4:lasting-change"),
    ),
)
def test_incomplete_or_mismatched_independent_closure_proof_denies(
    containment: bool,
    restoration: bool,
    evidence: str,
    risk_owner: str,
    change_request: str,
) -> None:
    policy = authority()
    contract = policy.sign_contract(complete_terms(), now=NOW)
    store = SecurityCaseStore()
    case = store.open_case(OriginatingRecord("flow2", "finding", "close-deny", "b" * 64))
    verifier = IndependentClosureAuthority(
        private_key=Ed25519PrivateKey.generate(),
        verifier_subject_id="closure-verifier-1",
        verify_containment=lambda exact_case, ref: exact_case == case and ref == "evidence:containment",
        verify_restoration=lambda exact_case, ref: exact_case == case and ref == "evidence:restoration",
    )
    proof = verifier.verify_closure(
        case=case,
        containment_verified=containment,
        restoration_verified=restoration,
        preserved_evidence_digest=evidence,
        residual_risk_owner=risk_owner,
        lasting_change_request=change_request,
        containment_evidence_ref="evidence:containment",
        restoration_evidence_ref="evidence:restoration",
    )
    handback = HandbackStatement(
        case.case_id,
        "restored",
        ("restricted",),
        ("monitor:security",),
        ("problem:open",),
        ("flow1:delivery-request:fix-close",),
        "ops-owner-1",
    )
    acceptance_authority = HandbackAcceptanceAuthority(
        private_key=Ed25519PrivateKey.generate(), registered_recipient="ops-owner-1"
    )
    acceptance = acceptance_authority.accept(handback, recipient_id="ops-owner-1", now=NOW)

    with pytest.raises(PermissionError, match="VERIFIED_EXPLICIT_SECURITY_CLOSE_REQUIRED"):
        store.close_case(
            case=case,
            contract=contract,
            policy_authority=policy,
            closure_proof=proof,
            closure_authority=verifier,
            handback=handback,
            acceptance=acceptance,
            acceptance_authority=acceptance_authority,
            now=NOW,
        )


def test_silence_or_caller_forged_handback_acceptance_never_closes_case() -> None:
    policy = authority()
    contract = policy.sign_contract(complete_terms(), now=NOW)
    store = SecurityCaseStore()
    case = store.open_case(OriginatingRecord("flow4", "incident", "inc-close", "4" * 64))
    closure_authority = IndependentClosureAuthority(
        private_key=Ed25519PrivateKey.generate(),
        verifier_subject_id="closure-verifier-1",
        verify_containment=lambda exact_case, ref: exact_case == case and ref == "evidence:containment",
        verify_restoration=lambda exact_case, ref: exact_case == case and ref == "evidence:restoration",
    )
    proof = closure_authority.verify_closure(
        case=case,
        containment_verified=True,
        restoration_verified=True,
        preserved_evidence_digest=case.preserved_evidence_digest,
        residual_risk_owner="risk-owner-1",
        lasting_change_request="flow1:delivery-request:fix-close",
        containment_evidence_ref="evidence:containment",
        restoration_evidence_ref="evidence:restoration",
    )
    handback = HandbackStatement(
        case.case_id,
        "restored",
        ("restricted",),
        ("monitor:security",),
        ("problem:open",),
        ("flow1:delivery-request:fix-close",),
        "ops-owner-1",
    )
    acceptance_authority = HandbackAcceptanceAuthority(
        private_key=Ed25519PrivateKey.generate(), registered_recipient="ops-owner-1"
    )
    forged = HandbackAcceptance(
        "forged",
        handback.digest,
        "ops-owner-1",
        NOW,
        b"forged",
    )

    for acceptance in (None, forged):
        with pytest.raises(PermissionError, match="VERIFIED_EXPLICIT_SECURITY_CLOSE_REQUIRED"):
            store.close_case(
                case=case,
                contract=contract,
                policy_authority=policy,
                closure_proof=proof,
                closure_authority=closure_authority,
                handback=handback,
                acceptance=acceptance,
                acceptance_authority=acceptance_authority,
                now=NOW,
            )
    assert store.is_closed(case.case_id) is False


def test_caller_asserted_restoration_booleans_are_not_independent_closure_evidence() -> None:
    case = SecurityCaseStore().open_case(
        OriginatingRecord("flow4", "incident", "caller-booleans", "d" * 64)
    )
    verifier = IndependentClosureAuthority(
        private_key=Ed25519PrivateKey.generate(), verifier_subject_id="closure-verifier-1"
    )

    with pytest.raises(PermissionError, match="INDEPENDENT_CLOSURE_EVIDENCE_REQUIRED"):
        verifier.verify_closure(
            case=case,
            containment_verified=True,
            restoration_verified=True,
            preserved_evidence_digest=case.preserved_evidence_digest,
            residual_risk_owner="risk-owner-1",
            lasting_change_request="flow1:delivery-request:fix-booleans",
        )


def test_flow5_origin_is_rejected_because_security_is_only_an_overlay() -> None:
    with pytest.raises(ValueError, match="SECURITY_OVERLAY_REQUIRES_FLOW1_TO_FLOW4_ORIGIN"):
        OriginatingRecord("flow5", "security", "case", "0" * 64)


def test_forged_origin_metadata_cannot_change_preserved_case_binding() -> None:
    store = SecurityCaseStore()
    origin = OriginatingRecord("flow1", "request", "same-record", "5" * 64)
    store.open_case(origin)

    with pytest.raises(PermissionError, match="ORIGINATING_RECORD_BINDING_MISMATCH"):
        store.open_case(replace(origin, evidence_digest="6" * 64))


@pytest.mark.parametrize("ordinary_subject", ("pm-1", "implementer-1", "reviewer-1", "gatekeeper-1", "ops-1"))
def test_ordinary_roles_never_inherit_security_authority(ordinary_subject: str) -> None:
    policy = authority()
    contract = policy.sign_contract(complete_terms(), now=NOW)
    case = SecurityCaseStore().open_case(OriginatingRecord("flow1", "request", "req-1", "1" * 64))

    with pytest.raises(PermissionError, match="SECURITY_SUBJECT_NOT_AUTHORIZED"):
        policy.issue_capability(
            contract=contract,
            case=case,
            subject_id=ordinary_subject,
            command="read_case",
            scope="service:checkout",
            evidence_class="restricted",
            expires_at=NOW + timedelta(minutes=5),
            nonce=f"ordinary-{ordinary_subject}",
            now=NOW,
        )


@pytest.mark.parametrize(
    ("mutation", "value"),
    (
        ("case_id", "broader-case"),
        ("subject_id", "ops-1"),
        ("command", "restore_workload"),
        ("scope", "service:all"),
        ("evidence_class", "secret"),
        ("expires_at", NOW + timedelta(hours=1)),
        ("authority_epoch", 8),
        ("nonce", "replacement-nonce"),
    ),
)
def test_capability_cannot_be_self_expanded_or_replayed_more_broadly(
    mutation: str, value: object
) -> None:
    policy = authority()
    contract = policy.sign_contract(complete_terms(), now=NOW)
    case = SecurityCaseStore().open_case(OriginatingRecord("flow3", "release", "release-1", "2" * 64))
    capability = policy.issue_capability(
        contract=contract,
        case=case,
        subject_id="incident-lead-1",
        command="inspect_audit_log",
        scope="service:checkout",
        evidence_class="restricted",
        expires_at=NOW + timedelta(minutes=5),
        nonce="exact-capability",
        now=NOW,
    )
    forged = replace(capability, **{mutation: value})
    request = SecurityCommandRequest(
        forged.case_id,
        forged.subject_id,
        forged.command,
        forged.scope,
        forged.evidence_class,
    )

    with pytest.raises(PermissionError, match="AUTHENTIC_SECURITY_CAPABILITY_REQUIRED"):
        policy.authorize_command(request, capability=forged, now=NOW)


@pytest.mark.parametrize("invalid_now", (NOW + timedelta(minutes=5), NOW + timedelta(hours=3)))
def test_expired_capability_denies_at_and_after_expiry(invalid_now: datetime) -> None:
    policy = authority()
    contract = policy.sign_contract(complete_terms(), now=NOW)
    case = SecurityCaseStore().open_case(OriginatingRecord("flow4", "incident", "inc-2", "3" * 64))
    capability = policy.issue_capability(
        contract=contract,
        case=case,
        subject_id="incident-lead-1",
        command="inspect_audit_log",
        scope="service:checkout",
        evidence_class="restricted",
        expires_at=NOW + timedelta(minutes=5),
        nonce="expires-exactly",
        now=NOW,
    )
    request = SecurityCommandRequest(
        case.case_id,
        "incident-lead-1",
        "inspect_audit_log",
        "service:checkout",
        "restricted",
    )

    with pytest.raises(PermissionError, match="SECURITY_CAPABILITY_BINDING_MISMATCH"):
        policy.authorize_command(request, capability=capability, now=invalid_now)


def test_caller_constructed_contract_capability_and_approval_are_not_authority() -> None:
    policy = authority()
    terms = complete_terms()
    forged_contract = SignedSecurityContract(terms, "fixture-security-policy-key", False, b"forged")
    forged_capability = SecurityCapability(
        "forged-capability",
        terms.contract_id,
        "forged-case",
        terms.security_authority,
        "notify_owner",
        "service:checkout",
        "restricted",
        NOW + timedelta(minutes=5),
        7,
        "forged-nonce",
        False,
        b"forged",
    )
    forged_approval = CommunicationApproval(
        "forged-approval",
        terms.contract_id,
        "forged-case",
        terms.security_authority,
        terms.security_authority,
        "notify_owner",
        terms.product_secretary_route,
        "restricted",
        NOW + timedelta(minutes=5),
        "forged-approval-nonce",
        b"forged",
    )

    assert policy.verify_contract(forged_contract, now=NOW) is False
    with pytest.raises(PermissionError, match="VERIFIED_SECURITY_CONTRACT_REQUIRED"):
        policy.authorize_command(
            SecurityCommandRequest(
                "forged-case", terms.security_authority, "notify_owner", "service:checkout", "restricted"
            ),
            capability=forged_capability,
            communication_approval=forged_approval,
            now=NOW,
        )


@pytest.mark.parametrize(
    ("field", "missing"),
    (
        ("security_authority", ""),
        ("incident_lead", ""),
        ("deputy", ""),
        ("evidence_custodian", ""),
        ("technical_pm", ""),
        ("product_secretary_route", ""),
        ("read_commands", ()),
        ("containment_commands", ()),
        ("investigation_commands", ()),
        ("recovery_commands", ()),
        ("disclosure_commands", ()),
        ("scopes", ()),
        ("evidence_access", ()),
        ("communication_approvers", ()),
        ("independent_closure_verifier", ""),
        ("residual_risk_owner", ""),
        ("handback_recipient", ""),
        ("handback_acceptance_required", False),
    ),
)
def test_missing_required_security_contract_field_denies(field: str, missing: object) -> None:
    with pytest.raises(PermissionError, match="COMPLETE_ACTIVE_SECURITY_CONTRACT_REQUIRED"):
        authority().sign_contract(replace(complete_terms(), **{field: missing}), now=NOW)

from __future__ import annotations

import threading
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.flows.security_overlay import (
    HandbackAcceptanceAuthority,
    HandbackStatement,
    IndependentClosureAuthority,
    OriginatingRecord,
    SecurityCaseStore,
    SecurityCommandRequest,
    SecurityContractTerms,
    SecurityPolicyAuthority,
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


def test_complete_contract_is_cryptographically_verified_and_fixture_labeled() -> None:
    authority = SecurityPolicyAuthority(
        private_key=Ed25519PrivateKey.generate(),
        policy_version="security-policy-v7",
        authority_epoch=7,
    )

    contract = authority.sign_contract(complete_terms(), now=NOW)

    assert authority.verify_contract(contract, now=NOW)
    assert contract.production_authority is False
    assert contract.signature


def test_exact_single_purpose_capability_records_only_its_allowlisted_command() -> None:
    authority = SecurityPolicyAuthority(
        private_key=Ed25519PrivateKey.generate(),
        policy_version="security-policy-v7",
        authority_epoch=7,
    )
    contract = authority.sign_contract(complete_terms(), now=NOW)
    case = SecurityCaseStore().open_case(
        OriginatingRecord("flow1", "delivery-request", "delivery-1", "c" * 64)
    )
    capability = authority.issue_capability(
        contract=contract,
        case=case,
        subject_id="incident-lead-1",
        command="inspect_audit_log",
        scope="service:checkout",
        evidence_class="restricted",
        expires_at=NOW + timedelta(minutes=10),
        nonce="nonce-investigate-1",
        now=NOW,
    )
    request = SecurityCommandRequest(
        case.case_id,
        "incident-lead-1",
        "inspect_audit_log",
        "service:checkout",
        "restricted",
    )

    receipt = authority.authorize_command(request, capability=capability, now=NOW)

    assert receipt.command == "inspect_audit_log"
    assert receipt.effect_executed is False
    assert receipt.production_authority is False
    with pytest.raises(PermissionError, match="SECURITY_CAPABILITY_ALREADY_USED"):
        authority.authorize_command(request, capability=capability, now=NOW)


def test_containment_is_time_limited_visible_and_links_permanent_flow1_remediation() -> None:
    authority = SecurityPolicyAuthority(
        private_key=Ed25519PrivateKey.generate(),
        policy_version="security-policy-v7",
        authority_epoch=7,
    )
    contract = authority.sign_contract(complete_terms(), now=NOW)
    case = SecurityCaseStore().open_case(OriginatingRecord("flow4", "incident", "inc-4", "d" * 64))
    capability = authority.issue_capability(
        contract=contract,
        case=case,
        subject_id="security-authority-1",
        command="isolate_workload",
        scope="service:checkout",
        evidence_class="restricted",
        expires_at=NOW + timedelta(minutes=20),
        nonce="nonce-containment-1",
        now=NOW,
    )
    plan = authority.issue_containment_plan(
        contract=contract,
        case=case,
        command="isolate_workload",
        scope="service:checkout",
        owner_visibility_route="technical-pm-1",
        expires_at=NOW + timedelta(minutes=15),
        permanent_remediation_request="flow1:delivery-request:remediate-77",
        now=NOW,
    )

    receipt = authority.authorize_containment(capability=capability, plan=plan, now=NOW)

    assert receipt.expires_at == NOW + timedelta(minutes=15)
    assert receipt.owner_visibility_route == "technical-pm-1"
    assert receipt.permanent_remediation_request.startswith("flow1:delivery-request:")
    assert receipt.lasting_change_authorized is False
    assert receipt.effect_executed is False


def test_authority_approved_disclosure_is_exactly_routed_and_recorded() -> None:
    authority = SecurityPolicyAuthority(
        private_key=Ed25519PrivateKey.generate(),
        policy_version="security-policy-v7",
        authority_epoch=7,
    )
    contract = authority.sign_contract(complete_terms(), now=NOW)
    case = SecurityCaseStore().open_case(OriginatingRecord("flow2", "finding", "finding-2", "9" * 64))
    capability = authority.issue_capability(
        contract=contract,
        case=case,
        subject_id="security-authority-1",
        command="notify_owner",
        scope="service:checkout",
        evidence_class="restricted",
        expires_at=NOW + timedelta(minutes=10),
        nonce="notify-capability",
        now=NOW,
    )
    approval = authority.issue_communication_approval(
        contract=contract,
        case=case,
        approver_subject_id="security-authority-1",
        subject_id="security-authority-1",
        command="notify_owner",
        route="product-secretary:security",
        evidence_class="restricted",
        expires_at=NOW + timedelta(minutes=5),
        nonce="notify-approval",
        now=NOW,
    )
    request = SecurityCommandRequest(
        case.case_id,
        "security-authority-1",
        "notify_owner",
        "service:checkout",
        "restricted",
    )

    receipt = authority.authorize_command(
        request, capability=capability, communication_approval=approval, now=NOW
    )

    assert receipt.command == "notify_owner"
    assert receipt.effect_executed is False


def test_explicit_verified_close_requires_independent_proof_and_accepted_exact_handback() -> None:
    policy = SecurityPolicyAuthority(
        private_key=Ed25519PrivateKey.generate(),
        policy_version="security-policy-v7",
        authority_epoch=7,
    )
    contract = policy.sign_contract(complete_terms(), now=NOW)
    store = SecurityCaseStore()
    case = store.open_case(OriginatingRecord("flow3", "release", "release-4", "e" * 64))
    verifier = IndependentClosureAuthority(
        private_key=Ed25519PrivateKey.generate(),
        verifier_subject_id="closure-verifier-1",
        verify_containment=lambda exact_case, ref: exact_case == case and ref == "evidence:containment",
        verify_restoration=lambda exact_case, ref: exact_case == case and ref == "evidence:restoration",
    )
    proof = verifier.verify_closure(
        case=case,
        containment_verified=True,
        restoration_verified=True,
        preserved_evidence_digest=case.preserved_evidence_digest,
        residual_risk_owner="risk-owner-1",
        lasting_change_request="flow1:delivery-request:security-fix-9",
        containment_evidence_ref="evidence:containment",
        restoration_evidence_ref="evidence:restoration",
    )
    handback = HandbackStatement(
        case_id=case.case_id,
        operational_state="restored-with-monitoring",
        restrictions=("privileged-write-disabled",),
        monitoring=("security-watch:checkout",),
        open_problems=("problem:token-rotation",),
        follow_up=("flow1:delivery-request:security-fix-9",),
        authority_resuming="ops-owner-1",
    )
    acceptance_authority = HandbackAcceptanceAuthority(
        private_key=Ed25519PrivateKey.generate(), registered_recipient="ops-owner-1"
    )
    acceptance = acceptance_authority.accept(handback, recipient_id="ops-owner-1", now=NOW)

    closed = store.close_case(
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

    assert closed.case_id == case.case_id
    assert closed.closed_explicitly is True
    assert closed.handback == handback
    assert store.is_closed(case.case_id)


@pytest.mark.parametrize("flow_id", ("flow1", "flow2", "flow3", "flow4"))
def test_each_delivery_flow_opens_an_immutable_least_disclosure_overlay_case(flow_id: str) -> None:
    origin = OriginatingRecord(
        flow_id=flow_id,
        record_type="typed-record",
        record_id=f"{flow_id}-record-7",
        evidence_digest="a" * 64,
    )
    store = SecurityCaseStore()

    case = store.open_case(origin)

    assert case.origin == origin
    assert case.preserved_evidence_digest == origin.evidence_digest
    assert case.routing == ("security-authority", "incident-lead", "evidence-custodian")
    assert case.is_overlay is True
    assert case.security_authority_granted is False
    with pytest.raises(FrozenInstanceError):
        case.is_overlay = False  # type: ignore[misc]


def test_concurrent_duplicate_entry_creates_exactly_one_case() -> None:
    barrier = threading.Barrier(2, timeout=5)
    arrivals: list[str] = []

    def before_create() -> None:
        arrivals.append("arrived")
        barrier.wait()

    store = SecurityCaseStore(before_create=before_create)
    origin = OriginatingRecord("flow2", "finding", "finding-9", "b" * 64)
    results: list[object] = []

    def open_at_boundary() -> None:
        results.append(store.open_case(origin))

    workers = [threading.Thread(target=open_at_boundary) for _ in range(2)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)

    assert barrier.n_waiting == 0
    assert len(arrivals) == 2
    assert len(results) == 2
    assert results[0] is results[1]
    assert store.case_count == 1

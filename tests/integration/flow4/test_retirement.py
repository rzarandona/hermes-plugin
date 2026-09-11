from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.flows.flow4 import (
    LegalHoldState,
    RetainedRecord,
    RetirementApprovalAuthority,
    RetirementEvidenceAuthority,
    RetirementLifecycle,
    RetirementSpec,
    RevocationState,
)


def _spec(*, legal_hold: LegalHoldState = LegalHoldState.CLEAR) -> RetirementSpec:
    return RetirementSpec(
        service_id="svc",
        environment_ids=("prod", "dr"),
        plan_version="plan-digest",
        resource_ids=("resource://svc/runtime/prod",),
        consumer_inventory_hash="consumers-digest",
        obligation_inventory_hash="obligations-digest",
        data_disposition_plan_hash="data-digest",
        credential_revocation_plan_hash="credentials-digest",
        dependency_removal_plan_hash="dependencies-digest",
        legal_hold_state=legal_hold,
        approved_from=100,
        approved_until=200,
        rollback_or_recovery_contract_id="recovery-contract",
        policy_version="policy-digest",
        owner_decision_id="owner-decision",
        authority_epoch=7,
        revocation_state=RevocationState.ACTIVE,
    )


def test_owner_exact_current_single_use_retirement_approval_begins_guarded_lifecycle() -> None:
    authority = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a"},
        current_authority_epoch=7,
    )
    spec = _spec()
    approval = authority.issue(spec, owner_subject_id="owner-a")
    lifecycle = RetirementLifecycle(approval_authority=authority)

    state = lifecycle.begin(spec, approval=approval, control_time=150)

    assert state.open
    assert not state.effect_executed
    assert state.spec_digest == spec.digest


def test_retirement_remains_open_for_any_unresolved_consumer() -> None:
    approvals = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a"},
        current_authority_epoch=7,
    )
    evidence = RetirementEvidenceAuthority(private_key=Ed25519PrivateKey.generate())
    spec = _spec()
    lifecycle = RetirementLifecycle(
        approval_authority=approvals, evidence_authority=evidence
    )
    lifecycle.begin(
        spec,
        approval=approvals.issue(spec, owner_subject_id="owner-a"),
        control_time=150,
    )
    proof = evidence.issue(
        service_id="svc",
        spec_digest=spec.digest,
        stop_use=True,
        consumers_migrated=True,
        consumers_notified=True,
        data_exported_or_disposed=True,
        dependencies_removed=True,
        credentials_revoked=True,
        access_revoked=True,
        traffic_drained=True,
        exact_resources_decommissioned=True,
        independent_absence_verified=True,
        unresolved_items=("consumer:legacy-mobile",),
    )

    state = lifecycle.assess(proof)

    assert state.open
    assert state.unresolved_items == ("consumer:legacy-mobile",)


def test_retirement_closes_only_after_every_staged_obligation_is_proven() -> None:
    approvals = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a"},
        current_authority_epoch=7,
    )
    evidence = RetirementEvidenceAuthority(private_key=Ed25519PrivateKey.generate())
    spec = _spec()
    lifecycle = RetirementLifecycle(
        approval_authority=approvals, evidence_authority=evidence
    )
    lifecycle.begin(
        spec,
        approval=approvals.issue(spec, owner_subject_id="owner-a"),
        control_time=150,
    )
    proof = evidence.issue(
        service_id="svc",
        spec_digest=spec.digest,
        stop_use=True,
        consumers_migrated=True,
        consumers_notified=True,
        data_exported_or_disposed=True,
        dependencies_removed=True,
        credentials_revoked=True,
        access_revoked=True,
        traffic_drained=True,
        exact_resources_decommissioned=True,
        independent_absence_verified=True,
        unresolved_items=(),
    )

    state = lifecycle.assess(proof)

    assert not state.open


@pytest.mark.parametrize(
    "incomplete_field",
    [
        "stop_use",
        "consumers_migrated",
        "consumers_notified",
        "data_exported_or_disposed",
        "dependencies_removed",
        "credentials_revoked",
        "access_revoked",
        "traffic_drained",
        "exact_resources_decommissioned",
        "independent_absence_verified",
    ],
)
def test_each_incomplete_retirement_stage_keeps_lifecycle_open(
    incomplete_field: str,
) -> None:
    approvals = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a"},
        current_authority_epoch=7,
    )
    evidence = RetirementEvidenceAuthority(private_key=Ed25519PrivateKey.generate())
    spec = _spec()
    lifecycle = RetirementLifecycle(
        approval_authority=approvals, evidence_authority=evidence
    )
    lifecycle.begin(
        spec,
        approval=approvals.issue(spec, owner_subject_id="owner-a"),
        control_time=150,
    )
    stages = {
        "stop_use": True,
        "consumers_migrated": True,
        "consumers_notified": True,
        "data_exported_or_disposed": True,
        "dependencies_removed": True,
        "credentials_revoked": True,
        "access_revoked": True,
        "traffic_drained": True,
        "exact_resources_decommissioned": True,
        "independent_absence_verified": True,
    }
    stages[incomplete_field] = False
    proof = evidence.issue(
        service_id="svc",
        spec_digest=spec.digest,
        unresolved_items=(),
        **stages,
    )

    assert lifecycle.assess(proof).open


def test_retained_retirement_records_reject_raw_keys_and_secrets() -> None:
    with pytest.raises(ValueError, match="RAW_SECRET_IN_RETAINED_RECORD"):
        RetainedRecord(
            record_id="record-1",
            key_escrow_reference="raw-key:super-secret-material",
            recovery_authority_metadata="authority:recovery-team",
            access_evidence_ref="evidence:access-review",
        )


def test_legal_hold_is_hard_retirement_veto() -> None:
    authority = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a"},
        current_authority_epoch=7,
    )
    spec = _spec(legal_hold=LegalHoldState.BLOCKED)

    with pytest.raises(PermissionError, match="LEGAL_HOLD_VETO"):
        RetirementLifecycle(approval_authority=authority).begin(
            spec,
            approval=authority.issue(spec, owner_subject_id="owner-a"),
            control_time=150,
        )


def test_retirement_approval_reuse_is_denied() -> None:
    authority = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a"},
        current_authority_epoch=7,
    )
    spec = _spec()
    approval = authority.issue(spec, owner_subject_id="owner-a")
    lifecycle = RetirementLifecycle(approval_authority=authority)
    lifecycle.begin(spec, approval=approval, control_time=150)

    with pytest.raises(PermissionError, match="RETIREMENT_APPROVAL_ALREADY_USED"):
        lifecycle.begin(spec, approval=approval, control_time=150)


def test_forged_retirement_approval_is_denied() -> None:
    authority = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a"},
        current_authority_epoch=7,
    )
    spec = _spec()
    authentic = authority.issue(spec, owner_subject_id="owner-a")

    with pytest.raises(PermissionError, match="AUTHENTIC_RETIREMENT_APPROVAL_REQUIRED"):
        RetirementLifecycle(approval_authority=authority).begin(
            spec,
            approval=replace(authentic, signature=b"forged"),
            control_time=150,
        )


@pytest.mark.parametrize(
    ("spec", "control_time"),
    [
        (replace(_spec(), authority_epoch=6), 150),
        (_spec(), 200),
        (replace(_spec(), revocation_state=RevocationState.REVOKED), 150),
    ],
)
def test_noncurrent_retirement_approval_is_denied(
    spec: RetirementSpec, control_time: int
) -> None:
    authority = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a"},
        current_authority_epoch=7,
    )
    approval = authority.issue(spec, owner_subject_id="owner-a")

    with pytest.raises(PermissionError, match="RETIREMENT_APPROVAL_NOT_CURRENT"):
        RetirementLifecycle(approval_authority=authority).begin(
            spec, approval=approval, control_time=control_time
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("service_id", "other"),
        ("environment_ids", ("prod",)),
        ("plan_version", "other-plan"),
        ("resource_ids", ("resource://other",)),
        ("consumer_inventory_hash", "other-consumers"),
        ("obligation_inventory_hash", "other-obligations"),
        ("data_disposition_plan_hash", "other-data"),
        ("credential_revocation_plan_hash", "other-credentials"),
        ("dependency_removal_plan_hash", "other-dependencies"),
        ("legal_hold_state", LegalHoldState.BLOCKED),
        ("approved_from", 101),
        ("approved_until", 201),
        ("rollback_or_recovery_contract_id", "other-recovery"),
        ("policy_version", "other-policy"),
        ("owner_decision_id", "other-decision"),
        ("authority_epoch", 8),
        ("revocation_state", RevocationState.REVOKED),
    ],
)
def test_every_retirement_spec_mismatch_denies_approval(field: str, value: object) -> None:
    authority = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a", "other": "owner-a"},
        current_authority_epoch=7,
    )
    spec = _spec()
    approval = authority.issue(spec, owner_subject_id="owner-a")
    changed = replace(spec, **{field: value})

    expected = "LEGAL_HOLD_VETO" if field == "legal_hold_state" else "RETIREMENT_APPROVAL"
    with pytest.raises(PermissionError, match=expected):
        RetirementLifecycle(approval_authority=authority).begin(
            changed, approval=approval, control_time=150
        )


@pytest.mark.parametrize(
    "unresolved",
    [
        "consumer:item",
        "obligation:item",
        "legal_hold:item",
        "credential:item",
        "dependency:item",
        "traffic:item",
        "export:item",
        "deletion:item",
        "archive:item",
    ],
)
def test_each_unresolved_retirement_item_keeps_lifecycle_open(unresolved: str) -> None:
    approvals = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a"},
        current_authority_epoch=7,
    )
    evidence = RetirementEvidenceAuthority(private_key=Ed25519PrivateKey.generate())
    spec = _spec()
    lifecycle = RetirementLifecycle(
        approval_authority=approvals, evidence_authority=evidence
    )
    lifecycle.begin(
        spec,
        approval=approvals.issue(spec, owner_subject_id="owner-a"),
        control_time=150,
    )
    proof = evidence.issue(
        service_id="svc",
        spec_digest=spec.digest,
        stop_use=True,
        consumers_migrated=True,
        consumers_notified=True,
        data_exported_or_disposed=True,
        dependencies_removed=True,
        credentials_revoked=True,
        access_revoked=True,
        traffic_drained=True,
        exact_resources_decommissioned=True,
        independent_absence_verified=True,
        unresolved_items=(unresolved,),
    )

    assert lifecycle.assess(proof).open


def test_forged_retirement_evidence_is_denied() -> None:
    approvals = RetirementApprovalAuthority(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"svc": "owner-a"},
        current_authority_epoch=7,
    )
    evidence = RetirementEvidenceAuthority(private_key=Ed25519PrivateKey.generate())
    spec = _spec()
    lifecycle = RetirementLifecycle(
        approval_authority=approvals, evidence_authority=evidence
    )
    lifecycle.begin(
        spec,
        approval=approvals.issue(spec, owner_subject_id="owner-a"),
        control_time=150,
    )
    authentic = evidence.issue(
        service_id="svc",
        spec_digest=spec.digest,
        stop_use=True,
        consumers_migrated=True,
        consumers_notified=True,
        data_exported_or_disposed=True,
        dependencies_removed=True,
        credentials_revoked=True,
        access_revoked=True,
        traffic_drained=True,
        exact_resources_decommissioned=True,
        independent_absence_verified=True,
        unresolved_items=(),
    )

    with pytest.raises(PermissionError, match="AUTHENTIC_EXACT_RETIREMENT_EVIDENCE_REQUIRED"):
        lifecycle.assess(replace(authentic, signature=b"forged"))

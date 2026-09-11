from datetime import UTC, datetime, timedelta

from hermes_kanban_workflow.activation import STAGE_CONTRACTS
from hermes_kanban_workflow.release_gate import AuditVerdict, evaluate_release_readiness


def test_activation_contracts_name_all_ten_entry_pass_owner_review_denial_kill_rollback_gates() -> None:
    assert [contract.stage for contract in STAGE_CONTRACTS] == list(range(1, 11))
    for contract in STAGE_CONTRACTS:
        assert contract.name
        assert contract.entry
        assert contract.passed
        assert contract.owner
        assert contract.reviewer_roles
        assert contract.denial
        assert contract.kill
        assert contract.rollback


def test_directly_constructed_legacy_audit_metadata_remains_fail_closed() -> None:
    now = datetime.now(UTC)
    verdict = AuditVerdict(
        reviewer_id="caller-value",
        scope_digest="scope",
        evidence_digest="evidence",
        verdict="PASS",
        open_p0=0,
        open_p1=0,
        p2_disposition="accepted",
        issued_at=now,
        expires_at=now + timedelta(days=1),
        gatekeeper_ack=True,
    )

    result = evaluate_release_readiness(verdict, now)

    assert not result.ready
    assert result.code == "AUTHENTICATED_INDEPENDENT_AUDIT_REQUIRED"

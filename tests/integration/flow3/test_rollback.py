from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.flows.flow3 import (
    ObjectiveObservation,
    OwnerApprovalRegistry,
    ReleaseBinding,
    RollbackPolicyRegistry,
    RolloutStrategy,
    decide_rollback,
)


def test_signed_objective_reversible_bounded_policy_permits_automatic_rollback() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    registry = RollbackPolicyRegistry(private_key=Ed25519PrivateKey.generate())
    authorization = registry.issue(
        artifact_id="artifact-a",
        rollback_contract="rollback-contract-2",
        objective="error-rate-bps",
        threshold=500,
        reversible=True,
        collateral_risk_bounded=True,
        expires_at=now + timedelta(minutes=5),
    )
    observation = ObjectiveObservation(
        objective="error-rate-bps",
        value=700,
        evidence_ref="ledger:objective:7",
        authentication_tag=b"verified-observation",
    )

    decision = decide_rollback(
        artifact_id="artifact-a",
        rollback_contract="rollback-contract-2",
        authorization=authorization,
        authorization_registry=registry,
        observation=observation,
        verify_observation=lambda value: value.authentication_tag == b"verified-observation",
        now=now,
    )

    assert decision.automatic is True
    assert decision.owner_approval_id is None


def test_forged_or_unsafe_automatic_rollback_metadata_requires_fresh_owner_approval() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    registry = RollbackPolicyRegistry(private_key=Ed25519PrivateKey.generate())
    unsafe = registry.issue(
        artifact_id="artifact-a",
        rollback_contract="rollback-contract-2",
        objective="error-rate-bps",
        threshold=500,
        reversible=False,
        collateral_risk_bounded=False,
        expires_at=now + timedelta(minutes=5),
    )
    forged = replace(unsafe, reversible=True, collateral_risk_bounded=True)
    observation = ObjectiveObservation(
        "error-rate-bps", 700, "ledger:objective:7", b"verified-observation"
    )

    with pytest.raises(PermissionError, match="FRESH_EXACT_OWNER_ROLLBACK_APPROVAL_REQUIRED"):
        decide_rollback(
            artifact_id="artifact-a",
            rollback_contract="rollback-contract-2",
            authorization=forged,
            authorization_registry=registry,
            observation=observation,
            verify_observation=lambda _value: True,
            now=now,
        )


def test_manual_rollback_owner_approval_must_bind_exact_requested_artifact() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    policy_registry = RollbackPolicyRegistry(private_key=Ed25519PrivateKey.generate())
    owner_registry = OwnerApprovalRegistry(
        private_key=Ed25519PrivateKey.generate(), owner_by_environment={"production": "owner-1"}
    )
    wrong_binding = ReleaseBinding(
        "artifact-b",
        "production",
        "config-7",
        "policy-4",
        RolloutStrategy.PROGRESSIVE,
        now,
        now + timedelta(minutes=5),
        "rollback-contract-2",
    )
    approval = owner_registry.issue(
        owner_subject_id="owner-1", binding=wrong_binding, decided_at=now
    )

    with pytest.raises(PermissionError, match="OWNER_ROLLBACK_BINDING_MISMATCH"):
        decide_rollback(
            artifact_id="artifact-a",
            rollback_contract="rollback-contract-2",
            authorization=None,
            authorization_registry=policy_registry,
            observation=ObjectiveObservation("ambiguous", 0, "ledger:ambiguous", b"verified"),
            verify_observation=lambda _value: True,
            now=now,
            owner_approval=approval,
            owner_registry=owner_registry,
            release_binding=wrong_binding,
        )

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.adapters.artifact_store import (
    ArtifactMaterial,
    EphemeralSigningAdapter,
    ImmutableArtifactStore,
    SigningCapability,
)
from hermes_kanban_workflow.flows.flow3 import (
    HealthGate,
    HealthGateKind,
    HealthStatus,
    OwnerApprovalRegistry,
    ReleaseBinding,
    RollbackReadinessReceipt,
    RolloutStrategy,
    create_promotion_command,
)


def test_emergency_lane_preserves_signature_owner_verification_and_rollback_gates() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    material = ArtifactMaterial(b"app", b"src", b"prov", b"tests", b"deps", b"cfg", b"sbom")
    signer = EphemeralSigningAdapter(
        lower_private_key=Ed25519PrivateKey.generate(),
        production_private_key=Ed25519PrivateKey.generate(),
    )
    capability = SigningCapability(
        material.material_digest,
        "production",
        now,
        now + timedelta(minutes=2),
        "cap-a",
    )
    artifact = ImmutableArtifactStore().build_once(
        material,
        signer=signer,
        environment="production",
        now=now,
        capability=capability,
    )
    binding = ReleaseBinding(
        artifact.artifact_id,
        "production",
        "config-7",
        "policy-4",
        RolloutStrategy.PROGRESSIVE,
        now,
        now + timedelta(minutes=5),
        "rollback-contract-2",
        True,
    )
    owner_registry = OwnerApprovalRegistry(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_environment={"production": "owner-1"},
    )
    approval = owner_registry.issue(
        owner_subject_id="owner-1", binding=binding, decided_at=now
    )
    readiness = RollbackReadinessReceipt(
        artifact.artifact_id,
        binding.rollback_contract,
        "ledger:rollback:ready",
        b"ready-auth",
    )

    command = create_promotion_command(
        artifact=artifact,
        signer=signer,
        binding=binding,
        approval=approval,
        owner_registry=owner_registry,
        release_lease_ref="lease:release:1",
        verify_release_lease=lambda ref, exact: ref == "lease:release:1" and exact == binding,
        health_gates=(HealthGate(HealthGateKind.TELEMETRY, HealthStatus.PASS, "ledger:health:1"),),
        verify_health_gate=lambda gate: gate.evidence_ref == "ledger:health:1",
        atomic_unavailability_evidence=None,
        rollback_readiness=readiness,
        verify_rollback_readiness=lambda receipt: receipt.authentication_tag == b"ready-auth",
        now=now,
    )

    assert command.emergency is True
    assert command.artifact_id == artifact.artifact_id
    assert command.owner_approval_id == approval.approval_id
    assert command.repository_fixture is True
    assert command.production_proof is False

    with pytest.raises(PermissionError, match="PRODUCTION_PROOF_REQUIRED"):
        command.as_effect_command()

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.flows.flow3 import (
    OperationalOwnerAcceptanceRegistry,
    ProductionVerificationRegistry,
    RollbackReadinessReceipt,
    closeout_release,
    durable_evidence_digest,
)


def test_closeout_requires_registry_backed_independent_verification_and_owner_acceptance() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    verification_registry = ProductionVerificationRegistry(
        private_key=Ed25519PrivateKey.generate(), deployment_actor="deployer-1"
    )
    verification = verification_registry.issue(
        artifact_id="artifact-a",
        verifier_subject_id="verifier-2",
        evidence_ref="ledger:production-verification:1",
        verified_at=now,
    )
    readiness = RollbackReadinessReceipt(
        artifact_id="artifact-a",
        contract="rollback-contract-2",
        evidence_ref="ledger:rollback-readiness:2",
        authentication_tag=b"verified-readiness",
    )
    evidence = (
        "ledger:effect:1",
        "ledger:production-verification:1",
        "ledger:rollback-readiness:2",
    )
    evidence_digest = durable_evidence_digest(evidence)
    owner_registry = OperationalOwnerAcceptanceRegistry(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"service-a": "operational-owner-1"},
    )
    acceptance = owner_registry.issue(
        service_id="service-a",
        artifact_id="artifact-a",
        owner_subject_id="operational-owner-1",
        evidence_digest=evidence_digest,
        accepted_at=now,
    )

    handoff = closeout_release(
        service_id="service-a",
        artifact_id="artifact-a",
        verification=verification,
        verification_registry=verification_registry,
        rollback_readiness=readiness,
        verify_rollback_readiness=lambda receipt: (
            receipt.authentication_tag == b"verified-readiness"
        ),
        durable_evidence=evidence,
        durable_evidence_digest=evidence_digest,
        operational_acceptance=acceptance,
        operational_owner_registry=owner_registry,
    )

    assert handoff.closed is True
    assert handoff.operational_owner_subject_id == "operational-owner-1"


def test_operational_owner_silence_and_forged_owner_string_grant_nothing() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    verification_registry = ProductionVerificationRegistry(
        private_key=Ed25519PrivateKey.generate(), deployment_actor="deployer-1"
    )
    verification = verification_registry.issue(
        artifact_id="artifact-a",
        verifier_subject_id="verifier-2",
        evidence_ref="ledger:verification:1",
        verified_at=now,
    )
    readiness = RollbackReadinessReceipt(
        "artifact-a", "rollback-contract-2", "ledger:readiness:1", b"ready"
    )
    evidence = ("ledger:effect:1", "ledger:verification:1", "ledger:readiness:1")
    digest = durable_evidence_digest(evidence)
    registry = OperationalOwnerAcceptanceRegistry(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_service={"service-a": "registered-owner"},
    )

    with pytest.raises(PermissionError, match="OPERATIONAL_OWNER_REGISTRY_MISMATCH"):
        registry.issue(
            service_id="service-a",
            artifact_id="artifact-a",
            owner_subject_id="caller-forged-owner",
            evidence_digest=digest,
            accepted_at=now,
        )

    with pytest.raises(PermissionError, match="EXPLICIT_OPERATIONAL_OWNER_ACCEPTANCE_REQUIRED"):
        closeout_release(
            service_id="service-a",
            artifact_id="artifact-a",
            verification=verification,
            verification_registry=verification_registry,
            rollback_readiness=readiness,
            verify_rollback_readiness=lambda receipt: receipt.authentication_tag == b"ready",
            durable_evidence=evidence,
            durable_evidence_digest=digest,
            operational_acceptance=None,
            operational_owner_registry=registry,
        )

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.flows.flow3 import (
    OwnerApprovalRegistry,
    ReleaseBinding,
    RolloutStrategy,
)


def _binding(*, artifact_id: str = "artifact-a") -> ReleaseBinding:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    return ReleaseBinding(
        artifact_id=artifact_id,
        environment="production",
        configuration_version="config-7",
        policy_version="policy-4",
        strategy=RolloutStrategy.PROGRESSIVE,
        valid_from=now,
        valid_until=now + timedelta(minutes=10),
        rollback_contract="rollback-contract-2",
        emergency=False,
    )


def test_owner_registry_consumes_exact_immutable_production_approval_once() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    registry = OwnerApprovalRegistry(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_environment={"production": "owner-subject-1"},
    )
    binding = _binding()
    approval = registry.issue(
        owner_subject_id="owner-subject-1", binding=binding, decided_at=now
    )

    consumed = registry.consume(approval, binding=binding, now=now + timedelta(seconds=1))

    assert consumed == approval
    assert approval.binding_digest == binding.digest


def test_owner_approval_reuse_is_denied() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    registry = OwnerApprovalRegistry(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_environment={"production": "owner-subject-1"},
    )
    binding = _binding()
    approval = registry.issue(
        owner_subject_id="owner-subject-1", binding=binding, decided_at=now
    )
    registry.consume(approval, binding=binding, now=now)

    with pytest.raises(PermissionError, match="OWNER_APPROVAL_ALREADY_USED"):
        registry.consume(approval, binding=binding, now=now + timedelta(seconds=1))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_id", "artifact-rebuilt"),
        ("environment", "production-other"),
        ("configuration_version", "config-8"),
        ("policy_version", "policy-5"),
        ("strategy", RolloutStrategy.ATOMIC),
        ("rollback_contract", "rollback-contract-3"),
        ("emergency", True),
    ],
)
def test_any_release_binding_mismatch_denies_owner_approval(field: str, value: object) -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    registry = OwnerApprovalRegistry(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_environment={"production": "owner-subject-1"},
    )
    binding = _binding()
    approval = registry.issue(
        owner_subject_id="owner-subject-1", binding=binding, decided_at=now
    )
    changed = replace(binding, **{field: value})

    with pytest.raises(PermissionError, match="OWNER_APPROVAL_BINDING_MISMATCH"):
        registry.consume(approval, binding=changed, now=now)


def test_expired_owner_approval_is_denied() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    registry = OwnerApprovalRegistry(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_environment={"production": "owner-subject-1"},
    )
    binding = _binding()
    approval = registry.issue(
        owner_subject_id="owner-subject-1", binding=binding, decided_at=now
    )

    with pytest.raises(PermissionError, match="OWNER_APPROVAL_EXPIRED"):
        registry.consume(approval, binding=binding, now=binding.valid_until)


def test_caller_forged_owner_receipt_metadata_is_denied() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    registry = OwnerApprovalRegistry(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_environment={"production": "owner-subject-1"},
    )
    binding = _binding()
    authentic = registry.issue(
        owner_subject_id="owner-subject-1", binding=binding, decided_at=now
    )
    forged = replace(authentic, binding_digest=binding.digest, signature=b"caller-forged")

    with pytest.raises(PermissionError, match="AUTHENTIC_OWNER_APPROVAL_REQUIRED"):
        registry.consume(forged, binding=binding, now=now)

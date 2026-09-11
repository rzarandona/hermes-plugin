from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.adapters.artifact_store import (
    ArtifactMaterial,
    EphemeralSigningAdapter,
    ImmutableArtifactStore,
    SigningCapability,
    SigningRootClass,
)
from hermes_kanban_workflow.flows.flow3 import ProductionVerificationRegistry


def _material(*, payload: bytes = b"release-bytes") -> ArtifactMaterial:
    return ArtifactMaterial(
        payload=payload,
        source=b"git:abc123",
        provenance=b"builder:fixture",
        tests=b"pytest:179-pass",
        dependencies=b"lock:sha256:deps",
        configuration=b"config:v7",
        sbom=b"spdx:fixture",
    )


def test_build_identity_binds_all_exact_material_bytes_and_signature() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    signer = EphemeralSigningAdapter(
        lower_private_key=Ed25519PrivateKey.generate(),
        production_private_key=Ed25519PrivateKey.generate(),
    )
    capability = SigningCapability(
        artifact_material_digest=_material().material_digest,
        environment="production",
        issued_at=now,
        expires_at=now + timedelta(minutes=2),
        capability_id="cap-1",
    )

    artifact = ImmutableArtifactStore().build_once(
        _material(), signer=signer, environment="production", now=now, capability=capability
    )

    assert artifact.material == _material()
    assert artifact.signature.signed_digest == artifact.material.material_digest
    assert artifact.signature.root_class is SigningRootClass.PRODUCTION_HARDWARE_MANAGED
    assert artifact.signature.non_exportable is True
    assert artifact.signature.hardware_backed is True
    assert artifact.signature.production_proof is False
    assert artifact.artifact_id == artifact.recompute_identity()
    assert artifact.build_receipt.artifact_id == artifact.artifact_id
    assert artifact.build_receipt.material_digest == artifact.material.material_digest


def test_production_signing_interface_models_managed_non_exportable_hardware_key() -> None:
    signer = EphemeralSigningAdapter(
        lower_private_key=Ed25519PrivateKey.generate(),
        production_private_key=Ed25519PrivateKey.generate(),
    )

    descriptor = signer.production_key_descriptor

    assert descriptor.managed is True
    assert descriptor.non_exportable is True
    assert descriptor.hardware_backed is True
    assert descriptor.production_proof is False


def test_expired_or_wrong_artifact_production_signing_capability_is_denied() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    signer = EphemeralSigningAdapter(
        lower_private_key=Ed25519PrivateKey.generate(),
        production_private_key=Ed25519PrivateKey.generate(),
    )
    expired = SigningCapability(
        _material().material_digest,
        "production",
        now - timedelta(minutes=2),
        now,
        "cap-expired",
    )
    wrong_artifact = SigningCapability(
        "0" * 64,
        "production",
        now,
        now + timedelta(minutes=1),
        "cap-wrong",
    )

    for capability, code in (
        (expired, "SIGNING_CAPABILITY_EXPIRED"),
        (wrong_artifact, "SIGNING_CAPABILITY_BINDING_MISMATCH"),
    ):
        with pytest.raises(PermissionError, match=code):
            ImmutableArtifactStore().build_once(
                _material(),
                signer=signer,
                environment="production",
                now=now,
                capability=capability,
            )


def test_material_rebuild_changes_identity_and_invalidates_exact_artifact_bindings() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    signer = EphemeralSigningAdapter(
        lower_private_key=Ed25519PrivateKey.generate(),
        production_private_key=Ed25519PrivateKey.generate(),
    )
    store = ImmutableArtifactStore()
    original = store.build_once(_material(), signer=signer, environment="staging", now=now)

    rebuilt = store.build_once(
        _material(payload=b"release-bytes-changed"),
        signer=signer,
        environment="staging",
        now=now,
    )

    assert rebuilt.artifact_id != original.artifact_id
    assert rebuilt.material.material_digest != original.material.material_digest


def test_lower_environment_uses_separate_lower_trust_root() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    signer = EphemeralSigningAdapter(
        lower_private_key=Ed25519PrivateKey.generate(),
        production_private_key=Ed25519PrivateKey.generate(),
    )

    artifact = ImmutableArtifactStore().build_once(
        _material(), signer=signer, environment="staging", now=now
    )

    assert artifact.signature.root_class is SigningRootClass.LOWER_ENVIRONMENT
    assert artifact.signature.key_id == "ephemeral-lower-root"
    assert artifact.signature.capability_id is None


def test_material_rebuild_invalidates_existing_production_verification() -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    signer = EphemeralSigningAdapter(
        lower_private_key=Ed25519PrivateKey.generate(),
        production_private_key=Ed25519PrivateKey.generate(),
    )
    store = ImmutableArtifactStore()
    original = store.build_once(_material(), signer=signer, environment="staging", now=now)
    rebuilt = store.build_once(
        _material(payload=b"material-rebuild"), signer=signer, environment="staging", now=now
    )
    registry = ProductionVerificationRegistry(
        private_key=Ed25519PrivateKey.generate(), deployment_actor="deployer"
    )
    verification = registry.issue(
        artifact_id=original.artifact_id,
        verifier_subject_id="independent-verifier",
        evidence_ref="ledger:verification:original",
        verified_at=now,
    )

    assert registry.verify(verification, artifact_id=rebuilt.artifact_id) is False

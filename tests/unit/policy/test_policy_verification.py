from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.policy.loader import load_verified_policy
from hermes_kanban_workflow.policy.verifier import (
    PolicyVerificationError,
    TrustRoot,
    TrustRootRevocationReceipt,
    TrustRootRotationReceipt,
    TrustStore,
)


def _policy(now: datetime) -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_id": "pilot-policy",
        "scope": "product-1",
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "trust_epoch": 1,
        "compatibility": {
            "host_version": "0.20.5",
            "plugin_version": "0.1.0",
            "executor_version": "1.0.0",
            "policy_version": "1",
        },
        "authority": {"effect_classes": ["read_only"]},
        "rules": {"observe_only": True},
    }


def _write_signed_policy(
    tmp_path: Path,
    document: dict[str, object],
    private_key: Ed25519PrivateKey,
) -> tuple[Path, bytes]:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    path = tmp_path / "policy.json"
    path.write_bytes(payload)
    return path, private_key.sign(payload)


def test_schema_validation_rejects_unknown_policy_fields(tmp_path: Path) -> None:
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    private_key = Ed25519PrivateKey.generate()
    document = _policy(now)
    document["unexpected"] = "not allowed"
    path, signature = _write_signed_policy(tmp_path, document, private_key)
    root = TrustRoot.from_public_key("root-1", 1, private_key.public_key())

    with pytest.raises(PolicyVerificationError, match="POLICY_SCHEMA_INVALID"):
        load_verified_policy(path, signature, root, now=now)


def test_valid_signature_yields_verified_policy_without_private_material(tmp_path: Path) -> None:
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    private_key = Ed25519PrivateKey.generate()
    path, signature = _write_signed_policy(tmp_path, _policy(now), private_key)
    root = TrustRoot.from_public_key("root-1", 1, private_key.public_key())

    verified = load_verified_policy(path, signature, root, now=now)

    assert verified.document.policy_id == "pilot-policy"
    assert verified.signer_key_id == "root-1"
    assert verified.is_usable(now)
    assert not hasattr(root, "private_key")
    assert not hasattr(verified, "private_key")


def test_tampered_policy_returns_typed_failure_metadata(tmp_path: Path) -> None:
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    private_key = Ed25519PrivateKey.generate()
    document = _policy(now)
    path, signature = _write_signed_policy(tmp_path, document, private_key)
    document["scope"] = "attacker-product"
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")))
    root = TrustRoot.from_public_key("root-1", 1, private_key.public_key())

    with pytest.raises(PolicyVerificationError) as failure:
        load_verified_policy(path, signature, root, now=now)

    assert failure.value.code == "POLICY_SIGNATURE_INVALID"
    assert failure.value.metadata == {"signer_key_id": "root-1", "trust_epoch": 1}


def test_expired_policy_is_rejected_with_rollback_metadata(tmp_path: Path) -> None:
    issued_at = datetime(2026, 8, 29, 10, tzinfo=UTC)
    checked_at = issued_at + timedelta(hours=2)
    private_key = Ed25519PrivateKey.generate()
    path, signature = _write_signed_policy(tmp_path, _policy(issued_at), private_key)
    root = TrustRoot.from_public_key("root-1", 1, private_key.public_key())

    with pytest.raises(PolicyVerificationError) as failure:
        load_verified_policy(
            path,
            signature,
            root,
            now=checked_at,
            last_known_compatible_digest="sha256:last-known-compatible",
        )

    assert failure.value.code == "POLICY_EXPIRED"
    assert failure.value.metadata["last_known_compatible_digest"] == (
        "sha256:last-known-compatible"
    )


def test_unsupported_schema_version_has_typed_metadata(tmp_path: Path) -> None:
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    private_key = Ed25519PrivateKey.generate()
    document = _policy(now)
    document["schema_version"] = 2
    path, signature = _write_signed_policy(tmp_path, document, private_key)
    root = TrustRoot.from_public_key("root-1", 1, private_key.public_key())

    with pytest.raises(PolicyVerificationError) as failure:
        load_verified_policy(path, signature, root, now=now)

    assert failure.value.code == "POLICY_VERSION_UNSUPPORTED"
    assert failure.value.metadata == {"received": 2, "supported": [1]}


def test_authority_expansion_is_rejected_without_owner_transition(tmp_path: Path) -> None:
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    private_key = Ed25519PrivateKey.generate()
    root = TrustRoot.from_public_key("root-1", 1, private_key.public_key())
    baseline_path, baseline_signature = _write_signed_policy(
        tmp_path, _policy(now), private_key
    )
    baseline = load_verified_policy(baseline_path, baseline_signature, root, now=now)
    expanded = _policy(now)
    expanded["authority"] = {"effect_classes": ["read_only", "irreversible"]}
    expanded_path = tmp_path / "expanded.json"
    expanded_payload = json.dumps(expanded, sort_keys=True, separators=(",", ":")).encode()
    expanded_path.write_bytes(expanded_payload)

    with pytest.raises(PolicyVerificationError) as failure:
        load_verified_policy(
            expanded_path,
            private_key.sign(expanded_payload),
            root,
            now=now,
            previous_policy=baseline,
        )

    assert failure.value.code == "POLICY_AUTHORITY_WEAKENING"
    assert failure.value.metadata["added_effect_classes"] == ["irreversible"]


def test_owner_signed_rotation_advances_trust_epoch_and_preserves_predecessor() -> None:
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    old_private = Ed25519PrivateKey.generate()
    new_private = Ed25519PrivateKey.generate()
    old_root = TrustRoot.from_public_key("root-1", 1, old_private.public_key())
    new_root = TrustRoot.from_public_key("root-2", 2, new_private.public_key())
    store = TrustStore(old_root)
    receipt = TrustRootRotationReceipt.create(
        previous=old_root,
        successor=new_root,
        effective_from=now,
        effective_until=now + timedelta(days=30),
        owner_approval_id="owner-transition-1",
    )

    accepted = store.rotate(receipt, old_private.sign(receipt.signing_bytes()), now=now)

    assert accepted.trust_epoch == 2
    assert accepted.predecessor_digest == old_root.digest
    assert store.last_known_valid_root() == new_root


def test_non_monotonic_rotation_is_denied_without_changing_last_known_valid() -> None:
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    old_private = Ed25519PrivateKey.generate()
    new_private = Ed25519PrivateKey.generate()
    old_root = TrustRoot.from_public_key("root-1", 1, old_private.public_key())
    successor = TrustRoot.from_public_key("root-2", 2, new_private.public_key())
    store = TrustStore(old_root)
    valid = TrustRootRotationReceipt.create(
        previous=old_root,
        successor=successor,
        effective_from=now,
        effective_until=now + timedelta(days=1),
        owner_approval_id="owner-transition-1",
    )
    stale = replace(valid, trust_epoch=1)

    with pytest.raises(PolicyVerificationError, match="TRUST_ROTATION_DENIED"):
        store.rotate(stale, old_private.sign(stale.signing_bytes()), now=now)

    assert store.last_known_valid_root() == old_root
    assert store.last_known_valid_receipt() is None


def test_previously_seen_root_cannot_be_restored_silently() -> None:
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    first_private = Ed25519PrivateKey.generate()
    second_private = Ed25519PrivateKey.generate()
    first = TrustRoot.from_public_key("root-1", 1, first_private.public_key())
    second = TrustRoot.from_public_key("root-2", 2, second_private.public_key())
    store = TrustStore(first)
    forward = TrustRootRotationReceipt.create(
        previous=first,
        successor=second,
        effective_from=now,
        effective_until=now + timedelta(days=2),
        owner_approval_id="owner-transition-1",
    )
    store.rotate(forward, first_private.sign(forward.signing_bytes()), now=now)
    restored_old_bytes = TrustRoot("root-1", 3, first.public_key_bytes)
    rollback = TrustRootRotationReceipt.create(
        previous=second,
        successor=restored_old_bytes,
        effective_from=now,
        effective_until=now + timedelta(days=2),
        owner_approval_id="owner-transition-2",
    )

    with pytest.raises(PolicyVerificationError, match="TRUST_ROOT_RESTORE_DENIED"):
        store.rotate(rollback, second_private.sign(rollback.signing_bytes()), now=now)

    assert store.last_known_valid_root() == second


def test_revocation_blocks_new_packages_but_preserves_prior_evidence() -> None:
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    first_private = Ed25519PrivateKey.generate()
    second_private = Ed25519PrivateKey.generate()
    first = TrustRoot.from_public_key("root-1", 1, first_private.public_key())
    second = TrustRoot.from_public_key("root-2", 2, second_private.public_key())
    store = TrustStore(first)
    rotation = TrustRootRotationReceipt.create(
        previous=first,
        successor=second,
        effective_from=now - timedelta(hours=1),
        effective_until=now + timedelta(days=2),
        owner_approval_id="owner-transition-1",
    )
    store.rotate(rotation, first_private.sign(rotation.signing_bytes()), now=now)
    evidence = b"immutable prior policy evidence"
    evidence_signature = first_private.sign(evidence)
    revocation = TrustRootRevocationReceipt(
        revoked_key_id="root-1",
        trust_epoch=3,
        predecessor_digest=second.digest,
        effective_from=now,
        effective_until=now + timedelta(days=30),
        revocation_reason="signing key suspected compromised",
    )

    store.revoke(revocation, second_private.sign(revocation.signing_bytes()), now=now)

    store.verify_evidence(
        evidence,
        evidence_signature,
        key_id="root-1",
        signed_at=now - timedelta(seconds=1),
    )
    with pytest.raises(PolicyVerificationError, match="TRUST_ROOT_REVOKED"):
        store.verify_evidence(
            evidence,
            first_private.sign(evidence),
            key_id="root-1",
            signed_at=now + timedelta(seconds=1),
        )
    assert store.trust_epoch == 3
    assert store.last_known_valid_revocation() == revocation


def test_policy_trust_epoch_rollback_is_rejected_with_metadata(tmp_path: Path) -> None:
    now = datetime(2026, 8, 29, 12, tzinfo=UTC)
    current_private = Ed25519PrivateKey.generate()
    current_root = TrustRoot.from_public_key("root-2", 2, current_private.public_key())
    path, signature = _write_signed_policy(tmp_path, _policy(now), current_private)

    with pytest.raises(PolicyVerificationError) as failure:
        load_verified_policy(path, signature, current_root, now=now)

    assert failure.value.code == "POLICY_TRUST_EPOCH_ROLLBACK"
    assert failure.value.metadata == {"policy_trust_epoch": 1, "current_trust_epoch": 2}

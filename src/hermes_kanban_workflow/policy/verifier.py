from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class PolicyVerificationError(ValueError):
    """A stable fail-closed policy verification failure."""

    def __init__(self, code: str, metadata: dict[str, object] | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.metadata = metadata or {}


@dataclass(frozen=True)
class TrustRoot:
    key_id: str
    trust_epoch: int
    public_key_bytes: bytes

    @classmethod
    def from_public_key(
        cls, key_id: str, trust_epoch: int, public_key: Ed25519PublicKey
    ) -> TrustRoot:
        return cls(
            key_id=key_id,
            trust_epoch=trust_epoch,
            public_key_bytes=public_key.public_bytes(Encoding.Raw, PublicFormat.Raw),
        )

    @property
    def digest(self) -> str:
        return sha256(self.public_key_bytes).hexdigest()

    def verify(self, signature: bytes | str, payload: bytes) -> None:
        try:
            decoded = base64.b64decode(signature, validate=True) if isinstance(signature, str) else signature
            Ed25519PublicKey.from_public_bytes(self.public_key_bytes).verify(decoded, payload)
        except (InvalidSignature, ValueError) as exc:
            raise PolicyVerificationError(
                "POLICY_SIGNATURE_INVALID",
                {"signer_key_id": self.key_id, "trust_epoch": self.trust_epoch},
            ) from exc


@dataclass(frozen=True)
class TrustRootRotationReceipt:
    previous_key_id: str
    successor_key_id: str
    successor_public_key: bytes
    trust_epoch: int
    predecessor_digest: str
    effective_from: datetime
    effective_until: datetime
    owner_approval_id: str

    @classmethod
    def create(
        cls,
        *,
        previous: TrustRoot,
        successor: TrustRoot,
        effective_from: datetime,
        effective_until: datetime,
        owner_approval_id: str,
    ) -> TrustRootRotationReceipt:
        return cls(
            previous_key_id=previous.key_id,
            successor_key_id=successor.key_id,
            successor_public_key=successor.public_key_bytes,
            trust_epoch=successor.trust_epoch,
            predecessor_digest=previous.digest,
            effective_from=effective_from,
            effective_until=effective_until,
            owner_approval_id=owner_approval_id,
        )

    def signing_bytes(self) -> bytes:
        body = {
            "effective_from": self.effective_from.isoformat(),
            "effective_until": self.effective_until.isoformat(),
            "owner_approval_id": self.owner_approval_id,
            "predecessor_digest": self.predecessor_digest,
            "previous_key_id": self.previous_key_id,
            "successor_key_id": self.successor_key_id,
            "successor_public_key": base64.b64encode(self.successor_public_key).decode(),
            "trust_epoch": self.trust_epoch,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class TrustRootRevocationReceipt:
    revoked_key_id: str
    trust_epoch: int
    predecessor_digest: str
    effective_from: datetime
    effective_until: datetime
    revocation_reason: str

    def signing_bytes(self) -> bytes:
        body = {
            "effective_from": self.effective_from.isoformat(),
            "effective_until": self.effective_until.isoformat(),
            "predecessor_digest": self.predecessor_digest,
            "revocation_reason": self.revocation_reason,
            "revoked_key_id": self.revoked_key_id,
            "trust_epoch": self.trust_epoch,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


class TrustStore:
    def __init__(self, initial_root: TrustRoot) -> None:
        self._current = initial_root
        self._trust_epoch = initial_root.trust_epoch
        self._roots = {initial_root.key_id: initial_root}
        self._last_receipt: TrustRootRotationReceipt | None = None
        self._last_revocation: TrustRootRevocationReceipt | None = None
        self._revoked_at: dict[str, datetime] = {}

    @property
    def trust_epoch(self) -> int:
        return self._trust_epoch

    def rotate(
        self,
        receipt: TrustRootRotationReceipt,
        signature: bytes,
        *,
        now: datetime,
    ) -> TrustRootRotationReceipt:
        exact = (
            receipt.previous_key_id == self._current.key_id
            and receipt.predecessor_digest == self._current.digest
            and receipt.trust_epoch == self._trust_epoch + 1
            and receipt.effective_from <= now < receipt.effective_until
            and bool(receipt.owner_approval_id)
        )
        if not exact:
            raise PolicyVerificationError("TRUST_ROTATION_DENIED")
        if receipt.successor_key_id in self._roots or any(
            root.public_key_bytes == receipt.successor_public_key for root in self._roots.values()
        ):
            raise PolicyVerificationError("TRUST_ROOT_RESTORE_DENIED")
        self._current.verify(signature, receipt.signing_bytes())
        successor = TrustRoot(
            receipt.successor_key_id,
            receipt.trust_epoch,
            receipt.successor_public_key,
        )
        self._roots[successor.key_id] = successor
        self._current = successor
        self._trust_epoch = receipt.trust_epoch
        self._last_receipt = receipt
        return receipt

    def revoke(
        self,
        receipt: TrustRootRevocationReceipt,
        signature: bytes,
        *,
        now: datetime,
    ) -> TrustRootRevocationReceipt:
        exact = (
            receipt.revoked_key_id in self._roots
            and receipt.revoked_key_id not in self._revoked_at
            and receipt.trust_epoch == self._trust_epoch + 1
            and receipt.predecessor_digest == self._current.digest
            and receipt.effective_from <= now < receipt.effective_until
            and bool(receipt.revocation_reason)
        )
        if not exact:
            raise PolicyVerificationError("TRUST_REVOCATION_DENIED")
        self._current.verify(signature, receipt.signing_bytes())
        self._revoked_at[receipt.revoked_key_id] = receipt.effective_from
        self._trust_epoch = receipt.trust_epoch
        self._last_revocation = receipt
        return receipt

    def verify_evidence(
        self,
        payload: bytes,
        signature: bytes,
        *,
        key_id: str,
        signed_at: datetime,
    ) -> None:
        root = self._roots.get(key_id)
        if root is None:
            raise PolicyVerificationError("TRUST_ROOT_UNKNOWN")
        revoked_at = self._revoked_at.get(key_id)
        if revoked_at is not None and signed_at >= revoked_at:
            raise PolicyVerificationError("TRUST_ROOT_REVOKED")
        root.verify(signature, payload)

    def last_known_valid_root(self) -> TrustRoot:
        return self._current

    def last_known_valid_receipt(self) -> TrustRootRotationReceipt | None:
        return self._last_receipt

    def last_known_valid_revocation(self) -> TrustRootRevocationReceipt | None:
        return self._last_revocation

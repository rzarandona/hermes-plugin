from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _frame(*values: bytes) -> bytes:
    return b"".join(len(value).to_bytes(8, "big") + value for value in values)


@dataclass(frozen=True, slots=True)
class ArtifactMaterial:
    payload: bytes
    source: bytes
    provenance: bytes
    tests: bytes
    dependencies: bytes
    configuration: bytes
    sbom: bytes

    @property
    def canonical_bytes(self) -> bytes:
        return _frame(
            self.payload,
            self.source,
            self.provenance,
            self.tests,
            self.dependencies,
            self.configuration,
            self.sbom,
        )

    @property
    def material_digest(self) -> str:
        return sha256(self.canonical_bytes).hexdigest()


class SigningRootClass(StrEnum):
    LOWER_ENVIRONMENT = "lower_environment"
    PRODUCTION_HARDWARE_MANAGED = "production_hardware_managed"


@dataclass(frozen=True, slots=True)
class ProductionKeyDescriptor:
    key_id: str
    managed: bool
    non_exportable: bool
    hardware_backed: bool
    production_proof: bool


@dataclass(frozen=True, slots=True)
class SigningCapability:
    artifact_material_digest: str
    environment: str
    issued_at: datetime
    expires_at: datetime
    capability_id: str

    def assert_usable(self, *, digest: str, environment: str, now: datetime) -> None:
        if digest != self.artifact_material_digest or environment != self.environment:
            raise PermissionError("SIGNING_CAPABILITY_BINDING_MISMATCH")
        if not self.issued_at <= now < self.expires_at:
            raise PermissionError("SIGNING_CAPABILITY_EXPIRED")


@dataclass(frozen=True, slots=True)
class ArtifactSignature:
    """Signers must authenticate descriptor_bytes, including every authority claim."""

    signed_digest: str
    signature: bytes
    key_id: str
    root_class: SigningRootClass
    environment: str
    capability_id: str | None
    non_exportable: bool
    hardware_backed: bool
    production_proof: bool

    @property
    def descriptor_bytes(self) -> bytes:
        return _frame(
            self.signed_digest.encode(),
            self.key_id.encode(),
            self.root_class.value.encode(),
            self.environment.encode(),
            (self.capability_id or "").encode(),
            str(self.non_exportable).encode(),
            str(self.hardware_backed).encode(),
            str(self.production_proof).encode(),
        )

    @property
    def canonical_bytes(self) -> bytes:
        return _frame(self.descriptor_bytes, self.signature)


class SigningAdapter(Protocol):
    def sign(
        self,
        digest: str,
        *,
        environment: str,
        now: datetime,
        capability: SigningCapability | None,
    ) -> ArtifactSignature: ...

    def verify(self, signature: ArtifactSignature) -> bool: ...


class ProductionSigningAdapter(SigningAdapter, Protocol):
    @property
    def production_key_descriptor(self) -> ProductionKeyDescriptor: ...


class EphemeralSigningAdapter:
    """Repository-only fake. It is deliberately never production proof."""

    def __init__(
        self,
        *,
        lower_private_key: Ed25519PrivateKey,
        production_private_key: Ed25519PrivateKey,
    ) -> None:
        self._lower = lower_private_key
        self._production = production_private_key
        self._public: dict[str, Ed25519PublicKey] = {
            "ephemeral-lower-root": lower_private_key.public_key(),
            "ephemeral-production-hardware-model": production_private_key.public_key(),
        }

    @property
    def production_key_descriptor(self) -> ProductionKeyDescriptor:
        return ProductionKeyDescriptor(
            key_id="ephemeral-production-hardware-model",
            managed=True,
            non_exportable=True,
            hardware_backed=True,
            production_proof=False,
        )

    def sign(
        self,
        digest: str,
        *,
        environment: str,
        now: datetime,
        capability: SigningCapability | None,
    ) -> ArtifactSignature:
        if environment == "production":
            if capability is None:
                raise PermissionError("PER_ARTIFACT_SIGNING_CAPABILITY_REQUIRED")
            capability.assert_usable(digest=digest, environment=environment, now=now)
            key = self._production
            key_id = "ephemeral-production-hardware-model"
            root_class = SigningRootClass.PRODUCTION_HARDWARE_MANAGED
            capability_id: str | None = capability.capability_id
            non_exportable = True
            hardware_backed = True
        else:
            if capability is not None:
                raise PermissionError("LOWER_ENVIRONMENT_CAPABILITY_ROOT_MISMATCH")
            key = self._lower
            key_id = "ephemeral-lower-root"
            root_class = SigningRootClass.LOWER_ENVIRONMENT
            capability_id = None
            non_exportable = False
            hardware_backed = False
        descriptor = ArtifactSignature(
            signed_digest=digest,
            signature=b"",
            key_id=key_id,
            root_class=root_class,
            environment=environment,
            capability_id=capability_id,
            non_exportable=non_exportable,
            hardware_backed=hardware_backed,
            production_proof=False,
        )
        return replace(descriptor, signature=key.sign(descriptor.descriptor_bytes))

    def verify(self, signature: ArtifactSignature) -> bool:
        if signature.production_proof:
            return False
        key = self._public.get(signature.key_id)
        if key is None:
            return False
        try:
            key.verify(signature.signature, signature.descriptor_bytes)
        except InvalidSignature:
            return False
        return True


@dataclass(frozen=True, slots=True)
class BuildReceipt:
    artifact_id: str
    material_digest: str
    signature_key_id: str
    signature_root_class: SigningRootClass


@dataclass(frozen=True, slots=True)
class SignedArtifact:
    artifact_id: str
    material: ArtifactMaterial
    signature: ArtifactSignature

    def recompute_identity(self) -> str:
        return sha256(
            _frame(self.material.canonical_bytes, self.signature.canonical_bytes)
        ).hexdigest()

    @property
    def build_receipt(self) -> BuildReceipt:
        return BuildReceipt(
            self.artifact_id,
            self.material.material_digest,
            self.signature.key_id,
            self.signature.root_class,
        )


class ImmutableArtifactStore:
    def __init__(self) -> None:
        self._artifacts: dict[str, SignedArtifact] = {}

    def build_once(
        self,
        material: ArtifactMaterial,
        *,
        signer: SigningAdapter,
        environment: str,
        now: datetime,
        capability: SigningCapability | None = None,
    ) -> SignedArtifact:
        signature = signer.sign(
            material.material_digest,
            environment=environment,
            now=now,
            capability=capability,
        )
        if not signer.verify(signature) or signature.signed_digest != material.material_digest:
            raise PermissionError("ARTIFACT_SIGNATURE_INVALID")
        candidate = SignedArtifact("", material, signature)
        artifact = SignedArtifact(candidate.recompute_identity(), material, signature)
        existing = self._artifacts.setdefault(artifact.artifact_id, artifact)
        if existing != artifact:
            raise RuntimeError("ARTIFACT_IDENTITY_COLLISION")
        return existing

    def get(self, artifact_id: str) -> SignedArtifact:
        return self._artifacts[artifact_id]

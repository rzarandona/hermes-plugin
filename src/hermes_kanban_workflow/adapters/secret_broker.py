from __future__ import annotations

import hmac
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Protocol


@dataclass(frozen=True, slots=True)
class OpaqueSecretReference:
    reference_id: str

    def __post_init__(self) -> None:
        if not self.reference_id or any(char.isspace() for char in self.reference_id):
            raise ValueError("SECRET_REFERENCE_INVALID")


@dataclass(frozen=True, slots=True)
class SecretResolutionReceipt:
    reference_id: str
    resolved: bool


class SecretAuthority(Protocol):
    def use_secret(
        self, reference: OpaqueSecretReference, consumer: Callable[[str], None]
    ) -> None: ...


class SecretBroker:
    def __init__(self, authority: SecretAuthority) -> None:
        self._authority = authority

    def use(
        self, reference: OpaqueSecretReference, consumer: Callable[[str], None]
    ) -> SecretResolutionReceipt:
        if not isinstance(reference, OpaqueSecretReference):
            raise TypeError("TRUSTED_OPAQUE_SECRET_REFERENCE_REQUIRED")

        def redacting_consumer(value: str) -> None:
            try:
                consumer(value)
            except Exception:  # noqa: BLE001 - redact arbitrary consumer failures
                raise _SecretConsumerFailed from None

        try:
            self._authority.use_secret(reference, redacting_consumer)
        except _SecretConsumerFailed:
            raise RuntimeError("SECRET_USE_FAILED") from None
        except PermissionError:
            raise PermissionError("SECRET_REFERENCE_UNTRUSTED") from None
        except Exception:  # noqa: BLE001 - redact arbitrary authority failures
            raise RuntimeError("SECRET_RESOLUTION_FAILED") from None
        return SecretResolutionReceipt(reference.reference_id, True)


class _SecretConsumerFailed(Exception):
    pass


class FixtureContext(StrEnum):
    LOCAL_ONLY = "local_only"
    REMOTE = "remote"
    SHARED = "shared"
    DEPLOYMENT = "deployment"
    PRODUCTION = "production"


@dataclass(frozen=True, slots=True)
class FixtureMetadata:
    fixture_id: str
    classification: str
    signature: str
    production_eligible: bool = False


class FixtureMetadataAuthority:
    """Repository fixture authority; never production authority or WP5 evidence."""

    def __init__(self, signing_key: bytes) -> None:
        if not signing_key:
            raise ValueError("FIXTURE_SIGNING_KEY_REQUIRED")
        self._signing_key = signing_key
        self._values: dict[str, str] = {}

    def _signature(self, fixture_id: str, classification: str) -> str:
        payload = f"{fixture_id}\0{classification}\0fixture-only".encode()
        return hmac.new(self._signing_key, payload, sha256).hexdigest()

    def issue(self, *, fixture_id: str, value: str, classification: str) -> FixtureMetadata:
        if classification != "disposable_non_secret":
            raise PermissionError("DISPOSABLE_NON_SECRET_CLASSIFICATION_REQUIRED")
        self._values[fixture_id] = value
        return FixtureMetadata(fixture_id, classification, self._signature(fixture_id, classification))

    def display(
        self,
        metadata: FixtureMetadata,
        context: FixtureContext,
        local_display: Callable[[str], None],
    ) -> SecretResolutionReceipt:
        expected = self._signature(metadata.fixture_id, metadata.classification)
        if (
            metadata.fixture_id not in self._values
            or metadata.classification != "disposable_non_secret"
            or not hmac.compare_digest(metadata.signature, expected)
            or metadata.production_eligible
        ):
            raise PermissionError("FIXTURE_METADATA_UNTRUSTED")
        if context is not FixtureContext.LOCAL_ONLY:
            raise PermissionError("LOCAL_FIXTURE_CONTEXT_DENIED")
        value = self._values.pop(metadata.fixture_id)
        local_display(value)
        return SecretResolutionReceipt(metadata.fixture_id, True)

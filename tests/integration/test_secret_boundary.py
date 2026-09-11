from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, replace

import pytest

from hermes_kanban_workflow.adapters.secret_broker import (
    FixtureContext,
    FixtureMetadataAuthority,
    OpaqueSecretReference,
    SecretBroker,
    SecretResolutionReceipt,
)


class MemorySecretAuthority:
    def __init__(self, reference: OpaqueSecretReference, value: str) -> None:
        self._reference = reference
        self._value = value

    def use_secret(
        self, reference: OpaqueSecretReference, consumer: Callable[[str], None]
    ) -> None:
        if reference is not self._reference:
            raise PermissionError("SECRET_REFERENCE_UNTRUSTED")
        consumer(self._value)


def test_trusted_opaque_reference_is_resolved_only_inside_consumer() -> None:
    reference = OpaqueSecretReference("vault:item:7")
    authority = MemorySecretAuthority(reference, "real-secret-7")
    observed: list[str] = []

    receipt = SecretBroker(authority).use(reference, observed.append)

    assert observed == ["real-secret-7"]
    assert receipt == SecretResolutionReceipt(reference_id="vault:item:7", resolved=True)
    assert "real-secret-7" not in repr(receipt)
    assert "real-secret-7" not in str(asdict(receipt))


def test_forged_opaque_reference_is_denied_by_injected_authority() -> None:
    trusted = OpaqueSecretReference("vault:item:7")
    broker = SecretBroker(MemorySecretAuthority(trusted, "real-secret-7"))

    with pytest.raises(PermissionError, match="SECRET_REFERENCE_UNTRUSTED"):
        broker.use(OpaqueSecretReference("vault:item:7"), lambda _value: None)


def test_non_reference_input_is_denied_before_authority_resolution() -> None:
    broker = SecretBroker(MemorySecretAuthority(OpaqueSecretReference("vault:item:7"), "secret"))

    with pytest.raises(TypeError, match="TRUSTED_OPAQUE_SECRET_REFERENCE_REQUIRED"):
        broker.use("vault:item:7", lambda _value: None)  # type: ignore[arg-type]


def test_signed_disposable_fixture_can_be_displayed_only_through_local_sink() -> None:
    authority = FixtureMetadataAuthority(b"fixture-test-key")
    metadata = authority.issue(
        fixture_id="otp-1", value="123456", classification="disposable_non_secret"
    )
    displayed: list[str] = []

    receipt = authority.display(metadata, FixtureContext.LOCAL_ONLY, displayed.append)

    assert displayed == ["123456"]
    assert receipt.reference_id == "otp-1"
    assert "123456" not in repr(receipt)
    assert "123456" not in repr(metadata)


@pytest.mark.parametrize(
    "context",
    [
        FixtureContext.REMOTE,
        FixtureContext.SHARED,
        FixtureContext.DEPLOYMENT,
        FixtureContext.PRODUCTION,
    ],
)
def test_local_fixture_is_denied_outside_local_only_context(context: FixtureContext) -> None:
    authority = FixtureMetadataAuthority(b"fixture-test-key")
    metadata = authority.issue(
        fixture_id="bootstrap-1", value="disposable-value", classification="disposable_non_secret"
    )

    with pytest.raises(PermissionError, match="LOCAL_FIXTURE_CONTEXT_DENIED"):
        authority.display(metadata, context, lambda _value: None)


def test_forged_fixture_metadata_is_denied() -> None:
    authority = FixtureMetadataAuthority(b"fixture-test-key")
    metadata = authority.issue(
        fixture_id="otp-1", value="123456", classification="disposable_non_secret"
    )
    forged = replace(metadata, classification="secret")

    with pytest.raises(PermissionError, match="FIXTURE_METADATA_UNTRUSTED"):
        authority.display(forged, FixtureContext.LOCAL_ONLY, lambda _value: None)


def test_secret_value_never_enters_loggable_or_persistable_outputs() -> None:
    secret = "REAL-TOKEN-should-never-leak"
    reference = OpaqueSecretReference("vault:production:token")
    receipt = SecretBroker(MemorySecretAuthority(reference, secret)).use(reference, lambda _v: None)
    outputs = {
        name: [receipt, {"reference": reference.reference_id}]
        for name in (
            "prompts",
            "cards",
            "conversations",
            "evidence",
            "logs",
            "traces",
            "telemetry",
            "repository",
            "shared_environment",
        )
    }

    assert all(secret not in repr(output) for output in outputs.values())


def test_secret_value_is_removed_from_consumer_errors() -> None:
    secret = "REAL-TOKEN-error-leak"
    reference = OpaqueSecretReference("vault:production:error")

    def leaking_consumer(value: str) -> None:
        raise RuntimeError(f"failed with {value}")

    with pytest.raises(RuntimeError, match="SECRET_USE_FAILED") as failure:
        SecretBroker(MemorySecretAuthority(reference, secret)).use(reference, leaking_consumer)

    assert secret not in repr(failure.value)
    assert failure.value.__cause__ is None


def test_local_fixture_is_single_use_and_removed_after_display() -> None:
    authority = FixtureMetadataAuthority(b"fixture-test-key")
    metadata = authority.issue(
        fixture_id="otp-once", value="654321", classification="disposable_non_secret"
    )
    authority.display(metadata, FixtureContext.LOCAL_ONLY, lambda _value: None)

    with pytest.raises(PermissionError, match="FIXTURE_METADATA_UNTRUSTED"):
        authority.display(metadata, FixtureContext.LOCAL_ONLY, lambda _value: None)

    assert metadata.production_eligible is False


def test_authority_errors_are_redacted_before_crossing_broker_boundary() -> None:
    secret = "REAL-TOKEN-authority-error"

    class FailingAuthority:
        def use_secret(
            self, reference: OpaqueSecretReference, consumer: Callable[[str], None]
        ) -> None:
            raise RuntimeError(f"authority failed with {secret}")

    with pytest.raises(RuntimeError, match="SECRET_RESOLUTION_FAILED") as failure:
        SecretBroker(FailingAuthority()).use(
            OpaqueSecretReference("vault:failed"), lambda _value: None
        )

    assert secret not in repr(failure.value)
    assert failure.value.__cause__ is None

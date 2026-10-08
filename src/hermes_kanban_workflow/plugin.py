"""Explicit plugin lifecycle with no implicit activation transitions."""

from __future__ import annotations

import base64
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from hermes_kanban_workflow.activation import ActivationChain, ActivationReceipt
from hermes_kanban_workflow.command.windows_profile import WindowsProfileReceipt
from hermes_kanban_workflow.policy.compatibility import (
    CompatibilityError,
    CompatibilityReceipt,
    assert_compatible,
)
from hermes_kanban_workflow.policy.model import VerifiedPolicy


@dataclass(frozen=True)
class HostIdentity:
    agent_version: str
    desktop_version: str
    source_commit: str
    python_range: str
    manifest_version: int
    api_version: int
    os_name: str
    os_build: int
    filesystem: str


HOST_CONTRACT = HostIdentity(
    agent_version="0.20.5",
    desktop_version="0.17.0",
    source_commit="a251e87d826f4ef7c75a8927d5304e24cf43ef54",
    python_range=">=3.11,<3.14",
    manifest_version=2,
    api_version=1,
    os_name="Windows 11 24H2 x64",
    os_build=26100,
    filesystem="NTFS",
)


class ObserveContext(Protocol):
    def register_tool(
        self,
        *,
        name: str,
        toolset: str,
        schema: dict[str, object],
        handler: object,
        description: str = "",
    ) -> object: ...


@dataclass(frozen=True)
class LoadedPackage:
    digest: str
    manifest: Mapping[str, Any]
    registered: bool = False


@dataclass(frozen=True)
class ObservationHandle:
    mode: str
    package_digest: str


@dataclass(frozen=True)
class PreflightReport:
    passed: bool
    code: str
    package_digest: str
    policy_digest: str
    host: HostIdentity


@dataclass(frozen=True)
class ServiceReadinessResponse:
    payload: Mapping[str, Any]
    signature: str


class ServiceReadinessVerifier:
    """Authority-owned verifier configuration; fixture roots never pass production preflight."""

    def __init__(self, public_key: bytes, *, service_identity: str, production_authority: bool) -> None:
        self._public_key = public_key
        self.service_identity = service_identity
        self.production_authority = production_authority

    def verify(self, response: object, expected: Mapping[str, Any]) -> bool:
        if not self.production_authority or not isinstance(response, ServiceReadinessResponse):
            return False
        if dict(response.payload) != dict(expected):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(self._public_key).verify(
                base64.b64decode(response.signature, validate=True), _canonical_readiness(response.payload)
            )
        except (InvalidSignature, ValueError):
            return False
        return True


def _canonical_readiness(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _digest(value: Mapping[str, Any]) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_package(bundle: Mapping[str, Any]) -> LoadedPackage:
    if bundle.get("manifest_version") != 2 or bundle.get("api_version") != 1:
        raise ValueError("PLUGIN_MANIFEST_UNSUPPORTED")
    return LoadedPackage(digest=_digest(bundle), manifest=dict(bundle))


def register_observe_only(
    ctx: ObserveContext,
    package: LoadedPackage,
    compatibility: CompatibilityReceipt,
) -> ObservationHandle:
    assert_compatible(
        compatibility.host_version,
        compatibility.plugin_version,
        compatibility.executor_version,
        compatibility.policy_version,
    )
    ctx.register_tool(
        name="kanban_status",
        toolset="kanban-workflow",
        schema={
            "name": "kanban_status",
            "description": "Read the standalone workflow plugin status.",
            "parameters": {
                "type": "object", "properties": {}, "additionalProperties": False,
            },
        },
        handler=lambda args=None, **kwargs: json.dumps(
            {"error": "NO_ARGUMENTS_ACCEPTED"} if args else {"mode": "observe-only"}
        ),
        description="Read the standalone workflow plugin status.",
    )
    return ObservationHandle(mode="observe-only", package_digest=package.digest)


def run_preflight(
    package: LoadedPackage,
    policy: object,
    host: HostIdentity,
    *,
    now: datetime | None = None,
    windows_profile: WindowsProfileReceipt | None = None,
    readiness_response: ServiceReadinessResponse | None = None,
    readiness_verifier: ServiceReadinessVerifier | None = None,
    nonce: str | None = None,
    client_identity: str = "hermes-kanban-workflow",
) -> PreflightReport:
    policy_digest = policy.digest if isinstance(policy, VerifiedPolicy) else "unverified"
    if host != HOST_CONTRACT:
        return PreflightReport(
            False, "HOST_COMPATIBILITY_UNSUPPORTED", package.digest, policy_digest, host
        )
    if not isinstance(policy, VerifiedPolicy):
        return PreflightReport(
            False, "POLICY_VERIFICATION_REQUIRED", package.digest, policy_digest, host
        )
    if not policy.is_usable(now or datetime.now(UTC)):
        return PreflightReport(
            False, "POLICY_EXPIRED", package.digest, policy_digest, host
        )
    compatibility = policy.document.compatibility
    try:
        assert_compatible(
            compatibility.host_version,
            compatibility.plugin_version,
            compatibility.executor_version,
            compatibility.policy_version,
        )
    except CompatibilityError:
        return PreflightReport(
            False, "COMPATIBILITY_UNSUPPORTED", package.digest, policy_digest, host
        )
    current = now or datetime.now(UTC)
    if readiness_response is not None and readiness_verifier is not None and nonce is not None:
        del current, readiness_response, readiness_verifier, nonce, client_identity
        return PreflightReport(
            False,
            "AUTHENTICATED_EXTERNAL_SERVICE_AUTHORITY_REQUIRED",
            package.digest,
            policy_digest,
            host,
        )
    if windows_profile is not None and windows_profile.enforcement_eligible:
        return PreflightReport(
            False,
            "AUTHENTICATED_SERVICE_READINESS_REQUIRED",
            package.digest,
            policy_digest,
            host,
        )
    if windows_profile is None or not windows_profile.enforcement_eligible:
        return PreflightReport(
            False,
            "EXTERNAL_WINDOWS_PROFILE_EVIDENCE_REQUIRED",
            package.digest,
            policy_digest,
            host,
        )
    raise AssertionError("unreachable")


def activate_enforcement(
    chain: ActivationChain,
    *,
    entry: object,
    passed: object,
    review: object,
    owner: object,
    now: datetime,
) -> ActivationReceipt:
    """Public in-process activation is unavailable without the authenticated service."""
    del chain, entry, passed, review, owner, now
    raise PermissionError("AUTHENTICATED_SERVICE_ACTIVATION_REQUIRED")

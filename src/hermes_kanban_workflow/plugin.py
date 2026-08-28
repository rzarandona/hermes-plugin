"""Explicit plugin lifecycle with no implicit activation transitions."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Mapping, Protocol


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
    def register_tool(self, name: str, handler: object) -> None: ...


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
class OwnerDecision:
    stage: int
    package_digest: str
    policy_digest: str


@dataclass(frozen=True)
class EnforcementHandle:
    stage: int
    package_digest: str


def _digest(value: Mapping[str, Any]) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_package(bundle: Mapping[str, Any]) -> LoadedPackage:
    if bundle.get("manifest_version") != 2 or bundle.get("api_version") != 1:
        raise ValueError("PLUGIN_MANIFEST_UNSUPPORTED")
    return LoadedPackage(digest=_digest(bundle), manifest=dict(bundle))


def register_observe_only(ctx: ObserveContext, package: LoadedPackage) -> ObservationHandle:
    ctx.register_tool("kanban_status", lambda: {"mode": "observe-only"})
    return ObservationHandle(mode="observe-only", package_digest=package.digest)


def run_preflight(
    package: LoadedPackage, policy: Mapping[str, Any], host: HostIdentity
) -> PreflightReport:
    policy_digest = _digest(policy)
    if host != HOST_CONTRACT:
        return PreflightReport(
            False, "HOST_COMPATIBILITY_UNSUPPORTED", package.digest, policy_digest, host
        )
    if policy.get("signed") is not True:
        return PreflightReport(False, "POLICY_SIGNATURE_INVALID", package.digest, policy_digest, host)
    return PreflightReport(True, "PASS", package.digest, policy_digest, host)


def activate_enforcement(
    preflight: PreflightReport, owner_decision: OwnerDecision
) -> EnforcementHandle:
    exact = (
        preflight.passed
        and owner_decision.stage == 1
        and owner_decision.package_digest == preflight.package_digest
        and owner_decision.policy_digest == preflight.policy_digest
    )
    if not exact:
        raise PermissionError("ACTIVATION_ENTRY_DENIED")
    return EnforcementHandle(owner_decision.stage, preflight.package_digest)


"""Verified package identity, upgrades, and side-effect-free bundle inspection."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

from hermes_kanban_workflow.activation import ActivationReceipt

PLUGIN_ID = "hermes-kanban-workflow"
PLUGIN_VERSION = "0.1.0"
AGENT_VERSION = "0.20.5"
DESKTOP_VERSION = "0.17.0"
SOURCE_COMMIT = "a251e87d826f4ef7c75a8927d5304e24cf43ef54"
PYTHON_RANGE = ">=3.11,<3.14"
MANIFEST_VERSION = 2
API_VERSION = 1


@dataclass(frozen=True)
class BundleInspection:
    valid: bool
    code: str
    install_relative_root: str | None
    agent_half_present: bool
    desktop_half_present: bool
    agent_enabled: bool = False
    desktop_enabled: bool = False


@dataclass(frozen=True)
class PackageState:
    version: str
    package_digest: str
    policy_digest: str
    trust_id: str
    trust_epoch: int
    package_path: Path


@dataclass(frozen=True)
class VerifiedUpgradeEvidence:
    candidate: PackageState
    host_digest: str
    compatibility_digest: str
    policy_digest: str
    package_bytes_digest: str
    nonce: str
    authority: str
    production_proof: bool = False


@dataclass(frozen=True)
class UpgradeDecision:
    allowed: bool
    code: str


PackageVerifier = Callable[[VerifiedUpgradeEvidence], bool]
ActivationReader = Callable[[], ActivationReceipt | None]


class UpgradeManager:
    """Consumes authority-verified evidence; caller claims can never expand trust."""

    def __init__(self, active: PackageState, *, history: tuple[str, ...], package_verifier: PackageVerifier, activation_reader: ActivationReader) -> None:
        self.active = active
        self.last_known_compatible = active
        self.staged: PackageState | None = None
        self.history = history
        self._history_digest = sha256("\0".join(history).encode()).hexdigest()
        self._package_verifier = package_verifier
        self._activation_reader = activation_reader
        self._used_nonces: set[str] = set()

    @staticmethod
    def _bytes_match(state: PackageState) -> bool:
        return state.package_path.is_file() and sha256(state.package_path.read_bytes()).hexdigest() == state.package_digest

    def stage(self, evidence: object) -> UpgradeDecision:
        self.staged = None
        if not isinstance(evidence, VerifiedUpgradeEvidence) or not self._package_verifier(evidence):
            return UpgradeDecision(False, "VERIFIED_UPGRADE_EVIDENCE_REQUIRED")
        candidate = evidence.candidate
        exact = (
            evidence.production_proof
            and evidence.nonce not in self._used_nonces
            and evidence.policy_digest == candidate.policy_digest == self.active.policy_digest
            and evidence.package_bytes_digest == candidate.package_digest
            and bool(evidence.host_digest)
            and bool(evidence.compatibility_digest)
            and candidate.trust_epoch >= self.active.trust_epoch
            and self._bytes_match(candidate)
        )
        if not exact:
            return UpgradeDecision(False, "UPGRADE_VERIFICATION_DENIED")
        self._used_nonces.add(evidence.nonce)
        self.staged = candidate
        return UpgradeDecision(True, "UPGRADE_STAGED")

    def promote(self, **caller_claims: object) -> UpgradeDecision:
        if caller_claims:
            return UpgradeDecision(False, "VERIFIED_ACTIVATION_READBACK_REQUIRED")
        if self.staged is None:
            return UpgradeDecision(False, "UPGRADE_ACTIVATION_DENIED")
        receipt = self._activation_reader()
        exact = (
            isinstance(receipt, ActivationReceipt)
            and receipt.stage == 10
            and receipt.package_digest == self.staged.package_digest
            and receipt.policy_digest == self.staged.policy_digest
            and receipt.plugin_version == self.staged.version
            and bool(receipt.host_digest)
            and bool(receipt.receipt_digest)
            and sha256("\0".join(self.history).encode()).hexdigest() == self._history_digest
        )
        if not exact:
            return UpgradeDecision(False, "VERIFIED_ACTIVATION_READBACK_REQUIRED")
        self.last_known_compatible = self.active
        self.active = self.staged
        self.staged = None
        return UpgradeDecision(True, "UPGRADE_PROMOTED")

    def rollback(self) -> UpgradeDecision:
        if not self._bytes_match(self.last_known_compatible):
            return UpgradeDecision(False, "ROLLBACK_PACKAGE_IDENTITY_DENIED")
        if sha256("\0".join(self.history).encode()).hexdigest() != self._history_digest:
            return UpgradeDecision(False, "UPGRADE_HISTORY_INTEGRITY_DENIED")
        self.active = self.last_known_compatible
        self.staged = None
        return UpgradeDecision(True, "LAST_KNOWN_COMPATIBLE_RESTORED")


@dataclass(frozen=True)
class DiscoveryDecision:
    allowed: bool
    code: str


def resolve_discovery_source(plugin_root: Path, *, hermes_home: Path) -> DiscoveryDecision:
    expected = (hermes_home / "plugins" / PLUGIN_ID).resolve()
    return DiscoveryDecision(plugin_root.resolve() == expected, "PASS" if plugin_root.resolve() == expected else "PROJECT_LOCAL_ACTIVATION_DENIED")


def inspect_plugin_bundle(path: Path) -> BundleInspection:
    with ZipFile(path) as archive:
        names = {PurePosixPath(name).as_posix().rstrip("/") for name in archive.namelist()}
    root = PLUGIN_ID
    agent = {f"{root}/plugin.yaml", f"{root}/__init__.py"} <= names
    desktop = f"{root}/desktop/plugin.js" in names
    dashboard = f"{root}/dashboard/manifest.json" in names
    valid = agent and desktop and dashboard and all(name == root or name.startswith(f"{root}/") for name in names)
    return BundleInspection(valid, "PASS" if valid else "PLUGIN_BUNDLE_LAYOUT_DENIED", f"plugins/{root}" if valid else None, agent, desktop)

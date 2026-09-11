from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class ArtifactLocatorCode(StrEnum):
    OPENED = "ARTIFACT_OPENED"
    REVEALED = "ARTIFACT_REVEALED"
    UNSUPPORTED = "ARTIFACT_LOCATOR_UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class ArtifactDeliverable:
    identity: str
    label: str
    canonical_locator: str

    def __post_init__(self) -> None:
        if not self.identity or not self.label or not self.canonical_locator:
            raise ValueError("ARTIFACT_IDENTITY_LABEL_LOCATOR_REQUIRED")


@dataclass(frozen=True, slots=True)
class HostCapabilitySet:
    declared: frozenset[str]
    verified: frozenset[str]


@dataclass(frozen=True, slots=True)
class ArtifactActionReceipt:
    action: str
    canonical_locator: str
    succeeded: bool
    verified: bool


@dataclass(frozen=True, slots=True)
class ArtifactLocatorResult:
    code: ArtifactLocatorCode
    deliverable: ArtifactDeliverable
    action: str | None
    manual_route: str
    release_ready: bool


class ArtifactHost(Protocol):
    def invoke_artifact_action(self, action: str, locator: str) -> ArtifactActionReceipt: ...


class ArtifactLocator:
    def __init__(self, host: ArtifactHost, capabilities: HostCapabilitySet) -> None:
        self._host = host
        self._capabilities = capabilities

    def locate(self, deliverable: ArtifactDeliverable) -> ArtifactLocatorResult:
        action = next(
            (
                candidate
                for candidate in ("open_artifact", "show_in_file_explorer")
                if candidate in self._capabilities.declared
                and candidate in self._capabilities.verified
            ),
            None,
        )
        manual_route = f"Open File Explorer and navigate to: {deliverable.canonical_locator}"
        if action is None:
            return ArtifactLocatorResult(
                ArtifactLocatorCode.UNSUPPORTED, deliverable, None, manual_route, False
            )
        try:
            receipt = self._host.invoke_artifact_action(action, deliverable.canonical_locator)
        except Exception:  # noqa: BLE001 - host adapters may fail arbitrarily
            return ArtifactLocatorResult(
                ArtifactLocatorCode.UNSUPPORTED, deliverable, action, manual_route, False
            )
        if (
            not receipt.succeeded
            or not receipt.verified
            or receipt.action != action
            or receipt.canonical_locator != deliverable.canonical_locator
        ):
            return ArtifactLocatorResult(
                ArtifactLocatorCode.UNSUPPORTED, deliverable, action, manual_route, False
            )
        code = (
            ArtifactLocatorCode.OPENED
            if action == "open_artifact"
            else ArtifactLocatorCode.REVEALED
        )
        return ArtifactLocatorResult(code, deliverable, action, manual_route, True)

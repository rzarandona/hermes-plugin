from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ArtifactLocator:
    label: str
    canonical_path: str
    supported: bool

    def to_dict(self) -> dict[str, str]:
        return {
            "label": self.label,
            "canonical_path": self.canonical_path,
            "outcome": "OPEN_ARTIFACT" if self.supported else "ARTIFACT_LOCATOR_UNSUPPORTED",
            "manual_route": self.canonical_path,
        }


@dataclass(frozen=True)
class OwnerBrief:
    requested_outcome: str
    accomplishment: str
    impact: str
    verification: str
    remaining_risk: str
    next_action: str
    artifact: ArtifactLocator | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        if self.artifact:
            value["artifact"] = self.artifact.to_dict()
        return value


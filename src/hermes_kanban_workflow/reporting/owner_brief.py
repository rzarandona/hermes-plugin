from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from hermes_kanban_workflow.reporting.artifact_locator import ArtifactLocatorResult
from hermes_kanban_workflow.reporting.technical_packet import PMRoute, TypedVerdict


@dataclass(frozen=True, slots=True)
class ArtifactLocatorSummary:
    identity: str
    label: str
    canonical_locator: str
    code: str
    manual_route: str


@dataclass(frozen=True, slots=True)
class VerificationSummary:
    result: str
    verdict: TypedVerdict
    accountability: str
    technical_packet_link: str
    artifact_locators: tuple[ArtifactLocatorSummary, ...] = ()


@dataclass(frozen=True, slots=True)
class ArtifactLocator:
    """Compatibility view for the pre-WP12 prototype constructor."""

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


@dataclass(frozen=True, init=False)
class OwnerBrief:
    requested_outcome: str
    accomplished: str
    product_impact: str
    verification: VerificationSummary | str
    remaining_risk: str
    next_action: str

    def __init__(
        self,
        requested_outcome: str,
        accomplished: str | None = None,
        product_impact: str | None = None,
        verification: VerificationSummary | str = "",
        remaining_risk: str = "",
        next_action: str = "",
        *,
        accomplishment: str | None = None,
        impact: str | None = None,
        artifact: ArtifactLocator | None = None,
    ) -> None:
        resolved_accomplished = accomplished if accomplished is not None else accomplishment
        resolved_impact = product_impact if product_impact is not None else impact
        if resolved_accomplished is None or resolved_impact is None:
            raise TypeError("OWNER_BRIEF_SIX_FIELDS_REQUIRED")
        object.__setattr__(self, "requested_outcome", requested_outcome)
        object.__setattr__(self, "accomplished", resolved_accomplished)
        object.__setattr__(self, "product_impact", resolved_impact)
        object.__setattr__(self, "verification", verification)
        object.__setattr__(self, "remaining_risk", remaining_risk)
        object.__setattr__(self, "next_action", next_action)
        object.__setattr__(self, "_legacy_artifact", artifact)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        artifact = getattr(self, "_legacy_artifact", None)
        if artifact is not None:
            value["artifact"] = artifact.to_dict()
        return value


def build_owner_brief(
    route: PMRoute,
    *,
    requested_outcome: str,
    accomplished: str,
    product_impact: str,
    verification_result: str,
    remaining_risk: str,
    next_action: str,
    artifact_locators: tuple[ArtifactLocatorResult, ...] = (),
) -> OwnerBrief:
    prefix = f"{route.verdict.value}:"
    result = verification_result
    if not result.startswith(prefix):
        result = f"{prefix} {result}"
    return OwnerBrief(
        requested_outcome=requested_outcome,
        accomplished=accomplished,
        product_impact=product_impact,
        verification=VerificationSummary(
            result=result,
            verdict=route.verdict,
            accountability=route.accountability,
            technical_packet_link=route.technical_route,
            artifact_locators=tuple(
                ArtifactLocatorSummary(
                    identity=item.deliverable.identity,
                    label=item.deliverable.label,
                    canonical_locator=item.deliverable.canonical_locator,
                    code=item.code.value,
                    manual_route=item.manual_route,
                )
                for item in artifact_locators
            ),
        ),
        remaining_risk=remaining_risk,
        next_action=next_action,
    )

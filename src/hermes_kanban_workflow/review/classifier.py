from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DeliveryProfile(StrEnum):
    RESEARCH_ONLY = "research-only"
    BOUNDED_IMPLEMENTATION = "bounded-implementation"
    COORDINATED_IMPLEMENTATION = "coordinated-implementation"
    DESIGN_REQUIRED = "design-required"
    PROTECTED_EFFECTFUL = "protected-effectful"


@dataclass(frozen=True)
class IntakeFacts:
    mutates_product: bool
    modules: int
    protected: bool
    external_effect: bool
    design_unknown: bool
    dependencies: tuple[str, ...]


@dataclass(frozen=True)
class DeliveryDecision:
    profile: DeliveryProfile
    required_reviews: int
    requires_gatekeeper: bool


class DeliveryClassifier:
    def classify(self, facts: IntakeFacts) -> DeliveryDecision:
        if not facts.mutates_product:
            return DeliveryDecision(DeliveryProfile.RESEARCH_ONLY, 0, False)
        if facts.protected or facts.external_effect:
            profile = DeliveryProfile.PROTECTED_EFFECTFUL
        elif facts.design_unknown:
            profile = DeliveryProfile.DESIGN_REQUIRED
        elif facts.modules > 2 or facts.dependencies:
            profile = DeliveryProfile.COORDINATED_IMPLEMENTATION
        else:
            profile = DeliveryProfile.BOUNDED_IMPLEMENTATION
        return DeliveryDecision(profile, 2, True)


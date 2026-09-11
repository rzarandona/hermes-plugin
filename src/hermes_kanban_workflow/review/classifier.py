from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any, Literal

from pydantic import Field

from hermes_kanban_workflow.domain.identity import FrozenModel
from hermes_kanban_workflow.policy.model import VerifiedPolicy


class DeliveryProfile(StrEnum):
    RESEARCH_ONLY = "research_only"
    BOUNDED_IMPLEMENTATION = "bounded_implementation"
    COORDINATED_IMPLEMENTATION = "coordinated_implementation"
    DESIGN_REQUIRED = "design_required"
    PROTECTED_OR_EFFECTFUL = "protected_or_effectful"


class ClassificationFacts(FrozenModel):
    product_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    workspace_id: str = Field(min_length=1)
    mutates_product: bool
    modules: tuple[str, ...]
    dependency_product_ids: tuple[str, ...]
    migration: bool
    protected_subsystems: tuple[str, ...]
    external_effect: bool
    deployment: bool
    material_configuration: bool
    uncertain_dependencies: bool
    design_unknown: bool

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


class ClassificationReceipt(FrozenModel):
    command_type: Literal["classify_delivery_profile"] = "classify_delivery_profile"
    facts_digest: str
    profile: DeliveryProfile
    classification_status: Literal[
        "accepted_signed_row", "accountable_evidence_required"
    ]
    evidence_source: Literal[
        "signed_classifier_policy", "accountable_pm_or_read_only_auditor"
    ]
    policy_digest: str | None
    policy_row_digest: str | None
    required_evidence_roles: tuple[Literal["accountable_pm", "read_only_auditor"], ...] = ()
    authority_granted: bool = False
    reason_code: str

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


def _row_digest(row: dict[str, Any]) -> str:
    return sha256(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def classify_delivery_profile(
    facts: ClassificationFacts,
    policy: VerifiedPolicy | None,
    *,
    protected_registry: frozenset[str],
    now: datetime | None = None,
) -> ClassificationReceipt:
    checked_at = now or datetime.now(UTC)
    if policy is not None and policy.is_usable(checked_at):
        rows = policy.document.rules.get("classifier_rows")
        if isinstance(rows, list):
            exact_rows = [
                row
                for row in rows
                if isinstance(row, dict)
                and row.get("facts_digest") == facts.digest
                and row.get("allowed_modules") == list(facts.modules)
            ]
            if len(exact_rows) == 1:
                row = exact_rows[0]
                profile_value = row.get("profile")
                try:
                    if not isinstance(profile_value, str):
                        raise TypeError("classifier profile must be a string")
                    profile = DeliveryProfile(profile_value)
                except (TypeError, ValueError):
                    pass
                else:
                    if facts.uncertain_dependencies or facts.design_unknown:
                        return ClassificationReceipt(
                            facts_digest=facts.digest,
                            profile=DeliveryProfile.DESIGN_REQUIRED,
                            classification_status="accountable_evidence_required",
                            evidence_source="accountable_pm_or_read_only_auditor",
                            policy_digest=policy.digest,
                            policy_row_digest=_row_digest(row),
                            required_evidence_roles=(
                                "accountable_pm",
                                "read_only_auditor",
                            ),
                            reason_code="CLASSIFICATION_UNCERTAINTY_ESCALATED",
                        )
                    if profile is DeliveryProfile.BOUNDED_IMPLEMENTATION:
                        protected = bool(facts.protected_subsystems) or bool(
                            protected_registry.intersection(facts.modules)
                        )
                        effectful = (
                            facts.migration
                            or protected
                            or facts.external_effect
                            or facts.deployment
                            or facts.material_configuration
                        )
                        uncertain = facts.uncertain_dependencies or facts.design_unknown
                        module_limit = row.get("module_limit")
                        module_limit_valid = (
                            isinstance(module_limit, int)
                            and not isinstance(module_limit, bool)
                            and len(facts.modules) <= module_limit
                        )
                        one_product = all(
                            dependency == facts.product_id
                            for dependency in facts.dependency_product_ids
                        )
                        if effectful or uncertain or not module_limit_valid or not one_product:
                            safer = (
                                DeliveryProfile.PROTECTED_OR_EFFECTFUL
                                if effectful
                                else DeliveryProfile.DESIGN_REQUIRED
                            )
                            return ClassificationReceipt(
                                facts_digest=facts.digest,
                                profile=safer,
                                classification_status="accountable_evidence_required",
                                evidence_source="accountable_pm_or_read_only_auditor",
                                policy_digest=policy.digest,
                                policy_row_digest=_row_digest(row),
                                required_evidence_roles=(
                                    "accountable_pm",
                                    "read_only_auditor",
                                ),
                                reason_code="BOUNDED_RISK_OR_UNCERTAINTY_DENIED",
                            )
                    return ClassificationReceipt(
                        facts_digest=facts.digest,
                        profile=profile,
                        classification_status="accepted_signed_row",
                        evidence_source="signed_classifier_policy",
                        policy_digest=policy.digest,
                        policy_row_digest=_row_digest(row),
                        reason_code="EXACT_SIGNED_CLASSIFIER_ROW",
                    )
    return ClassificationReceipt(
        facts_digest=facts.digest,
        profile=DeliveryProfile.DESIGN_REQUIRED,
        classification_status="accountable_evidence_required",
        evidence_source="accountable_pm_or_read_only_auditor",
        policy_digest=policy.digest if policy is not None else None,
        policy_row_digest=None,
        required_evidence_roles=("accountable_pm", "read_only_auditor"),
        reason_code="EXACT_SIGNED_CLASSIFIER_ROW_REQUIRED",
    )


# Compatibility surface: legacy structured facts can produce a proposal only; this API never grants authority.
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
            profile = DeliveryProfile.PROTECTED_OR_EFFECTFUL
        elif facts.design_unknown:
            profile = DeliveryProfile.DESIGN_REQUIRED
        elif facts.modules > 2 or facts.dependencies:
            profile = DeliveryProfile.COORDINATED_IMPLEMENTATION
        else:
            profile = DeliveryProfile.BOUNDED_IMPLEMENTATION
        return DeliveryDecision(profile, 2, True)

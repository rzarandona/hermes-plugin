from __future__ import annotations

import json
from collections.abc import Callable
from enum import StrEnum
from hashlib import sha256

from pydantic import Field

from hermes_kanban_workflow.domain.identity import FrozenModel
from hermes_kanban_workflow.policy.model import VerifiedPolicy
from hermes_kanban_workflow.review.classifier import (
    ClassificationFacts,
    ClassificationReceipt,
    DeliveryProfile,
    classify_delivery_profile,
)


class OwnerProfileChoice(StrEnum):
    APPROVE_PROPOSED_PROFILE = "approve_proposed_profile"
    REQUEST_SPEC_OR_PLAN = "request_spec_or_plan"
    REQUEST_UX_ARTIFACT = "request_ux_artifact"
    REQUEST_CLARIFICATION_OR_RECLASSIFICATION = "request_clarification_or_reclassification"
    DEFER = "defer"
    REJECT = "reject"


class OwnerProfileDecisionCommand(FrozenModel):
    command_type: str = "record_owner_profile_decision"
    decision_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1)
    proposed_profile: DeliveryProfile
    classification_digest: str = Field(min_length=1)
    choice: OwnerProfileChoice
    free_text: str | None = None

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


class OwnerProfileDecisionReceipt(FrozenModel):
    command_type: str = "record_owner_profile_decision"
    decision_id: str
    request_id: str
    choice: OwnerProfileChoice
    proposed_profile: DeliveryProfile
    classification_digest: str
    granted_profile: DeliveryProfile | None
    authority_expanded: bool = False
    command_digest: str

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


def record_owner_profile_decision(
    command: OwnerProfileDecisionCommand,
    classification: ClassificationReceipt,
) -> OwnerProfileDecisionReceipt:
    if (
        command.classification_digest != classification.digest
        or command.proposed_profile is not classification.profile
    ):
        raise PermissionError("OWNER_PROFILE_PROPOSAL_MISMATCH")
    granted = (
        command.proposed_profile
        if command.choice is OwnerProfileChoice.APPROVE_PROPOSED_PROFILE
        else None
    )
    return OwnerProfileDecisionReceipt(
        decision_id=command.decision_id,
        request_id=command.request_id,
        choice=command.choice,
        proposed_profile=command.proposed_profile,
        classification_digest=classification.digest,
        granted_profile=granted,
        command_digest=command.digest,
    )


class IntakeRequest(FrozenModel):
    request_id: str = Field(min_length=1)
    product_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    workspace_id: str = Field(min_length=1)
    dependency_product_ids: tuple[str, ...]
    actionable_content: object


class ProductBinding(FrozenModel):
    product_id: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    project_ids: frozenset[str]
    workspace_ids: frozenset[str]
    dependency_product_ids: frozenset[str]


class RejectWrongProductReceipt(FrozenModel):
    command_type: str = "reject_wrong_product"
    request_id: str
    presented_product_id: str
    expected_product_id: str
    correct_destination: str
    card_created: bool = False
    forwarded: bool = False

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


def reject_wrong_product(
    request: IntakeRequest,
    binding: ProductBinding,
    *,
    effect_recorder: Callable[[str], None] | None = None,
) -> RejectWrongProductReceipt:
    del effect_recorder
    return RejectWrongProductReceipt(
        request_id=request.request_id,
        presented_product_id=request.product_id,
        expected_product_id=binding.product_id,
        correct_destination=binding.destination,
    )


def _binding_is_exact(request: IntakeRequest, binding: ProductBinding) -> bool:
    return (
        request.product_id == binding.product_id
        and request.project_id in binding.project_ids
        and request.workspace_id in binding.workspace_ids
        and frozenset(request.dependency_product_ids) == binding.dependency_product_ids
    )


def handle_flow1_intake(
    request: IntakeRequest,
    binding: ProductBinding,
    facts: ClassificationFacts,
    policy: VerifiedPolicy | None,
    *,
    protected_registry: frozenset[str],
    effect_recorder: Callable[[str], None] | None = None,
) -> RejectWrongProductReceipt | ClassificationReceipt:
    # Identity and exact bindings are deliberately checked before actionable content or facts.
    if not _binding_is_exact(request, binding):
        return reject_wrong_product(request, binding)
    facts_are_bound = (
        facts.product_id == request.product_id
        and facts.project_id == request.project_id
        and facts.workspace_id == request.workspace_id
        and facts.dependency_product_ids == request.dependency_product_ids
    )
    if not facts_are_bound:
        return reject_wrong_product(request, binding)
    receipt = classify_delivery_profile(
        facts, policy, protected_registry=protected_registry
    )
    if receipt.classification_status == "accepted_signed_row" and effect_recorder is not None:
        effect_recorder("card_created")
    return receipt

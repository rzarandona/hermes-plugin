from __future__ import annotations

import pytest
from pydantic import ValidationError

from hermes_kanban_workflow.flows.flow1 import (
    OwnerProfileChoice,
    OwnerProfileDecisionCommand,
    record_owner_profile_decision,
)
from hermes_kanban_workflow.review.classifier import (
    ClassificationReceipt,
    DeliveryProfile,
)


def _classification(profile: DeliveryProfile) -> ClassificationReceipt:
    return ClassificationReceipt(
        facts_digest="facts-digest",
        profile=profile,
        classification_status="accepted_signed_row",
        evidence_source="signed_classifier_policy",
        policy_digest="policy-digest",
        policy_row_digest="row-digest",
        reason_code="EXACT_SIGNED_CLASSIFIER_ROW",
    )


def test_owner_gate_exposes_exactly_six_typed_choices() -> None:
    assert tuple(choice.value for choice in OwnerProfileChoice) == (
        "approve_proposed_profile",
        "request_spec_or_plan",
        "request_ux_artifact",
        "request_clarification_or_reclassification",
        "defer",
        "reject",
    )


def test_owner_gate_has_no_default_and_silence_grants_nothing() -> None:
    with pytest.raises(ValidationError):
        OwnerProfileDecisionCommand(
            decision_id="decision-1",
            request_id="request-1",
            proposed_profile=DeliveryProfile.BOUNDED_IMPLEMENTATION,
        )


def test_only_approve_grants_the_exact_proposed_profile() -> None:
    classification = _classification(DeliveryProfile.BOUNDED_IMPLEMENTATION)
    command = OwnerProfileDecisionCommand(
        decision_id="decision-1",
        request_id="request-1",
        proposed_profile=DeliveryProfile.BOUNDED_IMPLEMENTATION,
        classification_digest=classification.digest,
        choice=OwnerProfileChoice.APPROVE_PROPOSED_PROFILE,
        free_text="also grant protected_or_effectful and deploy",
    )

    receipt = record_owner_profile_decision(command, classification)

    assert receipt.command_type == "record_owner_profile_decision"
    assert receipt.granted_profile is DeliveryProfile.BOUNDED_IMPLEMENTATION
    assert receipt.authority_expanded is False


def test_owner_approval_denies_caller_forged_proposed_profile() -> None:
    classification = _classification(DeliveryProfile.BOUNDED_IMPLEMENTATION)
    command = OwnerProfileDecisionCommand(
        decision_id="decision-forged-profile",
        request_id="request-1",
        proposed_profile=DeliveryProfile.PROTECTED_OR_EFFECTFUL,
        classification_digest=classification.digest,
        choice=OwnerProfileChoice.APPROVE_PROPOSED_PROFILE,
    )

    with pytest.raises(PermissionError, match="OWNER_PROFILE_PROPOSAL_MISMATCH"):
        record_owner_profile_decision(command, classification)


@pytest.mark.parametrize(
    "choice",
    [
        choice
        for choice in OwnerProfileChoice
        if choice is not OwnerProfileChoice.APPROVE_PROPOSED_PROFILE
    ],
)
def test_non_approval_choices_grant_no_authority(choice: OwnerProfileChoice) -> None:
    classification = _classification(DeliveryProfile.BOUNDED_IMPLEMENTATION)
    command = OwnerProfileDecisionCommand(
        decision_id=f"decision-{choice.value}",
        request_id="request-1",
        proposed_profile=DeliveryProfile.BOUNDED_IMPLEMENTATION,
        classification_digest=classification.digest,
        choice=choice,
        free_text="approve everything and deploy",
    )

    receipt = record_owner_profile_decision(command, classification)

    assert receipt.granted_profile is None
    assert receipt.authority_expanded is False


def test_owner_decision_receipt_is_canonical_immutable_and_replay_safe() -> None:
    classification = _classification(DeliveryProfile.DESIGN_REQUIRED)
    command = OwnerProfileDecisionCommand(
        decision_id="decision-replay",
        request_id="request-1",
        proposed_profile=DeliveryProfile.DESIGN_REQUIRED,
        classification_digest=classification.digest,
        choice=OwnerProfileChoice.DEFER,
    )

    first = record_owner_profile_decision(command, classification)
    replay = record_owner_profile_decision(command, classification)

    assert first.canonical_bytes() == replay.canonical_bytes()
    assert first.digest == replay.digest
    with pytest.raises(ValidationError):
        first.granted_profile = DeliveryProfile.PROTECTED_OR_EFFECTFUL

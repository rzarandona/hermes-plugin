from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from hermes_kanban_workflow.review.verdicts import (
    BlindReviewSession,
    ReviewAssignment,
    ReviewSubmission,
    ReviewVerdict,
    SelfVerification,
    seal_authenticated_reviews,
    seal_independent_reviews,
    select_review_lenses,
)
from tests.policy_fixtures import verified_policy


def test_implementer_self_verification_requires_all_checks_and_evidence() -> None:
    with pytest.raises(ValidationError):
        SelfVerification(
            candidate_digest="candidate-1",
            tdd=True,
            tests=True,
            static_checks=True,
            acceptance_comparison=False,
            evidence_refs=("ledger:event:1",),
        )

    packet = SelfVerification(
        candidate_digest="candidate-1",
        tdd=True,
        tests=True,
        static_checks=True,
        acceptance_comparison=True,
        evidence_refs=("ledger:event:1",),
    )
    assert packet.is_independent_review is False


def _self_verification() -> SelfVerification:
    return SelfVerification(
        candidate_digest="candidate-1",
        tdd=True,
        tests=True,
        static_checks=True,
        acceptance_comparison=True,
        evidence_refs=("ledger:self",),
    )


def test_two_blind_reviews_are_sealed_with_correctness_and_risk_lenses() -> None:
    first = ReviewSubmission(
        review_id="review-1",
        assignment_id="assignment-1",
        reviewer_subject_id="reviewer-1",
        candidate_digest="candidate-1",
        verdict=ReviewVerdict.PASS,
        lenses=("goal_and_correctness",),
        evidence_refs=("ledger:review:1",),
        saw_peer_verdict=False,
    )
    second = ReviewSubmission(
        review_id="review-2",
        assignment_id="assignment-2",
        reviewer_subject_id="reviewer-2",
        candidate_digest="candidate-1",
        verdict=ReviewVerdict.PASS,
        lenses=("risk_and_regression",),
        evidence_refs=("ledger:review:2",),
        saw_peer_verdict=False,
    )

    session = BlindReviewSession("candidate-1")
    session.submit(first)
    session.submit(second)
    sealed = seal_independent_reviews(
        _self_verification(), first, second, blind_session=session
    )

    assert sealed.review_ids == ("review-1", "review-2")
    assert sealed.candidate_digest == "candidate-1"


def test_caller_asserted_blindness_boolean_is_not_seal_evidence() -> None:
    first = ReviewSubmission(
        review_id="review-forged-1",
        assignment_id="assignment-1",
        reviewer_subject_id="reviewer-1",
        candidate_digest="candidate-1",
        verdict=ReviewVerdict.PASS,
        lenses=("goal_and_correctness",),
        evidence_refs=("ledger:review:1",),
        saw_peer_verdict=False,
    )
    second = ReviewSubmission(
        review_id="review-forged-2",
        assignment_id="assignment-2",
        reviewer_subject_id="reviewer-2",
        candidate_digest="candidate-1",
        verdict=ReviewVerdict.PASS,
        lenses=("risk_and_regression",),
        evidence_refs=("ledger:review:2",),
        saw_peer_verdict=False,
    )

    with pytest.raises(
        PermissionError, match="AUTHENTICATED_BLIND_REVIEW_SESSION_REQUIRED"
    ):
        seal_independent_reviews(_self_verification(), first, second)


def test_sealing_consumes_authenticated_assignments_and_immutable_provenance() -> None:
    assignments = (
        ReviewAssignment(
            assignment_id="assignment-1",
            project_id="project-1",
            subject_id="reviewer-1",
            controller_subject_id="controller-1",
            credential_family_id="family-1",
            conflict_declared=True,
            relationships_resolved=True,
            provenance=("reviewer-1", "controller-1", "family-1", "webauthn", "1"),
        ),
        ReviewAssignment(
            assignment_id="assignment-2",
            project_id="project-1",
            subject_id="reviewer-2",
            controller_subject_id="controller-2",
            credential_family_id="family-2",
            conflict_declared=True,
            relationships_resolved=True,
            provenance=("reviewer-2", "controller-2", "family-2", "oidc", "1"),
        ),
    )
    reviews = (
        ReviewSubmission(
            review_id="review-1",
            assignment_id="assignment-1",
            reviewer_subject_id="reviewer-1",
            candidate_digest="candidate-1",
            verdict=ReviewVerdict.PASS,
            lenses=("goal_and_correctness",),
            evidence_refs=("ledger:r1",),
            saw_peer_verdict=False,
        ),
        ReviewSubmission(
            review_id="review-2",
            assignment_id="assignment-2",
            reviewer_subject_id="reviewer-2",
            candidate_digest="candidate-1",
            verdict=ReviewVerdict.PASS,
            lenses=("risk_and_regression",),
            evidence_refs=("ledger:r2",),
            saw_peer_verdict=False,
        ),
    )

    session = BlindReviewSession("candidate-1")
    session.submit(reviews[0])
    session.submit(reviews[1])
    sealed = seal_authenticated_reviews(
        _self_verification(),
        reviews,
        assignments,
        blind_session=session,
        forbidden_subject_ids=frozenset({"implementer", "pm", "gatekeeper"}),
        forbidden_controller_ids=frozenset({"implementer", "pm", "gatekeeper"}),
    )

    assert sealed.assignment_provenance == (
        assignments[0].provenance,
        assignments[1].provenance,
    )


def test_signed_policy_adds_specialist_lenses_and_pm_can_only_add(tmp_path: Path) -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    policy = verified_policy(
        tmp_path,
        now=now,
        rules={
            "specialist_lenses": {
                "component:auth": ["identity_security"],
                "dependency:sqlite": ["data_integrity"],
                "protected:release": ["release_safety"],
                "risk:high": ["abuse_case"],
            }
        },
    )

    lenses = select_review_lenses(
        policy=policy,
        now=now,
        changed_components=("auth",),
        dependencies=("sqlite",),
        protected_subsystems=("release",),
        risk_class="high",
        pm_additions=("accessibility",),
    )

    assert lenses == frozenset(
        {
            "goal_and_correctness",
            "risk_and_regression",
            "identity_security",
            "data_integrity",
            "release_safety",
            "abuse_case",
            "accessibility",
        }
    )

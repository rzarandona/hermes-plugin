from __future__ import annotations

from hermes_kanban_workflow.review.gatekeeper import (
    CandidatePacket,
    ChangeKind,
    Gatekeeper,
    GatekeeperVerdict,
    ImplementerReturn,
)
from hermes_kanban_workflow.review.qa import QAJourney, QAPacket


def test_gatekeeper_pass_is_typed_and_bound_to_candidate() -> None:
    packet = CandidatePacket(
        candidate_digest="candidate-1",
        checklist_complete=True,
        self_verification_ref="ledger:self",
        sealed_review_ids=("review-1", "review-2"),
        evidence_refs=("ledger:test",),
        contradictions=(),
        blocking_findings=(),
        conditions=(),
    )

    verdict = Gatekeeper(
        lambda candidate: candidate.candidate_digest == "candidate-1"
        and candidate.self_verification_ref == "ledger:self"
        and candidate.sealed_review_ids == ("review-1", "review-2")
        and candidate.evidence_refs == ("ledger:test",)
    ).evaluate(packet)

    assert verdict.outcome is GatekeeperVerdict.PASS
    assert verdict.candidate_digest == "candidate-1"


def test_gatekeeper_denies_caller_asserted_review_and_evidence_provenance() -> None:
    packet = CandidatePacket(
        candidate_digest="candidate-1",
        checklist_complete=True,
        self_verification_ref="caller:self",
        sealed_review_ids=("caller:r1", "caller:r2"),
        evidence_refs=("caller:test",),
        contradictions=(),
        blocking_findings=(),
        conditions=(),
    )

    verdict = Gatekeeper().evaluate(packet)

    assert verdict.outcome is GatekeeperVerdict.REQUEST_CHANGES
    assert verdict.reasons == ("AUTHENTICATED_CANDIDATE_EVIDENCE_REQUIRED",)


def test_material_change_returns_to_implementer_and_invalidates_review_evidence() -> None:
    gatekeeper = Gatekeeper(
        lambda candidate: candidate.candidate_digest == "candidate-1"
        and candidate.sealed_review_ids == ("review-1", "review-2")
    )
    decision = gatekeeper.evaluate(
        CandidatePacket(
            candidate_digest="candidate-1",
            checklist_complete=True,
            self_verification_ref="ledger:self",
            sealed_review_ids=("review-1", "review-2"),
            evidence_refs=("ledger:test",),
            contradictions=(),
            blocking_findings=(),
            conditions=(),
        )
    )

    returned = gatekeeper.reconcile(
        decision,
        change_kind=ChangeKind.TEST,
        new_candidate_digest="candidate-2",
    )

    assert returned == ImplementerReturn(
        previous_candidate_digest="candidate-1",
        new_candidate_digest="candidate-2",
        code="MATERIAL_CHANGE_REQUIRES_IMPLEMENTER",
        review_evidence_invalidated=True,
    )


def test_qa_packet_contains_enumerated_journeys_and_routes() -> None:
    packet = QAPacket(
        candidate_digest="candidate-1",
        journeys=(
            QAJourney(
                journey_id="QA-1",
                steps=("open card", "start attempt", "observe status"),
                expected_result="current attempt and truthful health are visible",
                evidence_requirements=("screenshot", "ledger event"),
                responsible_reviewer="reviewer-qa",
                pass_route="release-gate",
                fail_route="implementer",
                escalation_route="owner",
            ),
        ),
    )

    assert packet.journeys[0].journey_id == "QA-1"
    assert packet.journeys[0].fail_route == "implementer"

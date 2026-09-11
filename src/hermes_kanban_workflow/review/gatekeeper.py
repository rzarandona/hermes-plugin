from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum

from pydantic import Field

from hermes_kanban_workflow.domain.identity import FrozenModel


class GatekeeperVerdict(StrEnum):
    PASS = "PASS"
    PASS_WITH_CONDITIONS = "PASS_WITH_CONDITIONS"
    REQUEST_CHANGES = "REQUEST_CHANGES"


class ChangeKind(StrEnum):
    EVIDENCE_REFERENCE = "evidence_reference"
    DUPLICATE_FINDING = "duplicate_finding"
    REPORT_WORDING = "report_wording"
    SEVERITY_MAPPING = "severity_mapping"
    CODE = "code"
    BEHAVIOR = "behavior"
    SOURCE = "source"
    UI_TEXT = "ui_text"
    COMMENT = "comment"
    TEST = "test"
    EVIDENCE_ARTIFACT = "evidence_artifact"


class CandidatePacket(FrozenModel):
    candidate_digest: str = Field(min_length=1)
    checklist_complete: bool
    self_verification_ref: str = Field(min_length=1)
    sealed_review_ids: tuple[str, str]
    evidence_refs: tuple[str, ...]
    contradictions: tuple[str, ...]
    blocking_findings: tuple[str, ...]
    conditions: tuple[str, ...]


class GatekeeperDecision(FrozenModel):
    candidate_digest: str
    outcome: GatekeeperVerdict
    reasons: tuple[str, ...]


class ImplementerReturn(FrozenModel):
    previous_candidate_digest: str
    new_candidate_digest: str
    code: str
    review_evidence_invalidated: bool


class Gatekeeper:
    def __init__(
        self, verify_candidate_evidence: Callable[[CandidatePacket], bool] | None = None
    ) -> None:
        self._verify_candidate_evidence = verify_candidate_evidence

    def evaluate(self, packet: CandidatePacket) -> GatekeeperDecision:
        if self._verify_candidate_evidence is None or not self._verify_candidate_evidence(packet):
            return GatekeeperDecision(
                candidate_digest=packet.candidate_digest,
                outcome=GatekeeperVerdict.REQUEST_CHANGES,
                reasons=("AUTHENTICATED_CANDIDATE_EVIDENCE_REQUIRED",),
            )
        reasons = packet.contradictions + packet.blocking_findings
        if not packet.checklist_complete or not packet.evidence_refs or reasons:
            outcome = GatekeeperVerdict.REQUEST_CHANGES
        elif packet.conditions:
            outcome = GatekeeperVerdict.PASS_WITH_CONDITIONS
        else:
            outcome = GatekeeperVerdict.PASS
        return GatekeeperDecision(
            candidate_digest=packet.candidate_digest,
            outcome=outcome,
            reasons=reasons or packet.conditions,
        )

    def reconcile(
        self,
        decision: GatekeeperDecision,
        *,
        change_kind: ChangeKind,
        new_candidate_digest: str | None = None,
    ) -> GatekeeperDecision | ImplementerReturn:
        administrative = {
            ChangeKind.EVIDENCE_REFERENCE,
            ChangeKind.DUPLICATE_FINDING,
            ChangeKind.REPORT_WORDING,
            ChangeKind.SEVERITY_MAPPING,
        }
        if change_kind in administrative:
            if new_candidate_digest not in {None, decision.candidate_digest}:
                raise PermissionError("ADMIN_RECONCILIATION_CANNOT_CHANGE_CANDIDATE")
            return decision
        if not new_candidate_digest or new_candidate_digest == decision.candidate_digest:
            raise ValueError("MATERIAL_CHANGE_REQUIRES_NEW_CANDIDATE_DIGEST")
        return ImplementerReturn(
            previous_candidate_digest=decision.candidate_digest,
            new_candidate_digest=new_candidate_digest,
            code="MATERIAL_CHANGE_REQUIRES_IMPLEMENTER",
            review_evidence_invalidated=True,
        )

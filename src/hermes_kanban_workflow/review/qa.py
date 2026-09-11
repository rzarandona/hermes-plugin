from __future__ import annotations

from pydantic import Field, model_validator

from hermes_kanban_workflow.domain.identity import FrozenModel


class QAJourney(FrozenModel):
    journey_id: str = Field(min_length=1)
    steps: tuple[str, ...]
    expected_result: str = Field(min_length=1)
    evidence_requirements: tuple[str, ...]
    responsible_reviewer: str = Field(min_length=1)
    pass_route: str = Field(min_length=1)
    fail_route: str = Field(min_length=1)
    escalation_route: str = Field(min_length=1)

    @model_validator(mode="after")
    def complete(self) -> QAJourney:
        if not self.steps or not self.evidence_requirements:
            raise ValueError("QA_JOURNEY_INCOMPLETE")
        return self


class QAPacket(FrozenModel):
    candidate_digest: str = Field(min_length=1)
    journeys: tuple[QAJourney, ...]

    @model_validator(mode="after")
    def enumerated(self) -> QAPacket:
        ids = [journey.journey_id for journey in self.journeys]
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("ENUMERATED_QA_JOURNEYS_REQUIRED")
        return self

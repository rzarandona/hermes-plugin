from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AuthorityEpoch(FrozenModel):
    value: int = Field(ge=0)

    def is_newer_than(self, other: "AuthorityEpoch") -> bool:
        return self.value > other.value


class CorrelationEnvelope(FrozenModel):
    product_id: str
    project_id: str | None = None
    work_item_id: str | None = None
    attempt_id: str | None = None
    review_id: str | None = None
    release_id: str | None = None
    incident_id: str | None = None
    retirement_id: str | None = None


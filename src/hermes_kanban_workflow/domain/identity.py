from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator

OpaqueId = Annotated[str, Field(min_length=1)]
RecordType = Annotated[str, Field(min_length=1)]
PolicyVersion = Annotated[str, Field(min_length=1)]
ControlTime = Annotated[int, Field(ge=0)]


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class AuthorityEpoch(FrozenModel):
    value: int = Field(ge=1)

    def is_newer_than(self, other: AuthorityEpoch) -> bool:
        return self.value > other.value


class CorrelationEnvelope(FrozenModel):
    product_id: OpaqueId
    project_id: OpaqueId
    work_item_id: OpaqueId | None = None
    service_id: OpaqueId | None = None
    root_cause_id: OpaqueId | None = None
    parent_record_type: RecordType | None = None
    parent_record_id: OpaqueId | None = None
    record_type: RecordType
    record_id: OpaqueId
    generation: int | None = Field(default=None, ge=1)
    policy_version: PolicyVersion
    authority_epoch: int = Field(ge=1)
    created_at_control_time: ControlTime

    @model_validator(mode="after")
    def validate_parent_pair(self) -> CorrelationEnvelope:
        if (self.parent_record_type is None) != (self.parent_record_id is None):
            raise ValueError("parent correlation type and id must be present together")
        return self

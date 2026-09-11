from __future__ import annotations

import json
from collections.abc import Mapping
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Any, cast

from pydantic import Field, field_validator, model_validator

from .identity import CorrelationEnvelope, FrozenModel, OpaqueId, PolicyVersion, RecordType


class EffectClass(StrEnum):
    READ_ONLY = "read_only"
    IDEMPOTENT = "idempotent"
    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("payload object keys must be strings")
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"payload contains unsupported value type: {type(value).__name__}")


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _thaw_json(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class CommandEnvelope(FrozenModel):
    command_id: OpaqueId
    idempotency_key: OpaqueId
    command_type: RecordType
    actor_role: RecordType
    actor_id: OpaqueId
    product_id: OpaqueId
    project_id: OpaqueId
    target_type: RecordType
    target_id: OpaqueId
    work_item_id: OpaqueId | None = None
    run_id: OpaqueId | None = None
    artifact_id: OpaqueId | None = None
    environment_id: OpaqueId | None = None
    workspace_id: OpaqueId | None = None
    capability_id: OpaqueId
    policy_version: PolicyVersion
    authority_epoch: int = Field(ge=1)
    fencing_epoch: int | None = Field(default=None, ge=1)
    lease_ids: tuple[OpaqueId, ...] = ()
    reason_code: RecordType
    precondition_hash: OpaqueId
    expires_at_control_time: int = Field(ge=0)
    expected_effect_class: EffectClass
    payload: Mapping[str, Any] = Field(default_factory=dict)
    correlation: CorrelationEnvelope

    @field_validator("payload", mode="after")
    @classmethod
    def freeze_payload(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return cast(Mapping[str, Any], _freeze_json(value))

    @model_validator(mode="after")
    def validate_correlated_identity(self) -> CommandEnvelope:
        correlation = self.correlation
        exact = (
            self.product_id == correlation.product_id
            and self.project_id == correlation.project_id
            and self.work_item_id == correlation.work_item_id
            and self.target_type == correlation.record_type
            and self.target_id == correlation.record_id
            and self.policy_version == correlation.policy_version
            and self.authority_epoch == correlation.authority_epoch
        )
        if not exact:
            raise ValueError("target identity and correlation envelope must match exactly")
        return self

    def canonical_bytes(self) -> bytes:
        fields = self.model_dump(mode="python", exclude={"payload"})
        fields["payload"] = _thaw_json(self.payload)
        return _canonical_bytes(fields)

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()

    @property
    def payload_digest(self) -> str:
        return sha256(_canonical_bytes(self.payload)).hexdigest()

    @property
    def payload_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")

    def is_current(self, control_time: int) -> bool:
        return control_time < self.expires_at_control_time

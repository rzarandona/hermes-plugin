from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from hermes_kanban_workflow.domain.identity import FrozenModel


class CompatibilitySpec(FrozenModel):
    host_version: str = Field(min_length=1)
    plugin_version: str = Field(min_length=1)
    executor_version: str = Field(min_length=1)
    policy_version: str = Field(min_length=1)


class AuthoritySpec(FrozenModel):
    effect_classes: tuple[Literal["read_only", "idempotent", "reversible", "irreversible"], ...]


class PolicyDocument(FrozenModel):
    schema_version: Literal[1]
    policy_id: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    trust_epoch: int = Field(ge=1)
    compatibility: CompatibilitySpec
    authority: AuthoritySpec
    rules: dict[str, Any]

    @model_validator(mode="after")
    def valid_window(self) -> PolicyDocument:
        if self.expires_at <= self.issued_at:
            raise ValueError("policy expiry must follow issue time")
        return self


class VerifiedPolicy(FrozenModel):
    document: PolicyDocument
    digest: str
    signer_key_id: str
    signature: bytes
    verified_at: datetime

    def is_usable(self, now: datetime) -> bool:
        return self.document.issued_at <= now < self.document.expires_at


class SignedPolicy(FrozenModel):
    """Legacy in-memory policy used by the pre-existing trusted-core boundary."""

    policy_id: str
    scope: str
    issued_at: datetime
    expires_at: datetime
    rules: dict[str, Any]
    signature: str
    trust_epoch: int = Field(default=1, ge=1)

    def is_usable(self, now: datetime, scope: str) -> bool:
        return (
            bool(self.signature) and self.issued_at <= now < self.expires_at and self.scope == scope
        )

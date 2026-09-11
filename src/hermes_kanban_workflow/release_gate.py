"""Authenticated independent-audit intake; repository JSON is never authority."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from hermes_kanban_workflow.activation import ActivationTrustRegistry


class AuditVerdict(BaseModel):
    """Transport metadata only; direct construction cannot satisfy the gate."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    reviewer_id: str
    scope_digest: str
    evidence_digest: str
    verdict: str
    open_p0: int
    open_p1: int
    p2_disposition: str
    issued_at: datetime
    expires_at: datetime
    gatekeeper_ack: bool


class ReleaseReadiness(BaseModel):
    model_config = ConfigDict(frozen=True)
    ready: bool
    code: str


def verify_audit_intake(
    *,
    verdict: object,
    gatekeeper_ack: object,
    trust: ActivationTrustRegistry,
    expected_scope_digest: str,
    expected_evidence_digest: str,
    now: datetime,
) -> ReleaseReadiness:
    """Fail closed until an out-of-process audit authority is provisioned.

    A caller-selected registry cannot establish audit or Gatekeeper provenance
    inside the in-process plugin.  The signed-record verifier remains available
    to the future guarded service, but this public boundary cannot consume it.
    """
    del verdict, gatekeeper_ack, trust, expected_scope_digest, expected_evidence_digest, now
    return ReleaseReadiness(
        ready=False, code="AUTHENTICATED_EXTERNAL_AUDIT_AUTHORITY_REQUIRED"
    )


def evaluate_release_readiness(verdict: AuditVerdict, now: datetime) -> ReleaseReadiness:
    """Legacy metadata path intentionally fails closed; use verify_audit_intake."""
    del verdict, now
    return ReleaseReadiness(ready=False, code="AUTHENTICATED_INDEPENDENT_AUDIT_REQUIRED")

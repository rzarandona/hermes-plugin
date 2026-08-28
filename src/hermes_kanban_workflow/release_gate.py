from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditVerdict(BaseModel):
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


def evaluate_release_readiness(verdict: AuditVerdict, now: datetime) -> ReleaseReadiness:
    ready = (
        verdict.verdict == "PASS"
        and verdict.open_p0 == 0
        and verdict.open_p1 == 0
        and bool(verdict.p2_disposition)
        and verdict.issued_at <= now < verdict.expires_at
        and verdict.gatekeeper_ack
        and bool(verdict.reviewer_id and verdict.scope_digest and verdict.evidence_digest)
    )
    return ReleaseReadiness(ready=ready, code="PASS" if ready else "RELEASE_AUDIT_GATE_DENIED")


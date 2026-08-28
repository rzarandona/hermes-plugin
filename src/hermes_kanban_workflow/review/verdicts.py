from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ReviewVerdict(StrEnum):
    PASS = "pass"
    PASS_WITH_CONDITIONS = "pass-with-conditions"
    REQUEST_CHANGES = "request-changes"
    BLOCK = "block"


@dataclass(frozen=True)
class ReviewIdentity:
    subject_id: str
    controller_subject_id: str
    credential_family_id: str


@dataclass(frozen=True)
class ReviewPacket:
    review_id: str
    identity: ReviewIdentity
    verdict: ReviewVerdict
    lenses: tuple[str, ...]
    candidate_digest: str


@dataclass(frozen=True)
class SealedReviews:
    candidate_digest: str
    review_ids: tuple[str, str]


def seal_reviews(first: ReviewPacket, second: ReviewPacket) -> SealedReviews:
    a, b = first.identity, second.identity
    independent = (
        a.subject_id != b.subject_id
        and a.controller_subject_id != b.controller_subject_id
        and a.credential_family_id != b.credential_family_id
    )
    if not independent:
        raise PermissionError("REVIEWER_INDEPENDENCE_DENIED")
    if first.candidate_digest != second.candidate_digest:
        raise ValueError("REVIEW_CANDIDATE_MISMATCH")
    if first.verdict != ReviewVerdict.PASS or second.verdict != ReviewVerdict.PASS:
        raise PermissionError("REVIEW_NOT_APPROVED")
    return SealedReviews(first.candidate_digest, (first.review_id, second.review_id))


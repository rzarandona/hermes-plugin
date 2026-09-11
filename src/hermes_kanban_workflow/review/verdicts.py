from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, model_validator

from hermes_kanban_workflow.domain.identity import FrozenModel
from hermes_kanban_workflow.policy.model import VerifiedPolicy


class AuthMethod(StrEnum):
    WEBAUTHN = "webauthn"
    OIDC = "oidc"


class IdentityKind(StrEnum):
    HUMAN = "human"
    WORKLOAD = "workload"


class IdentityStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    REVOKED = "revoked"


class IdentityBinding(FrozenModel):
    subject_id: str = Field(min_length=1)
    controller_subject_id: str = Field(min_length=1)
    kind: IdentityKind
    auth_method: AuthMethod
    credential_family_id: str = Field(min_length=1)
    aliases: tuple[str, ...] = ()
    project_roles: dict[str, tuple[str, ...]]

    @model_validator(mode="after")
    def method_matches_kind(self) -> IdentityBinding:
        expected = AuthMethod.WEBAUTHN if self.kind is IdentityKind.HUMAN else AuthMethod.OIDC
        if self.auth_method is not expected:
            raise ValueError("IDENTITY_AUTH_METHOD_INVALID")
        return self


@dataclass(frozen=True, slots=True)
class IdentityEvent:
    event_type: str
    subject_id: str
    epoch: int


@dataclass(frozen=True, slots=True)
class AuthenticatedIdentity:
    subject_id: str
    controller_subject_id: str
    credential_family_id: str
    auth_method: AuthMethod
    epoch: int
    project_roles: tuple[tuple[str, tuple[str, ...]], ...]


class IdentityAuthority:
    def __init__(self) -> None:
        self._bindings: dict[str, IdentityBinding] = {}
        self._aliases: dict[str, str] = {}
        self._epochs: dict[str, int] = {}
        self._status: dict[str, IdentityStatus] = {}
        self._events: list[IdentityEvent] = []
        self._family_owner: dict[str, str] = {}
        self._lineage: dict[str, tuple[str, ...]] = {}

    def issue(self, binding: IdentityBinding) -> IdentityEvent:
        names = (binding.subject_id, *binding.aliases)
        if any(name in self._aliases or name in self._bindings for name in names):
            raise PermissionError("IDENTITY_ALIAS_REUSED")
        if binding.credential_family_id in self._family_owner:
            raise PermissionError("CREDENTIAL_FAMILY_REUSED")
        epoch = self._epochs.get(binding.subject_id, 0) + 1
        self._bindings[binding.subject_id] = binding
        self._epochs[binding.subject_id] = epoch
        self._status[binding.subject_id] = IdentityStatus.ACTIVE
        self._family_owner[binding.credential_family_id] = binding.subject_id
        self._lineage[binding.subject_id] = (binding.credential_family_id,)
        for alias in binding.aliases:
            self._aliases[alias] = binding.subject_id
        event = IdentityEvent("issued", binding.subject_id, epoch)
        self._events.append(event)
        return event

    def authenticate(self, subject_or_alias: str, epoch: int) -> AuthenticatedIdentity:
        subject = self._aliases.get(subject_or_alias, subject_or_alias)
        binding = self._bindings[subject]
        if epoch != self._epochs[subject]:
            raise PermissionError("IDENTITY_EPOCH_STALE")
        if self._status[subject] is not IdentityStatus.ACTIVE:
            raise PermissionError("IDENTITY_NOT_ACTIVE")
        return AuthenticatedIdentity(
            binding.subject_id,
            binding.controller_subject_id,
            binding.credential_family_id,
            binding.auth_method,
            epoch,
            tuple(sorted(binding.project_roles.items())),
        )

    def transition(self, subject_id: str, status: IdentityStatus) -> IdentityEvent:
        if subject_id not in self._bindings:
            raise KeyError(subject_id)
        previous = self._status[subject_id]
        self._epochs[subject_id] += 1
        self._status[subject_id] = status
        event_type = "reinstated" if status is IdentityStatus.ACTIVE and previous is not status else status.value
        event = IdentityEvent(event_type, subject_id, self._epochs[subject_id])
        self._events.append(event)
        return event

    def events(self, subject_id: str) -> tuple[IdentityEvent, ...]:
        return tuple(event for event in self._events if event.subject_id == subject_id)

    def rotate_credential_family(self, subject_id: str, new_family_id: str) -> IdentityEvent:
        if new_family_id in self._family_owner:
            raise PermissionError("CREDENTIAL_FAMILY_REUSED")
        binding = self._bindings[subject_id]
        self._bindings[subject_id] = binding.model_copy(
            update={"credential_family_id": new_family_id}
        )
        self._family_owner[new_family_id] = subject_id
        self._lineage[subject_id] += (new_family_id,)
        self._epochs[subject_id] += 1
        event = IdentityEvent("credential_rotated", subject_id, self._epochs[subject_id])
        self._events.append(event)
        return event

    def credential_lineage(self, subject_id: str) -> tuple[str, ...]:
        return self._lineage[subject_id]


class ReviewAssignment(FrozenModel):
    assignment_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    subject_id: str
    controller_subject_id: str
    credential_family_id: str
    conflict_declared: bool
    relationships_resolved: bool
    provenance: tuple[str, str, str, str, str]


def assign_reviewer(
    *,
    assignment_id: str,
    identity: AuthenticatedIdentity,
    project_id: str,
    conflict_declared: bool,
    relationships_resolved: bool,
) -> ReviewAssignment:
    roles = dict(identity.project_roles).get(project_id, ())
    if "reviewer" not in roles:
        raise PermissionError("REVIEWER_PROJECT_ROLE_INELIGIBLE")
    if not conflict_declared:
        raise PermissionError("CONFLICT_OF_INTEREST_UNDECLARED")
    if not relationships_resolved:
        raise PermissionError("REVIEWER_INDEPENDENCE_DENIED")
    provenance = (
        identity.subject_id,
        identity.controller_subject_id,
        identity.credential_family_id,
        identity.auth_method.value,
        str(identity.epoch),
    )
    return ReviewAssignment(
        assignment_id=assignment_id,
        project_id=project_id,
        subject_id=identity.subject_id,
        controller_subject_id=identity.controller_subject_id,
        credential_family_id=identity.credential_family_id,
        conflict_declared=True,
        relationships_resolved=True,
        provenance=provenance,
    )


def assert_review_independence(
    assignments: tuple[ReviewAssignment, ReviewAssignment],
    *,
    forbidden_subject_ids: frozenset[str],
    forbidden_controller_ids: frozenset[str],
) -> None:
    first, second = assignments
    denied = (
        not first.relationships_resolved
        or not second.relationships_resolved
        or first.subject_id == second.subject_id
        or first.controller_subject_id == second.controller_subject_id
        or first.credential_family_id == second.credential_family_id
        or first.subject_id in forbidden_subject_ids
        or second.subject_id in forbidden_subject_ids
        or first.controller_subject_id in forbidden_controller_ids
        or second.controller_subject_id in forbidden_controller_ids
    )
    if denied:
        raise PermissionError("REVIEWER_INDEPENDENCE_DENIED")


class SelfVerification(FrozenModel):
    candidate_digest: str = Field(min_length=1)
    tdd: bool
    tests: bool
    static_checks: bool
    acceptance_comparison: bool
    evidence_refs: tuple[str, ...]
    is_independent_review: bool = False

    @model_validator(mode="after")
    def complete(self) -> SelfVerification:
        if not all((self.tdd, self.tests, self.static_checks, self.acceptance_comparison)):
            raise ValueError("IMPLEMENTER_SELF_VERIFICATION_INCOMPLETE")
        if not self.evidence_refs or any(not ref for ref in self.evidence_refs):
            raise ValueError("IMPLEMENTER_EVIDENCE_REQUIRED")
        if self.is_independent_review:
            raise ValueError("SELF_VERIFICATION_IS_NOT_INDEPENDENT_REVIEW")
        return self


class ReviewVerdict(StrEnum):
    PASS = "pass"
    PASS_WITH_CONDITIONS = "pass-with-conditions"
    REQUEST_CHANGES = "request-changes"
    BLOCK = "block"


class ReviewSubmission(FrozenModel):
    review_id: str = Field(min_length=1)
    assignment_id: str = Field(min_length=1)
    reviewer_subject_id: str = Field(min_length=1)
    candidate_digest: str = Field(min_length=1)
    verdict: ReviewVerdict
    lenses: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    saw_peer_verdict: bool


class BlindReviewSession:
    """Service-owned submission state; submit never exposes peer review content."""

    def __init__(self, candidate_digest: str) -> None:
        if not candidate_digest:
            raise ValueError("REVIEW_CANDIDATE_REQUIRED")
        self._candidate_digest = candidate_digest
        self._submissions: list[ReviewSubmission] = []

    def submit(self, review: ReviewSubmission) -> str:
        if review.candidate_digest != self._candidate_digest:
            raise ValueError("REVIEW_CANDIDATE_MISMATCH")
        if review.saw_peer_verdict:
            raise PermissionError("REVIEW_SEAL_BROKEN")
        if any(
            existing.review_id == review.review_id
            or existing.assignment_id == review.assignment_id
            or existing.reviewer_subject_id == review.reviewer_subject_id
            for existing in self._submissions
        ):
            raise PermissionError("REVIEWER_INDEPENDENCE_DENIED")
        if len(self._submissions) >= 2:
            raise PermissionError("REVIEW_SESSION_COMPLETE")
        self._submissions.append(review)
        return review.review_id

    def attests(self, first: ReviewSubmission, second: ReviewSubmission) -> bool:
        return tuple(self._submissions) == (first, second)


@dataclass(frozen=True)
class StrictSealedReviews:
    candidate_digest: str
    review_ids: tuple[str, str]


@dataclass(frozen=True, slots=True)
class AuthenticatedSealedReviews:
    candidate_digest: str
    review_ids: tuple[str, str]
    assignment_provenance: tuple[
        tuple[str, str, str, str, str],
        tuple[str, str, str, str, str],
    ]


def seal_independent_reviews(
    self_verification: SelfVerification,
    first: ReviewSubmission,
    second: ReviewSubmission,
    *,
    blind_session: BlindReviewSession | None = None,
) -> StrictSealedReviews:
    if blind_session is None or not blind_session.attests(first, second):
        raise PermissionError("AUTHENTICATED_BLIND_REVIEW_SESSION_REQUIRED")
    if len({self_verification.candidate_digest, first.candidate_digest, second.candidate_digest}) != 1:
        raise ValueError("REVIEW_CANDIDATE_MISMATCH")
    if first.reviewer_subject_id == second.reviewer_subject_id:
        raise PermissionError("REVIEWER_INDEPENDENCE_DENIED")
    if first.saw_peer_verdict or second.saw_peer_verdict:
        raise PermissionError("REVIEW_SEAL_BROKEN")
    if first.verdict is not ReviewVerdict.PASS or second.verdict is not ReviewVerdict.PASS:
        raise PermissionError("REVIEW_NOT_APPROVED")
    lenses = set(first.lenses) | set(second.lenses)
    if not {"goal_and_correctness", "risk_and_regression"}.issubset(lenses):
        raise PermissionError("MANDATORY_REVIEW_LENS_MISSING")
    if not first.evidence_refs or not second.evidence_refs:
        raise PermissionError("REVIEW_EVIDENCE_REQUIRED")
    return StrictSealedReviews(first.candidate_digest, (first.review_id, second.review_id))


def seal_authenticated_reviews(
    self_verification: SelfVerification,
    reviews: tuple[ReviewSubmission, ReviewSubmission],
    assignments: tuple[ReviewAssignment, ReviewAssignment],
    *,
    blind_session: BlindReviewSession | None = None,
    forbidden_subject_ids: frozenset[str],
    forbidden_controller_ids: frozenset[str],
) -> AuthenticatedSealedReviews:
    assert_review_independence(
        assignments,
        forbidden_subject_ids=forbidden_subject_ids,
        forbidden_controller_ids=forbidden_controller_ids,
    )
    for review, assignment in zip(reviews, assignments, strict=True):
        if (
            review.assignment_id != assignment.assignment_id
            or review.reviewer_subject_id != assignment.subject_id
        ):
            raise PermissionError("REVIEW_ASSIGNMENT_PROVENANCE_MISMATCH")
    sealed = seal_independent_reviews(
        self_verification,
        reviews[0],
        reviews[1],
        blind_session=blind_session,
    )
    return AuthenticatedSealedReviews(
        candidate_digest=sealed.candidate_digest,
        review_ids=sealed.review_ids,
        assignment_provenance=(assignments[0].provenance, assignments[1].provenance),
    )


def select_review_lenses(
    *,
    policy: VerifiedPolicy,
    now: datetime,
    changed_components: tuple[str, ...],
    dependencies: tuple[str, ...],
    protected_subsystems: tuple[str, ...],
    risk_class: str,
    pm_additions: tuple[str, ...],
) -> frozenset[str]:
    if not policy.is_usable(now):
        raise PermissionError("VERIFIED_POLICY_REQUIRED")
    configured = policy.document.rules.get("specialist_lenses")
    if not isinstance(configured, dict):
        configured = {}
    keys = (
        *(f"component:{item}" for item in changed_components),
        *(f"dependency:{item}" for item in dependencies),
        *(f"protected:{item}" for item in protected_subsystems),
        f"risk:{risk_class}",
    )
    lenses = {"goal_and_correctness", "risk_and_regression", *pm_additions}
    for key in keys:
        values: Any = configured.get(key, ())
        if isinstance(values, list) and all(isinstance(value, str) for value in values):
            lenses.update(values)
    return frozenset(lenses)


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

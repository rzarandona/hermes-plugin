from __future__ import annotations

import pytest
from pydantic import ValidationError

from hermes_kanban_workflow.review.verdicts import (
    AuthMethod,
    IdentityAuthority,
    IdentityBinding,
    IdentityKind,
    IdentityStatus,
    ReviewAssignment,
    assert_review_independence,
    assign_reviewer,
)


def test_webauthn_human_and_oidc_workload_resolve_to_canonical_subjects() -> None:
    authority = IdentityAuthority()
    human = authority.issue(
        IdentityBinding(
            subject_id="human-1",
            controller_subject_id="human-1",
            kind=IdentityKind.HUMAN,
            auth_method=AuthMethod.WEBAUTHN,
            credential_family_id="family-human",
            aliases=("alice@example.test",),
            project_roles={"project-1": ("reviewer",)},
        )
    )
    agent = authority.issue(
        IdentityBinding(
            subject_id="agent-1",
            controller_subject_id="human-2",
            kind=IdentityKind.WORKLOAD,
            auth_method=AuthMethod.OIDC,
            credential_family_id="family-agent",
            aliases=("ci-reviewer",),
            project_roles={"project-1": ("reviewer",)},
        )
    )

    assert authority.authenticate("alice@example.test", human.epoch).subject_id == "human-1"
    authenticated_agent = authority.authenticate("ci-reviewer", agent.epoch)
    assert authenticated_agent.subject_id == "agent-1"
    assert authenticated_agent.controller_subject_id == "human-2"


def _human(subject: str = "human-1", family: str = "family-1") -> IdentityBinding:
    return IdentityBinding(
        subject_id=subject,
        controller_subject_id=subject,
        kind=IdentityKind.HUMAN,
        auth_method=AuthMethod.WEBAUTHN,
        credential_family_id=family,
        project_roles={"project-1": ("reviewer",)},
    )


def test_identity_lifecycle_events_invalidate_prior_epochs() -> None:
    authority = IdentityAuthority()
    issued = authority.issue(_human())

    for status in (
        IdentityStatus.SUSPENDED,
        IdentityStatus.ACTIVE,
        IdentityStatus.EXPIRED,
        IdentityStatus.ACTIVE,
        IdentityStatus.REVOKED,
        IdentityStatus.ACTIVE,
    ):
        event = authority.transition("human-1", status)
        assert event.epoch > issued.epoch
        with pytest.raises(PermissionError, match="IDENTITY_EPOCH_STALE"):
            authority.authenticate("human-1", issued.epoch)
        issued = event

    assert [event.event_type for event in authority.events("human-1")] == [
        "issued",
        "suspended",
        "reinstated",
        "expired",
        "reinstated",
        "revoked",
        "reinstated",
    ]


def test_credential_rotation_preserves_lineage_and_denies_family_reuse() -> None:
    authority = IdentityAuthority()
    issued = authority.issue(_human())

    rotated = authority.rotate_credential_family("human-1", "family-2")

    assert rotated.epoch > issued.epoch
    assert authority.credential_lineage("human-1") == ("family-1", "family-2")
    with pytest.raises(PermissionError, match="CREDENTIAL_FAMILY_REUSED"):
        authority.issue(_human("human-2", "family-1"))


def test_reviewer_assignment_requires_project_role_conflict_declaration_and_provenance() -> None:
    authority = IdentityAuthority()
    issued = authority.issue(_human())
    identity = authority.authenticate("human-1", issued.epoch)

    with pytest.raises(PermissionError, match="CONFLICT_OF_INTEREST_UNDECLARED"):
        assign_reviewer(
            assignment_id="assignment-1",
            identity=identity,
            project_id="project-1",
            conflict_declared=False,
            relationships_resolved=True,
        )

    assignment = assign_reviewer(
        assignment_id="assignment-1",
        identity=identity,
        project_id="project-1",
        conflict_declared=True,
        relationships_resolved=True,
    )
    assert assignment.provenance == (
        "human-1",
        "human-1",
        "family-1",
        "webauthn",
        "1",
    )
    with pytest.raises(ValidationError):
        assignment.project_id = "other"


def _assignment(
    slot: str,
    *,
    subject: str,
    controller: str,
    family: str,
    resolved: bool = True,
) -> ReviewAssignment:
    return ReviewAssignment(
        assignment_id=slot,
        project_id="project-1",
        subject_id=subject,
        controller_subject_id=controller,
        credential_family_id=family,
        conflict_declared=True,
        relationships_resolved=resolved,
        provenance=(subject, controller, family, "webauthn", "1"),
    )


@pytest.mark.parametrize(
    ("second", "forbidden_subjects", "forbidden_controllers"),
    [
        (_assignment("b", subject="reviewer-1", controller="c2", family="f2"), (), ()),
        (_assignment("b", subject="reviewer-2", controller="c1", family="f2"), (), ()),
        (_assignment("b", subject="reviewer-2", controller="c2", family="f1"), (), ()),
        (_assignment("b", subject="reviewer-2", controller="c2", family="f2", resolved=False), (), ()),
        (_assignment("b", subject="implementer", controller="c2", family="f2"), ("implementer",), ()),
        (_assignment("b", subject="reviewer-2", controller="gatekeeper", family="f2"), (), ("gatekeeper",)),
    ],
)
def test_adversarial_identity_relationships_deny_reviewer_independence(
    second: ReviewAssignment,
    forbidden_subjects: tuple[str, ...],
    forbidden_controllers: tuple[str, ...],
) -> None:
    first = _assignment("a", subject="reviewer-1", controller="c1", family="f1")

    with pytest.raises(PermissionError, match="REVIEWER_INDEPENDENCE_DENIED"):
        assert_review_independence(
            (first, second),
            forbidden_subject_ids=frozenset(forbidden_subjects),
            forbidden_controller_ids=frozenset(forbidden_controllers),
        )

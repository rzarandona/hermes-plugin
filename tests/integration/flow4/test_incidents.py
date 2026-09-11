from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.domain.incidents import (
    ClosureAuthority,
    ClosureProof,
    IncidentCommand,
    IncidentRole,
    IncidentRoles,
    IncidentStore,
    SeverityFacts,
    SeverityPolicyAuthority,
    ViolationAuthority,
    ViolationKind,
)


def _roles() -> IncidentRoles:
    return IncidentRoles(
        incident_commander="ic-a",
        responders=("responder-a",),
        pm="pm-a",
        secretary="secretary-a",
    )


def test_incident_severity_derives_from_signed_complete_facts() -> None:
    severity = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())
    violations = ViolationAuthority(private_key=Ed25519PrivateKey.generate())
    store = IncidentStore(severity_authority=severity, violation_authority=violations)
    facts = SeverityFacts(
        impact=3,
        scope=2,
        safety=0,
        integrity=2,
        security=1,
        duration=2,
        reversibility=1,
        uncertain=False,
    )
    assessment = severity.assess(facts)
    violation = violations.issue(
        dedupe_key="svc:checkout:window-7",
        service_id="svc",
        kind=ViolationKind.OBJECTIVE,
        evidence_ref="evidence:objective-window-7",
    )

    incident = store.open(violation, assessment=assessment, roles=_roles())

    assert incident.severity == "sev2"
    assert incident.roles.incident_commander == "ic-a"


def test_responder_may_record_only_named_scoped_incident_command() -> None:
    severity = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())
    violations = ViolationAuthority(private_key=Ed25519PrivateKey.generate())
    store = IncidentStore(severity_authority=severity, violation_authority=violations)
    incident = store.open(
        violations.issue(
            dedupe_key="svc:security:1",
            service_id="svc",
            kind=ViolationKind.SECURITY,
            evidence_ref="evidence:security",
        ),
        assessment=severity.assess(SeverityFacts(2, 2, 1, 1, 3, 1, 1, False)),
        roles=_roles(),
    )
    command = IncidentCommand(
        command_id="cmd-1",
        name="isolate_checkout_worker",
        scope="worker:checkout-7",
        actor_subject_id="responder-a",
        actor_role=IncidentRole.RESPONDER,
    )

    receipt = store.record_command(incident.incident_id, command)

    assert receipt.recorded
    assert not receipt.effect_executed


def test_incident_closure_requires_independent_complete_restoration_proof() -> None:
    severity = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())
    violations = ViolationAuthority(private_key=Ed25519PrivateKey.generate())
    closure = ClosureAuthority(
        private_key=Ed25519PrivateKey.generate(), forbidden_actor="responder-a"
    )
    store = IncidentStore(
        severity_authority=severity,
        violation_authority=violations,
        closure_authority=closure,
    )
    incident = store.open(
        violations.issue(
            dedupe_key="svc:integrity:1",
            service_id="svc",
            kind=ViolationKind.INVARIANT,
            evidence_ref="evidence:invariant",
        ),
        assessment=severity.assess(SeverityFacts(2, 2, 0, 3, 0, 2, 1, False)),
        roles=_roles(),
    )
    proof = closure.issue(
        ClosureProof(
            incident_id=incident.incident_id,
            verifier_subject_id="independent-verifier",
            restoration_evidence_ref="evidence:restored",
            objective_readback_ref="evidence:objective-readback",
            integrity_evidence_ref="evidence:integrity",
            residual_risk_owner="risk-owner",
            follow_up_ref="problem-or-action:1",
            explicit_close=True,
        )
    )

    closed = store.close(incident.incident_id, proof)

    assert not closed.open


def test_severe_incident_creates_problem_record() -> None:
    severity = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())
    violations = ViolationAuthority(private_key=Ed25519PrivateKey.generate())
    store = IncidentStore(severity_authority=severity, violation_authority=violations)
    incident = store.open(
        violations.issue(
            dedupe_key="svc:critical:1",
            service_id="svc",
            kind=ViolationKind.USER_IMPACT,
            evidence_ref="evidence:critical-impact",
        ),
        assessment=severity.assess(SeverityFacts(3, 3, 3, 3, 3, 3, 3, False)),
        roles=_roles(),
    )

    assert store.problem_records[0].incident_ids == (incident.incident_id,)
    assert store.problem_records[0].product_change_route == "flow1_then_flow2_after_authorization"


def test_repeated_incidents_create_problem_record() -> None:
    severity = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())
    violations = ViolationAuthority(private_key=Ed25519PrivateKey.generate())
    store = IncidentStore(severity_authority=severity, violation_authority=violations)
    assessment = severity.assess(SeverityFacts(1, 1, 0, 0, 0, 1, 0, False))
    first = store.open(
        violations.issue(
            dedupe_key="svc:dependency:window-1",
            service_id="svc",
            kind=ViolationKind.DEPENDENCY,
            evidence_ref="evidence:dependency-1",
        ),
        assessment=assessment,
        roles=_roles(),
    )
    second = store.open(
        violations.issue(
            dedupe_key="svc:dependency:window-2",
            service_id="svc",
            kind=ViolationKind.DEPENDENCY,
            evidence_ref="evidence:dependency-2",
        ),
        assessment=assessment,
        roles=_roles(),
    )

    assert store.problem_records[0].incident_ids == (first.incident_id, second.incident_id)


def test_uncertain_severity_escalates_one_level() -> None:
    authority = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())

    certain = authority.assess(SeverityFacts(1, 1, 0, 0, 0, 1, 0, False))
    uncertain = authority.assess(SeverityFacts(1, 1, 0, 0, 0, 1, 0, True))

    assert certain.severity == "sev4"
    assert uncertain.severity == "sev3"


def test_same_verified_violation_opens_one_incident() -> None:
    severity = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())
    violations = ViolationAuthority(private_key=Ed25519PrivateKey.generate())
    store = IncidentStore(severity_authority=severity, violation_authority=violations)
    violation = violations.issue(
        dedupe_key="svc:objective:one-window",
        service_id="svc",
        kind=ViolationKind.OBJECTIVE,
        evidence_ref="evidence:objective",
    )
    assessment = severity.assess(SeverityFacts(1, 1, 0, 0, 0, 1, 0, False))

    first = store.open(violation, assessment=assessment, roles=_roles())
    duplicate = store.open(violation, assessment=assessment, roles=_roles())

    assert duplicate == first


def test_forged_violation_receipt_is_denied() -> None:
    severity = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())
    violations = ViolationAuthority(private_key=Ed25519PrivateKey.generate())
    store = IncidentStore(severity_authority=severity, violation_authority=violations)
    violation = violations.issue(
        dedupe_key="svc:security:forged-violation",
        service_id="svc",
        kind=ViolationKind.SECURITY,
        evidence_ref="evidence:security",
    )
    assessment = severity.assess(SeverityFacts(2, 2, 0, 0, 3, 1, 1, False))

    with pytest.raises(PermissionError, match="VERIFIED_VIOLATION_REQUIRED"):
        store.open(
            replace(violation, signature=b"forged"),
            assessment=assessment,
            roles=_roles(),
        )


def test_forged_severity_receipt_is_denied() -> None:
    severity = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())
    violations = ViolationAuthority(private_key=Ed25519PrivateKey.generate())
    store = IncidentStore(severity_authority=severity, violation_authority=violations)
    violation = violations.issue(
        dedupe_key="svc:security:forged-severity",
        service_id="svc",
        kind=ViolationKind.SECURITY,
        evidence_ref="evidence:security",
    )
    assessment = severity.assess(SeverityFacts(2, 2, 0, 0, 3, 1, 1, False))

    with pytest.raises(PermissionError, match="SIGNED_SEVERITY_ASSESSMENT_REQUIRED"):
        store.open(
            violation,
            assessment=replace(assessment, severity="sev4", signature=b"forged"),
            roles=_roles(),
        )


def test_owner_attention_without_reservation_subscription_or_criticality_is_denied() -> None:
    severity = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())
    violations = ViolationAuthority(private_key=Ed25519PrivateKey.generate())
    store = IncidentStore(severity_authority=severity, violation_authority=violations)
    incident = store.open(
        violations.issue(
            dedupe_key="svc:user:1",
            service_id="svc",
            kind=ViolationKind.USER_IMPACT,
            evidence_ref="evidence:user",
        ),
        assessment=severity.assess(SeverityFacts(1, 1, 0, 0, 0, 1, 0, False)),
        roles=_roles(),
    )

    with pytest.raises(PermissionError, match="INCIDENT_COMMAND_SCOPE_DENIED"):
        store.record_command(
            incident.incident_id,
            IncidentCommand(
                "owner-command",
                "diagnose",
                "service:svc",
                "owner-a",
                IncidentRole.OWNER,
            ),
        )


def test_successful_command_is_not_incident_closure_proof() -> None:
    severity = SeverityPolicyAuthority(private_key=Ed25519PrivateKey.generate())
    violations = ViolationAuthority(private_key=Ed25519PrivateKey.generate())
    closure = ClosureAuthority(
        private_key=Ed25519PrivateKey.generate(), forbidden_actor="responder-a"
    )
    store = IncidentStore(
        severity_authority=severity,
        violation_authority=violations,
        closure_authority=closure,
    )
    incident = store.open(
        violations.issue(
            dedupe_key="svc:invariant:2",
            service_id="svc",
            kind=ViolationKind.INVARIANT,
            evidence_ref="evidence:invariant",
        ),
        assessment=severity.assess(SeverityFacts(2, 2, 0, 2, 0, 1, 1, False)),
        roles=_roles(),
    )
    forged = ClosureProof(
        incident.incident_id,
        "responder-a",
        "command:success",
        "",
        "",
        "",
        "",
        True,
        b"forged",
    )

    with pytest.raises(PermissionError, match="AUTHENTIC_COMPLETE_CLOSURE_PROOF_REQUIRED"):
        store.close(incident.incident_id, forged)

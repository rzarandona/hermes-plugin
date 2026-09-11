from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.flows.flow4 import (
    ActionableAlert,
    AlertRouter,
    HealthEvidenceAuthority,
    HealthSignalKind,
    ObjectiveSet,
    ObjectiveSetRegistry,
    ServiceIndicator,
    assess_service_health,
)


def test_owner_approved_versioned_objective_set_is_repository_verifiable() -> None:
    registry = ObjectiveSetRegistry(
        private_key=Ed25519PrivateKey.generate(), owner_by_service={"svc": "owner"}
    )
    objective = ObjectiveSet(
        service_id="svc",
        version="objectives-v2",
        indicators=(ServiceIndicator("checkout-success", "user", 99_900),),
        error_budget=100,
        exclusions=("synthetic-abuse",),
        criticality="critical",
        review_triggers=("budget-50-percent",),
    )

    approved = registry.approve(objective, owner_subject_id="owner", decided_at=datetime.now(UTC))

    assert registry.verify(approved, objective=objective)
    assert approved.objective_digest == objective.digest


def test_forged_objective_approval_is_denied() -> None:
    registry = ObjectiveSetRegistry(
        private_key=Ed25519PrivateKey.generate(), owner_by_service={"svc": "owner"}
    )
    objective = ObjectiveSet(
        "svc",
        "objectives-v1",
        (ServiceIndicator("availability", "user", 99_900),),
        100,
        (),
        "critical",
        ("budget-50-percent",),
    )
    authentic = registry.approve(
        objective, owner_subject_id="owner", decided_at=datetime.now(UTC)
    )

    assert not registry.verify(
        replace(authentic, signature=b"forged"), objective=objective
    )


def test_incomplete_objective_set_cannot_be_owner_approved() -> None:
    registry = ObjectiveSetRegistry(
        private_key=Ed25519PrivateKey.generate(), owner_by_service={"svc": "owner"}
    )
    incomplete = ObjectiveSet("svc", "v1", (), 0, (), "", ())

    with pytest.raises(ValueError, match="COMPLETE_SERVICE_OBJECTIVE_SET_REQUIRED"):
        registry.approve(incomplete, owner_subject_id="owner", decided_at=datetime.now(UTC))


def test_health_requires_five_independently_authenticated_signal_classes() -> None:
    authority = HealthEvidenceAuthority(private_key=Ed25519PrivateKey.generate())
    signals = tuple(
        authority.issue(
            service_id="svc", kind=kind, healthy=True, evidence_ref=f"evidence:{kind.value}"
        )
        for kind in HealthSignalKind
    )

    assessment = assess_service_health("svc", signals, verifier=authority)

    assert assessment.healthy
    assert assessment.signal_kinds == frozenset(HealthSignalKind)


def test_actionable_alert_pages_once_for_one_dedupe_identity() -> None:
    router = AlertRouter()
    alert = ActionableAlert(
        alert_id="alert-1",
        dedupe_key="svc:checkout:objective",
        alert_type="objective_violation",
        owner_subject_id="oncall-a",
        evidence_ref="evidence:objective-window",
        severity="sev2",
        runbook_ref="runbook:checkout",
        acknowledgement_lease_seconds=300,
        routing_policy="route:checkout-primary",
        false_positive_target_ppm=500,
        actionable=True,
        noisy=False,
    )

    first = router.page(alert)
    replay = router.page(alert)

    assert first.paged
    assert replay == first
    assert router.page_count == 1


def test_single_dashboard_cannot_prove_health() -> None:
    authority = HealthEvidenceAuthority(private_key=Ed25519PrivateKey.generate())
    dashboard = authority.issue(
        service_id="svc",
        kind=HealthSignalKind.TELEMETRY,
        healthy=True,
        evidence_ref="dashboard:all-green",
    )

    with pytest.raises(PermissionError, match="MULTI_SIGNAL_HEALTH_EVIDENCE_REQUIRED"):
        assess_service_health("svc", (dashboard,), verifier=authority)


def test_caller_forged_health_receipt_is_denied() -> None:
    authority = HealthEvidenceAuthority(private_key=Ed25519PrivateKey.generate())
    authentic = authority.issue(
        service_id="svc",
        kind=HealthSignalKind.DATA_INTEGRITY,
        healthy=False,
        evidence_ref="evidence:corruption",
    )
    forged = replace(authentic, healthy=True, signature=b"forged")

    with pytest.raises(PermissionError, match="AUTHENTIC_INDEPENDENT_HEALTH_EVIDENCE_REQUIRED"):
        assess_service_health("svc", (forged,), verifier=authority)


@pytest.mark.parametrize(
    ("field", "value"),
    [("owner_subject_id", ""), ("noisy", True), ("actionable", False)],
)
def test_noisy_or_unowned_or_inactionable_alert_is_denied(field: str, value: object) -> None:
    alert = ActionableAlert(
        alert_id="alert-x",
        dedupe_key="svc:x",
        alert_type="dependency_violation",
        owner_subject_id="oncall",
        evidence_ref="evidence:x",
        severity="sev2",
        runbook_ref="runbook:x",
        acknowledgement_lease_seconds=120,
        routing_policy="route:x",
        false_positive_target_ppm=100,
        actionable=True,
        noisy=False,
    )

    with pytest.raises(PermissionError, match="ACTIONABLE_OWNED_ALERT_REQUIRED"):
        AlertRouter().page(replace(alert, **{field: value}))

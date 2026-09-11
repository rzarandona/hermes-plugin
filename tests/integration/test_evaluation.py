from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hermes_kanban_workflow.evaluation.attribution import RootCause
from hermes_kanban_workflow.evaluation.metrics import (
    ALL_DIMENSIONS,
    EvaluationDenied,
    EvaluationService,
    ImmutableEvidence,
    MetricSample,
)
from hermes_kanban_workflow.evaluation.trends import build_weekly_trends

NOW = datetime(2026, 8, 29, 12, tzinfo=UTC)


def _samples() -> tuple[MetricSample, ...]:
    evidence = ImmutableEvidence("evidence-1", "sha256:abc", NOW, retained=True)
    return tuple(
        MetricSample("Implementer", dimension, 0.8, NOW - timedelta(days=offset), evidence)
        for dimension in ALL_DIMENSIONS
        for offset in range(7)
    )


def test_daily_exceptions_include_evidence_sample_size_and_confidence() -> None:
    service = EvaluationService(exception_thresholds={dimension: 0.9 for dimension in ALL_DIMENSIONS})

    exceptions = service.daily_exceptions(_samples(), day=NOW.date())

    assert {item.dimension for item in exceptions} == set(ALL_DIMENSIONS)
    assert all(item.sample_size == 1 for item in exceptions)
    assert all(0.0 <= item.confidence <= 1.0 for item in exceptions)
    assert all(item.evidence[0].digest == "sha256:abc" for item in exceptions)


def test_weekly_trends_are_role_dimension_specific_without_composite_leaderboard() -> None:
    trends = build_weekly_trends(_samples(), week_ending=NOW.date(), attribution=RootCause.WORKFLOW)

    assert {trend.dimension for trend in trends} == set(ALL_DIMENSIONS)
    assert all(trend.role == "Implementer" and trend.sample_size == 7 for trend in trends)
    assert all(trend.root_cause is RootCause.WORKFLOW for trend in trends)
    assert all(trend.trend in {"improving", "stable", "declining"} for trend in trends)
    assert not hasattr(trends, "leaderboard")
    assert "composite" not in {trend.dimension for trend in trends}


def test_weekly_trends_deny_incomplete_measurement_window() -> None:
    incomplete = _samples()[:-1]

    with pytest.raises(EvaluationDenied, match="MEASUREMENT_WINDOW_INCOMPLETE"):
        build_weekly_trends(incomplete, week_ending=NOW.date(), attribution=RootCause.POLICY)


def test_evaluation_can_only_submit_targeted_proposal_through_authority_gate() -> None:
    accepted: list[tuple[str, str, str]] = []
    service = EvaluationService(
        exception_thresholds={},
        proposal_gate=lambda role, dimension, action: accepted.append((role, dimension, action)),
    )

    proposal = service.propose_improvement("Implementer", "correctness", "add focused tests")

    assert proposal.status == "pending-authority-gate"
    assert accepted == [("Implementer", "correctness", "add focused tests")]
    for forbidden in ("punish", "replace", "dispatch", "grant authority", "change capabilities", "move cards"):
        with pytest.raises(EvaluationDenied, match="EVALUATION_AUTHORITY_DENIED"):
            service.perform(forbidden)


def test_root_cause_enum_is_exact() -> None:
    assert {cause.value for cause in RootCause} == {
        "agent behavior", "policy", "workflow", "resource", "dependency", "owner wait", "infrastructure"
    }

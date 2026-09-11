from __future__ import annotations

import pytest

from hermes_kanban_workflow.flows.flow3 import (
    HealthGate,
    HealthGateKind,
    HealthStatus,
    RolloutStrategy,
    evaluate_rollout,
    select_rollout_strategy,
)


def test_progressive_rollout_is_default_when_supported() -> None:
    assert (
        select_rollout_strategy(supports_progressive=True, requested=None)
        is RolloutStrategy.PROGRESSIVE
    )


def test_atomic_rollout_requires_recorded_technical_unavailability() -> None:
    with pytest.raises(PermissionError, match="ATOMIC_TECHNICAL_UNAVAILABILITY_EVIDENCE_REQUIRED"):
        select_rollout_strategy(
            supports_progressive=False,
            requested=RolloutStrategy.ATOMIC,
            atomic_unavailability_evidence=None,
        )

    assert (
        select_rollout_strategy(
            supports_progressive=False,
            requested=RolloutStrategy.ATOMIC,
            atomic_unavailability_evidence="ledger:technical-unavailability:7",
        )
        is RolloutStrategy.ATOMIC
    )


def test_typed_failing_health_gate_automatically_pauses_rollout() -> None:
    result = evaluate_rollout(
        (
            HealthGate(
                kind=HealthGateKind.TELEMETRY,
                status=HealthStatus.PASS,
                evidence_ref="ledger:health:1",
            ),
            HealthGate(
                kind=HealthGateKind.CRITICAL_JOURNEY,
                status=HealthStatus.FAIL,
                evidence_ref="ledger:health:2",
            ),
        )
    )

    assert result.paused is True
    assert result.reason == "HEALTH_GATE_FAILED_AUTOMATIC_PAUSE"

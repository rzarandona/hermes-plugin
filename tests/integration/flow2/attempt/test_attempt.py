from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from hermes_kanban_workflow.flows.flow2 import (
    Flow2Coordinator,
    NeverStartedIncident,
    RunHealth,
    RunLifecycle,
    RunResult,
    RunState,
    evaluate_start_ack,
)
from tests.policy_fixtures import verified_policy


def test_replacement_preserves_card_and_refreshes_attempt_bindings() -> None:
    flow = Flow2Coordinator()
    first = flow.start_attempt(
        card_id="card-1",
        workspace="workspace-a",
        resources=("resource://product/workspace/local/local/repo",),
    )

    replacement = flow.replace_attempt(first.run_id)

    assert replacement.card_id == first.card_id
    assert replacement.run_id != first.run_id
    assert replacement.fencing_epoch > first.fencing_epoch
    assert replacement.scratch_scope != first.scratch_scope
    assert replacement.workspace == first.workspace
    assert replacement.resources == first.resources


def test_run_state_is_immutable_with_orthogonal_projections() -> None:
    state = RunState(
        lifecycle=RunLifecycle.RUNNING,
        health=RunHealth.WAITING_RESOURCE,
        result=RunResult.NONE,
    )

    assert state.model_dump() == {
        "lifecycle": "running",
        "health": "waiting_resource",
        "result": "none",
    }
    with pytest.raises(ValidationError):
        state.health = RunHealth.HEALTHY


def test_superseded_attempt_rejects_late_update() -> None:
    flow = Flow2Coordinator()
    first = flow.start_attempt(card_id="card-1", workspace="w", resources=())
    flow.replace_attempt(first.run_id)

    with pytest.raises(PermissionError, match="SUPERSEDED_RUN_UPDATE_DENIED"):
        flow.accept_update(first.run_id, first.fencing_epoch)


def test_missing_ack_after_two_minutes_opens_never_started_incident() -> None:
    dispatched = datetime(2026, 8, 29, tzinfo=UTC)

    outcome = evaluate_start_ack(
        run_id="run-1",
        dispatched_at=dispatched,
        observed_at=dispatched + timedelta(seconds=121),
        acknowledged=False,
    )

    assert outcome == NeverStartedIncident(
        run_id="run-1", code="NEVER_STARTED", deadline_seconds=120
    )


def test_verified_signed_cold_start_policy_extends_ack_to_five_minutes(tmp_path: Path) -> None:
    dispatched = datetime(2026, 8, 29, tzinfo=UTC)
    policy = verified_policy(
        tmp_path,
        now=dispatched,
        rules={"cold_start_ack_seconds": 300, "cold_start_run_ids": ["run-1"]},
    )

    before_deadline = evaluate_start_ack(
        run_id="run-1",
        dispatched_at=dispatched,
        observed_at=dispatched + timedelta(seconds=299),
        acknowledged=False,
        policy=policy,
    )
    after_deadline = evaluate_start_ack(
        run_id="run-1",
        dispatched_at=dispatched,
        observed_at=dispatched + timedelta(seconds=301),
        acknowledged=False,
        policy=policy,
    )

    assert before_deadline is None
    assert after_deadline == NeverStartedIncident("run-1", "NEVER_STARTED", 300)
    assert evaluate_start_ack(
        run_id="unlisted-run",
        dispatched_at=dispatched,
        observed_at=dispatched + timedelta(seconds=121),
        acknowledged=False,
        policy=policy,
    ) == NeverStartedIncident("unlisted-run", "NEVER_STARTED", 120)

from __future__ import annotations

import pytest

from hermes_kanban_workflow.flows.flow2 import Milestone, ProgressTracker, RunHealth


def test_heartbeat_proves_presence_without_advancing_meaningful_milestone() -> None:
    progress = ProgressTracker(
        run_id="run-1",
        accountable_owner="implementer-1",
        health=RunHealth.WAITING_RESOURCE,
        blocker_or_next_action="waiting for build lane",
    )
    progress.record_milestone(Milestone.TDD_RED, control_time=10)

    view = progress.record_heartbeat(lease_id="lease-1", control_time=20)

    assert view.lease_present is True
    assert view.last_meaningful_milestone is Milestone.TDD_RED
    assert view.last_milestone_control_time == 10
    assert view.health is RunHealth.WAITING_RESOURCE
    assert view.blocker_or_next_action == "waiting for build lane"
    assert view.accountable_owner == "implementer-1"


def test_untyped_milestone_is_rejected() -> None:
    progress = ProgressTracker(
        run_id="run-1",
        accountable_owner="implementer-1",
        health=RunHealth.HEALTHY,
        blocker_or_next_action="run tests",
    )

    with pytest.raises(TypeError, match="TYPED_MILESTONE_REQUIRED"):
        progress.record_milestone("free-form", control_time=1)  # type: ignore[arg-type]

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from hermes_kanban_workflow.domain.identity import FrozenModel
from hermes_kanban_workflow.policy.model import VerifiedPolicy


class RunLifecycle(StrEnum):
    QUEUED = "queued"
    DISPATCHED = "dispatched"
    STARTING = "starting"
    RUNNING = "running"
    TERMINAL = "terminal"


class RunHealth(StrEnum):
    HEALTHY = "healthy"
    WAITING_RESOURCE = "waiting_resource"
    STALLED = "stalled"
    LEASE_LOST = "lease_lost"
    SUPERSEDED = "superseded"


class RunResult(StrEnum):
    NONE = "none"
    PASSED = "passed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXHAUSTED = "exhausted"


class Milestone(StrEnum):
    TDD_RED = "tdd_red"
    IMPLEMENTED = "implemented"
    TESTS_PASSED = "tests_passed"
    STATIC_CHECKS_PASSED = "static_checks_passed"
    ACCEPTANCE_COMPARED = "acceptance_compared"


class RunState(FrozenModel):
    lifecycle: RunLifecycle
    health: RunHealth
    result: RunResult


@dataclass(frozen=True, slots=True)
class NeverStartedIncident:
    run_id: str
    code: str
    deadline_seconds: int


@dataclass(frozen=True, slots=True)
class ProgressView:
    run_id: str
    lease_present: bool
    last_meaningful_milestone: Milestone | None
    last_milestone_control_time: int | None
    health: RunHealth
    blocker_or_next_action: str
    accountable_owner: str


class ProgressTracker:
    def __init__(
        self,
        *,
        run_id: str,
        accountable_owner: str,
        health: RunHealth,
        blocker_or_next_action: str,
    ) -> None:
        self.run_id = run_id
        self.accountable_owner = accountable_owner
        self.health = health
        self.blocker_or_next_action = blocker_or_next_action
        self._milestone: Milestone | None = None
        self._milestone_time: int | None = None

    def record_milestone(self, milestone: Milestone, *, control_time: int) -> ProgressView:
        if not isinstance(milestone, Milestone):
            raise TypeError("TYPED_MILESTONE_REQUIRED")
        self._milestone = milestone
        self._milestone_time = control_time
        return self._view(False)

    def record_heartbeat(self, *, lease_id: str, control_time: int) -> ProgressView:
        del control_time
        return self._view(bool(lease_id))

    def _view(self, lease_present: bool) -> ProgressView:
        return ProgressView(
            self.run_id,
            lease_present,
            self._milestone,
            self._milestone_time,
            self.health,
            self.blocker_or_next_action,
            self.accountable_owner,
        )


def evaluate_start_ack(
    *,
    run_id: str,
    dispatched_at: datetime,
    observed_at: datetime,
    acknowledged: bool,
    policy: VerifiedPolicy | None = None,
) -> NeverStartedIncident | None:
    deadline = 120
    if (
        policy is not None
        and policy.is_usable(dispatched_at)
        and policy.document.rules.get("cold_start_ack_seconds") == 300
        and isinstance(policy.document.rules.get("cold_start_run_ids"), list)
        and run_id in policy.document.rules["cold_start_run_ids"]
    ):
        deadline = 300
    if acknowledged or (observed_at - dispatched_at).total_seconds() <= deadline:
        return None
    return NeverStartedIncident(run_id, "NEVER_STARTED", deadline)


@dataclass(frozen=True, slots=True)
class AttemptBindings:
    card_id: str
    run_id: str
    fencing_epoch: int
    scratch_scope: str
    workspace: str
    resources: tuple[str, ...]


class Flow2Coordinator:
    def __init__(self) -> None:
        self._attempts: dict[str, AttemptBindings] = {}
        self._superseded: set[str] = set()

    def start_attempt(
        self, *, card_id: str, workspace: str, resources: tuple[str, ...]
    ) -> AttemptBindings:
        attempt = AttemptBindings(
            card_id=card_id,
            run_id=str(uuid4()),
            fencing_epoch=1,
            scratch_scope=str(uuid4()),
            workspace=workspace,
            resources=resources,
        )
        self._attempts[attempt.run_id] = attempt
        return attempt

    def replace_attempt(self, run_id: str) -> AttemptBindings:
        previous = self._attempts[run_id]
        replacement = replace(
            previous,
            run_id=str(uuid4()),
            fencing_epoch=previous.fencing_epoch + 1,
            scratch_scope=str(uuid4()),
        )
        self._attempts[replacement.run_id] = replacement
        self._superseded.add(run_id)
        return replacement

    def accept_update(self, run_id: str, fencing_epoch: int) -> AttemptBindings:
        if run_id in self._superseded:
            raise PermissionError("SUPERSEDED_RUN_UPDATE_DENIED")
        attempt = self._attempts[run_id]
        if attempt.fencing_epoch != fencing_epoch:
            raise PermissionError("STALE_FENCING_EPOCH")
        return attempt

from __future__ import annotations

import json
import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.domain.resources import ResourceUri
from hermes_kanban_workflow.policy.loader import load_verified_policy
from hermes_kanban_workflow.policy.verifier import TrustRoot
from hermes_kanban_workflow.scheduler.leases import (
    HolderBinding,
    LeaseDenied,
    LeaseService,
    SchedulerStore,
)
from hermes_kanban_workflow.scheduler.precedence import PrecedenceModel, PriorityClass
from hermes_kanban_workflow.scheduler.queues import PreemptionDisposition, WaitQueue
from hermes_kanban_workflow.scheduler.wakeup import (
    EligibilitySnapshot,
    WakeDenied,
    WakeupService,
)


def test_resource_uri_is_canonical_and_globally_scoped() -> None:
    uri = ResourceUri.parse("resource://product-a/build-lane/github/us-east-1/windows-x64")

    assert str(uri) == "resource://product-a/build-lane/github/us-east-1/windows-x64"
    assert uri.scope == "product-a"
    with pytest.raises(ValueError, match="RESOURCE_URI_NON_CANONICAL"):
        ResourceUri.parse("resource://PRODUCT-A/build-lane/github/us-east-1/windows-x64")
    with pytest.raises(ValueError, match="RESOURCE_URI_CLASS_INVALID"):
        ResourceUri.parse("resource://product-a/other/github/us-east-1/windows-x64")
    with pytest.raises(ValueError, match="RESOURCE_URI_NON_CANONICAL"):
        ResourceUri.parse("resource://product-a/build-lane/github/us-east-1/windows%2Dx64")


def _holder(subject: str, *, work_item: str = "work-1") -> HolderBinding:
    return HolderBinding(
        role="build-worker",
        subject=subject,
        product_id="product-a",
        project_id="project-a",
        work_item_id=work_item,
        service_id=None,
        command_class="routine-build",
    )


def test_lease_is_exclusive_and_survives_service_restart(tmp_path: Path) -> None:
    db = tmp_path / "scheduler.db"
    resource = ResourceUri.parse("resource://product-a/build-lane/github/us-east-1/windows-x64")
    first = LeaseService(SchedulerStore(db), lambda: 100).acquire(
        resource, _holder("worker-a"), ttl=20, renewable_conditions=("policy-current",)
    )

    restarted = LeaseService(SchedulerStore(db), lambda: 101)
    with pytest.raises(LeaseDenied, match="RESOURCE_BUSY"):
        restarted.acquire(
            resource, _holder("worker-b"), ttl=20, renewable_conditions=("policy-current",)
        )

    assert restarted.current(resource) == first


def test_expired_lease_can_be_replaced_with_new_fence(tmp_path: Path) -> None:
    now = [10]
    resource = ResourceUri.parse("resource://shared/test-device/lab/global/device-1")
    service = LeaseService(SchedulerStore(tmp_path / "scheduler.db"), lambda: now[0])
    first = service.acquire(resource, _holder("worker-a"), ttl=5, renewable_conditions=())

    now[0] = 15
    second = service.acquire(resource, _holder("worker-b"), ttl=5, renewable_conditions=())

    assert second.fencing_epoch == first.fencing_epoch + 1
    assert not service.is_authoritative(first)
    assert service.is_authoritative(second)


def test_release_requires_exact_holder_and_lease(tmp_path: Path) -> None:
    resource = ResourceUri.parse("resource://shared/database/postgres/global/integration")
    service = LeaseService(SchedulerStore(tmp_path / "scheduler.db"), lambda: 20)
    lease = service.acquire(resource, _holder("worker-a"), ttl=5, renewable_conditions=())

    with pytest.raises(LeaseDenied, match="LEASE_HOLDER_MISMATCH"):
        service.release(lease.lease_id, _holder("worker-b"), lease.fencing_epoch)
    released = service.release(lease.lease_id, _holder("worker-a"), lease.fencing_epoch)

    assert released.revoked
    assert service.current(resource) is None


def test_renewal_advances_fence_only_when_conditions_hold(tmp_path: Path) -> None:
    now = [30]
    resource = ResourceUri.parse("resource://product-a/workspace/local/us-east-1/work-1")
    service = LeaseService(SchedulerStore(tmp_path / "scheduler.db"), lambda: now[0])
    first = service.acquire(
        resource,
        _holder("worker-a"),
        ttl=10,
        renewable_conditions=("policy-current", "capability-current"),
    )

    with pytest.raises(LeaseDenied, match="RENEW_CONDITIONS_UNSATISFIED"):
        service.renew(first.lease_id, _holder("worker-a"), ttl=10, satisfied={"policy-current"})
    now[0] = 31
    renewed = service.renew(
        first.lease_id,
        _holder("worker-a"),
        ttl=10,
        satisfied={"policy-current", "capability-current"},
    )

    assert renewed.fencing_epoch == first.fencing_epoch + 1
    assert not service.is_authoritative(first)
    assert service.is_authoritative(renewed)


def test_stale_worker_cannot_release_renewed_fence(tmp_path: Path) -> None:
    resource = ResourceUri.parse("resource://product-a/workspace/local/global/stale")
    service = LeaseService(SchedulerStore(tmp_path / "scheduler.db"), lambda: 1)
    first = service.acquire(resource, _holder("worker-a"), ttl=10, renewable_conditions=())
    renewed = service.renew(first.lease_id, _holder("worker-a"), ttl=10, satisfied=set())

    with pytest.raises(LeaseDenied, match="STALE_FENCING_EPOCH"):
        service.release(first.lease_id, first.holder, first.fencing_epoch)

    assert service.is_authoritative(renewed)


def test_fencing_epoch_is_monotonic_per_global_resource(tmp_path: Path) -> None:
    store = SchedulerStore(tmp_path / "scheduler.db")
    service = LeaseService(store, lambda: 1)
    first_resource = ResourceUri.parse("resource://shared/database/postgres/global/a")
    second_resource = ResourceUri.parse("resource://shared/database/postgres/global/b")
    first = service.acquire(first_resource, _holder("worker-a"), ttl=10, renewable_conditions=())
    other = service.acquire(second_resource, _holder("worker-b"), ttl=10, renewable_conditions=())
    service.renew(other.lease_id, other.holder, ttl=10, satisfied=set())

    renewed = service.renew(first.lease_id, first.holder, ttl=10, satisfied=set())

    assert renewed.fencing_epoch == 2


def test_scheduler_rejects_control_time_rollback(tmp_path: Path) -> None:
    now = [100]
    resource = ResourceUri.parse("resource://shared/database/postgres/global/clock")
    service = LeaseService(SchedulerStore(tmp_path / "scheduler.db"), lambda: now[0])
    lease = service.acquire(resource, _holder("worker-a"), ttl=10, renewable_conditions=())

    now[0] = 99
    with pytest.raises(LeaseDenied, match="CONTROL_TIME_ROLLBACK"):
        service.release(lease.lease_id, lease.holder, lease.fencing_epoch)

    now[0] = 100
    assert service.is_authoritative(lease)


def test_wait_queue_is_durable_fifo_within_priority_class(tmp_path: Path) -> None:
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/windows")
    store = SchedulerStore(tmp_path / "scheduler.db")
    queue = WaitQueue(store, lambda: 100, PrecedenceModel.default())
    first = queue.enqueue(
        resource,
        _holder("worker-a", work_item="work-a"),
        PriorityClass.ROUTINE,
        authority=frozenset({"build"}),
    )
    second = queue.enqueue(
        resource,
        _holder("worker-b", work_item="work-b"),
        PriorityClass.ROUTINE,
        authority=frozenset({"build"}),
    )

    restarted = WaitQueue(SchedulerStore(store.path), lambda: 101, PrecedenceModel.default())
    ordered = restarted.ordered(resource)

    assert [item.token for item in ordered] == [first.token, second.token]
    assert [item.position for item in ordered] == [1, 2]


def _signed_precedence(tmp_path: Path, edges: list[list[str]]) -> PrecedenceModel:
    now = datetime.now(UTC)
    private = Ed25519PrivateKey.generate()
    document = {
        "schema_version": 1,
        "policy_id": "scheduler-policy",
        "scope": "product-a",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "trust_epoch": 1,
        "compatibility": {
            "host_version": "0.20.5",
            "plugin_version": "0.1.0",
            "executor_version": "1.0.0",
            "policy_version": "1",
        },
        "authority": {"effect_classes": ["read_only"]},
        "rules": {"scheduler": {"dependency_edges": edges}},
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    path = tmp_path / "scheduler-policy.json"
    path.write_bytes(payload)
    verified = load_verified_policy(
        path,
        private.sign(payload),
        TrustRoot.from_public_key("fixture-root", 1, private.public_key()),
        now=now,
    )
    return PrecedenceModel.from_verified_policy(verified)


def test_signed_dependency_edge_precedes_fifo(tmp_path: Path) -> None:
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/linux")
    queue = WaitQueue(
        SchedulerStore(tmp_path / "scheduler.db"),
        lambda: 100,
        _signed_precedence(tmp_path, [["work-a", "work-b"]]),
    )
    dependent = queue.enqueue(
        resource,
        _holder("worker-b", work_item="work-b"),
        PriorityClass.ROUTINE,
        authority=frozenset({"build"}),
    )
    prerequisite = queue.enqueue(
        resource,
        _holder("worker-a", work_item="work-a"),
        PriorityClass.ROUTINE,
        authority=frozenset({"build"}),
    )

    assert [item.token for item in queue.ordered(resource)] == [
        prerequisite.token,
        dependent.token,
    ]


def test_starvation_escalates_visibility_without_authority_expansion(tmp_path: Path) -> None:
    now = [0]
    resource = ResourceUri.parse("resource://shared/test-device/lab/global/device-2")
    queue = WaitQueue(
        SchedulerStore(tmp_path / "scheduler.db"), lambda: now[0], PrecedenceModel.default()
    )
    waiting = queue.enqueue(
        resource,
        _holder("worker-a"),
        PriorityClass.ROUTINE,
        authority=frozenset({"test"}),
    )

    now[0] = 50
    escalated = queue.escalate_starved(resource, threshold=40)

    assert escalated[0].token == waiting.token
    assert escalated[0].escalated
    assert escalated[0].priority is PriorityClass.ROUTINE
    assert escalated[0].authority == frozenset({"test"})


def test_non_cancellable_preemption_queues_without_interrupt(tmp_path: Path) -> None:
    resource = ResourceUri.parse("resource://shared/release-lane/github/global/production")
    store = SchedulerStore(tmp_path / "scheduler.db")
    leases = LeaseService(store, lambda: 5)
    active = leases.acquire(resource, _holder("release-worker"), ttl=20, renewable_conditions=())
    queue = WaitQueue(store, lambda: 5, PrecedenceModel.default())

    decision = queue.request_preemption(
        resource,
        _holder("emergency-worker", work_item="work-emergency"),
        PriorityClass.EMERGENCY,
        authority=frozenset({"release"}),
        active_cancellable=False,
        safely_checkpointed=True,
    )

    assert decision.disposition is PreemptionDisposition.QUEUED
    assert leases.is_authoritative(active)
    assert queue.ordered(resource)[0].token == decision.wait_token.token


def _eligible(authority: frozenset[str] = frozenset({"build"})) -> EligibilitySnapshot:
    return EligibilitySnapshot(
        policy_current=True,
        exact_hold_members=frozenset(),
        blockers=frozenset(),
        workspace_matches=True,
        capability_authority=authority,
        budget_remaining=1,
        resource_eligible=True,
    )


def test_release_rechecks_all_eligibility_before_fresh_attempt(tmp_path: Path) -> None:
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/macos")
    store = SchedulerStore(tmp_path / "scheduler.db")
    queue = WaitQueue(store, lambda: 100, PrecedenceModel.default())
    waiting = queue.enqueue(
        resource,
        _holder("worker-a"),
        PriorityClass.ROUTINE,
        authority=frozenset({"build"}),
    )
    started = []
    wakeup = WakeupService(
        store,
        LeaseService(store, lambda: 100),
        queue,
        lambda _: _eligible(),
        started.append,
        lambda: 100,
    )

    result = wakeup.on_release("release-1", resource, ttl=10)

    assert result.wait_token == waiting.token
    assert result.attempt.attempt_id != waiting.token
    assert result.attempt.fencing_epoch == result.lease.fencing_epoch
    assert result.attempt.authority == waiting.authority
    assert started == [result.attempt]


def test_lost_release_replay_repairs_acquired_wait_token(tmp_path: Path) -> None:
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/replay")
    store = SchedulerStore(tmp_path / "scheduler.db")
    queue = WaitQueue(store, lambda: 100, PrecedenceModel.default())
    waiting = queue.enqueue(
        resource,
        _holder("worker-a"),
        PriorityClass.ROUTINE,
        authority=frozenset({"build"}),
    )
    leases = LeaseService(store, lambda: 100)
    orphaned = leases.acquire(
        resource,
        waiting.holder,
        ttl=10,
        renewable_conditions=("policy-current",),
        queue_token=waiting.token,
    )
    started = []
    restarted = WakeupService(
        SchedulerStore(store.path),
        LeaseService(SchedulerStore(store.path), lambda: 101),
        WaitQueue(SchedulerStore(store.path), lambda: 101, PrecedenceModel.default()),
        lambda _: _eligible(),
        started.append,
        lambda: 101,
    )

    repaired = restarted.on_release("release-replay", resource, ttl=10)

    assert repaired.lease == orphaned
    assert repaired.attempt.fencing_epoch == orphaned.fencing_epoch
    assert started == [repaired.attempt]


def test_duplicate_wake_dedupes_exact_release_but_denies_rebinding(tmp_path: Path) -> None:
    first_resource = ResourceUri.parse("resource://shared/build-lane/github/global/duplicate-a")
    second_resource = ResourceUri.parse("resource://shared/build-lane/github/global/duplicate-b")
    store = SchedulerStore(tmp_path / "scheduler.db")
    queue = WaitQueue(store, lambda: 10, PrecedenceModel.default())
    queue.enqueue(
        first_resource,
        _holder("worker-a"),
        PriorityClass.ROUTINE,
        authority=frozenset({"build"}),
    )
    started = []
    service = WakeupService(
        store,
        LeaseService(store, lambda: 10),
        queue,
        lambda _: _eligible(),
        started.append,
        lambda: 10,
    )
    first = service.on_release("release-duplicate", first_resource, ttl=10)

    assert service.on_release("release-duplicate", first_resource, ttl=10) == first
    assert started == [first.attempt]
    with pytest.raises(WakeDenied, match="DUPLICATE_RELEASE_MISMATCH"):
        service.on_release("release-duplicate", second_resource, ttl=10)


def test_dispatch_failure_blocks_uncertain_fresh_attempt_replay(tmp_path: Path) -> None:
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/dispatch-repair")
    store = SchedulerStore(tmp_path / "scheduler.db")
    queue = WaitQueue(store, lambda: 10, PrecedenceModel.default())
    queue.enqueue(
        resource,
        _holder("worker-a"),
        PriorityClass.ROUTINE,
        authority=frozenset({"build"}),
    )
    failed_attempts = []

    def crash_after_wake_commit(attempt: object) -> None:
        failed_attempts.append(attempt)
        raise RuntimeError("DISPATCH_CRASH")

    first = WakeupService(
        store,
        LeaseService(store, lambda: 10),
        queue,
        lambda _: _eligible(),
        crash_after_wake_commit,
        lambda: 10,
    )
    with pytest.raises(RuntimeError, match="DISPATCH_CRASH"):
        first.on_release("release-dispatch-repair", resource, ttl=10)

    repaired_attempts = []
    restarted = WakeupService(
        SchedulerStore(store.path),
        LeaseService(SchedulerStore(store.path), lambda: 11),
        WaitQueue(SchedulerStore(store.path), lambda: 11, PrecedenceModel.default()),
        lambda _: _eligible(),
        repaired_attempts.append,
        lambda: 11,
    )
    with pytest.raises(WakeDenied, match="WAKE_DISPATCH_OUTCOME_UNCERTAIN"):
        restarted.on_release("release-dispatch-repair", resource, ttl=10)
    assert len(failed_attempts) == 1
    assert repaired_attempts == []


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"policy_current": False}, "POLICY_NOT_CURRENT"),
        ({"exact_hold_members": frozenset({"work-1"})}, "EXACT_PROJECT_HOLD"),
        ({"blockers": frozenset({"dependency"})}, "BLOCKER_PRESENT"),
        ({"workspace_matches": False}, "WORKSPACE_MISMATCH"),
        ({"capability_authority": frozenset()}, "CAPABILITY_INSUFFICIENT"),
        ({"budget_remaining": 0}, "BUDGET_EXHAUSTED"),
        ({"resource_eligible": False}, "RESOURCE_INELIGIBLE"),
    ],
)
def test_each_current_eligibility_gate_denies_before_attempt(
    tmp_path: Path, change: dict[str, object], code: str
) -> None:
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/gated")
    store = SchedulerStore(tmp_path / "scheduler.db")
    queue = WaitQueue(store, lambda: 10, PrecedenceModel.default())
    queue.enqueue(
        resource,
        _holder("worker-a"),
        PriorityClass.ROUTINE,
        authority=frozenset({"build"}),
    )
    started = []
    service = WakeupService(
        store,
        LeaseService(store, lambda: 10),
        queue,
        lambda _: replace(_eligible(), **change),
        started.append,
        lambda: 10,
    )

    with pytest.raises(WakeDenied, match=code):
        service.on_release(f"release-{code}", resource, ttl=10)

    assert started == []
    assert LeaseService(store, lambda: 10).current(resource) is None


def test_project_hold_membership_is_exact(tmp_path: Path) -> None:
    resource = ResourceUri.parse("resource://shared/test-device/lab/global/exact-hold")
    store = SchedulerStore(tmp_path / "scheduler.db")
    queue = WaitQueue(store, lambda: 10, PrecedenceModel.default())
    queue.enqueue(
        resource,
        _holder("worker-a", work_item="work-1"),
        PriorityClass.VERIFICATION,
        authority=frozenset({"test"}),
    )
    service = WakeupService(
        store,
        LeaseService(store, lambda: 10),
        queue,
        lambda _: replace(
            _eligible(frozenset({"test"})),
            exact_hold_members=frozenset({"other-project-work"}),
        ),
        lambda _: None,
        lambda: 10,
    )

    result = service.on_release("release-exact-hold", resource, ttl=10)

    assert result.attempt.work_item_id == "work-1"


def test_capability_superset_does_not_expand_attempt_authority(tmp_path: Path) -> None:
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/no-expansion")
    store = SchedulerStore(tmp_path / "scheduler.db")
    queue = WaitQueue(store, lambda: 10, PrecedenceModel.default())
    queue.enqueue(
        resource,
        _holder("worker-a"),
        PriorityClass.ROUTINE,
        authority=frozenset({"build"}),
    )
    service = WakeupService(
        store,
        LeaseService(store, lambda: 10),
        queue,
        lambda _: _eligible(frozenset({"build", "deploy", "policy-write"})),
        lambda _: None,
        lambda: 10,
    )

    result = service.on_release("release-no-expansion", resource, ttl=10)

    assert result.attempt.authority == frozenset({"build"})


@pytest.mark.parametrize("seed", [7, 19, 41, 73, 101])
def test_randomized_queue_schedules_preserve_priority_fifo(tmp_path: Path, seed: int) -> None:
    resource = ResourceUri.parse(f"resource://shared/build-lane/github/global/seed-{seed}")
    queue = WaitQueue(
        SchedulerStore(tmp_path / f"scheduler-{seed}.db"),
        lambda: 10,
        PrecedenceModel.default(),
    )
    randomizer = random.Random(seed)
    priorities = [PriorityClass.ROUTINE, PriorityClass.EMERGENCY, PriorityClass.VERIFICATION] * 4
    randomizer.shuffle(priorities)
    inserted = []
    for index, priority in enumerate(priorities):
        inserted.append(
            queue.enqueue(
                resource,
                _holder(f"worker-{index}", work_item=f"work-{index}"),
                priority,
                authority=frozenset({"build"}),
            )
        )

    expected = sorted(inserted, key=lambda item: (int(item.priority), item.ordinal))

    assert [item.token for item in queue.ordered(resource)] == [item.token for item in expected]

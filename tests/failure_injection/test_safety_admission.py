from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from multiprocessing import get_context
from pathlib import Path
from threading import Barrier, Event

import pytest

from hermes_kanban_workflow.adapters.artifact_store import SigningRootClass
from hermes_kanban_workflow.domain.resources import ResourceUri
from hermes_kanban_workflow.effects.receipts import ReadbackReceipt
from hermes_kanban_workflow.effects.reconciler import EffectReconciler
from hermes_kanban_workflow.effects.state_machine import EffectState, EffectStore
from hermes_kanban_workflow.scheduler.leases import LeaseService, SchedulerStore
from hermes_kanban_workflow.scheduler.precedence import PrecedenceModel, PriorityClass
from hermes_kanban_workflow.scheduler.queues import WaitQueue
from hermes_kanban_workflow.scheduler.wakeup import WakeDenied, WakeupService
from tests.failure_injection.test_audit_safety import artifact_fixture
from tests.failure_injection.test_resource_scheduler import _eligible, _holder
from tests.ledger_fixtures import command, guarded_service


def _hard_command_crash(database: str, marker: str) -> None:
    service, principal = guarded_service(Path(database))

    def crash(_command: object) -> None:
        Path(marker).write_text("callback reached", encoding="utf-8")
        os._exit(91)

    service.execute(command(), principal, effect=crash)


def _hard_effect_crash(database: str, marker: str) -> None:
    with EffectStore(database) as store:
        _intent(store)

        def crash(_record):
            Path(marker).write_text("callback reached", encoding="utf-8")
            os._exit(91)

        EffectReconciler(store, dispatch=crash, readback=lambda _: None).dispatch("op")


def test_process_crash_blocks_effect_redispatch_without_readback(tmp_path):
    database, marker = tmp_path / "effects.db", tmp_path / "callback.txt"
    child = get_context("spawn").Process(
        target=_hard_effect_crash, args=(str(database), str(marker))
    )
    child.start()
    child.join(timeout=20)
    if child.is_alive():
        child.terminate()
        child.join(timeout=5)
        pytest.fail("fixture process did not exit")
    assert child.exitcode == 91
    assert marker.read_text(encoding="utf-8") == "callback reached"
    callbacks = []
    with EffectStore(database) as reopened:
        assert reopened.get("op").state is EffectState.EFFECT_STARTED
        assert reopened.get("op").attempts == 1
        with pytest.raises(RuntimeError, match="EFFECT_START_STATE_INVALID"):
            EffectReconciler(reopened, dispatch=callbacks.append, readback=lambda _: None).dispatch(
                "op"
            )
    assert callbacks == []


def test_process_crash_preserves_command_uncertainty_and_blocks_restart(tmp_path):
    database, marker = tmp_path / "ledger.db", tmp_path / "callback.txt"
    child = get_context("spawn").Process(
        target=_hard_command_crash, args=(str(database), str(marker))
    )
    child.start()
    child.join(timeout=20)
    if child.is_alive():
        child.terminate()
        child.join(timeout=5)
        pytest.fail("fixture process did not exit")
    assert child.exitcode == 91
    assert marker.read_text(encoding="utf-8") == "callback reached"
    restarted, principal = guarded_service(database)
    callbacks = []
    with pytest.raises(RuntimeError, match="COMMAND_OUTCOME_UNCERTAIN"):
        restarted.execute(command(), principal, effect=callbacks.append)
    assert callbacks == []
    assert tuple(restarted._ledger.iter_events()) == ()


def test_concurrent_command_callers_reserve_before_callback(tmp_path):
    database = tmp_path / "ledger.db"
    first, principal = guarded_service(database)
    second, _ = guarded_service(database)
    reached, finish = Event(), Event()
    callbacks = []

    def callback(envelope):
        callbacks.append(envelope.command_id)
        reached.set()
        assert finish.wait(timeout=10)

    with ThreadPoolExecutor(max_workers=2) as pool:
        winner = pool.submit(first.execute, command(), principal, effect=callback)
        try:
            assert reached.wait(timeout=10)
            with pytest.raises(RuntimeError, match="COMMAND_OUTCOME_UNCERTAIN"):
                second.execute(command(), principal, effect=callbacks.append)
        finally:
            finish.set()
        receipt = winner.result(timeout=10)
    assert second.execute(command(), principal, effect=callbacks.append) == receipt
    assert callbacks == ["command-1"]


def _intent(store):
    store.record_intent(
        operation_id="op", idempotency_key="stable-op", provider="fixture", payload_digest="a" * 64
    )


def test_concurrent_dispatch_admission_across_separate_connections(tmp_path):
    database = tmp_path / "effects.db"
    with EffectStore(database) as store:
        _intent(store)
    barrier = Barrier(12)
    callbacks = []

    def contender(_index):
        with EffectStore(database) as store:

            def dispatch(record):
                callbacks.append((record.operation_id, record.idempotency_key))
                raise TimeoutError("uncertain fixture")

            reconciler = EffectReconciler(store, dispatch=dispatch, readback=lambda _: None)
            barrier.wait(timeout=10)
            try:
                reconciler.dispatch("op")
                return "admitted"
            except RuntimeError:
                return "blocked"

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(contender, range(12)))
    assert results.count("admitted") == 1
    assert callbacks == [("op", "stable-op")]
    with EffectStore(database) as reopened:
        assert reopened.get("op").attempts == 1
        assert reopened.get("op").state is EffectState.RECONCILIATION_REQUIRED


def test_generic_provider_failure_is_durable_uncertainty(tmp_path):
    database = tmp_path / "effects.db"
    callbacks = []
    with EffectStore(database) as store:
        _intent(store)

        def dispatch(record):
            callbacks.append(record.operation_id)
            raise ValueError("provider transport failure")

        reconciler = EffectReconciler(store, dispatch=dispatch, readback=lambda _: None)
        with pytest.raises(ValueError, match="provider transport failure"):
            reconciler.dispatch("op")
    with EffectStore(database) as reopened:
        assert reopened.get("op").state is EffectState.RECONCILIATION_REQUIRED
        assert reopened.get("op").attempts == 1
        with pytest.raises(RuntimeError, match="AUTHORITATIVE_ABSENCE_REQUIRED"):
            EffectReconciler(reopened, dispatch=dispatch, readback=lambda _: None).dispatch("op")
    assert callbacks == ["op"]


def test_retry_revalidates_persisted_absence_with_current_trust(tmp_path):
    database = tmp_path / "effects.db"
    with EffectStore(database, readback_verifier=lambda _: True) as store:
        _intent(store)
        started = store.mark_started("op")
        store.require_reconciliation("op", "fixture callback returned", expected=started)
        pending = store.mark_readback_pending("op")
        store.append_readback_receipt(
            ReadbackReceipt("absence", "op", "absent", "a", "e"), expected=pending
        )
    callbacks = []
    with (
        EffectStore(database, readback_verifier=lambda _: False) as reopened,
        pytest.raises(PermissionError, match="AUTHORITATIVE_READBACK_VERIFICATION_REQUIRED"),
    ):
        EffectReconciler(reopened, dispatch=callbacks.append, readback=lambda _: None).dispatch(
            "op"
        )
    assert callbacks == []


def test_concurrent_wake_replay_does_not_duplicate_callback(tmp_path):
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/concurrent")
    store = SchedulerStore(tmp_path / "scheduler.db")
    queue = WaitQueue(store, lambda: 10, PrecedenceModel.default())
    queue.enqueue(
        resource, _holder("worker"), PriorityClass.ROUTINE, authority=frozenset({"build"})
    )
    reached, finish = Event(), Event()
    callbacks = []

    def start(attempt):
        callbacks.append(attempt)
        if len(callbacks) == 1:
            reached.set()
            assert finish.wait(timeout=10)

    service = WakeupService(
        store, LeaseService(store, lambda: 10), queue, lambda _: _eligible(), start, lambda: 10
    )
    with ThreadPoolExecutor(max_workers=2) as pool:
        winner = pool.submit(service.on_release, "release", resource, ttl=10)
        try:
            assert reached.wait(timeout=10)
            with pytest.raises(WakeDenied, match="WAKE_DISPATCH_OUTCOME_UNCERTAIN"):
                service.on_release("release", resource, ttl=10)
        finally:
            finish.set()
        result = winner.result(timeout=10)
    assert callbacks == [result.attempt]


class _CrashBeforeWakeAdmission(WakeupService):
    def _dispatch(self, result):
        raise RuntimeError("fixture crash before dispatch admission")


@pytest.mark.parametrize("change", ["hold", "expiry", "revoked", "fence"])
def test_pre_admission_wake_recovery_rechecks_current_authority(tmp_path, change):
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/recovery")
    store = SchedulerStore(tmp_path / "scheduler.db")
    now, snapshot = [10], [_eligible()]
    clock = lambda: now[0]
    leases = LeaseService(store, clock)
    queue = WaitQueue(store, clock, PrecedenceModel.default())
    queue.enqueue(
        resource, _holder("worker"), PriorityClass.ROUTINE, authority=frozenset({"build"})
    )
    callbacks = []
    first = _CrashBeforeWakeAdmission(
        store, leases, queue, lambda _: snapshot[0], callbacks.append, clock
    )
    with pytest.raises(RuntimeError, match="fixture crash before dispatch admission"):
        first.on_release("release", resource, ttl=10)
    lease = leases.current(resource)
    assert lease is not None
    if change == "hold":
        snapshot[0] = replace(snapshot[0], exact_hold_members=frozenset({"work-1"}))
    elif change == "expiry":
        now[0] = 21
    elif change == "revoked":
        leases.release(lease.lease_id, lease.holder, lease.fencing_epoch)
    else:
        leases.renew(
            lease.lease_id,
            lease.holder,
            ttl=10,
            satisfied={"policy-current", "capability-current", "budget-remaining"},
        )
    restarted = WakeupService(store, leases, queue, lambda _: snapshot[0], callbacks.append, clock)
    with pytest.raises(WakeDenied):
        restarted.on_release("release", resource, ttl=10)
    assert callbacks == []


@pytest.mark.parametrize(
    "changed",
    [
        {"signed_digest": "a" * 64},
        {"key_id": "ephemeral-lower-root"},
        {"root_class": SigningRootClass.LOWER_ENVIRONMENT},
        {"environment": "staging"},
        {"capability_id": "different"},
        {"non_exportable": False},
        {"hardware_backed": False},
        {"production_proof": True},
    ],
)
def test_signature_authenticates_every_authority_descriptor_field(changed):
    _, signer, artifact = artifact_fixture()
    assert signer.verify(artifact.signature)
    assert not signer.verify(replace(artifact.signature, **changed))

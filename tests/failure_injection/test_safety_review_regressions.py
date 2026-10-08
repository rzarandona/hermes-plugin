from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from hermes_kanban_workflow.domain.resources import ResourceUri
from hermes_kanban_workflow.effects.receipts import ProviderReceipt, ReadbackReceipt
from hermes_kanban_workflow.effects.reconciler import EffectReconciler
from hermes_kanban_workflow.effects.state_machine import EffectState, EffectStore
from hermes_kanban_workflow.ledger.repository import IdempotencyIntegrityError
from hermes_kanban_workflow.scheduler.leases import LeaseService, SchedulerStore
from hermes_kanban_workflow.scheduler.precedence import PrecedenceModel, PriorityClass
from hermes_kanban_workflow.scheduler.queues import WaitQueue
from hermes_kanban_workflow.scheduler.wakeup import WakeDenied, WakeupService
from tests.failure_injection.test_resource_scheduler import _eligible, _holder
from tests.failure_injection.test_safety_admission import _intent
from tests.ledger_fixtures import command, guarded_service


def test_absent_readback_during_active_dispatch_cannot_start_second_callback(tmp_path):
    database = tmp_path / "effects.db"
    reached, finish = Event(), Event()
    callbacks = []
    with (
        EffectStore(database, readback_verifier=lambda _: True) as first,
        EffectStore(database, readback_verifier=lambda _: True) as second,
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        _intent(first)

        def dispatch_one(_record):
            callbacks.append("first")
            reached.set()
            assert finish.wait(timeout=10)
            raise TimeoutError("fixture")

        def dispatch_two(_record):
            callbacks.append("second")
            raise TimeoutError("fixture")

        readback = lambda record: ReadbackReceipt("absent", record.operation_id, "absent", "a", "e")
        winner = pool.submit(
            EffectReconciler(first, dispatch=dispatch_one, readback=readback).dispatch, "op"
        )
        try:
            assert reached.wait(timeout=10)
            EffectReconciler(second, dispatch=dispatch_two, readback=readback).retry("op")
            assert callbacks == ["first"]
            assert second.get("op").attempts == 1
        finally:
            finish.set()
        winner.result(timeout=10)


@pytest.mark.parametrize(
    "change",
    [{}, {"payload": {"changed": True}}, {"command_id": "other"}, {"idempotency_key": "other"}],
)
def test_public_append_cannot_override_uncertain_guarded_reservation(tmp_path, change):
    service, principal = guarded_service(tmp_path / "ledger.db")

    def crash(_command):
        raise RuntimeError("fixture uncertain callback")

    with pytest.raises(RuntimeError, match="fixture uncertain callback"):
        service.execute(command(), principal, effect=crash)
    with pytest.raises((RuntimeError, IdempotencyIntegrityError)):
        service._ledger.append(command(**change))
    assert tuple(service._ledger.iter_events()) == ()
    with pytest.raises(RuntimeError, match="COMMAND_OUTCOME_UNCERTAIN"):
        service.execute(command(), principal)


def test_public_append_cannot_race_active_guarded_callback(tmp_path):
    service, principal = guarded_service(tmp_path / "ledger.db")
    reached, finish = Event(), Event()

    def callback(_command):
        reached.set()
        assert finish.wait(timeout=10)

    with ThreadPoolExecutor(max_workers=1) as pool:
        winner = pool.submit(service.execute, command(), principal, effect=callback)
        try:
            assert reached.wait(timeout=10)
            with pytest.raises(RuntimeError, match="COMMAND_OUTCOME_UNCERTAIN"):
                service._ledger.append(command())
        finally:
            finish.set()
        receipt = winner.result(timeout=10)
    assert service.execute(command(), principal) == receipt


def test_distinct_release_ids_cannot_consume_same_queue_head(tmp_path):
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/review")
    store = SchedulerStore(tmp_path / "scheduler.db")
    queue = WaitQueue(store, lambda: 10, PrecedenceModel.default())
    queue.enqueue(
        resource, _holder("worker"), PriorityClass.ROUTINE, authority=frozenset({"build"})
    )
    selected, resume = Event(), Event()
    callbacks = []

    def slow_loader(_item):
        selected.set()
        assert resume.wait(timeout=10)
        return _eligible()

    slow = WakeupService(
        store, LeaseService(store, lambda: 10), queue, slow_loader, callbacks.append, lambda: 10
    )
    fast = WakeupService(
        store,
        LeaseService(store, lambda: 10),
        queue,
        lambda _: _eligible(),
        callbacks.append,
        lambda: 10,
    )
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(slow.on_release, "release-slow", resource, ttl=10)
        try:
            assert selected.wait(timeout=10)
            admitted = fast.on_release("release-fast", resource, ttl=10)
        finally:
            resume.set()
        with pytest.raises(WakeDenied):
            pending.result(timeout=10)
    assert callbacks == [admitted.attempt]
    assert sum(row["event_type"] == "wake_created" for row in store.events()) == 1


def test_late_timeout_cannot_regress_authoritative_confirmation(tmp_path):
    database = tmp_path / "effects.db"
    reached, finish = Event(), Event()
    with (
        EffectStore(database, readback_verifier=lambda _: True) as first,
        EffectStore(database, readback_verifier=lambda _: True) as second,
        ThreadPoolExecutor(max_workers=1) as pool,
    ):
        _intent(first)

        def dispatch(_record):
            reached.set()
            assert finish.wait(timeout=10)
            raise TimeoutError("late timeout")

        readback = lambda record: ReadbackReceipt(
            "applied", record.operation_id, "applied", "a", "e"
        )
        pending = pool.submit(
            EffectReconciler(first, dispatch=dispatch, readback=readback).dispatch, "op"
        )
        try:
            assert reached.wait(timeout=10)
            assert (
                EffectReconciler(second, dispatch=dispatch, readback=readback).reconcile("op").state
                is EffectState.CONFIRMED
            )
        finally:
            finish.set()
        assert pending.result(timeout=10).state is EffectState.CONFIRMED
        assert second.get("op").state is EffectState.CONFIRMED


def test_stale_absence_readback_cannot_replace_newer_applied_confirmation(tmp_path):
    database = tmp_path / "effects.db"
    dispatching, return_provider, reading, return_readback = Event(), Event(), Event(), Event()
    with (
        EffectStore(database, readback_verifier=lambda _: True) as first,
        EffectStore(database, readback_verifier=lambda _: True) as second,
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        _intent(first)

        def dispatch(record):
            dispatching.set()
            assert return_provider.wait(timeout=10)
            return ProviderReceipt(
                "provider", record.operation_id, record.idempotency_key, "accepted", "p"
            )

        def slow_readback(record):
            reading.set()
            assert return_readback.wait(timeout=10)
            return ReadbackReceipt("stale-absence", record.operation_id, "absent", "a", "e")

        fresh_readback = lambda record: ReadbackReceipt(
            "fresh-applied", record.operation_id, "applied", "a", "e"
        )
        provider = pool.submit(
            EffectReconciler(first, dispatch=dispatch, readback=fresh_readback).dispatch, "op"
        )
        try:
            assert dispatching.wait(timeout=10)
            stale = pool.submit(
                EffectReconciler(second, dispatch=dispatch, readback=slow_readback).reconcile, "op"
            )
            assert reading.wait(timeout=10)
            return_provider.set()
            assert provider.result(timeout=10).state is EffectState.CONFIRMED
        finally:
            return_provider.set()
            return_readback.set()
        with pytest.raises(RuntimeError, match="STALE"):
            stale.result(timeout=10)
        assert second.get("op").state is EffectState.CONFIRMED


def test_consumed_absence_and_old_attempt_cannot_reauthorize_new_attempt(tmp_path):
    with EffectStore(tmp_path / "effects.db", readback_verifier=lambda _: True) as store:
        _intent(store)
        first = store.mark_started("op")
        store.require_reconciliation("op", "first callback returned", expected=first)
        first_snapshot = store.mark_readback_pending("op")
        absence = ReadbackReceipt("first-absence", "op", "absent", "a", "e")
        store.append_readback_receipt(absence, expected=first_snapshot)
        second = store.mark_started("op")
        assert second.attempts == 2
        store.require_reconciliation("op", "second callback returned", expected=second)
        current = store.mark_readback_pending("op")

        with pytest.raises(RuntimeError, match="ALREADY_CONSUMED_STALE"):
            store.append_readback_receipt(absence, expected=current)
        with pytest.raises(RuntimeError, match="ATTEMPT_STALE"):
            store.require_reconciliation("op", "late first timeout", expected=first)
        with pytest.raises(RuntimeError, match="ATTEMPT_STALE"):
            store.append_provider_receipt(
                ProviderReceipt("late-first", "op", "stable-op", "accepted", "p"), expected=first
            )
        assert store.get("op") == current
        assert not store.retry_authorized("op")
        applied = store.append_readback_receipt(
            ReadbackReceipt("second-applied", "op", "applied", "a", "e"), expected=current
        )
        assert applied.state is EffectState.CONFIRMED
        late = store.require_reconciliation("op", "late second timeout", expected=second)
        assert late.state is EffectState.CONFIRMED
        assert late.receipt == "second-applied"

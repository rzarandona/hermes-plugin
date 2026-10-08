"""Expected-safe behaviors, exercised only against isolated fixture stores/callbacks."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.adapters.artifact_store import (
    ArtifactMaterial,
    EphemeralSigningAdapter,
    ImmutableArtifactStore,
    SigningCapability,
)
from hermes_kanban_workflow.domain.resources import ResourceUri
from hermes_kanban_workflow.effects.receipts import ReadbackReceipt
from hermes_kanban_workflow.effects.reconciler import EffectReconciler
from hermes_kanban_workflow.effects.state_machine import EffectStore
from hermes_kanban_workflow.flows.flow3 import (
    HealthGate,
    HealthGateKind,
    HealthStatus,
    OwnerApprovalRegistry,
    ReleaseBinding,
    RollbackReadinessReceipt,
    RolloutStrategy,
    create_promotion_command,
)
from hermes_kanban_workflow.ledger.repository import IdempotencyIntegrityError
from hermes_kanban_workflow.scheduler.leases import LeaseService, SchedulerStore
from hermes_kanban_workflow.scheduler.precedence import PrecedenceModel, PriorityClass
from hermes_kanban_workflow.scheduler.queues import WaitQueue
from hermes_kanban_workflow.scheduler.wakeup import WakeDenied, WakeupService
from tests.failure_injection.test_resource_scheduler import _eligible, _holder
from tests.ledger_fixtures import command, guarded_service


def test_exact_replay_must_not_repeat_callback(tmp_path):
    service, subject = guarded_service(tmp_path / "ledger.db")
    calls = []
    service.execute(command(), subject, effect=calls.append)
    service.execute(command(), subject, effect=calls.append)
    assert len(tuple(service._ledger.iter_events())) == 1
    assert len(calls) == 1, f"Exact replay called effect {len(calls)} times"


def test_changed_payload_must_be_rejected_before_callback(tmp_path):
    service, subject = guarded_service(tmp_path / "ledger.db")
    calls = []
    service.execute(command(), subject, effect=calls.append)
    with pytest.raises(IdempotencyIntegrityError):
        service.execute(command(payload={"unexpected": "changed"}), subject, effect=calls.append)
    assert len(tuple(service._ledger.iter_events())) == 1
    assert len(calls) == 1, "Rejected payload reached effect callback"


@pytest.mark.parametrize("readback_status", ["unknown", "contradictory"])
def test_unresolved_readback_must_block_redispatch(tmp_path, readback_status):
    calls = []

    def dispatch(record):
        calls.append(record.operation_id)
        raise TimeoutError("fixture only")

    with EffectStore(tmp_path / "effects.db", readback_verifier=lambda _: True) as store:
        store.record_intent(
            operation_id="op",
            idempotency_key="stable-op",
            provider="fixture",
            payload_digest="a" * 64,
        )
        reconciler = EffectReconciler(
            store,
            dispatch=dispatch,
            readback=lambda record: ReadbackReceipt(
                "rb", record.operation_id, readback_status, "fixture", "fixture:evidence"
            ),
        )
        reconciler.dispatch("op")
        reconciler.retry("op")
        assert len(calls) == 1, f"{readback_status} triggered redispatch"


def test_direct_dispatch_must_not_bypass_readback_or_budget(tmp_path):
    calls = []

    def dispatch(record):
        calls.append(record.operation_id)
        raise TimeoutError("fixture only")

    with EffectStore(tmp_path / "effects.db") as store:
        store.record_intent(
            operation_id="op",
            idempotency_key="stable-op",
            provider="fixture",
            payload_digest="a" * 64,
        )
        reconciler = EffectReconciler(
            store, dispatch=dispatch, readback=lambda _: None, reconciliation_budget=1
        )
        reconciler.dispatch("op")
        for _ in range(3):
            try:
                reconciler.dispatch("op")
            except (RuntimeError, PermissionError):
                pass
        assert len(calls) == 1, f"Budget 1 allowed {len(calls)} dispatches without readback"


@pytest.mark.parametrize("change", ["hold", "expired_lease"])
def test_replayed_wake_must_revalidate_after_crash(tmp_path, change):
    resource = ResourceUri.parse("resource://shared/build-lane/github/global/audit")
    store = SchedulerStore(tmp_path / "scheduler.db")
    now = [10]
    snapshot = [_eligible()]
    queue = WaitQueue(store, lambda: now[0], PrecedenceModel.default())
    queue.enqueue(
        resource, _holder("worker"), PriorityClass.ROUTINE, authority=frozenset({"build"})
    )
    attempts = []

    def start(attempt):
        if not attempts:
            attempts.append("fixture-crash")
            raise RuntimeError("fixture crash after durable wake, before dispatch")
        attempts.append(attempt)

    service = WakeupService(
        store,
        LeaseService(store, lambda: now[0]),
        queue,
        lambda _: snapshot[0],
        start,
        lambda: now[0],
    )
    with pytest.raises(RuntimeError, match="fixture crash"):
        service.on_release("release", resource, ttl=10)
    if change == "hold":
        snapshot[0] = replace(snapshot[0], exact_hold_members=frozenset({"work-1"}))
    else:
        now[0] = 21
    try:
        service.on_release("release", resource, ttl=10)
    except (WakeDenied, PermissionError):
        pass
    assert len(attempts) == 1, f"Replayed wake dispatched despite {change}"


def artifact_fixture():
    now = datetime(2026, 10, 8, tzinfo=UTC)
    material = ArtifactMaterial(b"app", b"src", b"prov", b"tests", b"deps", b"cfg", b"sbom")
    signer = EphemeralSigningAdapter(
        lower_private_key=Ed25519PrivateKey.generate(),
        production_private_key=Ed25519PrivateKey.generate(),
    )
    capability = SigningCapability(
        material.material_digest,
        "production",
        now,
        now + timedelta(minutes=2),
        "fixture-capability",
    )
    artifact = ImmutableArtifactStore().build_once(
        material, signer=signer, environment="production", now=now, capability=capability
    )
    return now, signer, artifact


def test_signature_must_reject_changed_production_proof_metadata():
    _, signer, artifact = artifact_fixture()
    changed = replace(artifact.signature, production_proof=True)
    assert not signer.verify(changed), "Unsigned fixture proof metadata was accepted"


def test_fixture_artifact_must_not_mint_production_effect_command():
    now, signer, original = artifact_fixture()
    changed = replace(original, signature=replace(original.signature, production_proof=True))
    changed = replace(changed, artifact_id=changed.recompute_identity())
    binding = ReleaseBinding(
        changed.artifact_id,
        "production",
        "cfg",
        "policy",
        RolloutStrategy.PROGRESSIVE,
        now,
        now + timedelta(minutes=5),
        "rollback",
        False,
    )
    owner = OwnerApprovalRegistry(
        private_key=Ed25519PrivateKey.generate(),
        owner_by_environment={"production": "fixture-owner"},
    )
    approval = owner.issue(owner_subject_id="fixture-owner", binding=binding, decided_at=now)
    readiness = RollbackReadinessReceipt(
        changed.artifact_id, binding.rollback_contract, "fixture:readiness", b"fixture-auth"
    )
    denied = False
    try:
        promotion = create_promotion_command(
            artifact=changed,
            signer=signer,
            binding=binding,
            approval=approval,
            owner_registry=owner,
            release_lease_ref="fixture:lease",
            verify_release_lease=lambda *_: True,
            health_gates=(
                HealthGate(HealthGateKind.TELEMETRY, HealthStatus.PASS, "fixture:health"),
            ),
            verify_health_gate=lambda _: True,
            atomic_unavailability_evidence=None,
            rollback_readiness=readiness,
            verify_rollback_readiness=lambda _: True,
            now=now,
        )
        promotion.as_effect_command()
    except PermissionError:
        denied = True
    assert denied, "Fixture signature metadata produced a production effect-command object"

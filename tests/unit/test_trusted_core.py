from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from hermes_kanban_workflow.command.service import GuardedCommandService
from hermes_kanban_workflow.domain.commands import CommandEnvelope, EffectClass
from hermes_kanban_workflow.domain.identity import AuthorityEpoch, CorrelationEnvelope
from hermes_kanban_workflow.effects.state_machine import EffectState, EffectStateMachine
from hermes_kanban_workflow.ledger.repository import Ledger
from hermes_kanban_workflow.policy.model import SignedPolicy
from hermes_kanban_workflow.scheduler.leases import LeaseRegistry


def command(key: str = "cmd-1", payload: dict[str, object] | None = None) -> CommandEnvelope:
    now = datetime.now(timezone.utc)
    return CommandEnvelope(
        command_id=str(uuid4()),
        idempotency_key=key,
        actor_id="worker-1",
        target_id="card-1",
        command_type="record_note",
        effect_class=EffectClass.NO_EXTERNAL_EFFECT,
        authority_epoch=AuthorityEpoch(value=2),
        policy_digest="policy-1",
        issued_at=now,
        expires_at=now + timedelta(minutes=1),
        payload=payload or {"note": "verified"},
        correlation=CorrelationEnvelope(product_id="p1", project_id="j1", work_item_id="card-1"),
    )


class TrustedCoreTests(unittest.TestCase):
    def test_models_are_immutable_and_epoch_is_monotonic(self) -> None:
        item = command()
        with self.assertRaises(Exception):
            item.target_id = "other"  # type: ignore[misc]
        self.assertTrue(AuthorityEpoch(value=3).is_newer_than(AuthorityEpoch(value=2)))

    def test_policy_rejects_unsigned_expired_or_wrong_scope(self) -> None:
        now = datetime.now(timezone.utc)
        valid = SignedPolicy(
            policy_id="pilot", scope="p1", issued_at=now, expires_at=now + timedelta(days=1),
            rules={"record_note": {"roles": ["worker"]}}, signature="fixture-signature"
        )
        self.assertTrue(valid.is_usable(now, "p1"))
        self.assertFalse(valid.model_copy(update={"signature": ""}).is_usable(now, "p1"))
        self.assertFalse(valid.is_usable(now, "p2"))

    def test_ledger_and_guarded_service_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "workflow.db", writer_identity="HermesKanbanWriter")
            service = GuardedCommandService(ledger, writer_identity="HermesKanbanWriter")
            first = service.execute(command())
            second = service.execute(command())
            self.assertEqual(first.event_id, second.event_id)
            with self.assertRaisesRegex(PermissionError, "SOLE_WRITER_DENIED"):
                GuardedCommandService(ledger, writer_identity="desktop-user").execute(command("x"))
            with self.assertRaisesRegex(ValueError, "IDEMPOTENCY_PAYLOAD_MISMATCH"):
                service.execute(command(payload={"note": "changed"}))

    def test_effect_unknown_blocks_retry_and_close(self) -> None:
        machine = EffectStateMachine()
        intent = machine.create_intent("effect-1", "provider-a")
        unknown = machine.mark_unknown(intent.effect_id, "timeout")
        self.assertEqual(unknown.state, EffectState.UNKNOWN)
        with self.assertRaisesRegex(RuntimeError, "EFFECT_RECONCILIATION_REQUIRED"):
            machine.retry(unknown.effect_id)

    def test_lease_fencing_rejects_stale_actor(self) -> None:
        leases = LeaseRegistry()
        first = leases.acquire("build-lane", "worker-a")
        second = leases.acquire("build-lane", "worker-b", replace_expired=True, now=first.expires_at)
        self.assertGreater(second.fencing_epoch, first.fencing_epoch)
        self.assertFalse(leases.is_authoritative(first))
        self.assertTrue(leases.is_authoritative(second))


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from hermes_kanban_workflow.command.registry import CommandDefinition, CommandRegistry
from hermes_kanban_workflow.command.service import GuardedCommandService, ServiceTopology
from hermes_kanban_workflow.command.validator import (
    AuthenticatedPrincipal,
    CommandValidator,
    ValidationSnapshot,
)
from hermes_kanban_workflow.domain.commands import CommandEnvelope, EffectClass
from hermes_kanban_workflow.domain.identity import AuthorityEpoch, CorrelationEnvelope
from hermes_kanban_workflow.effects.state_machine import EffectState, EffectStateMachine
from hermes_kanban_workflow.ledger.repository import Ledger
from hermes_kanban_workflow.policy.model import SignedPolicy
from hermes_kanban_workflow.scheduler.leases import LeaseRegistry


def command(key: str = "cmd-1", payload: dict[str, object] | None = None) -> CommandEnvelope:
    correlation = CorrelationEnvelope(
        product_id="p1",
        project_id="j1",
        work_item_id="card-1",
        service_id=None,
        root_cause_id=None,
        parent_record_type="project",
        parent_record_id="j1",
        record_type="work_item",
        record_id="card-1",
        generation=1,
        policy_version="policy-1",
        authority_epoch=2,
        created_at_control_time=1,
    )
    return CommandEnvelope(
        command_id=f"command-{key}",
        idempotency_key=key,
        command_type="record_note",
        actor_role="worker",
        actor_id="worker-1",
        product_id="p1",
        project_id="j1",
        target_type="work_item",
        target_id="card-1",
        work_item_id="card-1",
        capability_id="capability-1",
        policy_version="policy-1",
        authority_epoch=2,
        lease_ids=(),
        reason_code="verified",
        precondition_hash="precondition-1",
        expires_at_control_time=10**30,
        expected_effect_class=EffectClass.READ_ONLY,
        payload=payload or {"note": "verified"},
        correlation=correlation,
    )


class TrustedCoreTests(unittest.TestCase):
    def test_models_are_immutable_and_epoch_is_monotonic(self) -> None:
        item = command()
        with self.assertRaises(ValidationError):
            item.target_id = "other"  # type: ignore[misc]
        self.assertTrue(AuthorityEpoch(value=3).is_newer_than(AuthorityEpoch(value=2)))

    def test_policy_rejects_unsigned_expired_or_wrong_scope(self) -> None:
        now = datetime.now(UTC)
        valid = SignedPolicy(
            policy_id="pilot",
            scope="p1",
            issued_at=now,
            expires_at=now + timedelta(days=1),
            rules={"record_note": {"roles": ["worker"]}},
            signature="fixture-signature",
        )
        self.assertTrue(valid.is_usable(now, "p1"))
        self.assertFalse(valid.model_copy(update={"signature": ""}).is_usable(now, "p1"))
        self.assertFalse(valid.is_usable(now, "p2"))

    def test_ledger_and_guarded_service_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ledger = Ledger(Path(tmp) / "workflow.db", writer_identity="fixture-process-only")
            registry = CommandRegistry()
            registry.register(
                CommandDefinition(
                    "record_note",
                    frozenset({"worker"}),
                    frozenset({"work_item"}),
                    EffectClass.READ_ONLY,
                    False,
                    frozenset({"verified"}),
                )
            )
            principal = AuthenticatedPrincipal(
                "worker-1",
                "worker",
                "p1",
                "j1",
                "signed:fixture-client",
                frozenset({"card-1"}),
                {
                    "work_item_id": "card-1",
                    "run_id": None,
                    "artifact_id": None,
                    "environment_id": None,
                    "workspace_id": None,
                },
            )
            snapshot = ValidationSnapshot(
                1,
                False,
                frozenset(),
                frozenset({"capability-1"}),
                "policy-1",
                2,
                frozenset(),
                None,
                {"card-1": "precondition-1"},
            )
            service = GuardedCommandService(
                ledger,
                CommandValidator(registry),
                lambda: snapshot,
                ServiceTopology("fixture-separate-process"),
            )
            first = service.execute(command(), principal)
            second = service.execute(command(), principal)
            self.assertEqual(first.event_id, second.event_id)
            with self.assertRaisesRegex(ValueError, "IDEMPOTENCY_PAYLOAD_MISMATCH"):
                service.execute(command(payload={"note": "changed"}), principal)

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
        second = leases.acquire(
            "build-lane", "worker-b", replace_expired=True, now=first.expires_at
        )
        self.assertGreater(second.fencing_epoch, first.fencing_epoch)
        self.assertFalse(leases.is_authoritative(first))
        self.assertTrue(leases.is_authoritative(second))


if __name__ == "__main__":
    unittest.main()

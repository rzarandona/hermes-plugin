from __future__ import annotations

from pathlib import Path

from hermes_kanban_workflow.command.registry import CommandDefinition, CommandRegistry
from hermes_kanban_workflow.command.service import GuardedCommandService, ServiceTopology
from hermes_kanban_workflow.command.validator import (
    AuthenticatedPrincipal,
    CommandValidator,
    ValidationSnapshot,
)
from hermes_kanban_workflow.domain.commands import CommandEnvelope, EffectClass
from hermes_kanban_workflow.domain.identity import CorrelationEnvelope
from hermes_kanban_workflow.ledger.repository import Ledger


def command(**updates: object) -> CommandEnvelope:
    correlation = CorrelationEnvelope(
        product_id="product-1",
        project_id="project-1",
        work_item_id="work-1",
        service_id=None,
        root_cause_id=None,
        parent_record_type="project",
        parent_record_id="project-1",
        record_type="work_item",
        record_id="work-1",
        generation=1,
        policy_version="sha256:policy",
        authority_epoch=2,
        created_at_control_time=100,
    )
    data: dict[str, object] = {
        "command_id": "command-1",
        "idempotency_key": "stable-key",
        "command_type": "record_note",
        "actor_role": "worker",
        "actor_id": "worker-1",
        "product_id": "product-1",
        "project_id": "project-1",
        "target_type": "work_item",
        "target_id": "work-1",
        "work_item_id": "work-1",
        "capability_id": "capability-1",
        "policy_version": "sha256:policy",
        "authority_epoch": 2,
        "lease_ids": (),
        "reason_code": "verified",
        "precondition_hash": "sha256:precondition",
        "expires_at_control_time": 10**30,
        "expected_effect_class": EffectClass.READ_ONLY,
        "payload": {"note": "verified"},
        "correlation": correlation,
    }
    data.update(updates)
    return CommandEnvelope(**data)  # type: ignore[arg-type]


def ledger(path: Path) -> Ledger:
    return Ledger(path, writer_identity="HermesKanbanWriter")


def guarded_service(path: Path) -> tuple[GuardedCommandService, AuthenticatedPrincipal]:
    registry = CommandRegistry()
    registry.register(
        CommandDefinition(
            name="record_note",
            allowed_roles=frozenset({"worker"}),
            target_types=frozenset({"work_item"}),
            effect_class=EffectClass.READ_ONLY,
            requires_lease=False,
            allowed_reason_codes=frozenset({"verified"}),
        )
    )
    principal = AuthenticatedPrincipal(
        actor_id="worker-1",
        actor_role="worker",
        product_id="product-1",
        project_id="project-1",
        executable_identity="signed:fixture-client",
        target_ids=frozenset({"work-1"}),
        bindings={
            "work_item_id": "work-1",
            "run_id": None,
            "artifact_id": None,
            "environment_id": None,
            "workspace_id": None,
        },
    )
    snapshot = ValidationSnapshot(
        control_time=100,
        disabled=False,
        held_target_ids=frozenset(),
        capability_ids=frozenset({"capability-1"}),
        policy_version="sha256:policy",
        authority_epoch=2,
        lease_ids=frozenset(),
        fencing_epoch=None,
        precondition_hashes={"work-1": "sha256:precondition"},
    )
    service = GuardedCommandService(
        ledger(path),
        CommandValidator(registry),
        lambda: snapshot,
        ServiceTopology("fixture-separate-process"),
    )
    return service, principal

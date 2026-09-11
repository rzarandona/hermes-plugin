from __future__ import annotations

import pytest
from pydantic import ValidationError

from hermes_kanban_workflow.domain.commands import CommandEnvelope, EffectClass
from hermes_kanban_workflow.domain.identity import CorrelationEnvelope


def correlation() -> CorrelationEnvelope:
    return CorrelationEnvelope(
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


def command(**updates: object) -> CommandEnvelope:
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
        "run_id": None,
        "artifact_id": None,
        "environment_id": None,
        "workspace_id": None,
        "capability_id": "capability-1",
        "policy_version": "sha256:policy",
        "authority_epoch": 2,
        "fencing_epoch": None,
        "lease_ids": (),
        "reason_code": "verified",
        "precondition_hash": "sha256:precondition",
        "expires_at_control_time": 200,
        "expected_effect_class": EffectClass.READ_ONLY,
        "payload": {"nested": {"value": 1}, "items": ["a", "b"]},
        "correlation": correlation(),
    }
    data.update(updates)
    return CommandEnvelope(**data)  # type: ignore[arg-type]


def test_effect_classes_match_the_frozen_specification_exactly() -> None:
    assert [value.value for value in EffectClass] == [
        "read_only",
        "idempotent",
        "reversible",
        "irreversible",
    ]


def test_command_requires_positive_epochs_and_exact_target_identity() -> None:
    with pytest.raises(ValidationError):
        command(authority_epoch=0)
    with pytest.raises(ValidationError, match="target identity"):
        command(target_id="other")


def test_payload_is_deeply_immutable() -> None:
    envelope = command()
    with pytest.raises(TypeError):
        envelope.payload["new"] = "value"  # type: ignore[index]
    nested = envelope.payload["nested"]
    with pytest.raises(TypeError):
        nested["value"] = 2  # type: ignore[index]


def test_canonical_serialization_is_order_independent() -> None:
    first = command(payload={"a": 1, "b": {"x": 2, "y": 3}})
    second = command(payload={"b": {"y": 3, "x": 2}, "a": 1})
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.digest == second.digest
    assert first.payload_digest == second.payload_digest

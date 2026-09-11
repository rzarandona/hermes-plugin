from __future__ import annotations

import pytest
from pydantic import ValidationError

from hermes_kanban_workflow.command.registry import (
    CommandDefinition,
    CommandRegistry,
    RegistryError,
)
from hermes_kanban_workflow.command.validator import (
    AuthenticatedPrincipal,
    CommandValidationError,
    CommandValidator,
    ValidationSnapshot,
)
from hermes_kanban_workflow.domain.commands import EffectClass
from tests.ledger_fixtures import command


def definition() -> CommandDefinition:
    return CommandDefinition(
        name="record_note",
        allowed_roles=frozenset({"worker"}),
        target_types=frozenset({"work_item"}),
        effect_class=EffectClass.READ_ONLY,
        requires_lease=False,
        allowed_reason_codes=frozenset({"verified"}),
    )


@pytest.mark.parametrize(
    "field",
    [
        "command_id",
        "idempotency_key",
        "command_type",
        "actor_role",
        "actor_id",
        "product_id",
        "project_id",
        "target_type",
        "target_id",
        "capability_id",
        "policy_version",
        "reason_code",
        "precondition_hash",
    ],
)
def test_common_envelope_required_text_fields_reject_empty_values(field: str) -> None:
    with pytest.raises(ValidationError):
        command(**{field: ""})


def test_registry_rejects_duplicate_named_definition() -> None:
    registry = CommandRegistry()
    registry.register(definition())

    with pytest.raises(RegistryError, match="COMMAND_ALREADY_REGISTERED"):
        registry.register(definition())


def test_validator_reports_unregistered_command_as_atomic_denial() -> None:
    registry = CommandRegistry()

    with pytest.raises(CommandValidationError) as caught:
        CommandValidator(registry).validate(command(), principal(), snapshot())

    assert caught.value.failures == ("COMMAND_UNREGISTERED",)


def validator() -> CommandValidator:
    registry = CommandRegistry()
    registry.register(definition())
    return CommandValidator(registry)


def principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        actor_id="worker-1",
        actor_role="worker",
        product_id="product-1",
        project_id="project-1",
        executable_identity="signed:test-client",
        target_ids=frozenset({"work-1"}),
        bindings={
            "work_item_id": "work-1",
            "run_id": None,
            "artifact_id": None,
            "environment_id": None,
            "workspace_id": None,
        },
    )


def snapshot() -> ValidationSnapshot:
    return ValidationSnapshot(
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


def test_validator_accepts_exact_authenticated_envelope() -> None:
    accepted = validator().validate(command(), principal(), snapshot())

    assert accepted.definition == definition()
    assert accepted.command.digest == command().digest


def test_validator_reports_all_atomic_semantic_failures() -> None:
    hostile_principal = AuthenticatedPrincipal(
        actor_id="attacker",
        actor_role="hostile_plugin",
        product_id="other-product",
        project_id="other-project",
        executable_identity="unsigned:injected-module",
        target_ids=frozenset({"other-target"}),
        bindings={
            "work_item_id": "other-work",
            "run_id": "run-evil",
            "artifact_id": "copied-artifact",
            "environment_id": "production",
            "workspace_id": "symlink-workspace",
        },
    )
    stale = ValidationSnapshot(
        control_time=10**31,
        disabled=True,
        held_target_ids=frozenset({"work-1"}),
        capability_ids=frozenset(),
        policy_version="sha256:other",
        authority_epoch=3,
        lease_ids=frozenset(),
        fencing_epoch=9,
        precondition_hashes={"work-1": "sha256:changed"},
    )

    with pytest.raises(CommandValidationError) as caught:
        validator().validate(command(), hostile_principal, stale)

    assert set(caught.value.failures) == {
        "ACTOR_ID_MISMATCH",
        "ACTOR_ROLE_DENIED",
        "PRODUCT_SCOPE_MISMATCH",
        "PROJECT_SCOPE_MISMATCH",
        "TARGET_ID_DENIED",
        "WORK_ITEM_BINDING_MISMATCH",
        "RUN_BINDING_MISMATCH",
        "ARTIFACT_BINDING_MISMATCH",
        "ENVIRONMENT_BINDING_MISMATCH",
        "WORKSPACE_BINDING_MISMATCH",
        "CLIENT_EXECUTABLE_UNTRUSTED",
        "CAPABILITY_DENIED",
        "POLICY_MISMATCH",
        "STALE_AUTHORITY_EPOCH",
        "COMMAND_EXPIRED",
        "FENCING_EPOCH_MISMATCH",
        "PRECONDITION_FAILED",
        "ENFORCEMENT_DISABLED",
        "TARGET_HELD",
    }


def test_registered_definition_enforces_reason_effect_and_required_lease() -> None:
    registry = CommandRegistry()
    registry.register(
        CommandDefinition(
            name="record_note",
            allowed_roles=frozenset({"worker"}),
            target_types=frozenset({"work_item"}),
            effect_class=EffectClass.IDEMPOTENT,
            requires_lease=True,
            allowed_reason_codes=frozenset({"approved"}),
        )
    )

    with pytest.raises(CommandValidationError) as caught:
        CommandValidator(registry).validate(command(), principal(), snapshot())

    assert set(caught.value.failures) == {
        "REASON_CODE_DENIED",
        "EFFECT_CLASS_MISMATCH",
        "LEASE_REQUIRED",
    }


def test_immediate_pre_effect_recheck_denies_changed_state_before_callback() -> None:
    validated = validator().validate(command(), principal(), snapshot())
    effects: list[str] = []

    with pytest.raises(CommandValidationError) as caught:
        validator().recheck_before_effect(
            validated,
            principal(),
            lambda: ValidationSnapshot(**{**snapshot().__dict__, "disabled": True}),
            lambda _command: effects.append("applied"),
        )

    assert "ENFORCEMENT_DISABLED" in caught.value.failures
    assert effects == []

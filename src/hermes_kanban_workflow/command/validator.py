from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TypeVar

from hermes_kanban_workflow.command.registry import (
    CommandDefinition,
    CommandRegistry,
    RegistryError,
)
from hermes_kanban_workflow.domain.commands import CommandEnvelope

EffectResult = TypeVar("EffectResult")


class CommandValidationError(PermissionError):
    def __init__(self, failures: tuple[str, ...]) -> None:
        self.code = "COMMAND_VALIDATION_DENIED"
        self.failures = failures
        super().__init__(self.code)


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    actor_id: str
    actor_role: str
    product_id: str
    project_id: str
    executable_identity: str
    target_ids: frozenset[str]
    bindings: Mapping[str, str | None]


@dataclass(frozen=True)
class ValidationSnapshot:
    control_time: int
    disabled: bool
    held_target_ids: frozenset[str]
    capability_ids: frozenset[str]
    policy_version: str
    authority_epoch: int
    lease_ids: frozenset[str]
    fencing_epoch: int | None
    precondition_hashes: Mapping[str, str]


@dataclass(frozen=True)
class ValidatedCommand:
    command: CommandEnvelope
    definition: CommandDefinition


class CommandValidator:
    def __init__(self, registry: CommandRegistry) -> None:
        self._registry = registry

    def validate(
        self,
        command: CommandEnvelope,
        principal: AuthenticatedPrincipal,
        snapshot: ValidationSnapshot,
    ) -> ValidatedCommand:
        try:
            definition = self._registry.resolve(command.command_type)
        except RegistryError as exc:
            raise CommandValidationError(("COMMAND_UNREGISTERED",)) from exc
        failures: list[str] = []
        if command.actor_id != principal.actor_id:
            failures.append("ACTOR_ID_MISMATCH")
        if command.actor_role != principal.actor_role or command.actor_role not in definition.allowed_roles:
            failures.append("ACTOR_ROLE_DENIED")
        if command.product_id != principal.product_id:
            failures.append("PRODUCT_SCOPE_MISMATCH")
        if command.project_id != principal.project_id:
            failures.append("PROJECT_SCOPE_MISMATCH")
        if command.target_type not in definition.target_types:
            failures.append("TARGET_TYPE_DENIED")
        if command.target_id not in principal.target_ids:
            failures.append("TARGET_ID_DENIED")
        binding_fields = {
            "work_item_id": "WORK_ITEM_BINDING_MISMATCH",
            "run_id": "RUN_BINDING_MISMATCH",
            "artifact_id": "ARTIFACT_BINDING_MISMATCH",
            "environment_id": "ENVIRONMENT_BINDING_MISMATCH",
            "workspace_id": "WORKSPACE_BINDING_MISMATCH",
        }
        for field_name, code in binding_fields.items():
            if getattr(command, field_name) != principal.bindings.get(field_name):
                failures.append(code)
        if not principal.executable_identity.startswith("signed:"):
            failures.append("CLIENT_EXECUTABLE_UNTRUSTED")
        if command.reason_code not in definition.allowed_reason_codes:
            failures.append("REASON_CODE_DENIED")
        if command.capability_id not in snapshot.capability_ids:
            failures.append("CAPABILITY_DENIED")
        if command.policy_version != snapshot.policy_version:
            failures.append("POLICY_MISMATCH")
        if command.authority_epoch != snapshot.authority_epoch:
            failures.append("STALE_AUTHORITY_EPOCH")
        if not command.is_current(snapshot.control_time):
            failures.append("COMMAND_EXPIRED")
        if command.expected_effect_class != definition.effect_class:
            failures.append("EFFECT_CLASS_MISMATCH")
        if definition.requires_lease and not command.lease_ids:
            failures.append("LEASE_REQUIRED")
        if not set(command.lease_ids).issubset(snapshot.lease_ids):
            failures.append("LEASE_DENIED")
        if command.fencing_epoch != snapshot.fencing_epoch:
            failures.append("FENCING_EPOCH_MISMATCH")
        if snapshot.precondition_hashes.get(command.target_id) != command.precondition_hash:
            failures.append("PRECONDITION_FAILED")
        if snapshot.disabled:
            failures.append("ENFORCEMENT_DISABLED")
        if command.target_id in snapshot.held_target_ids:
            failures.append("TARGET_HELD")
        if failures:
            raise CommandValidationError(tuple(failures))
        return ValidatedCommand(command, definition)

    def recheck_before_effect(
        self,
        validated: ValidatedCommand,
        principal: AuthenticatedPrincipal,
        snapshot_loader: Callable[[], ValidationSnapshot],
        effect: Callable[[CommandEnvelope], EffectResult],
    ) -> EffectResult:
        """Reload every mutable guard and invoke the effect with no intervening work."""
        self.validate(validated.command, principal, snapshot_loader())
        return effect(validated.command)

from __future__ import annotations

from dataclasses import dataclass

from hermes_kanban_workflow.domain.commands import EffectClass


class RegistryError(ValueError):
    """Stable denial raised by the typed command allowlist."""


@dataclass(frozen=True)
class CommandDefinition:
    name: str
    allowed_roles: frozenset[str]
    target_types: frozenset[str]
    effect_class: EffectClass
    requires_lease: bool
    allowed_reason_codes: frozenset[str]

    def __post_init__(self) -> None:
        if (
            not self.name
            or not self.allowed_roles
            or not self.target_types
            or not self.allowed_reason_codes
        ):
            raise RegistryError("COMMAND_DEFINITION_INVALID")


class CommandRegistry:
    def __init__(self) -> None:
        self._definitions: dict[str, CommandDefinition] = {}

    def register(self, definition: CommandDefinition) -> None:
        if definition.name in self._definitions:
            raise RegistryError("COMMAND_ALREADY_REGISTERED")
        self._definitions[definition.name] = definition

    def resolve(self, name: str) -> CommandDefinition:
        try:
            return self._definitions[name]
        except KeyError as exc:
            raise RegistryError("COMMAND_UNREGISTERED") from exc

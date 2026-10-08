from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from hermes_kanban_workflow.command.receipts import CommandReceipt
from hermes_kanban_workflow.command.validator import (
    AuthenticatedPrincipal,
    CommandValidator,
    ValidationSnapshot,
)
from hermes_kanban_workflow.command.windows_profile import WindowsProfileReceipt
from hermes_kanban_workflow.domain.commands import CommandEnvelope
from hermes_kanban_workflow.ledger.repository import Ledger


@dataclass(frozen=True)
class ServiceTopology:
    mode: Literal["fixture-separate-process", "external-windows-service", "combined-observe-only"]
    profile: WindowsProfileReceipt | None = None

    @property
    def enforcement_ready(self) -> bool:
        return (
            self.mode == "external-windows-service"
            and self.profile is not None
            and self.profile.enforcement_eligible
        )


class GuardedCommandService:
    """Command boundary intended to live only inside the writer service process."""

    def __init__(
        self,
        ledger: Ledger,
        validator: CommandValidator,
        snapshot_loader: Callable[[], ValidationSnapshot],
        topology: ServiceTopology,
    ) -> None:
        if topology.mode == "external-windows-service" and not topology.enforcement_ready:
            raise PermissionError("EXTERNAL_WINDOWS_PROFILE_EVIDENCE_REQUIRED")
        self._ledger = ledger
        self._validator = validator
        self._snapshot_loader = snapshot_loader
        self._topology = topology

    @property
    def enforcement_ready(self) -> bool:
        return self._topology.enforcement_ready

    def execute(
        self,
        command: CommandEnvelope,
        principal: AuthenticatedPrincipal,
        *,
        effect: Callable[[CommandEnvelope], None] | None = None,
    ) -> CommandReceipt:
        validated = self._validator.validate(command, principal, self._snapshot_loader())

        def perform() -> None:
            if effect is not None:
                self._validator.recheck_before_effect(
                    validated,
                    principal,
                    self._snapshot_loader,
                    effect,
                )

        return self._ledger.execute_once(command, perform)

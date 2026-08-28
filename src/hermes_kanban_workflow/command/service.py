from __future__ import annotations

from datetime import datetime, timezone

from hermes_kanban_workflow.domain.commands import CommandEnvelope
from hermes_kanban_workflow.domain.events import WorkflowEvent
from hermes_kanban_workflow.ledger.repository import Ledger


class GuardedCommandService:
    REQUIRED_IDENTITY = "HermesKanbanWriter"

    def __init__(self, ledger: Ledger, writer_identity: str) -> None:
        self._ledger = ledger
        self._writer_identity = writer_identity

    def execute(self, command: CommandEnvelope) -> WorkflowEvent:
        if self._writer_identity != self.REQUIRED_IDENTITY or self._ledger.writer_identity != self.REQUIRED_IDENTITY:
            raise PermissionError("SOLE_WRITER_DENIED")
        if not command.is_current(datetime.now(timezone.utc)):
            raise PermissionError("COMMAND_EXPIRED")
        if command.authority_epoch.value < 1:
            raise PermissionError("STALE_AUTHORITY_EPOCH")
        return self._ledger.append(command)


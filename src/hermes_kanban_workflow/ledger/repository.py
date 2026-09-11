from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from hermes_kanban_workflow.command.receipts import CommandReceipt
from hermes_kanban_workflow.domain.commands import CommandEnvelope
from hermes_kanban_workflow.domain.events import WorkflowEvent
from hermes_kanban_workflow.domain.identity import CorrelationEnvelope
from hermes_kanban_workflow.ledger.schema import migrate, open_database


class IdempotencyIntegrityError(ValueError):
    def __init__(
        self, code: str, *, existing_digest: str | None = None, presented_digest: str | None = None
    ) -> None:
        self.code = code
        self.existing_digest = existing_digest
        self.presented_digest = presented_digest
        super().__init__(code)


class Ledger:
    """Transactional append-only SQLite ledger; not a WP5 writer-security boundary."""

    def __init__(self, path: Path, writer_identity: str) -> None:
        self._path = path
        self.writer_identity = writer_identity
        migrate(path)

    def _connect(self) -> sqlite3.Connection:
        return open_database(self._path)

    def append(
        self,
        command: CommandEnvelope,
        *,
        before_commit: Callable[[], None] | None = None,
    ) -> CommandReceipt:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            replay = db.execute(
                "SELECT * FROM events WHERE idempotency_key=?", (command.idempotency_key,)
            ).fetchone()
            if replay is not None:
                receipt = self._validate_replay(replay, command)
                db.commit()
                return receipt
            command_row = db.execute(
                "SELECT * FROM events WHERE command_id=?", (command.command_id,)
            ).fetchone()
            if command_row is not None:
                raise IdempotencyIntegrityError("COMMAND_ID_REUSE_MISMATCH")

            sequence = int(
                db.execute("SELECT COALESCE(MAX(sequence), 0) + 1 FROM events").fetchone()[0]
            )
            event = WorkflowEvent(
                event_id=str(uuid4()),
                sequence=sequence,
                event_type=command.command_type,
                target_id=command.target_id,
                command_id=command.command_id,
                payload=command.payload,
                correlation=command.correlation,
                occurred_at=datetime.now(UTC),
            )
            receipt = CommandReceipt(event=event, command_digest=command.digest)
            receipt_bytes = receipt.canonical_bytes()
            db.execute(
                "INSERT INTO events(sequence,event_id,event_type,target_id,command_id,"
                "idempotency_key,command_digest,payload_digest,payload,correlation,"
                "occurred_at,receipt) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    sequence,
                    event.event_id,
                    event.event_type,
                    event.target_id,
                    command.command_id,
                    command.idempotency_key,
                    command.digest,
                    command.payload_digest,
                    command.payload_json,
                    command.correlation.model_dump_json(),
                    event.occurred_at.isoformat(),
                    receipt_bytes,
                ),
            )
            if before_commit is not None:
                before_commit()
            db.commit()
            return receipt
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def lookup_idempotency(self, key: str) -> CommandReceipt | None:
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT receipt FROM events WHERE idempotency_key=?", (key,)
            ).fetchone()
        if row is None:
            return None
        return CommandReceipt.from_canonical_bytes(bytes(row["receipt"]))

    @staticmethod
    def _validate_replay(row: sqlite3.Row, command: CommandEnvelope) -> CommandReceipt:
        if row["payload_digest"] != command.payload_digest:
            raise IdempotencyIntegrityError(
                "IDEMPOTENCY_PAYLOAD_MISMATCH",
                existing_digest=row["payload_digest"],
                presented_digest=command.payload_digest,
            )
        if row["command_digest"] != command.digest:
            raise IdempotencyIntegrityError(
                "IDEMPOTENCY_COMMAND_MISMATCH",
                existing_digest=row["command_digest"],
                presented_digest=command.digest,
            )
        return CommandReceipt.from_canonical_bytes(bytes(row["receipt"]))

    @staticmethod
    def _event(row: sqlite3.Row) -> WorkflowEvent:
        return WorkflowEvent(
            event_id=row["event_id"],
            sequence=row["sequence"],
            event_type=row["event_type"],
            target_id=row["target_id"],
            command_id=row["command_id"],
            payload=json.loads(row["payload"]),
            correlation=CorrelationEnvelope.model_validate_json(row["correlation"]),
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
        )

    def iter_events(self, *, after_sequence: int = 0) -> Iterator[WorkflowEvent]:
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT * FROM events WHERE sequence > ? ORDER BY sequence ASC",
                (after_sequence,),
            ).fetchall()
        yield from (self._event(row) for row in rows)

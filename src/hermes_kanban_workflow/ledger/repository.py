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
        self._active_completions: dict[str, tuple[str, object]] = {}
        migrate(path)

    def _connect(self) -> sqlite3.Connection:
        return open_database(self._path)

    def execute_once(
        self, command: CommandEnvelope, callback: Callable[[], None]
    ) -> CommandReceipt:
        """Reserve identity durably before callbacks; crashes require manual reconciliation."""
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT * FROM events WHERE idempotency_key=?", (command.idempotency_key,)
                ).fetchone()
                if row is not None:
                    self._check_completion(db, command)
                    receipt = self._validate_replay(row, command)
                    db.commit()
                    return receipt
                admission = db.execute(
                    "SELECT * FROM command_admissions WHERE idempotency_key=?",
                    (command.idempotency_key,),
                ).fetchone()
                if admission is not None:
                    if admission["payload_digest"] != command.payload_digest:
                        raise IdempotencyIntegrityError("IDEMPOTENCY_PAYLOAD_MISMATCH")
                    if admission["command_digest"] != command.digest:
                        raise IdempotencyIntegrityError("IDEMPOTENCY_COMMAND_MISMATCH")
                    raise RuntimeError("COMMAND_OUTCOME_UNCERTAIN_RECONCILIATION_REQUIRED")
                if (
                    db.execute(
                        "SELECT 1 FROM events WHERE command_id=? UNION ALL "
                        "SELECT 1 FROM command_admissions WHERE command_id=?",
                        (command.command_id, command.command_id),
                    ).fetchone()
                    is not None
                ):
                    raise IdempotencyIntegrityError("COMMAND_ID_REUSE_MISMATCH")
                db.execute(
                    "INSERT INTO command_admissions VALUES(?,?,?,?, 'uncertain')",
                    (
                        command.command_id,
                        command.idempotency_key,
                        command.digest,
                        command.payload_digest,
                    ),
                )
                db.commit()
            except BaseException:
                db.rollback()
                raise
        completion = object()
        try:
            callback()
            self._active_completions[command.idempotency_key] = (command.digest, completion)
            return self._append(command, completion=completion)
        finally:
            self._active_completions.pop(command.idempotency_key, None)

    def append(
        self,
        command: CommandEnvelope,
        *,
        before_commit: Callable[[], None] | None = None,
    ) -> CommandReceipt:
        return self._append(command, before_commit=before_commit)

    @staticmethod
    def _check_completion(db: sqlite3.Connection, command: CommandEnvelope) -> None:
        admissions = db.execute(
            "SELECT * FROM command_admissions WHERE idempotency_key=? OR command_id=?",
            (command.idempotency_key, command.command_id),
        ).fetchall()
        for admission in admissions:
            completed = db.execute(
                "SELECT 1 FROM command_completions WHERE idempotency_key=? AND command_id=? "
                "AND command_digest=?",
                (
                    admission["idempotency_key"],
                    admission["command_id"],
                    admission["command_digest"],
                ),
            ).fetchone()
            if completed is None:
                raise RuntimeError("COMMAND_OUTCOME_UNCERTAIN_RECONCILIATION_REQUIRED")

    def _append(
        self,
        command: CommandEnvelope,
        *,
        before_commit: Callable[[], None] | None = None,
        completion: object | None = None,
    ) -> CommandReceipt:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            completing = completion is not None
            if completing:
                active = self._active_completions.get(command.idempotency_key)
                if active is None or active != (command.digest, completion):
                    raise PermissionError("GUARDED_COMPLETION_AUTHORITY_REQUIRED")
                admission = db.execute(
                    "SELECT 1 FROM command_admissions WHERE idempotency_key=? AND command_id=? "
                    "AND command_digest=?",
                    (command.idempotency_key, command.command_id, command.digest),
                ).fetchone()
                if admission is None:
                    raise PermissionError("GUARDED_COMPLETION_BINDING_MISMATCH")
            else:
                self._check_completion(db, command)
            replay = db.execute(
                "SELECT * FROM events WHERE idempotency_key=?", (command.idempotency_key,)
            ).fetchone()
            if replay is not None:
                self._check_completion(db, command)
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
            if completing:
                db.execute(
                    "INSERT INTO command_completions VALUES(?,?,?,?)",
                    (command.idempotency_key, command.command_id, command.digest, event.event_id),
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
            incomplete = db.execute(
                "SELECT 1 FROM command_admissions a LEFT JOIN command_completions c "
                "ON c.idempotency_key=a.idempotency_key AND c.command_id=a.command_id "
                "AND c.command_digest=a.command_digest "
                "WHERE a.idempotency_key=? AND c.idempotency_key IS NULL",
                (key,),
            ).fetchone()
            if incomplete is not None:
                raise RuntimeError("COMMAND_OUTCOME_UNCERTAIN_RECONCILIATION_REQUIRED")
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

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from threading import RLock
from uuid import uuid4

from hermes_kanban_workflow.domain.commands import CommandEnvelope
from hermes_kanban_workflow.domain.events import WorkflowEvent


class Ledger:
    """Pilot append-only ledger. Its path is private to the guarded service."""

    def __init__(self, path: Path, writer_identity: str) -> None:
        self._path = path
        self.writer_identity = writer_identity
        self._lock = RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        db = self._connect()
        try:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE NOT NULL, event_type TEXT NOT NULL, target_id TEXT NOT NULL, command_id TEXT NOT NULL, idempotency_key TEXT UNIQUE NOT NULL, payload_digest TEXT NOT NULL, payload TEXT NOT NULL, occurred_at TEXT NOT NULL)")
            db.commit()
        finally:
            db.close()

    def append(self, command: CommandEnvelope) -> WorkflowEvent:
        with self._lock:
            db = self._connect()
            try:
                return self._append_with_connection(db, command)
            finally:
                db.close()

    def _append_with_connection(
        self, db: sqlite3.Connection, command: CommandEnvelope
    ) -> WorkflowEvent:
            row = db.execute("SELECT * FROM events WHERE idempotency_key=?", (command.idempotency_key,)).fetchone()
            if row:
                if row["payload_digest"] != command.payload_digest:
                    raise ValueError("IDEMPOTENCY_PAYLOAD_MISMATCH")
                return self._event(row)
            event_id = str(uuid4())
            now = datetime.now(timezone.utc)
            cursor = db.execute(
                "INSERT INTO events(event_id,event_type,target_id,command_id,idempotency_key,payload_digest,payload,occurred_at) VALUES(?,?,?,?,?,?,?,?)",
                (event_id, command.command_type, command.target_id, command.command_id, command.idempotency_key, command.payload_digest, json.dumps(command.payload, sort_keys=True), now.isoformat()),
            )
            db.commit()
            return WorkflowEvent(event_id=event_id, sequence=int(cursor.lastrowid), event_type=command.command_type, target_id=command.target_id, command_id=command.command_id, payload=command.payload, occurred_at=now)

    @staticmethod
    def _event(row: sqlite3.Row) -> WorkflowEvent:
        return WorkflowEvent(event_id=row["event_id"], sequence=row["sequence"], event_type=row["event_type"], target_id=row["target_id"], command_id=row["command_id"], payload=json.loads(row["payload"]), occurred_at=datetime.fromisoformat(row["occurred_at"]))

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

SCHEMA_VERSION = 3

_SCHEMA_V3 = (
    """CREATE TABLE command_completions (
        idempotency_key TEXT PRIMARY KEY,
        command_id TEXT NOT NULL UNIQUE,
        command_digest TEXT NOT NULL,
        event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id)
    )""",
    """CREATE TRIGGER command_completions_deny_update BEFORE UPDATE ON command_completions
        BEGIN SELECT RAISE(ABORT, 'COMMAND_COMPLETIONS_APPEND_ONLY'); END""",
    """CREATE TRIGGER command_completions_deny_delete BEFORE DELETE ON command_completions
        BEGIN SELECT RAISE(ABORT, 'COMMAND_COMPLETIONS_APPEND_ONLY'); END""",
)

_SCHEMA_V2 = """CREATE TABLE command_admissions (
    command_id TEXT NOT NULL UNIQUE,
    idempotency_key TEXT PRIMARY KEY,
    command_digest TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state = 'uncertain')
)"""

_SCHEMA_V1 = (
    "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)",
    """CREATE TABLE events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        command_id TEXT NOT NULL UNIQUE,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_digest TEXT NOT NULL,
        payload_digest TEXT NOT NULL,
        payload TEXT NOT NULL,
        correlation TEXT NOT NULL,
        occurred_at TEXT NOT NULL,
        receipt BLOB NOT NULL
    )""",
    """CREATE TRIGGER events_deny_update BEFORE UPDATE ON events BEGIN
        SELECT RAISE(ABORT, 'EVENTS_APPEND_ONLY');
    END""",
    """CREATE TRIGGER events_deny_delete BEFORE DELETE ON events BEGIN
        SELECT RAISE(ABORT, 'EVENTS_APPEND_ONLY');
    END""",
    """CREATE TABLE projection_state (
        target_id TEXT PRIMARY KEY,
        event_count INTEGER NOT NULL,
        last_event_id TEXT NOT NULL,
        last_sequence INTEGER NOT NULL,
        payload TEXT NOT NULL
    )""",
    """CREATE TABLE projection_checkpoint (
        name TEXT PRIMARY KEY,
        sequence INTEGER NOT NULL
    )""",
)


def open_database(path: Path) -> sqlite3.Connection:
    db = sqlite3.connect(path, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def schema_version(path: Path) -> int:
    with closing(open_database(path)) as db:
        return int(db.execute("PRAGMA user_version").fetchone()[0])


def migrate(path: Path, *, before_commit: Callable[[], None] | None = None) -> None:
    """Create or upgrade a ledger atomically; reject unversioned legacy rows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(open_database(path)) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("BEGIN IMMEDIATE")
        try:
            version = int(db.execute("PRAGMA user_version").fetchone()[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError("LEDGER_SCHEMA_NEWER_THAN_RUNTIME")
            if version == 0:
                legacy = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'"
                ).fetchone()
                if legacy is not None:
                    raise RuntimeError("LEGACY_LEDGER_CANNOT_BE_TRUTHFULLY_MIGRATED")
                for statement in _SCHEMA_V1:
                    db.execute(statement)
                db.execute(
                    "INSERT INTO schema_migrations(version, applied_at) "
                    "VALUES(1, strftime('%Y-%m-%dT%H:%M:%fZ','now'))"
                )
                version = 1
            if version == 1:
                db.execute(_SCHEMA_V2)
                db.execute(
                    "INSERT INTO schema_migrations(version, applied_at) "
                    "VALUES(2, strftime('%Y-%m-%dT%H:%M:%fZ','now'))"
                )
                version = 2
            if version == 2:
                for statement in _SCHEMA_V3:
                    db.execute(statement)
                db.execute(
                    "INSERT INTO schema_migrations(version, applied_at) "
                    "VALUES(3, strftime('%Y-%m-%dT%H:%M:%fZ','now'))"
                )
                db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            if before_commit is not None:
                before_commit()
            db.commit()
        except BaseException:
            db.rollback()
            raise

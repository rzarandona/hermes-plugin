from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from multiprocessing import get_context
from pathlib import Path

import pytest

from hermes_kanban_workflow.ledger.projector import Projector
from hermes_kanban_workflow.ledger.schema import migrate, open_database, schema_version
from tests.ledger_fixtures import command, ledger


def _append_without_projection(path: str) -> None:
    ledger(Path(path)).append(command(command_id="command-2", idempotency_key="key-2"))
    os._exit(91)


def test_failed_schema_migration_leaves_no_partial_schema(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"

    def fail() -> None:
        raise RuntimeError("injected-migration-failure")

    with pytest.raises(RuntimeError, match="injected-migration-failure"):
        migrate(path, before_commit=fail)

    with closing(open_database(path)) as db:
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
    assert tables == []
    assert schema_version(path) == 0


def test_schema_migration_is_versioned_and_recorded(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    ledger(path)

    assert schema_version(path) == 1
    with closing(open_database(path)) as db:
        assert [row["version"] for row in db.execute("SELECT version FROM schema_migrations")] == [1]


def test_event_identity_columns_have_database_unique_constraints(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    ledger(path)

    with closing(open_database(path)) as db:
        indexes = db.execute("PRAGMA index_list(events)").fetchall()
        unique_columns = {
            tuple(row["name"] for row in db.execute(f"PRAGMA index_info('{index['name']}')"))
            for index in indexes
            if index["unique"]
        }

    assert ("event_id",) in unique_columns
    assert ("idempotency_key",) in unique_columns
    assert ("command_id",) in unique_columns


def test_unversioned_legacy_rows_are_rejected_not_fabricated(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    with closing(open_database(path)) as db:
        db.execute("CREATE TABLE events(sequence INTEGER PRIMARY KEY, payload TEXT)")
        db.execute("INSERT INTO events VALUES(1, '{}')")
        db.commit()

    with pytest.raises(RuntimeError, match="LEGACY_LEDGER_CANNOT_BE_TRUTHFULLY_MIGRATED"):
        migrate(path)

    assert schema_version(path) == 0


def test_database_denies_event_update_and_delete(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    receipt = ledger(path).append(command())

    with closing(open_database(path)) as db:
        with pytest.raises(sqlite3.IntegrityError, match="EVENTS_APPEND_ONLY"):
            db.execute("UPDATE events SET event_type='changed' WHERE event_id=?", (receipt.event_id,))
        with pytest.raises(sqlite3.IntegrityError, match="EVENTS_APPEND_ONLY"):
            db.execute("DELETE FROM events WHERE event_id=?", (receipt.event_id,))


def test_failure_before_commit_rolls_back_every_ledger_byte(tmp_path: Path) -> None:
    store = ledger(tmp_path / "ledger.db")

    def fail() -> None:
        raise RuntimeError("injected-before-commit")

    with pytest.raises(RuntimeError, match="injected-before-commit"):
        store.append(command(), before_commit=fail)

    assert store.lookup_idempotency("stable-key") is None
    assert list(store.iter_events()) == []


def test_rebuild_is_pure_deterministic_and_checkpoints_full_replay(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    store = ledger(path)
    store.append(command(command_id="command-1", idempotency_key="key-1"))
    store.append(command(command_id="command-2", idempotency_key="key-2", target_id="work-2", correlation=command().correlation.model_copy(update={"record_id": "work-2"})))
    projector = Projector(path, store)
    expected = Projector.reduce(tuple(store.iter_events()))

    assert projector.rebuild() == expected
    assert projector.rebuild() == expected
    assert projector.checkpoint() == 2


def test_crash_after_append_repairs_once_without_duplicate_effects(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    store = ledger(path)
    projector = Projector(path, store)
    store.append(command(command_id="command-1", idempotency_key="key-1"))
    assert projector.repair() == 1

    # Forced process death after durable append, before the projector can run.
    crashed = get_context("spawn").Process(target=_append_without_projection, args=(str(path),))
    crashed.start()
    crashed.join(timeout=30)
    assert crashed.exitcode == 91

    assert projector.repair() == 1
    assert projector.repair() == 0
    state = projector.snapshot()
    assert len(state) == 1
    assert state[0].event_count == 2
    assert state[0].last_sequence == 2


def test_event_iteration_is_strictly_sequence_ordered(tmp_path: Path) -> None:
    store = ledger(tmp_path / "ledger.db")
    store.append(command(command_id="command-2", idempotency_key="key-2"))
    store.append(command(command_id="command-1", idempotency_key="key-1"))

    assert [event.sequence for event in store.iter_events()] == [1, 2]
    assert [event.command_id for event in store.iter_events(after_sequence=1)] == ["command-1"]

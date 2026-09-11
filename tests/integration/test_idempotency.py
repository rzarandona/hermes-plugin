from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest
from pydantic import ValidationError

from hermes_kanban_workflow.command.receipts import CommandReceipt
from hermes_kanban_workflow.ledger.repository import IdempotencyIntegrityError
from hermes_kanban_workflow.ledger.schema import open_database
from tests.ledger_fixtures import command, guarded_service, ledger


def _append_in_process(path: str) -> bytes:
    return ledger(Path(path)).append(command()).canonical_bytes()


def test_changed_payload_reuse_has_typed_denial(tmp_path: Path) -> None:
    store = ledger(tmp_path / "ledger.db")
    store.append(command())

    with pytest.raises(IdempotencyIntegrityError) as caught:
        store.append(command(payload={"note": "changed"}))

    assert caught.value.code == "IDEMPOTENCY_PAYLOAD_MISMATCH"
    assert caught.value.existing_digest == command().payload_digest
    assert caught.value.presented_digest == command(payload={"note": "changed"}).payload_digest


def test_cross_process_race_returns_byte_identical_original_receipt(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    ledger(path)

    with ProcessPoolExecutor(max_workers=8) as workers:
        receipts = list(workers.map(_append_in_process, [str(path)] * 16))

    assert len(set(receipts)) == 1
    with closing(open_database(path)) as db:
        assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_changed_non_payload_reuse_has_typed_denial(tmp_path: Path) -> None:
    store = ledger(tmp_path / "ledger.db")
    store.append(command())
    changed = command(reason_code="different")

    with pytest.raises(IdempotencyIntegrityError) as caught:
        store.append(changed)

    assert caught.value.code == "IDEMPOTENCY_COMMAND_MISMATCH"
    assert caught.value.existing_digest == command().digest
    assert caught.value.presented_digest == changed.digest


def test_lookup_returns_durable_canonical_receipt_bytes(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    store = ledger(path)
    original = store.append(command())

    looked_up = store.lookup_idempotency("stable-key")

    assert looked_up is not None
    assert looked_up.canonical_bytes() == original.canonical_bytes()
    with closing(open_database(path)) as db:
        durable = bytes(db.execute("SELECT receipt FROM events").fetchone()["receipt"])
    assert durable == original.canonical_bytes()


def test_service_returns_immutable_command_receipt(tmp_path: Path) -> None:
    service, principal = guarded_service(tmp_path / "ledger.db")
    receipt = service.execute(command(), principal)

    assert isinstance(receipt, CommandReceipt)
    assert receipt.event_id == receipt.event.event_id
    assert receipt.command_digest == command().digest
    with pytest.raises(ValidationError):
        receipt.command_digest = "changed"  # type: ignore[misc]

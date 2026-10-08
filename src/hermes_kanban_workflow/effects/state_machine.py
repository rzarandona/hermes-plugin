from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Self

from hermes_kanban_workflow.effects.receipts import ProviderReceipt, ReadbackReceipt


class EffectState(StrEnum):
    INTENT_RECORDED = "intent_recorded"
    EFFECT_STARTED = "effect_started"
    EFFECT_RECEIPT_RECORDED = "effect_receipt_recorded"
    READBACK_PENDING = "readback_pending"
    CONFIRMED = "confirmed"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    MANUAL_ESCALATION = "manual_escalation"
    CLOSED = "closed"

    # Compatibility aliases from the pre-WP14 in-memory prototype.
    DISPATCHED = EFFECT_STARTED
    FAILED = RECONCILIATION_REQUIRED
    UNKNOWN = RECONCILIATION_REQUIRED


@dataclass(frozen=True, slots=True)
class EffectRecord:
    effect_id: str
    provider: str
    state: EffectState
    receipt: str | None = None
    idempotency_key: str = ""
    payload_digest: str = ""
    owner: str | None = None
    blocked_next_action: str | None = None
    attempts: int = 0
    generation: int = 0
    dispatch_active: bool = False

    @property
    def operation_id(self) -> str:
        return self.effect_id


class EffectStore:
    """Reopenable SQLite store for external-effect intent and reconciliation state."""

    def __init__(
        self,
        path: str | Path,
        *,
        readback_verifier: Callable[[ReadbackReceipt], bool] | None = None,
    ) -> None:
        self._connection = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._readback_verifier = readback_verifier
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS effects (
                operation_id TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                provider TEXT NOT NULL,
                payload_digest TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN (
                    'intent_recorded', 'effect_started', 'effect_receipt_recorded',
                    'readback_pending', 'confirmed', 'reconciliation_required',
                    'manual_escalation', 'closed'
                )),
                latest_receipt TEXT,
                owner TEXT,
                blocked_next_action TEXT,
                attempts INTEGER NOT NULL DEFAULT 0,
                generation INTEGER NOT NULL DEFAULT 0,
                dispatch_active INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS effect_intents (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_id TEXT NOT NULL UNIQUE,
                idempotency_key TEXT NOT NULL UNIQUE,
                provider TEXT NOT NULL,
                payload_digest TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS provider_receipts (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                operation_id TEXT NOT NULL,
                receipt_digest TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT -1,
                generation INTEGER NOT NULL DEFAULT -1
            );
            CREATE TABLE IF NOT EXISTS readback_receipts (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                operation_id TEXT NOT NULL,
                receipt_digest TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT -1,
                generation INTEGER NOT NULL DEFAULT -1
            );
            CREATE TRIGGER IF NOT EXISTS provider_receipts_no_update
            BEFORE UPDATE ON provider_receipts BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECEIPT'); END;
            CREATE TRIGGER IF NOT EXISTS provider_receipts_no_delete
            BEFORE DELETE ON provider_receipts BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECEIPT'); END;
            CREATE TRIGGER IF NOT EXISTS readback_receipts_no_update
            BEFORE UPDATE ON readback_receipts BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECEIPT'); END;
            CREATE TRIGGER IF NOT EXISTS readback_receipts_no_delete
            BEFORE DELETE ON readback_receipts BEGIN SELECT RAISE(ABORT, 'IMMUTABLE_RECEIPT'); END;
            """
        )
        with self._transaction():
            columns = {
                str(row["name"]) for row in self._connection.execute("PRAGMA table_info(effects)")
            }
            if "generation" not in columns:
                self._connection.execute(
                    "ALTER TABLE effects ADD generation INTEGER NOT NULL DEFAULT 0"
                )
            if "dispatch_active" not in columns:
                self._connection.execute(
                    "ALTER TABLE effects ADD dispatch_active INTEGER NOT NULL DEFAULT 0"
                )
                # Historical rows cannot prove an old callback has retired.
                self._connection.execute("UPDATE effects SET dispatch_active=1 WHERE attempts>0")
            for table in ("provider_receipts", "readback_receipts"):
                columns = {
                    str(row["name"])
                    for row in self._connection.execute(f"PRAGMA table_info({table})")
                }
                for column in ("attempt", "generation"):
                    if column not in columns:
                        self._connection.execute(
                            f"ALTER TABLE {table} ADD {column} INTEGER NOT NULL DEFAULT -1"
                        )

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise

    def __enter__(self) -> Self:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    @staticmethod
    def _record(row: sqlite3.Row) -> EffectRecord:
        return EffectRecord(
            effect_id=str(row["operation_id"]),
            provider=str(row["provider"]),
            state=EffectState(str(row["state"])),
            receipt=None if row["latest_receipt"] is None else str(row["latest_receipt"]),
            idempotency_key=str(row["idempotency_key"]),
            payload_digest=str(row["payload_digest"]),
            owner=None if row["owner"] is None else str(row["owner"]),
            blocked_next_action=(
                None if row["blocked_next_action"] is None else str(row["blocked_next_action"])
            ),
            attempts=int(row["attempts"]),
            generation=int(row["generation"]),
            dispatch_active=bool(row["dispatch_active"]),
        )

    def record_intent(
        self,
        *,
        operation_id: str,
        idempotency_key: str,
        provider: str,
        payload_digest: str,
    ) -> EffectRecord:
        if not all((operation_id, idempotency_key, provider, payload_digest)):
            raise ValueError("EFFECT_INTENT_BINDINGS_REQUIRED")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT * FROM effects WHERE operation_id = ? OR idempotency_key = ?",
                    (operation_id, idempotency_key),
                ).fetchone()
                if row is not None:
                    existing = self._record(row)
                    if (
                        existing.effect_id != operation_id
                        or existing.idempotency_key != idempotency_key
                        or existing.provider != provider
                        or existing.payload_digest != payload_digest
                    ):
                        raise ValueError("EFFECT_IDEMPOTENCY_BINDING_MISMATCH")
                    self._connection.execute("COMMIT")
                    return existing
                self._connection.execute(
                    "INSERT INTO effect_intents"
                    " (operation_id, idempotency_key, provider, payload_digest) VALUES (?, ?, ?, ?)",
                    (operation_id, idempotency_key, provider, payload_digest),
                )
                self._connection.execute(
                    "INSERT INTO effects"
                    " (operation_id, idempotency_key, provider, payload_digest, state)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        operation_id,
                        idempotency_key,
                        provider,
                        payload_digest,
                        EffectState.INTENT_RECORDED.value,
                    ),
                )
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
        return self.get(operation_id)

    def get(self, operation_id: str) -> EffectRecord:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM effects WHERE operation_id = ?", (operation_id,)
            ).fetchone()
        if row is None:
            raise KeyError(operation_id)
        return self._record(row)

    def intent_count(self, operation_id: str) -> int:
        row = self._connection.execute(
            "SELECT COUNT(*) AS count FROM effect_intents WHERE operation_id = ?", (operation_id,)
        ).fetchone()
        assert row is not None
        return int(row["count"])

    def _transition(
        self,
        current: EffectRecord,
        state: EffectState,
        *,
        receipt: str | None = None,
        owner: str | None = None,
        blocked_next_action: str | None = None,
        increment_attempts: bool = False,
        dispatch_active: bool | None = None,
    ) -> EffectRecord:
        latest = current.receipt if receipt is None else receipt
        attempts = current.attempts + (1 if increment_attempts else 0)
        updated = self._connection.execute(
            "UPDATE effects SET state = ?, latest_receipt = ?, owner = ?,"
            " blocked_next_action = ?, attempts = ?, generation = generation+1,"
            " dispatch_active = ? WHERE operation_id = ? AND generation = ? AND attempts = ?",
            (
                state.value,
                latest,
                current.owner if owner is None else owner,
                current.blocked_next_action if blocked_next_action is None else blocked_next_action,
                attempts,
                current.dispatch_active if dispatch_active is None else dispatch_active,
                current.operation_id,
                current.generation,
                current.attempts,
            ),
        )
        if updated.rowcount != 1:
            raise RuntimeError("EFFECT_TRANSITION_STALE")
        return self.get(current.operation_id)

    @staticmethod
    def _expect_snapshot(current: EffectRecord, expected: EffectRecord) -> None:
        if current != expected:
            raise RuntimeError("EFFECT_READBACK_SNAPSHOT_STALE")

    @staticmethod
    def _expect_attempt(current: EffectRecord, expected: EffectRecord) -> None:
        if (
            current.operation_id != expected.operation_id
            or current.idempotency_key != expected.idempotency_key
            or current.payload_digest != expected.payload_digest
            or current.provider != expected.provider
            or current.attempts != expected.attempts
            or expected.state is not EffectState.EFFECT_STARTED
            or not expected.dispatch_active
        ):
            raise RuntimeError("EFFECT_DISPATCH_ATTEMPT_STALE")

    def _absence_receipt(self, current: EffectRecord) -> ReadbackReceipt | None:
        if current.dispatch_active or current.state is not EffectState.RECONCILIATION_REQUIRED:
            return None
        row = self._connection.execute(
            "SELECT receipt_json FROM readback_receipts WHERE operation_id=? AND receipt_id=? "
            "AND attempt=? AND generation=?",
            (current.operation_id, current.receipt, current.attempts, current.generation),
        ).fetchone()
        if row is None:
            return None
        receipt = ReadbackReceipt(**json.loads(row["receipt_json"]))
        return receipt if receipt.status == "absent" else None

    def mark_started(self, operation_id: str, *, attempt_budget: int = 3) -> EffectRecord:
        """Atomically consume one attempt and any verified-absence retry authorization."""
        with self._transaction():
            current = self.get(operation_id)
            if current.attempts >= attempt_budget:
                raise RuntimeError("EFFECT_DISPATCH_BUDGET_EXHAUSTED")
            if current.dispatch_active:
                raise RuntimeError("EFFECT_START_STATE_INVALID:DISPATCH_STILL_ACTIVE")
            if current.state is EffectState.RECONCILIATION_REQUIRED:
                readback = self._absence_receipt(current)
                if readback is None:
                    raise RuntimeError("AUTHORITATIVE_ABSENCE_REQUIRED_BEFORE_RETRY")
                if self._readback_verifier is None or not self._readback_verifier(readback):
                    raise PermissionError("AUTHORITATIVE_READBACK_VERIFICATION_REQUIRED")
            elif current.state is not EffectState.INTENT_RECORDED:
                raise RuntimeError("EFFECT_START_STATE_INVALID")
            return self._transition(
                current,
                EffectState.EFFECT_STARTED,
                receipt="DISPATCH_OUTCOME_UNCERTAIN",
                increment_attempts=True,
                dispatch_active=True,
            )

    def retry_authorized(self, operation_id: str) -> bool:
        with self._lock:
            return self._absence_receipt(self.get(operation_id)) is not None

    def append_provider_receipt(
        self, receipt: ProviderReceipt, *, expected: EffectRecord
    ) -> EffectRecord:
        with self._transaction():
            current = self.get(receipt.operation_id)
            self._expect_attempt(current, expected)
            if current.idempotency_key != receipt.idempotency_key:
                raise ValueError("PROVIDER_RECEIPT_BINDING_MISMATCH")
            existing = self._connection.execute(
                "SELECT receipt_digest, attempt FROM provider_receipts WHERE receipt_id = ?",
                (receipt.receipt_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["receipt_digest"]) != receipt.digest:
                    raise ValueError("PROVIDER_RECEIPT_ID_REUSED")
                if int(existing["attempt"]) != expected.attempts:
                    raise RuntimeError("PROVIDER_RECEIPT_ATTEMPT_STALE")
                return current
            encoded = json.dumps(asdict(receipt), sort_keys=True, separators=(",", ":"))
            self._connection.execute(
                "INSERT INTO provider_receipts (receipt_id, operation_id, receipt_digest,"
                " receipt_json, attempt, generation) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    receipt.receipt_id,
                    receipt.operation_id,
                    receipt.digest,
                    encoded,
                    expected.attempts,
                    expected.generation,
                ),
            )
            if current.state in {
                EffectState.CONFIRMED,
                EffectState.CLOSED,
                EffectState.MANUAL_ESCALATION,
            }:
                return self._transition(current, current.state, dispatch_active=False)
            if not current.dispatch_active:
                raise RuntimeError("EFFECT_DISPATCH_ALREADY_RETIRED")
            return self._transition(
                current,
                EffectState.EFFECT_RECEIPT_RECORDED,
                receipt=receipt.receipt_id,
                dispatch_active=False,
            )

    def mark_readback_pending(
        self, operation_id: str, *, expected: EffectRecord | None = None
    ) -> EffectRecord:
        with self._transaction():
            current = self.get(operation_id)
            if expected is not None:
                self._expect_snapshot(current, expected)
            if current.state not in {
                EffectState.EFFECT_STARTED,
                EffectState.EFFECT_RECEIPT_RECORDED,
                EffectState.RECONCILIATION_REQUIRED,
                EffectState.READBACK_PENDING,
            }:
                raise RuntimeError("EFFECT_READBACK_STATE_INVALID")
            return self._transition(current, EffectState.READBACK_PENDING)

    def append_readback_receipt(
        self, receipt: ReadbackReceipt, *, expected: EffectRecord
    ) -> EffectRecord:
        if self._readback_verifier is None or not self._readback_verifier(receipt):
            raise PermissionError("AUTHORITATIVE_READBACK_VERIFICATION_REQUIRED")
        with self._transaction():
            current = self.get(receipt.operation_id)
            self._expect_snapshot(current, expected)
            if expected.state is not EffectState.READBACK_PENDING:
                raise RuntimeError("EFFECT_READBACK_SNAPSHOT_INVALID")
            existing = self._connection.execute(
                "SELECT receipt_digest FROM readback_receipts WHERE receipt_id = ?",
                (receipt.receipt_id,),
            ).fetchone()
            if existing is not None:
                if str(existing["receipt_digest"]) != receipt.digest:
                    raise ValueError("READBACK_RECEIPT_ID_REUSED")
                # Receipt identity is single-use: no old absence can authorize a newer generation.
                raise RuntimeError("READBACK_RECEIPT_ALREADY_CONSUMED_STALE")
            encoded = json.dumps(asdict(receipt), sort_keys=True, separators=(",", ":"))
            self._connection.execute(
                "INSERT INTO readback_receipts (receipt_id, operation_id, receipt_digest,"
                " receipt_json, attempt, generation) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    receipt.receipt_id,
                    receipt.operation_id,
                    receipt.digest,
                    encoded,
                    current.attempts,
                    current.generation + 1,
                ),
            )
            state = (
                EffectState.CONFIRMED
                if receipt.status == "applied"
                else EffectState.RECONCILIATION_REQUIRED
            )
            # Active/crashed dispatches remain active even when readback currently says absent.
            return self._transition(current, state, receipt=receipt.receipt_id)

    def require_reconciliation(
        self, operation_id: str, reason: str, *, expected: EffectRecord
    ) -> EffectRecord:
        with self._transaction():
            current = self.get(operation_id)
            self._expect_attempt(current, expected)
            if current.state in {
                EffectState.CONFIRMED,
                EffectState.CLOSED,
                EffectState.MANUAL_ESCALATION,
            }:
                return self._transition(current, current.state, dispatch_active=False)
            if not current.dispatch_active:
                return current
            return self._transition(
                current,
                EffectState.RECONCILIATION_REQUIRED,
                receipt=reason,
                dispatch_active=False,
            )

    def escalate(
        self,
        operation_id: str,
        *,
        owner: str,
        blocked_next_action: str,
        expected: EffectRecord | None = None,
    ) -> EffectRecord:
        if not owner or not blocked_next_action:
            raise ValueError("MANUAL_ESCALATION_OWNER_AND_BLOCKED_ACTION_REQUIRED")
        with self._transaction():
            current = self.get(operation_id)
            if current.state in {EffectState.CONFIRMED, EffectState.CLOSED}:
                return current
            if expected is not None:
                self._expect_snapshot(current, expected)
            return self._transition(
                current,
                EffectState.MANUAL_ESCALATION,
                owner=owner,
                blocked_next_action=blocked_next_action,
            )

    def close_effect(self, operation_id: str) -> EffectRecord:
        with self._transaction():
            current = self.get(operation_id)
            readback = self._connection.execute(
                "SELECT COUNT(*) AS count FROM readback_receipts WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            assert readback is not None
            if current.state is not EffectState.CONFIRMED or int(readback["count"]) == 0:
                raise RuntimeError("AUTHORITATIVE_READBACK_REQUIRED_BEFORE_CLOSURE")
            return self._transition(current, EffectState.CLOSED)

    def provider_receipt_count(self, operation_id: str) -> int:
        row = self._connection.execute(
            "SELECT COUNT(*) AS count FROM provider_receipts WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        assert row is not None
        return int(row["count"])


class EffectStateMachine:
    """Compatibility facade retained for earlier unit contracts."""

    def __init__(self) -> None:
        self._records: dict[str, EffectRecord] = {}

    def create_intent(self, effect_id: str, provider: str) -> EffectRecord:
        if effect_id in self._records:
            raise ValueError("EFFECT_ALREADY_EXISTS")
        record = EffectRecord(effect_id, provider, EffectState.INTENT_RECORDED)
        self._records[effect_id] = record
        return record

    def mark_unknown(self, effect_id: str, receipt: str) -> EffectRecord:
        record = replace(
            self._records[effect_id], state=EffectState.RECONCILIATION_REQUIRED, receipt=receipt
        )
        self._records[effect_id] = record
        return record

    def retry(self, effect_id: str) -> EffectRecord:
        record = self._records[effect_id]
        if record.state == EffectState.RECONCILIATION_REQUIRED:
            raise RuntimeError("EFFECT_RECONCILIATION_REQUIRED")
        return record

    def reconcile(self, effect_id: str, confirmed: bool, receipt: str) -> EffectRecord:
        record = replace(
            self._records[effect_id],
            state=EffectState.CONFIRMED if confirmed else EffectState.MANUAL_ESCALATION,
            receipt=receipt,
        )
        self._records[effect_id] = record
        return record

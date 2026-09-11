from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Callable
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
                attempts INTEGER NOT NULL DEFAULT 0
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
                receipt_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS readback_receipts (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                operation_id TEXT NOT NULL,
                receipt_digest TEXT NOT NULL,
                receipt_json TEXT NOT NULL
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

    def _set_state(
        self,
        operation_id: str,
        state: EffectState,
        *,
        receipt: str | None = None,
        owner: str | None = None,
        blocked_next_action: str | None = None,
        increment_attempts: bool = False,
    ) -> EffectRecord:
        current = self.get(operation_id)
        latest = current.receipt if receipt is None else receipt
        attempts = current.attempts + (1 if increment_attempts else 0)
        self._connection.execute(
            "UPDATE effects SET state = ?, latest_receipt = ?, owner = ?,"
            " blocked_next_action = ?, attempts = ? WHERE operation_id = ?",
            (state.value, latest, owner, blocked_next_action, attempts, operation_id),
        )
        return self.get(operation_id)

    def mark_started(self, operation_id: str) -> EffectRecord:
        current = self.get(operation_id)
        if current.state not in {
            EffectState.INTENT_RECORDED,
            EffectState.RECONCILIATION_REQUIRED,
        }:
            raise RuntimeError("EFFECT_START_STATE_INVALID")
        return self._set_state(
            operation_id, EffectState.EFFECT_STARTED, increment_attempts=True
        )

    def append_provider_receipt(self, receipt: ProviderReceipt) -> EffectRecord:
        current = self.get(receipt.operation_id)
        if current.idempotency_key != receipt.idempotency_key:
            raise ValueError("PROVIDER_RECEIPT_BINDING_MISMATCH")
        encoded = json.dumps(asdict(receipt), sort_keys=True, separators=(",", ":"))
        existing = self._connection.execute(
            "SELECT receipt_digest FROM provider_receipts WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone()
        if existing is not None:
            if str(existing["receipt_digest"]) != receipt.digest:
                raise ValueError("PROVIDER_RECEIPT_ID_REUSED")
            return self.get(receipt.operation_id)
        self._connection.execute(
            "INSERT INTO provider_receipts"
            " (receipt_id, operation_id, receipt_digest, receipt_json) VALUES (?, ?, ?, ?)",
            (receipt.receipt_id, receipt.operation_id, receipt.digest, encoded),
        )
        return self._set_state(
            receipt.operation_id,
            EffectState.EFFECT_RECEIPT_RECORDED,
            receipt=receipt.receipt_id,
        )

    def mark_readback_pending(self, operation_id: str) -> EffectRecord:
        current = self.get(operation_id)
        if current.state not in {
            EffectState.EFFECT_STARTED,
            EffectState.EFFECT_RECEIPT_RECORDED,
            EffectState.RECONCILIATION_REQUIRED,
        }:
            raise RuntimeError("EFFECT_READBACK_STATE_INVALID")
        return self._set_state(operation_id, EffectState.READBACK_PENDING)

    def append_readback_receipt(self, receipt: ReadbackReceipt) -> EffectRecord:
        if self._readback_verifier is None or not self._readback_verifier(receipt):
            raise PermissionError("AUTHORITATIVE_READBACK_VERIFICATION_REQUIRED")
        self.get(receipt.operation_id)
        encoded = json.dumps(asdict(receipt), sort_keys=True, separators=(",", ":"))
        existing = self._connection.execute(
            "SELECT receipt_digest FROM readback_receipts WHERE receipt_id = ?",
            (receipt.receipt_id,),
        ).fetchone()
        if existing is not None:
            if str(existing["receipt_digest"]) != receipt.digest:
                raise ValueError("READBACK_RECEIPT_ID_REUSED")
            return self.get(receipt.operation_id)
        self._connection.execute(
            "INSERT INTO readback_receipts"
            " (receipt_id, operation_id, receipt_digest, receipt_json) VALUES (?, ?, ?, ?)",
            (receipt.receipt_id, receipt.operation_id, receipt.digest, encoded),
        )
        state = (
            EffectState.CONFIRMED
            if receipt.status == "applied"
            else EffectState.RECONCILIATION_REQUIRED
        )
        return self._set_state(receipt.operation_id, state, receipt=receipt.receipt_id)

    def require_reconciliation(self, operation_id: str, reason: str) -> EffectRecord:
        return self._set_state(
            operation_id, EffectState.RECONCILIATION_REQUIRED, receipt=reason
        )

    def escalate(
        self, operation_id: str, *, owner: str, blocked_next_action: str
    ) -> EffectRecord:
        if not owner or not blocked_next_action:
            raise ValueError("MANUAL_ESCALATION_OWNER_AND_BLOCKED_ACTION_REQUIRED")
        return self._set_state(
            operation_id,
            EffectState.MANUAL_ESCALATION,
            owner=owner,
            blocked_next_action=blocked_next_action,
        )

    def close_effect(self, operation_id: str) -> EffectRecord:
        current = self.get(operation_id)
        readback = self._connection.execute(
            "SELECT COUNT(*) AS count FROM readback_receipts WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        assert readback is not None
        if current.state is not EffectState.CONFIRMED or int(readback["count"]) == 0:
            raise RuntimeError("AUTHORITATIVE_READBACK_REQUIRED_BEFORE_CLOSURE")
        return self._set_state(operation_id, EffectState.CLOSED)

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

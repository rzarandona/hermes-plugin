from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

from hermes_kanban_workflow.domain.resources import ResourceUri

ControlClock = Callable[[], int]


class LeaseDenied(PermissionError):
    pass


@dataclass(frozen=True, slots=True)
class HolderBinding:
    role: str
    subject: str
    product_id: str
    project_id: str
    work_item_id: str | None
    service_id: str | None
    command_class: str

    def __post_init__(self) -> None:
        if (self.work_item_id is None) == (self.service_id is None):
            raise ValueError("HOLDER_REQUIRES_EXACT_WORK_ITEM_OR_SERVICE")
        if not all((self.role, self.subject, self.product_id, self.project_id, self.command_class)):
            raise ValueError("HOLDER_BINDING_INCOMPLETE")


@dataclass(frozen=True, slots=True)
class DurableLease:
    lease_id: str
    resource: str
    holder: HolderBinding
    issued_epoch: int
    issued_at: int
    expires_at: int
    renewable_conditions: tuple[str, ...]
    queue_token: str | None
    revoked: bool
    fencing_epoch: int


class SchedulerStore:
    """Append-only, versioned scheduler event store colocated with no credentials."""

    SCHEMA_VERSION = 1

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "CREATE TABLE IF NOT EXISTS scheduler_meta (version INTEGER PRIMARY KEY)"
            )
            row = db.execute("SELECT version FROM scheduler_meta").fetchone()
            if row is None:
                db.execute("INSERT INTO scheduler_meta(version) VALUES(?)", (self.SCHEMA_VERSION,))
            elif int(row[0]) != self.SCHEMA_VERSION:
                raise RuntimeError("SCHEDULER_SCHEMA_VERSION_UNSUPPORTED")
            db.execute(
                """CREATE TABLE IF NOT EXISTS scheduler_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    control_time INTEGER NOT NULL,
                    payload TEXT NOT NULL
                )"""
            )
            db.execute(
                """CREATE TRIGGER IF NOT EXISTS scheduler_events_deny_update
                BEFORE UPDATE ON scheduler_events BEGIN
                    SELECT RAISE(ABORT, 'SCHEDULER_EVENTS_APPEND_ONLY');
                END"""
            )
            db.execute(
                """CREATE TRIGGER IF NOT EXISTS scheduler_events_deny_delete
                BEFORE DELETE ON scheduler_events BEGIN
                    SELECT RAISE(ABORT, 'SCHEDULER_EVENTS_APPEND_ONLY');
                END"""
            )
            db.commit()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    @staticmethod
    def _insert(
        db: sqlite3.Connection,
        event_type: str,
        resource: str,
        control_time: int,
        payload: dict[str, Any],
    ) -> None:
        previous = db.execute(
            "SELECT MAX(control_time) FROM scheduler_events"
        ).fetchone()[0]
        if previous is not None and control_time < int(previous):
            raise LeaseDenied("CONTROL_TIME_ROLLBACK")
        db.execute(
            "INSERT INTO scheduler_events(event_id,event_type,resource,control_time,payload) "
            "VALUES(?,?,?,?,?)",
            (
                str(uuid4()),
                event_type,
                resource,
                control_time,
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
            ),
        )

    def events(self, resource: str | None = None) -> Iterator[sqlite3.Row]:
        with closing(self._connect()) as db:
            if resource is None:
                rows = db.execute("SELECT * FROM scheduler_events ORDER BY sequence").fetchall()
            else:
                rows = db.execute(
                    "SELECT * FROM scheduler_events WHERE resource=? ORDER BY sequence", (resource,)
                ).fetchall()
        yield from rows


class LeaseService:
    def __init__(self, store: SchedulerStore, clock: ControlClock) -> None:
        self._store = store
        self._clock = clock

    @staticmethod
    def _lease_from_payload(payload: dict[str, Any]) -> DurableLease:
        holder = HolderBinding(**payload["holder"])
        return DurableLease(
            lease_id=payload["lease_id"],
            resource=payload["resource"],
            holder=holder,
            issued_epoch=payload["issued_epoch"],
            issued_at=payload["issued_at"],
            expires_at=payload["expires_at"],
            renewable_conditions=tuple(payload["renewable_conditions"]),
            queue_token=payload["queue_token"],
            revoked=payload["revoked"],
            fencing_epoch=payload["fencing_epoch"],
        )

    @classmethod
    def _project(cls, rows: list[sqlite3.Row]) -> tuple[DurableLease | None, int]:
        current: DurableLease | None = None
        highest_epoch = 0
        for row in rows:
            payload = json.loads(row["payload"])
            if row["event_type"] in {"lease_acquired", "lease_renewed"}:
                current = cls._lease_from_payload(payload)
                highest_epoch = max(highest_epoch, current.fencing_epoch)
            elif row["event_type"] in {"lease_released", "lease_revoked"}:
                if current is not None and current.lease_id == payload["lease_id"]:
                    current = None
        return current, highest_epoch

    def current(self, resource: ResourceUri, *, include_expired: bool = True) -> DurableLease | None:
        rows = list(self._store.events(str(resource)))
        current, _ = self._project(rows)
        if current is not None and not include_expired and self._clock() >= current.expires_at:
            return None
        return current

    def is_authoritative(self, lease: DurableLease) -> bool:
        current, _ = self._project(list(self._store.events(lease.resource)))
        return (
            current == lease
            and not lease.revoked
            and self._clock() < lease.expires_at
        )

    def acquire(
        self,
        resource: ResourceUri,
        holder: HolderBinding,
        *,
        ttl: int,
        renewable_conditions: tuple[str, ...],
        queue_token: str | None = None,
    ) -> DurableLease:
        if ttl <= 0:
            raise ValueError("LEASE_TTL_INVALID")
        now = self._clock()
        db = self._store._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT * FROM scheduler_events WHERE resource=? ORDER BY sequence",
                (str(resource),),
            ).fetchall()
            current, highest_epoch = self._project(rows)
            if current is not None and not current.revoked and now < current.expires_at:
                raise LeaseDenied("RESOURCE_BUSY")
            epoch = highest_epoch + 1
            lease = DurableLease(
                lease_id=str(uuid4()),
                resource=str(resource),
                holder=holder,
                issued_epoch=epoch,
                issued_at=now,
                expires_at=now + ttl,
                renewable_conditions=renewable_conditions,
                queue_token=queue_token,
                revoked=False,
                fencing_epoch=epoch,
            )
            payload = asdict(lease)
            self._store._insert(db, "lease_acquired", str(resource), now, payload)
            db.commit()
            return lease
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def renew(
        self,
        lease_id: str,
        holder: HolderBinding,
        *,
        ttl: int,
        satisfied: set[str],
    ) -> DurableLease:
        now = self._clock()
        if ttl <= 0:
            raise ValueError("LEASE_TTL_INVALID")
        db = self._store._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM scheduler_events ORDER BY sequence").fetchall()
            current: DurableLease | None = None
            resource_epoch = 0
            for resource in {str(row["resource"]) for row in rows}:
                projected, epoch = self._project(
                    [row for row in rows if row["resource"] == resource]
                )
                if projected is not None and projected.lease_id == lease_id:
                    current = projected
                    resource_epoch = epoch
            if current is None or now >= current.expires_at:
                raise LeaseDenied("LEASE_NOT_ACTIVE")
            if current.holder != holder:
                raise LeaseDenied("LEASE_HOLDER_MISMATCH")
            if not set(current.renewable_conditions).issubset(satisfied):
                raise LeaseDenied("RENEW_CONDITIONS_UNSATISFIED")
            renewed = DurableLease(
                lease_id=current.lease_id,
                resource=current.resource,
                holder=holder,
                issued_epoch=current.issued_epoch + 1,
                issued_at=now,
                expires_at=now + ttl,
                renewable_conditions=current.renewable_conditions,
                queue_token=current.queue_token,
                revoked=False,
                fencing_epoch=resource_epoch + 1,
            )
            self._store._insert(db, "lease_renewed", current.resource, now, asdict(renewed))
            db.commit()
            return renewed
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def release(
        self, lease_id: str, holder: HolderBinding, fencing_epoch: int
    ) -> DurableLease:
        now = self._clock()
        db = self._store._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM scheduler_events ORDER BY sequence").fetchall()
            resources = {str(row["resource"]) for row in rows}
            current: DurableLease | None = None
            for resource in resources:
                resource_rows = [row for row in rows if row["resource"] == resource]
                projected, _ = self._project(resource_rows)
                if projected is not None and projected.lease_id == lease_id:
                    current = projected
                    break
            if current is None:
                raise LeaseDenied("LEASE_NOT_ACTIVE")
            if current.fencing_epoch != fencing_epoch:
                raise LeaseDenied("STALE_FENCING_EPOCH")
            if current.holder != holder:
                raise LeaseDenied("LEASE_HOLDER_MISMATCH")
            released = DurableLease(**{**asdict(current), "revoked": True, "holder": holder})
            self._store._insert(
                db,
                "lease_released",
                current.resource,
                now,
                {"lease_id": current.lease_id, "holder": asdict(holder)},
            )
            db.commit()
            return released
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()


# Compatibility-only pre-WP6 helper; it is not an authority store.
@dataclass(frozen=True)
class Lease:
    resource_id: str
    holder_id: str
    fencing_epoch: int
    expires_at: datetime


class LeaseRegistry:
    def __init__(self, ttl: timedelta = timedelta(minutes=5)) -> None:
        self._ttl = ttl
        self._leases: dict[str, Lease] = {}
        self._epochs: dict[str, int] = {}

    def acquire(
        self,
        resource_id: str,
        holder_id: str,
        *,
        replace_expired: bool = False,
        now: datetime | None = None,
    ) -> Lease:
        at = now or datetime.now(UTC)
        current = self._leases.get(resource_id)
        if current and current.expires_at > at:
            raise PermissionError("RESOURCE_BUSY")
        if current and not replace_expired:
            raise PermissionError("EXPIRED_LEASE_REQUIRES_EXPLICIT_REPLACEMENT")
        epoch = self._epochs.get(resource_id, 0) + 1
        lease = Lease(resource_id, holder_id, epoch, at + self._ttl)
        self._epochs[resource_id] = epoch
        self._leases[resource_id] = lease
        return lease

    def is_authoritative(self, lease: Lease) -> bool:
        return self._leases.get(lease.resource_id) == lease

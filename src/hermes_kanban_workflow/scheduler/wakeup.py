from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from hermes_kanban_workflow.domain.resources import ResourceUri
from hermes_kanban_workflow.scheduler.leases import (
    ControlClock,
    DurableLease,
    HolderBinding,
    LeaseService,
    SchedulerStore,
)
from hermes_kanban_workflow.scheduler.queues import WaitQueue, WaitToken


class WakeDenied(PermissionError):
    pass


@dataclass(frozen=True, slots=True)
class EligibilitySnapshot:
    policy_current: bool
    exact_hold_members: frozenset[str]
    blockers: frozenset[str]
    workspace_matches: bool
    capability_authority: frozenset[str]
    budget_remaining: int
    resource_eligible: bool


@dataclass(frozen=True, slots=True)
class FreshAttempt:
    attempt_id: str
    work_item_id: str | None
    service_id: str | None
    holder_subject: str
    fencing_epoch: int
    authority: frozenset[str]
    queue_token: str
    created_at: int


@dataclass(frozen=True, slots=True)
class WakeResult:
    release_id: str
    wait_token: str
    attempt: FreshAttempt
    lease: DurableLease


class WakeupService:
    def __init__(
        self,
        store: SchedulerStore,
        leases: LeaseService,
        queue: WaitQueue,
        eligibility_loader: Callable[[WaitToken], EligibilitySnapshot],
        start_fresh_attempt: Callable[[FreshAttempt], None],
        clock: ControlClock,
    ) -> None:
        self._store = store
        self._leases = leases
        self._queue = queue
        self._eligibility_loader = eligibility_loader
        self._start_fresh_attempt = start_fresh_attempt
        self._clock = clock

    @staticmethod
    def _validate(item: WaitToken, snapshot: EligibilitySnapshot) -> None:
        work_item = item.holder.work_item_id
        failures: list[str] = []
        if not snapshot.policy_current:
            failures.append("POLICY_NOT_CURRENT")
        if work_item is not None and work_item in snapshot.exact_hold_members:
            failures.append("EXACT_PROJECT_HOLD")
        if snapshot.blockers:
            failures.append("BLOCKER_PRESENT")
        if not snapshot.workspace_matches:
            failures.append("WORKSPACE_MISMATCH")
        if not item.authority.issubset(snapshot.capability_authority):
            failures.append("CAPABILITY_INSUFFICIENT")
        if snapshot.budget_remaining <= 0:
            failures.append("BUDGET_EXHAUSTED")
        if not snapshot.resource_eligible:
            failures.append("RESOURCE_INELIGIBLE")
        if failures:
            raise WakeDenied(";".join(failures))

    @staticmethod
    def _lease_from_dict(value: dict[str, Any]) -> DurableLease:
        return DurableLease(
            lease_id=str(value["lease_id"]),
            resource=str(value["resource"]),
            holder=HolderBinding(**value["holder"]),
            issued_epoch=int(value["issued_epoch"]),
            issued_at=int(value["issued_at"]),
            expires_at=int(value["expires_at"]),
            renewable_conditions=tuple(str(item) for item in value["renewable_conditions"]),
            queue_token=None if value["queue_token"] is None else str(value["queue_token"]),
            revoked=bool(value["revoked"]),
            fencing_epoch=int(value["fencing_epoch"]),
        )

    @classmethod
    def _result_from_payload(cls, payload: dict[str, Any]) -> WakeResult:
        raw_attempt = payload["attempt"]
        assert isinstance(raw_attempt, dict)
        attempt = FreshAttempt(
            attempt_id=str(raw_attempt["attempt_id"]),
            work_item_id=(
                None if raw_attempt["work_item_id"] is None else str(raw_attempt["work_item_id"])
            ),
            service_id=(
                None if raw_attempt["service_id"] is None else str(raw_attempt["service_id"])
            ),
            holder_subject=str(raw_attempt["holder_subject"]),
            fencing_epoch=int(raw_attempt["fencing_epoch"]),
            authority=frozenset(str(item) for item in raw_attempt["authority"]),
            queue_token=str(raw_attempt["queue_token"]),
            created_at=int(raw_attempt["created_at"]),
        )
        raw_lease = payload["lease"]
        assert isinstance(raw_lease, dict)
        return WakeResult(
            release_id=str(payload["release_id"]),
            wait_token=str(payload["wait_token"]),
            attempt=attempt,
            lease=cls._lease_from_dict(raw_lease),
        )

    def _existing(self, release_id: str) -> WakeResult | None:
        for row in self._store.events():
            if row["event_type"] != "wake_created":
                continue
            payload = json.loads(row["payload"])
            if payload["release_id"] == release_id:
                return self._result_from_payload(payload)
        return None

    def _was_dispatched(self, release_id: str) -> bool:
        for row in self._store.events():
            if row["event_type"] != "wake_dispatched":
                continue
            payload = json.loads(row["payload"])
            if payload["release_id"] == release_id:
                return True
        return False

    def _mark_dispatched(self, result: WakeResult) -> None:
        now = self._clock()
        db = self._store._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            self._store._insert(
                db,
                "wake_dispatched",
                result.lease.resource,
                now,
                {
                    "release_id": result.release_id,
                    "attempt_id": result.attempt.attempt_id,
                },
            )
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _revalidate(self, result: WakeResult) -> None:
        item = None
        owners = []
        for row in self._store.events(result.lease.resource):
            payload = json.loads(row["payload"])
            if row["event_type"] == "queue_enqueued" and payload["token"] == result.wait_token:
                item = WaitQueue._from_payload(payload)
            elif row["event_type"] == "wake_created" and payload["wait_token"] == result.wait_token:
                owners.append((payload["release_id"], payload["attempt"]["attempt_id"]))
        if owners != [(result.release_id, result.attempt.attempt_id)]:
            raise WakeDenied("WAKE_QUEUE_TOKEN_OWNERSHIP_MISMATCH")
        if item is None or item.holder != result.lease.holder:
            raise WakeDenied("WAKE_QUEUE_BINDING_MISMATCH")
        self._validate(item, self._eligibility_loader(item))
        if (
            not self._leases.is_authoritative(result.lease)
            or result.attempt.fencing_epoch != result.lease.fencing_epoch
            or result.attempt.authority != item.authority
        ):
            raise WakeDenied("WAKE_LEASE_NOT_AUTHORITATIVE")

    def _dispatch(self, result: WakeResult) -> None:
        db = self._store._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute(
                "SELECT * FROM scheduler_events WHERE event_type IN "
                "('wake_dispatch_started', 'wake_dispatched') ORDER BY sequence"
            ).fetchall()
            for row in rows:
                payload = json.loads(row["payload"])
                if payload["release_id"] == result.release_id:
                    raise WakeDenied("WAKE_DISPATCH_OUTCOME_UNCERTAIN")
            self._revalidate(result)
            self._store._insert(
                db,
                "wake_dispatch_started",
                result.lease.resource,
                self._clock(),
                {"release_id": result.release_id, "attempt_id": result.attempt.attempt_id},
            )
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
        # No transaction spans the callback. Its admission survives callback/process failure.
        self._start_fresh_attempt(result.attempt)
        self._mark_dispatched(result)

    def on_release(self, release_id: str, resource: ResourceUri, *, ttl: int) -> WakeResult:
        existing = self._existing(release_id)
        if existing is not None:
            if existing.lease.resource != str(resource):
                raise WakeDenied("DUPLICATE_RELEASE_MISMATCH")
            if not self._was_dispatched(release_id):
                self._dispatch(existing)
            return existing
        ordered = self._queue.ordered(resource)
        if not ordered:
            raise WakeDenied("WAIT_QUEUE_EMPTY")
        item = ordered[0]
        snapshot = self._eligibility_loader(item)
        self._validate(item, snapshot)
        current = self._leases.current(resource, include_expired=False)
        if (
            current is not None
            and current.queue_token == item.token
            and current.holder == item.holder
        ):
            lease = current
        else:
            lease = self._leases.acquire(
                resource,
                item.holder,
                ttl=ttl,
                renewable_conditions=(
                    "policy-current",
                    "capability-current",
                    "budget-remaining",
                ),
                queue_token=item.token,
            )
        now = self._clock()
        attempt = FreshAttempt(
            attempt_id=str(uuid5(NAMESPACE_URL, f"{release_id}:{item.token}")),
            work_item_id=item.holder.work_item_id,
            service_id=item.holder.service_id,
            holder_subject=item.holder.subject,
            fencing_epoch=lease.fencing_epoch,
            authority=item.authority,
            queue_token=item.token,
            created_at=now,
        )
        result = WakeResult(release_id, item.token, attempt, lease)
        payload = asdict(result)
        payload["attempt"]["authority"] = sorted(attempt.authority)
        db = self._store._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            for row in db.execute(
                "SELECT payload FROM scheduler_events WHERE event_type='wake_created'"
            ):
                previous = json.loads(row["payload"])
                if previous["release_id"] == release_id:
                    raise WakeDenied("WAKE_CREATION_ALREADY_ADMITTED")
                if previous["wait_token"] == item.token:
                    raise WakeDenied("WAKE_QUEUE_TOKEN_ALREADY_CONSUMED")
            if not any(
                entry.token == item.token for entry in WaitQueue._active_rows(db, str(resource))
            ):
                raise WakeDenied("WAKE_QUEUE_TOKEN_ALREADY_CONSUMED")
            self._store._insert(db, "queue_woken", str(resource), now, {"token": item.token})
            self._store._insert(db, "wake_created", str(resource), now, payload)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
        self._dispatch(result)
        return result

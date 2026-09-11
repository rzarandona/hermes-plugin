from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from typing import Any
from uuid import uuid4

from hermes_kanban_workflow.domain.resources import ResourceUri
from hermes_kanban_workflow.scheduler.leases import ControlClock, HolderBinding, SchedulerStore
from hermes_kanban_workflow.scheduler.precedence import PrecedenceModel, PriorityClass


@dataclass(frozen=True, slots=True)
class WaitToken:
    token: str
    resource: str
    holder: HolderBinding
    priority: PriorityClass
    authority: frozenset[str]
    enqueued_at: int
    ordinal: int
    position: int
    dependencies: tuple[str, ...]
    cancellable: bool
    escalated: bool = False


class PreemptionDisposition(StrEnum):
    QUEUED = "queued"
    INTERRUPT_PERMITTED = "interrupt_permitted"


@dataclass(frozen=True, slots=True)
class PreemptionDecision:
    disposition: PreemptionDisposition
    wait_token: WaitToken | None


class WaitQueue:
    def __init__(
        self, store: SchedulerStore, clock: ControlClock, precedence: PrecedenceModel
    ) -> None:
        self._store = store
        self._clock = clock
        self._precedence = precedence

    @staticmethod
    def _from_payload(payload: dict[str, Any]) -> WaitToken:
        return WaitToken(
            token=str(payload["token"]),
            resource=str(payload["resource"]),
            holder=HolderBinding(**payload["holder"]),
            priority=PriorityClass(int(payload["priority"])),
            authority=frozenset(str(item) for item in payload["authority"]),
            enqueued_at=int(payload["enqueued_at"]),
            ordinal=int(payload["ordinal"]),
            position=int(payload["position"]),
            dependencies=tuple(str(item) for item in payload["dependencies"]),
            cancellable=bool(payload["cancellable"]),
            escalated=bool(payload.get("escalated", False)),
        )

    def enqueue(
        self,
        resource: ResourceUri,
        holder: HolderBinding,
        priority: PriorityClass,
        *,
        authority: frozenset[str],
        dependencies: tuple[str, ...] = (),
        cancellable: bool = False,
    ) -> WaitToken:
        now = self._clock()
        db = self._store._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            ordinal = int(
                db.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM scheduler_events"
                ).fetchone()[0]
            )
            active = self._active_rows(db, str(resource))
            item = WaitToken(
                token=str(uuid4()),
                resource=str(resource),
                holder=holder,
                priority=priority,
                authority=authority,
                enqueued_at=now,
                ordinal=ordinal,
                position=len(active) + 1,
                dependencies=dependencies,
                cancellable=cancellable,
            )
            payload = asdict(item)
            payload["priority"] = int(priority)
            payload["authority"] = sorted(authority)
            self._store._insert(db, "queue_enqueued", str(resource), now, payload)
            db.commit()
            return item
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def request_preemption(
        self,
        resource: ResourceUri,
        holder: HolderBinding,
        priority: PriorityClass,
        *,
        authority: frozenset[str],
        active_cancellable: bool,
        safely_checkpointed: bool,
    ) -> PreemptionDecision:
        if active_cancellable and safely_checkpointed:
            return PreemptionDecision(PreemptionDisposition.INTERRUPT_PERMITTED, None)
        token = self.enqueue(
            resource,
            holder,
            priority,
            authority=authority,
            cancellable=False,
        )
        return PreemptionDecision(PreemptionDisposition.QUEUED, token)

    @staticmethod
    def _active_rows(db: sqlite3.Connection, resource: str) -> list[WaitToken]:
        rows = db.execute(
            "SELECT * FROM scheduler_events WHERE resource=? ORDER BY sequence", (resource,)
        ).fetchall()
        active: dict[str, WaitToken] = {}
        for row in rows:
            payload = json.loads(row["payload"])
            if row["event_type"] == "queue_enqueued":
                item = WaitQueue._from_payload(payload)
                active[item.token] = item
            elif row["event_type"] == "queue_escalated":
                token = str(payload["token"])
                if token in active:
                    active[token] = replace(active[token], escalated=True)
            elif row["event_type"] in {"queue_removed", "queue_woken"}:
                active.pop(str(payload["token"]), None)
        return list(active.values())

    def escalate_starved(
        self, resource: ResourceUri, *, threshold: int
    ) -> tuple[WaitToken, ...]:
        if threshold <= 0:
            raise ValueError("STARVATION_THRESHOLD_INVALID")
        now = self._clock()
        db = self._store._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            active = self._active_rows(db, str(resource))
            for item in active:
                if not item.escalated and now - item.enqueued_at >= threshold:
                    self._store._insert(
                        db,
                        "queue_escalated",
                        str(resource),
                        now,
                        {"token": item.token, "reason": "STARVATION_THRESHOLD"},
                    )
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
        return tuple(item for item in self.ordered(resource) if item.escalated)

    def ordered(self, resource: ResourceUri) -> tuple[WaitToken, ...]:
        db = self._store._connect()
        try:
            active = self._active_rows(db, str(resource))
        finally:
            db.close()

        def dependency_depth(item: WaitToken, seen: frozenset[str] = frozenset()) -> int:
            work_item = item.holder.work_item_id
            if work_item is None:
                return 0
            if work_item in seen:
                raise ValueError("DEPENDENCY_EDGE_CYCLE")
            predecessors = [
                before
                for before, after in self._precedence.dependency_edges
                if after == work_item
            ]
            if not predecessors:
                return 0
            depths = []
            for predecessor in predecessors:
                predecessor_item = next(
                    (entry for entry in active if entry.holder.work_item_id == predecessor), None
                )
                depths.append(
                    1
                    if predecessor_item is None
                    else 1 + dependency_depth(predecessor_item, seen | {work_item})
                )
            return max(depths)

        active.sort(
            key=lambda item: (
                self._precedence.rank(item.priority),
                dependency_depth(item),
                item.ordinal,
            )
        )
        return tuple(replace(item, position=index) for index, item in enumerate(active, 1))

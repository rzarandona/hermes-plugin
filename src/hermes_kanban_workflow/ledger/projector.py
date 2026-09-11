from __future__ import annotations

import json
from collections.abc import Iterable
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from hermes_kanban_workflow.domain.commands import _thaw_json
from hermes_kanban_workflow.domain.events import WorkflowEvent
from hermes_kanban_workflow.ledger.repository import Ledger
from hermes_kanban_workflow.ledger.schema import open_database


@dataclass(frozen=True)
class ProjectionState:
    target_id: str
    event_count: int
    last_event_id: str
    last_sequence: int
    payload: str


class Projector:
    """Deterministic projection derived only from ordered immutable events."""

    CHECKPOINT = "canonical"

    def __init__(self, path: Path, ledger: Ledger) -> None:
        self._path = path
        self._ledger = ledger

    @staticmethod
    def reduce(events: Iterable[WorkflowEvent]) -> tuple[ProjectionState, ...]:
        states: dict[str, ProjectionState] = {}
        for event in events:
            previous = states.get(event.target_id)
            count = 1 if previous is None else previous.event_count + 1
            payload = json.dumps(
                _thaw_json(event.payload),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            states[event.target_id] = ProjectionState(
                target_id=event.target_id,
                event_count=count,
                last_event_id=event.event_id,
                last_sequence=event.sequence,
                payload=payload,
            )
        return tuple(states[key] for key in sorted(states))

    def rebuild(self) -> tuple[ProjectionState, ...]:
        events = tuple(self._ledger.iter_events())
        state = self.reduce(events)
        checkpoint = events[-1].sequence if events else 0
        self._replace(state, checkpoint)
        return state

    def checkpoint(self) -> int:
        with closing(open_database(self._path)) as db:
            row = db.execute(
                "SELECT sequence FROM projection_checkpoint WHERE name=?", (self.CHECKPOINT,)
            ).fetchone()
        return 0 if row is None else int(row["sequence"])

    def repair(self) -> int:
        checkpoint = self.checkpoint()
        pending = tuple(self._ledger.iter_events(after_sequence=checkpoint))
        if not pending:
            return 0
        self.rebuild()
        return len(pending)

    def snapshot(self) -> tuple[ProjectionState, ...]:
        with closing(open_database(self._path)) as db:
            rows = db.execute(
                "SELECT target_id,event_count,last_event_id,last_sequence,payload "
                "FROM projection_state ORDER BY target_id"
            ).fetchall()
        return tuple(
            ProjectionState(
                target_id=row["target_id"],
                event_count=row["event_count"],
                last_event_id=row["last_event_id"],
                last_sequence=row["last_sequence"],
                payload=row["payload"],
            )
            for row in rows
        )

    def _replace(self, state: tuple[ProjectionState, ...], checkpoint: int) -> None:
        with closing(open_database(self._path)) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM projection_state")
            db.executemany(
                "INSERT INTO projection_state(target_id,event_count,last_event_id,last_sequence,payload) "
                "VALUES(?,?,?,?,?)",
                (
                    (
                        item.target_id,
                        item.event_count,
                        item.last_event_id,
                        item.last_sequence,
                        item.payload,
                    )
                    for item in state
                ),
            )
            db.execute(
                "INSERT INTO projection_checkpoint(name,sequence) VALUES(?,?) "
                "ON CONFLICT(name) DO UPDATE SET sequence=excluded.sequence",
                (self.CHECKPOINT, checkpoint),
            )
            db.commit()

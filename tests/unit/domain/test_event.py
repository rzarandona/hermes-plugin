from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from hermes_kanban_workflow.domain.events import WorkflowEvent
from tests.unit.domain.test_command_envelope import correlation


def test_event_requires_correlation_positive_sequence_and_immutable_payload() -> None:
    event = WorkflowEvent(
        event_id="event-1",
        sequence=1,
        event_type="note_recorded",
        target_id="work-1",
        command_id="command-1",
        payload={"nested": {"value": 1}},
        correlation=correlation(),
        occurred_at=datetime.now(UTC),
    )
    assert event.correlation.record_id == "work-1"
    with pytest.raises(TypeError):
        event.payload["nested"]["value"] = 2  # type: ignore[index]
    with pytest.raises(ValidationError):
        WorkflowEvent(
            event_id="event-2",
            sequence=0,
            event_type="note_recorded",
            target_id="work-1",
            command_id="command-1",
            payload={},
            correlation=correlation(),
            occurred_at=datetime.now(UTC),
        )

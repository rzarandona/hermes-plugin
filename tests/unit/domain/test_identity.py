from __future__ import annotations

import pytest
from pydantic import ValidationError

from hermes_kanban_workflow.domain.identity import AuthorityEpoch, CorrelationEnvelope


def valid_correlation(**updates: object) -> CorrelationEnvelope:
    data: dict[str, object] = {
        "product_id": "product-1",
        "project_id": "project-1",
        "work_item_id": None,
        "service_id": None,
        "root_cause_id": None,
        "parent_record_type": None,
        "parent_record_id": None,
        "record_type": "work_item",
        "record_id": "work-1",
        "generation": None,
        "policy_version": "sha256:policy",
        "authority_epoch": 1,
        "created_at_control_time": 100,
    }
    data.update(updates)
    return CorrelationEnvelope(**data)  # type: ignore[arg-type]


def test_identity_hierarchy_and_nullable_correlation_fields() -> None:
    correlation = valid_correlation()
    assert correlation.work_item_id is None
    assert correlation.service_id is None
    assert correlation.parent_record_id is None
    assert correlation.record_id == "work-1"


def test_generations_and_authority_epochs_start_at_one() -> None:
    with pytest.raises(ValidationError):
        AuthorityEpoch(value=0)
    with pytest.raises(ValidationError):
        valid_correlation(authority_epoch=0)
    with pytest.raises(ValidationError):
        valid_correlation(generation=0)


def test_parent_type_and_id_are_present_or_absent_together() -> None:
    with pytest.raises(ValidationError, match="parent correlation"):
        valid_correlation(parent_record_type="project")


def test_correlation_is_immutable() -> None:
    correlation = valid_correlation()
    with pytest.raises(ValidationError):
        correlation.record_id = "other"  # type: ignore[misc]

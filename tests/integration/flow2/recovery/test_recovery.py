from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from hermes_kanban_workflow.flows.flow2 import Flow2Coordinator
from hermes_kanban_workflow.recovery.budget import RecoveryBudget
from hermes_kanban_workflow.recovery.classes import RecoveryClass, RecoveryClassifier
from hermes_kanban_workflow.recovery.executor import (
    ExternalEffectState,
    RecoveryExecutor,
)
from tests.policy_fixtures import verified_policy


def test_recovery_classes_distinguish_r0_r1_r2_r3_and_unknown() -> None:
    classifier = RecoveryClassifier(
        {
            "recompute-view": RecoveryClass.R0,
            "restart-worker": RecoveryClass.R1,
            "undo-migration": RecoveryClass.R2,
            "destroy-data": RecoveryClass.R3,
        }
    )

    assert classifier.classify("recompute-view").recovery_class is RecoveryClass.R0
    assert classifier.classify("restart-worker").recovery_class is RecoveryClass.R1
    assert classifier.classify("undo-migration").recovery_class is RecoveryClass.R2
    assert classifier.classify("destroy-data").recovery_class is RecoveryClass.R3
    unknown = classifier.classify("mystery")
    assert unknown.recovery_class is RecoveryClass.R3
    assert unknown.known is False


def test_default_budget_allows_one_auto_recovery_and_signed_policy_can_narrow(tmp_path: Path) -> None:
    now = datetime(2026, 8, 29, tzinfo=UTC)
    default = RecoveryBudget.from_policy(None, now=now)
    assert default.consume().remaining == 0
    with pytest.raises(PermissionError, match="RECOVERY_BUDGET_EXHAUSTED"):
        default.consume().consume()

    narrowed_policy = verified_policy(
        tmp_path,
        now=now,
        rules={"max_automatic_recoveries": 0},
    )
    narrowed = RecoveryBudget.from_policy(narrowed_policy, now=now)
    with pytest.raises(PermissionError, match="RECOVERY_BUDGET_EXHAUSTED"):
        narrowed.consume()


def test_automatic_r1_retry_has_fresh_exact_bindings_and_reacquired_resources() -> None:
    flow = Flow2Coordinator()
    first = flow.start_attempt(
        card_id="card-1",
        workspace="workspace-exact",
        resources=("resource://product/build-lane/local/local/windows",),
    )
    classification = RecoveryClassifier(
        {"restart-worker": RecoveryClass.R1}
    ).classify("restart-worker")
    reacquired: list[tuple[str, ...]] = []
    executor = RecoveryExecutor(
        flow,
        allowlisted_r1=frozenset({"restart-worker"}),
        reacquire_resources=lambda resources: reacquired.append(resources) or resources,
    )

    command = executor.retry(
        previous=first,
        classification=classification,
        budget=RecoveryBudget(1),
        effect_state=ExternalEffectState.NONE,
    )

    assert command.attempt.card_id == first.card_id
    assert command.attempt.run_id != first.run_id
    assert command.attempt.fencing_epoch > first.fencing_epoch
    assert command.attempt.scratch_scope != first.scratch_scope
    assert command.attempt.workspace == "workspace-exact"
    assert command.attempt.resources == first.resources
    assert command.resources_reacquired is True
    assert reacquired == [first.resources]
    assert command.budget.remaining == 0


def test_r2_compensation_uses_separately_authorized_named_command_and_verification() -> None:
    flow = Flow2Coordinator()
    first = flow.start_attempt(card_id="card-1", workspace="w", resources=())
    classification = RecoveryClassifier(
        {"undo-migration": RecoveryClass.R2}
    ).classify("undo-migration")
    authorization_calls: list[tuple[str, str, str]] = []
    verification_calls: list[str] = []
    executor = RecoveryExecutor(
        flow,
        allowlisted_r1=frozenset(),
        reacquire_resources=lambda resources: resources,
        authorize_compensation=lambda command, authority, run_id: (
            authorization_calls.append((command, authority, run_id)) or True
        ),
        verify_compensation=lambda evidence: verification_calls.append(evidence) or True,
    )

    result = executor.compensate(
        previous=first,
        classification=classification,
        compensation_command="compensate-migration",
        authority_subject_id="owner-1",
        verification_evidence_ref="ledger:compensation:verified",
    )

    assert result.verified is True
    assert authorization_calls == [("compensate-migration", "owner-1", first.run_id)]
    assert verification_calls == ["ledger:compensation:verified"]


def test_r3_and_unknown_recovery_are_forbidden() -> None:
    flow = Flow2Coordinator()
    first = flow.start_attempt(card_id="card-1", workspace="w", resources=())
    executor = RecoveryExecutor(
        flow,
        allowlisted_r1=frozenset(),
        reacquire_resources=lambda resources: resources,
    )
    classifier = RecoveryClassifier({"forbidden": RecoveryClass.R3})

    cases = (
        (classifier.classify("forbidden"), "R3_RECOVERY_FORBIDDEN"),
        (classifier.classify("unknown"), "UNKNOWN_RECOVERY_FORBIDDEN"),
    )
    for classification, code in cases:
        with pytest.raises(PermissionError, match=code):
            executor.retry(
                previous=first,
                classification=classification,
                budget=RecoveryBudget(1),
                effect_state=ExternalEffectState.NONE,
            )


def test_partial_effect_requires_authoritative_reconciliation_before_retry() -> None:
    flow = Flow2Coordinator()
    first = flow.start_attempt(card_id="card-1", workspace="w", resources=())
    classification = RecoveryClassifier(
        {"recompute": RecoveryClass.R0}
    ).classify("recompute")
    unverified = RecoveryExecutor(
        flow,
        allowlisted_r1=frozenset(),
        reacquire_resources=lambda resources: resources,
    )

    with pytest.raises(PermissionError, match="AUTHORITATIVE_EFFECT_RECONCILIATION_REQUIRED"):
        unverified.retry(
            previous=first,
            classification=classification,
            budget=RecoveryBudget(1),
            effect_state=ExternalEffectState.PARTIAL,
            reconciliation_ref="caller-asserted",
        )

    verified = RecoveryExecutor(
        flow,
        allowlisted_r1=frozenset(),
        reacquire_resources=lambda resources: resources,
        verify_reconciliation=lambda ref, run_id: (
            ref == "ledger:authoritative:1" and run_id == first.run_id
        ),
    )
    command = verified.retry(
        previous=first,
        classification=classification,
        budget=RecoveryBudget(1),
        effect_state=ExternalEffectState.PARTIAL,
        reconciliation_ref="ledger:authoritative:1",
    )
    assert command.reconciliation_ref == "ledger:authoritative:1"

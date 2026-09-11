from __future__ import annotations

import pytest

from hermes_kanban_workflow.adapters.effects import (
    AuthenticatedReconciliationBoundary,
    EffectCommand,
    ReconciliationReceipt,
)


def test_effect_boundary_uses_injected_authenticated_reconciliation_only() -> None:
    command = EffectCommand(
        operation_id="promote-1",
        action="promote",
        artifact_id="artifact-a",
        environment="production",
        binding_digest="binding-a",
    )
    calls: list[EffectCommand] = []

    def reconcile(value: EffectCommand) -> ReconciliationReceipt:
        calls.append(value)
        return ReconciliationReceipt(
            operation_id=value.operation_id,
            command_digest=value.digest,
            reconciler_subject_id="fixture-reconciler",
            status="accepted",
            evidence_ref="ledger:effect:1",
            authentication_tag=b"fixture-authenticated",
            repository_fixture=True,
        )

    boundary = AuthenticatedReconciliationBoundary(
        reconcile=reconcile,
        verify=lambda receipt, expected: (
            receipt.command_digest == expected.digest
            and receipt.authentication_tag == b"fixture-authenticated"
        ),
    )

    receipt = boundary.execute(command)

    assert calls == [command]
    assert receipt.repository_fixture is True
    assert receipt.production_proof is False


def test_caller_forged_effect_receipt_is_denied() -> None:
    command = EffectCommand("promote-1", "promote", "artifact-a", "production", "binding-a")
    forged = ReconciliationReceipt(
        command.operation_id,
        command.digest,
        "forged-subject",
        "accepted",
        "caller:evidence",
        b"forged",
        True,
    )
    boundary = AuthenticatedReconciliationBoundary(
        reconcile=lambda _command: forged,
        verify=lambda receipt, _command: receipt.authentication_tag == b"authority-tag",
    )

    with pytest.raises(PermissionError, match="AUTHENTIC_EFFECT_RECONCILIATION_REQUIRED"):
        boundary.execute(command)

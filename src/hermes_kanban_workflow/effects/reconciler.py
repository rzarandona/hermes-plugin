from __future__ import annotations

from collections.abc import Callable

from hermes_kanban_workflow.effects.receipts import ProviderReceipt, ReadbackReceipt
from hermes_kanban_workflow.effects.state_machine import EffectRecord, EffectState, EffectStore

DispatchAdapter = Callable[[EffectRecord], ProviderReceipt]
ReadbackAdapter = Callable[[EffectRecord], ReadbackReceipt]


class EffectReconciler:
    """Coordinates test-double dispatch and authoritative read-back.

    Delivery is at-least-once with a stable idempotency identity. Provider-side
    deduplication is required; this class intentionally makes no exactly-once claim.
    """

    delivery_semantics = "at-least-once stable-ID delivery plus provider dedupe"

    def __init__(
        self,
        store: EffectStore,
        *,
        dispatch: DispatchAdapter,
        readback: ReadbackAdapter,
        reconciliation_budget: int = 3,
        escalation_owner: str = "workflow-owner",
        blocked_next_action: str = "external effect retry or closure",
        fenceable: bool = True,
    ) -> None:
        if reconciliation_budget < 0:
            raise ValueError("RECONCILIATION_BUDGET_INVALID")
        self._store = store
        self._dispatch = dispatch
        self._readback = readback
        self._budget = reconciliation_budget
        self._owner = escalation_owner
        self._blocked_next_action = blocked_next_action
        self._fenceable = fenceable

    def dispatch(self, operation_id: str) -> EffectRecord:
        record = self._store.mark_started(operation_id, attempt_budget=self._budget)
        try:
            receipt = self._dispatch(record)
            if receipt.operation_id != operation_id:
                raise ValueError("PROVIDER_RECEIPT_BINDING_MISMATCH")
            recorded = self._store.append_provider_receipt(receipt, expected=record)
        except TimeoutError:
            return self._store.require_reconciliation(
                operation_id, "PROVIDER_TIMEOUT_UNKNOWN", expected=record
            )
        except BaseException:
            self._store.require_reconciliation(
                operation_id, "PROVIDER_FAILURE_UNKNOWN", expected=record
            )
            raise
        return self.reconcile(recorded.operation_id)

    def reconcile(self, operation_id: str) -> EffectRecord:
        record = self._store.get(operation_id)
        if record.state in {
            EffectState.CONFIRMED,
            EffectState.CLOSED,
            EffectState.MANUAL_ESCALATION,
        }:
            return record
        if not self._fenceable:
            return self._store.escalate(
                operation_id,
                owner=self._owner,
                blocked_next_action=self._blocked_next_action,
                expected=record,
            )
        if record.attempts >= self._budget and self._budget >= 0:
            return self._store.escalate(
                operation_id,
                owner=self._owner,
                blocked_next_action=self._blocked_next_action,
                expected=record,
            )
        snapshot = self._store.mark_readback_pending(operation_id, expected=record)
        receipt = self._readback(snapshot)
        if receipt.operation_id != operation_id:
            raise ValueError("READBACK_RECEIPT_BINDING_MISMATCH")
        return self._store.append_readback_receipt(receipt, expected=snapshot)

    def retry(self, operation_id: str) -> EffectRecord:
        reconciled = self.reconcile(operation_id)
        if reconciled.state is EffectState.CONFIRMED:
            return reconciled
        if reconciled.state is EffectState.MANUAL_ESCALATION:
            return reconciled
        if reconciled.state is not EffectState.RECONCILIATION_REQUIRED:
            raise RuntimeError("AUTHORITATIVE_READBACK_REQUIRED_BEFORE_RETRY")
        if not self._store.retry_authorized(operation_id):
            return reconciled
        return self.dispatch(operation_id)

    def close(self, operation_id: str) -> EffectRecord:
        reconciled = self.reconcile(operation_id)
        if reconciled.state is not EffectState.CONFIRMED:
            raise RuntimeError("AUTHORITATIVE_READBACK_REQUIRED_BEFORE_CLOSURE")
        return self._store.close_effect(operation_id)

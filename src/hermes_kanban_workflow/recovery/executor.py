from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from hermes_kanban_workflow.flows.flow2 import AttemptBindings, Flow2Coordinator
from hermes_kanban_workflow.recovery.budget import RecoveryBudget
from hermes_kanban_workflow.recovery.classes import RecoveryClass, RecoveryClassification


class ExternalEffectState(StrEnum):
    NONE = "none"
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RecoveryCommand:
    command_name: str
    previous_run_id: str
    attempt: AttemptBindings
    resources_reacquired: bool
    reconciliation_ref: str | None
    budget: RecoveryBudget


@dataclass(frozen=True, slots=True)
class CompensationResult:
    original_command_name: str
    compensation_command: str
    authority_subject_id: str
    original_run_id: str
    verification_evidence_ref: str
    verified: bool


class RecoveryExecutor:
    def __init__(
        self,
        coordinator: Flow2Coordinator,
        *,
        allowlisted_r1: frozenset[str],
        reacquire_resources: Callable[[tuple[str, ...]], tuple[str, ...]],
        authorize_compensation: Callable[[str, str, str], bool] | None = None,
        verify_compensation: Callable[[str], bool] | None = None,
        verify_reconciliation: Callable[[str, str], bool] | None = None,
    ) -> None:
        self._coordinator = coordinator
        self._allowlisted_r1 = allowlisted_r1
        self._reacquire_resources = reacquire_resources
        self._authorize_compensation = authorize_compensation
        self._verify_compensation = verify_compensation
        self._verify_reconciliation = verify_reconciliation

    def retry(
        self,
        *,
        previous: AttemptBindings,
        classification: RecoveryClassification,
        budget: RecoveryBudget,
        effect_state: ExternalEffectState,
        reconciliation_ref: str | None = None,
    ) -> RecoveryCommand:
        if not classification.known:
            raise PermissionError("UNKNOWN_RECOVERY_FORBIDDEN")
        if classification.recovery_class is RecoveryClass.R3:
            raise PermissionError("R3_RECOVERY_FORBIDDEN")
        eligible = classification.recovery_class is RecoveryClass.R0 or (
            classification.recovery_class is RecoveryClass.R1
            and classification.command_name in self._allowlisted_r1
        )
        if not eligible:
            raise PermissionError("AUTOMATIC_RECOVERY_FORBIDDEN")
        if effect_state in {ExternalEffectState.PARTIAL, ExternalEffectState.UNKNOWN} and (
            not reconciliation_ref
            or self._verify_reconciliation is None
            or not self._verify_reconciliation(reconciliation_ref, previous.run_id)
        ):
            raise PermissionError("AUTHORITATIVE_EFFECT_RECONCILIATION_REQUIRED")
        next_budget = budget.consume()
        reacquired = self._reacquire_resources(previous.resources)
        if reacquired != previous.resources:
            raise PermissionError("RECOVERY_RESOURCE_BINDING_MISMATCH")
        attempt = self._coordinator.replace_attempt(previous.run_id)
        return RecoveryCommand(
            command_name=classification.command_name,
            previous_run_id=previous.run_id,
            attempt=attempt,
            resources_reacquired=True,
            reconciliation_ref=reconciliation_ref,
            budget=next_budget,
        )

    def compensate(
        self,
        *,
        previous: AttemptBindings,
        classification: RecoveryClassification,
        compensation_command: str,
        authority_subject_id: str,
        verification_evidence_ref: str,
    ) -> CompensationResult:
        if classification.recovery_class is not RecoveryClass.R2:
            raise PermissionError("COMPENSATION_ONLY_FOR_R2")
        if self._authorize_compensation is None or not self._authorize_compensation(
            compensation_command, authority_subject_id, previous.run_id
        ):
            raise PermissionError("SEPARATE_COMPENSATION_AUTHORIZATION_REQUIRED")
        if self._verify_compensation is None or not self._verify_compensation(
            verification_evidence_ref
        ):
            raise PermissionError("COMPENSATION_VERIFICATION_REQUIRED")
        return CompensationResult(
            original_command_name=classification.command_name,
            compensation_command=compensation_command,
            authority_subject_id=authority_subject_id,
            original_run_id=previous.run_id,
            verification_evidence_ref=verification_evidence_ref,
            verified=True,
        )

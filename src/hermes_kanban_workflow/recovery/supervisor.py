from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from threading import Lock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class SupervisorDenied(ValueError):
    """A typed, fail-closed supervisor denial."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical(body: dict[str, object]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class DisableRecoveryCommand:
    command_id: str
    executor: str
    capabilities: tuple[str, ...]
    policy_digest: str
    epoch: int
    effective_at: datetime
    expires_at: datetime

    def signing_bytes(self) -> bytes:
        return _canonical(
            {
                "capabilities": list(self.capabilities),
                "command_id": self.command_id,
                "effective_at": self.effective_at.isoformat(),
                "epoch": self.epoch,
                "executor": self.executor,
                "expires_at": self.expires_at.isoformat(),
                "policy_digest": self.policy_digest,
            }
        )


@dataclass(frozen=True)
class DisableRecoveryReceipt:
    revoked_capabilities: tuple[str, ...]
    fencing_epoch: int


@dataclass
class InFlightEffect:
    effect_id: str
    status: str


@dataclass
class MemberState:
    member_id: str
    status: str
    fencing_epoch: int
    dispatch_enabled: bool = True
    checkpoint_id: str | None = None
    attempt_id: str | None = None
    independently_blocked: bool = False
    intentionally_held: bool = False
    eligible: bool = True


@dataclass(frozen=True)
class ProjectHoldCommand:
    command_id: str
    hold_id: str
    project_id: str
    members: tuple[str, ...]
    reason: str
    policy_digest: str
    epoch: int
    effective_at: datetime
    expires_at: datetime

    def signing_bytes(self) -> bytes:
        return _canonical(
            {
                "command_id": self.command_id,
                "effective_at": self.effective_at.isoformat(),
                "epoch": self.epoch,
                "expires_at": self.expires_at.isoformat(),
                "hold_id": self.hold_id,
                "members": list(self.members),
                "policy_digest": self.policy_digest,
                "project_id": self.project_id,
                "reason": self.reason,
            }
        )


@dataclass(frozen=True)
class ProjectHoldRecord:
    hold_id: str
    project_id: str
    members: tuple[str, ...]
    policy_digest: str
    epoch: int


@dataclass(frozen=True)
class ResumeProjectHoldCommand:
    command_id: str
    hold_id: str
    project_id: str
    members: tuple[str, ...]
    policy_digest: str
    epoch: int
    effective_at: datetime
    expires_at: datetime

    def signing_bytes(self) -> bytes:
        return _canonical(
            {
                "command_id": self.command_id,
                "effective_at": self.effective_at.isoformat(),
                "epoch": self.epoch,
                "expires_at": self.expires_at.isoformat(),
                "hold_id": self.hold_id,
                "members": list(self.members),
                "policy_digest": self.policy_digest,
                "project_id": self.project_id,
            }
        )


class RecoverySupervisor:
    def __init__(
        self,
        *,
        recovery_capabilities: set[str],
        visible_roles: set[str],
        fencing_epoch: int,
        owner_public_key: Ed25519PublicKey,
        policy_digest: str,
        members: dict[str, MemberState] | None = None,
        project_members: tuple[str, ...] | None = None,
        in_flight_effects: list[InFlightEffect] | None = None,
    ) -> None:
        self._recovery_capabilities = frozenset(recovery_capabilities)
        self.visible_roles = frozenset(visible_roles)
        self.fencing_epoch = fencing_epoch
        self._owner_public_key = owner_public_key
        self._policy_digest = policy_digest
        self._recovery_enabled = True
        self._members = members or {}
        self._project_members = project_members
        self._holds: dict[str, ProjectHoldRecord] = {}
        self._used_commands: set[str] = set()
        self._in_flight_effects = in_flight_effects or []
        self.external_actions: tuple[str, ...] = ()

    def role_authorized(self, role: str) -> bool:
        return role != "Recovery Executor" or self._recovery_enabled

    def disable_recovery(
        self,
        command: DisableRecoveryCommand,
        signature: bytes,
        *,
        now: datetime,
    ) -> DisableRecoveryReceipt:
        exact = (
            command.executor == "Recovery Executor"
            and frozenset(command.capabilities) == self._recovery_capabilities
            and len(command.capabilities) == len(self._recovery_capabilities)
            and command.policy_digest == self._policy_digest
            and command.epoch == self.fencing_epoch
            and command.effective_at <= now < command.expires_at
        )
        if not exact:
            raise SupervisorDenied("DISABLE_RECOVERY_DENIED")
        try:
            self._owner_public_key.verify(signature, command.signing_bytes())
        except InvalidSignature as exc:
            raise SupervisorDenied("COMMAND_SIGNATURE_INVALID") from exc
        self._recovery_enabled = False
        self.fencing_epoch += 1
        for effect in self._in_flight_effects:
            effect.status = "reconciled-no-external-action"
        return DisableRecoveryReceipt(tuple(sorted(self._recovery_capabilities)), self.fencing_epoch)

    def project_hold(
        self,
        command: ProjectHoldCommand,
        signature: bytes,
        *,
        now: datetime,
    ) -> ProjectHoldRecord:
        expected = self._project_members
        exact = (
            expected is not None
            and command.command_id not in self._used_commands
            and command.hold_id not in self._holds
            and command.members == expected
            and len(set(command.members)) == len(command.members)
            and all(member in self._members for member in command.members)
            and command.policy_digest == self._policy_digest
            and command.epoch == self.fencing_epoch
            and bool(command.reason)
            and command.effective_at <= now < command.expires_at
        )
        if not exact:
            raise SupervisorDenied("PROJECT_HOLD_DENIED")
        try:
            self._owner_public_key.verify(signature, command.signing_bytes())
        except InvalidSignature as exc:
            raise SupervisorDenied("COMMAND_SIGNATURE_INVALID") from exc
        record = ProjectHoldRecord(
            command.hold_id,
            command.project_id,
            command.members,
            command.policy_digest,
            command.epoch,
        )
        for member_id in record.members:
            member = self._members[member_id]
            member.checkpoint_id = f"checkpoint:{record.hold_id}:{member_id}"
            member.dispatch_enabled = False
            member.status = "Blocked"
        self._holds[record.hold_id] = record
        self._used_commands.add(command.command_id)
        return record

    def resume_project_hold(
        self,
        command: ResumeProjectHoldCommand,
        signature: bytes,
        *,
        now: datetime,
    ) -> tuple[str, ...]:
        record = self._holds.get(command.hold_id)
        exact = (
            record is not None
            and command.command_id not in self._used_commands
            and command.project_id == record.project_id
            and command.members == record.members
            and command.policy_digest == record.policy_digest
            and command.epoch == record.epoch + 1
            and command.epoch > self.fencing_epoch
            and command.effective_at <= now < command.expires_at
        )
        if not exact:
            raise SupervisorDenied("PROJECT_RESUME_DENIED")
        assert record is not None
        try:
            self._owner_public_key.verify(signature, command.signing_bytes())
        except InvalidSignature as exc:
            raise SupervisorDenied("COMMAND_SIGNATURE_INVALID") from exc
        started: list[str] = []
        for member_id in record.members:
            member = self._members[member_id]
            if member.eligible and not member.independently_blocked and not member.intentionally_held:
                member.fencing_epoch = command.epoch
                member.attempt_id = f"attempt:{record.hold_id}:{member_id}:{command.epoch}"
                member.dispatch_enabled = True
                member.status = "Running"
                started.append(member_id)
        self.fencing_epoch = command.epoch
        self._used_commands.add(command.command_id)
        return tuple(started)


@dataclass(frozen=True)
class ReconciliationReceipt:
    role: str
    leader_id: str
    epoch: int
    ledger_position: int


@dataclass(frozen=True)
class TakeoverReceipt:
    leader_id: str
    epoch: int


class RoleFailover:
    """Atomic active-passive leadership with reconciliation-bound takeover."""

    def __init__(self, role: str, *, leader_id: str, epoch: int) -> None:
        self.role = role
        self.leader_id = leader_id
        self.epoch = epoch
        self._active = {leader_id}
        self._lock = Lock()
        self._authoritative_receipt: ReconciliationReceipt | None = None

    @property
    def active_leaders(self) -> frozenset[str]:
        return frozenset(self._active)

    def authoritative_reconcile(self, *, ledger_position: int = 0) -> ReconciliationReceipt:
        receipt = ReconciliationReceipt(self.role, self.leader_id, self.epoch, ledger_position)
        self._authoritative_receipt = receipt
        return receipt

    def takeover(
        self,
        candidate: str,
        reconciliation: ReconciliationReceipt,
        *,
        new_epoch: int,
    ) -> TakeoverReceipt:
        with self._lock:
            if (
                reconciliation is not self._authoritative_receipt
                or reconciliation.role != self.role
                or reconciliation.epoch != self.epoch
                or new_epoch <= self.epoch
            ):
                raise SupervisorDenied("TAKEOVER_RECONCILIATION_DENIED")
            self._active.clear()
            self.leader_id = candidate
            self.epoch = new_epoch
            self._active.add(candidate)
            self._authoritative_receipt = None
            return TakeoverReceipt(candidate, new_epoch)

    def authorize(self, leader_id: str, *, epoch: int) -> None:
        if leader_id != self.leader_id or epoch != self.epoch:
            raise SupervisorDenied("STALE_LEADER_DENIED")

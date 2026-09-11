from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import Barrier, Thread

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.recovery.supervisor import (
    DisableRecoveryCommand,
    InFlightEffect,
    MemberState,
    ProjectHoldCommand,
    RecoverySupervisor,
    ResumeProjectHoldCommand,
    RoleFailover,
    SupervisorDenied,
)

NOW = datetime(2026, 8, 29, 12, tzinfo=UTC)


def test_disable_recovery_revokes_only_exact_executor_capabilities() -> None:
    key = Ed25519PrivateKey.generate()
    supervisor = RecoverySupervisor(
        recovery_capabilities={"recover", "replay"},
        visible_roles={"Recovery Executor", "Watchdog", "Ledger"},
        fencing_epoch=7,
        owner_public_key=key.public_key(),
        policy_digest="policy-a",
    )
    command = DisableRecoveryCommand(
        command_id="disable-1",
        executor="Recovery Executor",
        capabilities=("recover", "replay"),
        policy_digest="policy-a",
        epoch=7,
        effective_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
    )

    receipt = supervisor.disable_recovery(command, key.sign(command.signing_bytes()), now=NOW)

    assert receipt.revoked_capabilities == ("recover", "replay")
    assert receipt.fencing_epoch == 8
    assert supervisor.visible_roles == frozenset({"Recovery Executor", "Watchdog", "Ledger"})
    assert supervisor.role_authorized("Watchdog")
    assert supervisor.role_authorized("Ledger")
    assert not supervisor.role_authorized("Recovery Executor")


def test_caller_cannot_self_issue_owner_authority_or_project_membership() -> None:
    trusted_key = Ed25519PrivateKey.generate()
    forged_key = Ed25519PrivateKey.generate()
    states = {
        "a": MemberState("a", "Running", fencing_epoch=3),
        "b": MemberState("b", "Ready", fencing_epoch=3),
    }
    supervisor = RecoverySupervisor(
        recovery_capabilities=set(),
        visible_roles=set(),
        fencing_epoch=3,
        owner_public_key=trusted_key.public_key(),
        policy_digest="policy-a",
        members=states,
        project_members=("a", "b"),
    )
    forged = ProjectHoldCommand(
        "forged-command",
        "forged-hold",
        "project-1",
        ("a", "b"),
        "attacker-signed hold",
        "policy-a",
        3,
        NOW - timedelta(seconds=1),
        NOW + timedelta(minutes=1),
    )

    with pytest.raises(SupervisorDenied, match="COMMAND_SIGNATURE_INVALID"):
        supervisor.project_hold(
            forged,
            forged_key.sign(forged.signing_bytes()),
            now=NOW,
        )

    assert trusted_key.public_key() != forged_key.public_key()
    assert all(state.dispatch_enabled for state in states.values())


def test_project_hold_checkpoints_only_immutable_exact_members() -> None:
    key = Ed25519PrivateKey.generate()
    states = {
        "a": MemberState("a", "Running", fencing_epoch=3),
        "b": MemberState("b", "Ready", fencing_epoch=3),
        "unrelated": MemberState("unrelated", "Ready", fencing_epoch=3),
    }
    supervisor = RecoverySupervisor(
        recovery_capabilities=set(),
        visible_roles=set(),
        fencing_epoch=3,
        owner_public_key=key.public_key(),
        policy_digest="policy-a",
        members=states,
        project_members=("a", "b"),
    )
    command = ProjectHoldCommand(
        command_id="hold-1",
        hold_id="hold-1",
        project_id="project-1",
        members=("a", "b"),
        reason="owner pause",
        policy_digest="policy-a",
        epoch=3,
        effective_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=1),
    )

    record = supervisor.project_hold(command, key.sign(command.signing_bytes()), now=NOW)

    assert record.members == ("a", "b")
    assert states["a"].status == states["b"].status == "Blocked"
    assert states["a"].checkpoint_id and states["b"].checkpoint_id
    assert not states["a"].dispatch_enabled and not states["b"].dispatch_enabled
    assert states["unrelated"].status == "Ready"
    assert states["unrelated"].dispatch_enabled


def test_resume_starts_only_eligible_members_with_fresh_fencing_and_attempts() -> None:
    key = Ed25519PrivateKey.generate()
    states = {
        "eligible": MemberState("eligible", "Ready", fencing_epoch=4),
        "blocked": MemberState("blocked", "Ready", fencing_epoch=4, independently_blocked=True),
        "intentional": MemberState("intentional", "Ready", fencing_epoch=4, intentionally_held=True),
        "unrelated": MemberState("unrelated", "Ready", fencing_epoch=4),
    }
    supervisor = RecoverySupervisor(
        recovery_capabilities=set(),
        visible_roles=set(),
        fencing_epoch=4,
        owner_public_key=key.public_key(),
        policy_digest="policy-a",
        members=states,
        project_members=("eligible", "blocked", "intentional"),
    )
    hold = ProjectHoldCommand(
        "hold-command", "hold-2", "project", ("eligible", "blocked", "intentional"),
        "pause", "policy-a", 4, NOW - timedelta(seconds=1), NOW + timedelta(minutes=2),
    )
    supervisor.project_hold(hold, key.sign(hold.signing_bytes()), now=NOW)
    resume = ResumeProjectHoldCommand(
        "resume-command", "hold-2", "project", hold.members, "policy-a", 5,
        NOW, NOW + timedelta(minutes=1),
    )

    started = supervisor.resume_project_hold(
        resume, key.sign(resume.signing_bytes()), now=NOW
    )

    assert started == ("eligible",)
    assert states["eligible"].fencing_epoch == 5
    assert states["eligible"].attempt_id == "attempt:hold-2:eligible:5"
    assert states["eligible"].dispatch_enabled
    assert states["blocked"].status == states["intentional"].status == "Blocked"
    assert not states["blocked"].dispatch_enabled and not states["intentional"].dispatch_enabled
    assert states["unrelated"].attempt_id is None


def test_disable_recovery_reconciles_without_authorizing_external_action() -> None:
    key = Ed25519PrivateKey.generate()
    effect = InFlightEffect("effect-1", "sent")
    supervisor = RecoverySupervisor(
        recovery_capabilities={"recover"},
        visible_roles={"Watchdog", "Ledger"},
        fencing_epoch=2,
        owner_public_key=key.public_key(),
        policy_digest="policy",
        in_flight_effects=[effect],
    )
    command = DisableRecoveryCommand(
        "disable-2", "Recovery Executor", ("recover",), "policy", 2,
        NOW - timedelta(seconds=1), NOW + timedelta(minutes=1),
    )

    supervisor.disable_recovery(command, key.sign(command.signing_bytes()), now=NOW)

    assert effect.status == "reconciled-no-external-action"
    assert supervisor.external_actions == ()


def test_active_passive_failover_has_one_winner_after_authoritative_reconciliation() -> None:
    failover = RoleFailover("Secretary", leader_id="primary", epoch=9)
    receipt = failover.authoritative_reconcile()
    rendezvous = Barrier(2, timeout=2)
    outcomes: list[tuple[str, int] | tuple[str, str]] = []

    def contend(candidate: str) -> None:
        rendezvous.wait()
        try:
            takeover = failover.takeover(candidate, receipt, new_epoch=10)
            outcomes.append((takeover.leader_id, takeover.epoch))
        except SupervisorDenied as exc:
            outcomes.append((candidate, exc.code))

    threads = [Thread(target=contend, args=(candidate,)) for candidate in ("standby-a", "standby-b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)

    assert rendezvous.n_waiting == 0
    assert sum(isinstance(value, int) for _, value in outcomes) == 1
    assert failover.active_leaders == frozenset({failover.leader_id})
    assert failover.epoch == 10
    with pytest.raises(SupervisorDenied, match="STALE_LEADER_DENIED"):
        failover.authorize("primary", epoch=9)

from __future__ import annotations

import os
import secrets
import tempfile
from dataclasses import dataclass
from multiprocessing import AuthenticationError, get_context
from multiprocessing.connection import Client, Connection, Listener
from pathlib import Path
from typing import Any
from uuid import uuid4

from hermes_kanban_workflow.command.receipts import CommandReceipt
from hermes_kanban_workflow.command.registry import CommandDefinition, CommandRegistry
from hermes_kanban_workflow.command.service import GuardedCommandService, ServiceTopology
from hermes_kanban_workflow.command.validator import (
    AuthenticatedPrincipal,
    CommandValidator,
    ValidationSnapshot,
)
from hermes_kanban_workflow.domain.commands import CommandEnvelope, EffectClass
from hermes_kanban_workflow.ledger.repository import Ledger


@dataclass(frozen=True)
class FixtureIpcIdentityReceipt:
    server_pid: int
    service_account: str
    authenticated: bool
    fixture_evidence: bool
    database_path_disclosed: bool = False


@dataclass(frozen=True)
class FixtureIpcResult:
    receipt: CommandReceipt
    identity: FixtureIpcIdentityReceipt


def _registry() -> CommandRegistry:
    registry = CommandRegistry()
    registry.register(
        CommandDefinition(
            name="record_note",
            allowed_roles=frozenset({"worker"}),
            target_types=frozenset({"work_item"}),
            effect_class=EffectClass.READ_ONLY,
            requires_lease=False,
            allowed_reason_codes=frozenset({"verified"}),
        )
    )
    return registry


def _principal() -> AuthenticatedPrincipal:
    return AuthenticatedPrincipal(
        actor_id="worker-1",
        actor_role="worker",
        product_id="product-1",
        project_id="project-1",
        executable_identity="signed:fixture-client",
        target_ids=frozenset({"work-1"}),
        bindings={
            "work_item_id": "work-1",
            "run_id": None,
            "artifact_id": None,
            "environment_id": None,
            "workspace_id": None,
        },
    )


def _snapshot() -> ValidationSnapshot:
    return ValidationSnapshot(
        control_time=100,
        disabled=False,
        held_target_ids=frozenset(),
        capability_ids=frozenset({"capability-1"}),
        policy_version="sha256:policy",
        authority_epoch=2,
        lease_ids=frozenset(),
        fencing_epoch=None,
        precondition_hashes={"work-1": "sha256:precondition"},
    )


def _serve_fixture(control: Connection) -> None:
    address = rf"\\.\pipe\hermes-kanban-fixture-{uuid4()}"
    authkey = secrets.token_bytes(32)
    listener = Listener(address, family="AF_PIPE", authkey=authkey)
    control.send((address, authkey, os.getpid()))
    with tempfile.TemporaryDirectory(prefix="hermes-writer-fixture-") as private_root:
        store = Ledger(Path(private_root) / "workflow.db", writer_identity="fixture-process-only")
        service = GuardedCommandService(
            store,
            CommandValidator(_registry()),
            _snapshot,
            ServiceTopology("fixture-separate-process"),
        )
        running = True
        while running:
            try:
                connection = listener.accept()
            except AuthenticationError:
                continue
            try:
                request = connection.recv()
                operation = request.get("operation")
                if operation == "execute":
                    envelope = CommandEnvelope.model_validate_json(request["command"])
                    receipt = service.execute(envelope, _principal())
                    connection.send(
                        {
                            "receipt": receipt.canonical_bytes(),
                            "server_pid": os.getpid(),
                        }
                    )
                elif operation == "count":
                    connection.send(sum(1 for _ in store.iter_events()))
                elif operation == "shutdown":
                    connection.send(True)
                    running = False
                else:
                    connection.send({"error": "IPC_OPERATION_DENIED"})
            finally:
                connection.close()
    listener.close()
    control.close()


class FixtureServiceClient:
    """Authenticated AF_PIPE test client; explicitly not deployment evidence."""

    def __init__(self, address: str, authkey: bytes, process: Any) -> None:
        self._address = address
        self._authkey = authkey
        self._process = process

    def _request(self, payload: dict[str, object], *, authkey: bytes | None = None) -> Any:
        connection = Client(
            self._address,
            family="AF_PIPE",
            authkey=self._authkey if authkey is None else authkey,
        )
        try:
            connection.send(payload)
            return connection.recv()
        finally:
            connection.close()

    def execute(self, command: CommandEnvelope) -> FixtureIpcResult:
        response = self._request({"operation": "execute", "command": command.canonical_bytes()})
        return FixtureIpcResult(
            CommandReceipt.from_canonical_bytes(response["receipt"]),
            FixtureIpcIdentityReceipt(
                server_pid=response["server_pid"],
                service_account=r"NT SERVICE\HermesKanbanWriter",
                authenticated=True,
                fixture_evidence=True,
            ),
        )

    def execute_with_forged_key(self, command: CommandEnvelope) -> None:
        try:
            self._request(
                {"operation": "execute", "command": command.canonical_bytes()},
                authkey=b"forged-local-caller-key-00000000",
            )
        except AuthenticationError as exc:
            raise PermissionError("IPC_AUTHENTICATION_DENIED") from exc
        raise PermissionError("IPC_AUTHENTICATION_BYPASS")

    def service_event_count(self) -> int:
        return int(self._request({"operation": "count"}))

    def request_private_storage(self, _presented_path: str) -> None:
        """The client protocol intentionally has no database/path operation."""
        raise PermissionError("PRIVATE_STORAGE_REQUEST_DENIED")

    def close(self) -> None:
        if self._process.is_alive():
            self._request({"operation": "shutdown"})
            self._process.join(timeout=10)
        if self._process.is_alive():
            self._process.terminate()
            self._process.join(timeout=5)


def start_fixture_service_process() -> FixtureServiceClient:
    context = get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_serve_fixture, args=(child,), name="HermesKanbanWriterFixture")
    process.start()
    child.close()
    if not parent.poll(15):
        process.terminate()
        process.join(timeout=5)
        raise RuntimeError("FIXTURE_SERVICE_START_TIMEOUT")
    address, authkey, _pid = parent.recv()
    parent.close()
    return FixtureServiceClient(str(address), bytes(authkey), process)

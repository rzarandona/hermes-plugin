from __future__ import annotations

import os

import pytest

from hermes_kanban_workflow.command.ipc import start_fixture_service_process
from tests.ledger_fixtures import command


def test_authenticated_ipc_fixture_runs_real_separate_sole_writer_process() -> None:
    client = start_fixture_service_process()
    try:
        result = client.execute(command())

        assert result.receipt.command_digest == command().digest
        assert result.identity.server_pid != os.getpid()
        assert result.identity.service_account == r"NT SERVICE\HermesKanbanWriter"
        assert result.identity.authenticated is True
        assert result.identity.fixture_evidence is True
        assert result.identity.database_path_disclosed is False
        assert client.service_event_count() == 1
    finally:
        client.close()


def test_forged_ipc_authentication_key_is_rejected() -> None:
    client = start_fixture_service_process()
    try:
        with pytest.raises(PermissionError, match="IPC_AUTHENTICATION_DENIED"):
            client.execute_with_forged_key(command())
        assert client.service_event_count() == 0
    finally:
        client.close()

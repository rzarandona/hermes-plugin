from __future__ import annotations

from pathlib import Path

import pytest

from hermes_kanban_workflow.command.ipc import start_fixture_service_process
from hermes_kanban_workflow.command.registry import CommandDefinition, CommandRegistry
from hermes_kanban_workflow.command.service import ServiceTopology
from hermes_kanban_workflow.command.validator import (
    AuthenticatedPrincipal,
    CommandValidationError,
    CommandValidator,
    ValidationSnapshot,
)
from hermes_kanban_workflow.command.windows_profile import (
    REQUIRED_NEGATIVE_OPERATIONS,
    REQUIRED_NEGATIVE_PRINCIPALS,
    BinaryIdentityEvidence,
    IpcIdentityEvidence,
    ServiceIdentityEvidence,
    WindowsAclEvidence,
    WindowsProfileEvidence,
    WindowsProfileReceipt,
    WindowsProfileVerifier,
)
from hermes_kanban_workflow.domain.commands import EffectClass
from hermes_kanban_workflow.plugin import HOST_CONTRACT, load_package, run_preflight
from tests.ledger_fixtures import command
from tests.policy_fixtures import verified_policy

SERVICE_SID = "S-1-5-80-111-222-333-444-555"
EXPECTED_SDDL = f"O:{SERVICE_SID}D:P(A;;FA;;;SY)(A;;FA;;;{SERVICE_SID})(A;;FR;;;BA)"


def fixture_profile() -> WindowsProfileEvidence:
    return WindowsProfileEvidence(
        evidence_kind="fixture",
        evidence_label="FIXTURE EVIDENCE - NOT CLEAN-VM EVIDENCE",
        os_name="Windows 11 24H2 x64",
        os_build=26100,
        filesystem="NTFS",
        binary=BinaryIdentityEvidence(
            path=r"C:\Program Files\HermesKanban\writer.exe",
            sha256="a" * 64,
            signature_valid=True,
            publisher="Fixture Publisher",
        ),
        service=ServiceIdentityEvidence(
            name="HermesKanbanWriter",
            account=r"NT SERVICE\HermesKanbanWriter",
            sid=SERVICE_SID,
            start_mode="auto-delayed",
        ),
        acl=WindowsAclEvidence(
            owner_sid=SERVICE_SID,
            normalized_sddl=EXPECTED_SDDL,
            expected_sddl=EXPECTED_SDDL,
            write_principals=frozenset({SERVICE_SID, "S-1-5-18"}),
        ),
        dpapi_ng_descriptor=f"SID={SERVICE_SID}",
        dpapi_ng_denied_principals=REQUIRED_NEGATIVE_PRINCIPALS,
        positive_service_transaction=True,
        denied_operations={
            principal: REQUIRED_NEGATIVE_OPERATIONS for principal in REQUIRED_NEGATIVE_PRINCIPALS
        },
        ipc=IpcIdentityEvidence(
            service_sid=SERVICE_SID,
            authenticated=True,
            signed_client=True,
            forged_token_rejected=True,
            wrong_process_sid_rejected=True,
            replayed_handshake_rejected=True,
            stale_epoch_rejected=True,
        ),
        no_private_path_or_credential_exposure=True,
        receipts_signed=True,
        os_backed=False,
        uninstall_rehearsal_passed=True,
    )


def test_fixture_profile_validates_logic_but_cannot_enable_enforcement(tmp_path: Path) -> None:
    receipt = WindowsProfileVerifier().verify(fixture_profile())

    assert receipt.logic_passed is True
    assert receipt.enforcement_eligible is False
    assert receipt.code == "FIXTURE_EVIDENCE_NOT_ENFORCEMENT_ELIGIBLE"
    package = load_package({"manifest_version": 2, "api_version": 1})
    denied = run_preflight(
        package,
        verified_policy(tmp_path),
        HOST_CONTRACT,
        windows_profile=receipt,
    )
    assert denied.passed is False
    assert denied.code == "EXTERNAL_WINDOWS_PROFILE_EVIDENCE_REQUIRED"


def test_forged_external_evidence_boole_cannot_create_eligible_receipt() -> None:
    forged = fixture_profile().model_copy(
        update={
            "evidence_kind": "external-clean-vm",
            "evidence_label": "forged-local-object",
            "os_backed": True,
            "receipts_signed": True,
        }
    )

    receipt = WindowsProfileVerifier().verify(forged)

    assert receipt.logic_passed is True
    assert receipt.enforcement_eligible is False
    assert receipt.code == "EXTERNAL_ATTESTATION_VERIFIER_REQUIRED"


def test_caller_constructed_profile_receipt_cannot_pass_host_preflight(tmp_path: Path) -> None:
    forged_receipt = WindowsProfileReceipt(
        logic_passed=True,
        enforcement_eligible=True,
        attestation_verified=True,
        code="PASS",
        failures=(),
        evidence_digest="a" * 64,
        evidence_kind="external-clean-vm",
    )
    package = load_package({"manifest_version": 2, "api_version": 1})

    denied = run_preflight(
        package,
        verified_policy(tmp_path),
        HOST_CONTRACT,
        windows_profile=forged_receipt,
    )

    assert denied.passed is False
    assert denied.code == "AUTHENTICATED_SERVICE_READINESS_REQUIRED"


def test_combined_process_and_direct_import_topology_never_claim_enforcement() -> None:
    topology = ServiceTopology("combined-observe-only")

    assert topology.enforcement_ready is False


def test_unsigned_injected_plugin_principal_is_denied_atomically() -> None:
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
    hostile = AuthenticatedPrincipal(
        actor_id="worker-1",
        actor_role="worker",
        product_id="product-1",
        project_id="project-1",
        executable_identity="unsigned:hostile-plugin-module",
        target_ids=frozenset({"work-1"}),
        bindings={
            "work_item_id": "work-1",
            "run_id": None,
            "artifact_id": None,
            "environment_id": None,
            "workspace_id": None,
        },
    )
    current = ValidationSnapshot(
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

    with pytest.raises(CommandValidationError) as caught:
        CommandValidator(registry).validate(command(), hostile, current)

    assert caught.value.failures == ("CLIENT_EXECUTABLE_UNTRUSTED",)


def test_copied_or_symlink_database_path_requests_are_not_ipc_operations() -> None:
    client = start_fixture_service_process()
    try:
        with pytest.raises(PermissionError, match="PRIVATE_STORAGE_REQUEST_DENIED"):
            client.request_private_storage(r"C:\copied\workflow.db")
        assert client.service_event_count() == 0
    finally:
        client.close()

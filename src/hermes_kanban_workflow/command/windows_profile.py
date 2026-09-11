from __future__ import annotations

import json
from collections.abc import Callable
from hashlib import sha256
from typing import Literal

from pydantic import Field

from hermes_kanban_workflow.domain.identity import FrozenModel

SERVICE_NAME = "HermesKanbanWriter"
SERVICE_ACCOUNT = r"NT SERVICE\HermesKanbanWriter"
SYSTEM_SID = "S-1-5-18"
REQUIRED_NEGATIVE_PRINCIPALS = frozenset(
    {"HermesDesktop", "Watchdog", "RecoveryExecutor", "Worker", "UnprivilegedLocal"}
)
REQUIRED_NEGATIVE_OPERATIONS = frozenset(
    {
        "open",
        "create",
        "rename",
        "replace",
        "hard-link",
        "symlink",
        "copy",
        "wal",
        "shm",
        "dpapi-ng-unprotect",
    }
)


class BinaryIdentityEvidence(FrozenModel):
    path: str = Field(min_length=1)
    sha256: str = Field(min_length=64, max_length=64)
    signature_valid: bool
    publisher: str = Field(min_length=1)


class ServiceIdentityEvidence(FrozenModel):
    name: str
    account: str
    sid: str = Field(min_length=1)
    start_mode: str


class WindowsAclEvidence(FrozenModel):
    owner_sid: str
    normalized_sddl: str
    expected_sddl: str
    write_principals: frozenset[str]


class IpcIdentityEvidence(FrozenModel):
    service_sid: str
    authenticated: bool
    signed_client: bool
    forged_token_rejected: bool
    wrong_process_sid_rejected: bool
    replayed_handshake_rejected: bool
    stale_epoch_rejected: bool


class WindowsProfileEvidence(FrozenModel):
    evidence_kind: Literal["fixture", "external-clean-vm"]
    evidence_label: str
    os_name: str
    os_build: int
    filesystem: str
    binary: BinaryIdentityEvidence
    service: ServiceIdentityEvidence
    acl: WindowsAclEvidence
    dpapi_ng_descriptor: str
    dpapi_ng_denied_principals: frozenset[str]
    positive_service_transaction: bool
    denied_operations: dict[str, frozenset[str]]
    ipc: IpcIdentityEvidence
    no_private_path_or_credential_exposure: bool
    receipts_signed: bool
    os_backed: bool
    uninstall_rehearsal_passed: bool


class WindowsProfileReceipt(FrozenModel):
    logic_passed: bool
    enforcement_eligible: bool
    attestation_verified: bool
    code: str
    failures: tuple[str, ...]
    evidence_digest: str
    evidence_kind: Literal["fixture", "external-clean-vm"]


class WindowsProfileVerifier:
    """Pure verifier for externally collected evidence; never applies machine state."""

    def __init__(
        self,
        external_attestation_verifier: Callable[[WindowsProfileEvidence], bool] | None = None,
    ) -> None:
        self._external_attestation_verifier = external_attestation_verifier

    def verify(self, evidence: WindowsProfileEvidence) -> WindowsProfileReceipt:
        failures: list[str] = []
        service_sid = evidence.service.sid
        exact_profile = (
            evidence.os_name == "Windows 11 24H2 x64"
            and evidence.os_build == 26100
            and evidence.filesystem == "NTFS"
        )
        if not exact_profile:
            failures.append("WINDOWS_PROFILE_UNSUPPORTED")
        if not evidence.binary.signature_valid or len(evidence.binary.sha256) != 64:
            failures.append("SIGNED_BINARY_IDENTITY_INVALID")
        if (
            evidence.service.name != SERVICE_NAME
            or evidence.service.account != SERVICE_ACCOUNT
            or evidence.service.start_mode != "auto-delayed"
        ):
            failures.append("SERVICE_IDENTITY_INVALID")
        if evidence.acl.owner_sid != service_sid:
            failures.append("ACL_OWNER_INVALID")
        if evidence.acl.normalized_sddl != evidence.acl.expected_sddl:
            failures.append("NORMALIZED_SDDL_MISMATCH")
        if evidence.acl.write_principals != frozenset({service_sid, SYSTEM_SID}):
            failures.append("WRITE_PRINCIPALS_INVALID")
        if evidence.dpapi_ng_descriptor != f"SID={service_sid}":
            failures.append("DPAPI_NG_DESCRIPTOR_INVALID")
        if evidence.dpapi_ng_denied_principals != REQUIRED_NEGATIVE_PRINCIPALS:
            failures.append("DPAPI_NG_DENIAL_EVIDENCE_INCOMPLETE")
        if not evidence.positive_service_transaction:
            failures.append("POSITIVE_SERVICE_TRANSACTION_MISSING")
        for principal in REQUIRED_NEGATIVE_PRINCIPALS:
            if evidence.denied_operations.get(principal) != REQUIRED_NEGATIVE_OPERATIONS:
                failures.append(f"NEGATIVE_PRINCIPAL_OPERATIONS_INCOMPLETE:{principal}")
        ipc_checks = (
            evidence.ipc.service_sid == service_sid,
            evidence.ipc.authenticated,
            evidence.ipc.signed_client,
            evidence.ipc.forged_token_rejected,
            evidence.ipc.wrong_process_sid_rejected,
            evidence.ipc.replayed_handshake_rejected,
            evidence.ipc.stale_epoch_rejected,
        )
        if not all(ipc_checks):
            failures.append("IPC_IDENTITY_RECEIPT_INVALID")
        if not evidence.no_private_path_or_credential_exposure:
            failures.append("PRIVATE_MATERIAL_EXPOSURE")
        if not evidence.uninstall_rehearsal_passed:
            failures.append("UNINSTALL_REHEARSAL_MISSING")
        if evidence.evidence_kind == "fixture" and not evidence.evidence_label.startswith(
            "FIXTURE EVIDENCE"
        ):
            failures.append("FIXTURE_EVIDENCE_LABEL_MISSING")

        payload = evidence.model_dump(mode="json")
        digest = sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        logic_passed = not failures
        attestation_verified = False
        if (
            logic_passed
            and evidence.evidence_kind == "external-clean-vm"
            and self._external_attestation_verifier is not None
        ):
            attestation_verified = bool(self._external_attestation_verifier(evidence))
        eligible = (
            logic_passed
            and evidence.evidence_kind == "external-clean-vm"
            and evidence.os_backed
            and evidence.receipts_signed
            and attestation_verified
        )
        if failures:
            code = "WINDOWS_PROFILE_VERIFICATION_DENIED"
        elif evidence.evidence_kind == "fixture":
            code = "FIXTURE_EVIDENCE_NOT_ENFORCEMENT_ELIGIBLE"
        elif not attestation_verified:
            code = "EXTERNAL_ATTESTATION_VERIFIER_REQUIRED"
        else:
            code = "PASS"
        return WindowsProfileReceipt(
            logic_passed=logic_passed,
            enforcement_eligible=eligible,
            attestation_verified=attestation_verified,
            code=code,
            failures=tuple(failures),
            evidence_digest=digest,
            evidence_kind=evidence.evidence_kind,
        )

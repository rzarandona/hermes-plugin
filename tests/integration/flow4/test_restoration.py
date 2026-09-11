from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.flows.flow4 import (
    BackupAuthority,
    RestorationDrillAuthority,
    evaluate_restoration,
)


def test_backup_job_success_alone_never_proves_recoverability() -> None:
    backups = BackupAuthority(private_key=Ed25519PrivateKey.generate())
    backup = backups.issue(
        backup_id="backup-1",
        service_id="svc",
        encrypted=True,
        provenance_ref="artifact:release-9",
        sensitivity_tier="restricted",
        access_review_ref="review:backup-access",
        job_succeeded=True,
    )

    with pytest.raises(PermissionError, match="INDEPENDENT_RESTORATION_DRILL_REQUIRED"):
        evaluate_restoration(backup, backup_authority=backups, drill=None)


def test_independent_drill_proves_rto_rpo_integrity_key_access_and_usability() -> None:
    backups = BackupAuthority(private_key=Ed25519PrivateKey.generate())
    drills = RestorationDrillAuthority(
        private_key=Ed25519PrivateKey.generate(), backup_actor="backup-operator"
    )
    backup = backups.issue(
        backup_id="backup-2",
        service_id="svc",
        encrypted=True,
        provenance_ref="artifact:release-9",
        sensitivity_tier="restricted",
        access_review_ref="review:backup-access",
        job_succeeded=True,
    )
    drill = drills.issue(
        drill_id="drill-1",
        backup_id="backup-2",
        verifier_subject_id="recovery-auditor",
        rto_met=True,
        rpo_met=True,
        integrity_verified=True,
        key_access_verified=True,
        service_usable=True,
        evidence_ref="evidence:restoration-drill",
    )

    result = evaluate_restoration(
        backup, backup_authority=backups, drill=drill, drill_authority=drills
    )

    assert result.recoverable


def test_forged_drill_receipt_is_denied() -> None:
    backups = BackupAuthority(private_key=Ed25519PrivateKey.generate())
    drills = RestorationDrillAuthority(
        private_key=Ed25519PrivateKey.generate(), backup_actor="backup-operator"
    )
    backup = backups.issue(
        backup_id="backup-3",
        service_id="svc",
        encrypted=True,
        provenance_ref="artifact:release-9",
        sensitivity_tier="restricted",
        access_review_ref="review:backup-access",
        job_succeeded=True,
    )
    drill = drills.issue(
        drill_id="drill-3",
        backup_id="backup-3",
        verifier_subject_id="recovery-auditor",
        rto_met=True,
        rpo_met=True,
        integrity_verified=True,
        key_access_verified=True,
        service_usable=True,
        evidence_ref="evidence:restoration-drill",
    )

    with pytest.raises(PermissionError, match="INDEPENDENT_RESTORATION_DRILL_REQUIRED"):
        evaluate_restoration(
            backup,
            backup_authority=backups,
            drill=replace(drill, signature=b"forged"),
            drill_authority=drills,
        )

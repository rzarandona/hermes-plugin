from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.activation import (
    ActivationTrustRegistry,
    TrustEntry,
    sign_activation_record,
)
from hermes_kanban_workflow.release_gate import verify_audit_intake

NOW = datetime(2026, 8, 29, tzinfo=UTC)


def test_caller_created_audit_json_cannot_manufacture_release_readiness() -> None:
    result = verify_audit_intake(
        verdict={
            "reviewer_id": "independent-reviewer",
            "authenticated": True,
            "eligible": True,
            "independent": True,
            "scope_digest": "scope",
            "evidence_digest": "evidence",
            "verdict": "PASS",
            "open_p0": 0,
            "open_p1": 0,
            "p2_disposition": "accepted",
            "expires_at": (NOW + timedelta(days=1)).isoformat(),
        },
        gatekeeper_ack={"acknowledged": True},
        trust=ActivationTrustRegistry({}, minimum_epoch=1),
        expected_scope_digest="scope",
        expected_evidence_digest="evidence",
        now=NOW,
    )

    assert not result.ready
    assert result.code == "AUTHENTICATED_EXTERNAL_AUDIT_AUTHORITY_REQUIRED"


def test_caller_supplied_audit_trust_cannot_mint_release_readiness() -> None:
    auditor = Ed25519PrivateKey.generate()
    gatekeeper = Ed25519PrivateKey.generate()
    trust = ActivationTrustRegistry(
        {
            "auditor": TrustEntry.from_private_key(auditor, {"Independent Auditor"}, 3),
            "gatekeeper": TrustEntry.from_private_key(gatekeeper, {"Gatekeeper"}, 3),
        },
        minimum_epoch=3,
    )
    verdict = sign_activation_record(
        {
            "kind": "independent-audit-verdict",
            "eligible": True,
            "independent": True,
            "scope_digest": "scope",
            "evidence_digest": "evidence",
            "verdict": "PASS",
            "open_p0": 0,
            "open_p1": 0,
            "p2_disposition": "none-open",
            "expires_at": (NOW + timedelta(days=1)).isoformat(),
        },
        "auditor",
        auditor,
    )
    ack = sign_activation_record(
        {
            "kind": "gatekeeper-acknowledgement",
            "acknowledged": True,
            "scope_digest": "scope",
            "evidence_digest": "evidence",
            "verdict_digest": verdict.digest,
        },
        "gatekeeper",
        gatekeeper,
    )

    result = verify_audit_intake(
        verdict=verdict,
        gatekeeper_ack=ack,
        trust=trust,
        expected_scope_digest="scope",
        expected_evidence_digest="evidence",
        now=NOW,
    )

    assert not result.ready
    assert result.code == "AUTHENTICATED_EXTERNAL_AUDIT_AUTHORITY_REQUIRED"


def test_release_artifacts_preserve_owner_assignments_and_fourteen_honest_rows() -> None:
    expected_owners = {
        "docs/operator-guide.md": "Operations",
        "docs/role-guide.md": "Product Governance",
        "docs/recovery-rollback-runbook.md": "Recovery and Release",
        "docs/known-limitations.md": "PM and Security",
    }
    for name, owner in expected_owners.items():
        text = Path(name).read_text(encoding="utf-8")
        assert f"Owner: {owner}" in text

    locators = json.loads(Path("release/evidence-locators.json").read_text(encoding="utf-8"))
    assert len(locators["completion_matrix"]) == 14
    assert all(row["status"] in {"PASS", "BLOCKED", "UNSUPPORTED"} for row in locators["completion_matrix"])
    assert locators["completion_matrix"][2]["status"] == "BLOCKED"
    assert locators["completion_matrix"][10]["status"] == "BLOCKED"
    assert locators["completion_matrix"][13]["status"] == "BLOCKED"

    audit = json.loads(Path("release/audit-verdict.json").read_text(encoding="utf-8"))
    assert audit["status"] in {"UNEXECUTED", "BLOCKED"}
    assert audit["release_ready"] is False


def test_release_builder_rejects_unapproved_output_before_writing(tmp_path: Path) -> None:
    target = tmp_path / "outside.zip"
    completed = __import__("subprocess").run(
        [__import__("sys").executable, "tools/build_release.py", "--output", str(target)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 2
    assert "OUTPUT_MUST_BE_REPO_DIST_OR_EXPLICIT_TEMP_VERIFICATION_ROOT" in completed.stderr
    assert not target.exists()


def test_release_inventory_enumerates_all_required_classes_and_checksums_reproduce() -> None:
    inventory = json.loads(Path("release/package-inventory.json").read_text(encoding="utf-8"))
    entries = inventory["entries"]
    assert inventory["owner"] == "Build"
    checksum_lines = Path("release/checksums.txt").read_text(encoding="utf-8").splitlines()
    assert checksum_lines[0] == "# owner: Build"
    categories = {entry["category"] for entry in entries}
    assert {
        "wheel",
        "plugin-bundle",
        "manifest",
        "policy",
        "signature",
        "skill",
        "document",
        "schema",
        "migration",
        "test-evidence-index",
    } <= categories
    assert inventory["installation_authorized"] is False
    assert inventory["activation_authorized"] is False

    checksum_rows = {
        line.split("  ", 1)[1]: line.split("  ", 1)[0]
        for line in checksum_lines
        if line and not line.startswith("#")
    }
    expected_paths = {entry["path"] for entry in entries} | {"release/package-inventory.json"}
    assert set(checksum_rows) == expected_paths
    assert checksum_rows["release/package-inventory.json"] == sha256(
        Path("release/package-inventory.json").read_bytes()
    ).hexdigest()
    for entry in entries:
        path = Path(entry["path"])
        assert checksum_rows[entry["path"]] == sha256(path.read_bytes()).hexdigest()

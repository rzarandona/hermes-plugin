from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.activation import (
    STAGE_CONTRACTS,
    ActivationChain,
    ActivationTrustRegistry,
    SignedActivationRecord,
    TrustEntry,
    sign_activation_record,
)

NOW = datetime(2026, 8, 29, tzinfo=UTC)
IDENTITY = {"package_digest": "pkg-sha256", "policy_digest": "policy-sha256", "host_digest": "host-sha256", "plugin_version": "0.1.0"}


def _keys() -> dict[str, Ed25519PrivateKey]:
    names = {"evidence", "owner"}
    names.update(role for contract in STAGE_CONTRACTS for role in contract.reviewer_roles)
    return {name: Ed25519PrivateKey.generate() for name in names}


def _registry(keys: dict[str, Ed25519PrivateKey]) -> ActivationTrustRegistry:
    entries = {
        "evidence": TrustEntry.from_private_key(keys["evidence"], {"Evidence Custodian"}, 2),
        "owner": TrustEntry.from_private_key(keys["owner"], {"Owner"}, 2),
    }
    entries.update({role: TrustEntry.from_private_key(keys[role], {role}, 2) for role in keys if role not in {"evidence", "owner"}})
    return ActivationTrustRegistry(entries, minimum_epoch=2)


def _stage_records(keys: dict[str, Ed25519PrivateKey], stage: int, predecessor: str | None, prefix: str, *, exact_evidence: bool = True) -> dict[str, object]:
    contract = STAGE_CONTRACTS[stage - 1]
    common = {**IDENTITY, "stage": stage, "predecessor_digest": predecessor, "expires_at": (NOW + timedelta(hours=1)).isoformat()}
    reviews: dict[str, SignedActivationRecord] = {}
    for role in contract.reviewer_roles:
        reviews[role] = sign_activation_record({**common, "kind": "review", "nonce": f"{prefix}-review-{role}", "verdict": "PASS", "reviewer_role": role, "contract_digest": contract.digest}, role, keys[role])
    entry_payload: dict[str, object] = {**common, "kind": "entry", "nonce": f"{prefix}-entry", "status": "PASS"}
    pass_payload: dict[str, object] = {**common, "kind": "pass", "nonce": f"{prefix}-pass", "status": "PASS"}
    if exact_evidence:
        entry_payload["evidence"] = contract.evidence("entry")
        pass_payload["evidence"] = contract.evidence("pass")
    return {
        "entry": sign_activation_record(entry_payload, "evidence", keys["evidence"]),
        "passed": sign_activation_record(pass_payload, "evidence", keys["evidence"]),
        "review": reviews,
        "owner": sign_activation_record({**common, "kind": "owner-decision", "nonce": f"{prefix}-owner", "decision": f"ACTIVATE_STAGE_{stage}", "contract_digest": contract.digest}, "owner", keys["owner"]),
    }


def test_stage_one_rejects_generic_pass_without_exact_gate_contract_evidence() -> None:
    keys = _keys()
    chain = ActivationChain(**IDENTITY, trust=_registry(keys))
    with pytest.raises(PermissionError, match="ACTIVATION_GATE_EVIDENCE_SCHEMA_DENIED"):
        chain.advance(**_stage_records(keys, 1, None, "generic", exact_evidence=False), now=NOW)
    assert chain.current_stage == 0
    assert chain.denials[-1].code == "ACTIVATION_GATE_EVIDENCE_SCHEMA_DENIED"


def test_all_ten_stages_validate_distinct_required_reviewers_and_exact_contracts() -> None:
    keys = _keys()
    chain = ActivationChain(**IDENTITY, trust=_registry(keys))
    predecessor = None
    for stage in range(1, 11):
        receipt = chain.advance(**_stage_records(keys, stage, predecessor, f"s{stage}"), now=NOW)
        assert receipt.predecessor_digest == predecessor
        predecessor = receipt.receipt_digest
    assert chain.current_stage == 10
    assert chain.agent_stage == 10
    assert chain.desktop_stage == 10


def test_missing_named_reviewer_and_owner_reuse_are_denied() -> None:
    keys = _keys()
    records = _stage_records(keys, 1, None, "missing")
    reviews = dict(records["review"])  # type: ignore[arg-type]
    reviews.pop(next(iter(reviews)))
    records["review"] = reviews
    chain = ActivationChain(**IDENTITY, trust=_registry(keys))
    with pytest.raises(PermissionError, match="ACTIVATION_ALL_REVIEWER_ROLES_REQUIRED"):
        chain.advance(**records, now=NOW)
    assert chain.current_stage == 0


def test_forged_caller_records_deny_before_transition_and_append_audit() -> None:
    keys = _keys()
    chain = ActivationChain(**IDENTITY, trust=_registry(keys))
    with pytest.raises(PermissionError, match="ACTIVATION_AUTHENTICATED_EVIDENCE_REQUIRED"):
        chain.advance(entry={}, passed={}, review={}, owner={}, now=NOW)
    assert chain.current_stage == 0
    assert chain.denials[-1].code == "ACTIVATION_AUTHENTICATED_EVIDENCE_REQUIRED"


def test_exact_identity_predecessor_expiry_and_nonce_are_enforced() -> None:
    keys = _keys()
    mutations = [("package_digest", "other"), ("predecessor_digest", "forged"), ("expires_at", (NOW - timedelta(seconds=1)).isoformat())]
    for field, value in mutations:
        records = _stage_records(keys, 1, None, f"bad-{field}")
        entry = records["entry"]
        assert isinstance(entry, SignedActivationRecord)
        records["entry"] = sign_activation_record({**entry.payload, field: value}, "evidence", keys["evidence"])
        chain = ActivationChain(**IDENTITY, trust=_registry(keys))
        with pytest.raises(PermissionError, match="ACTIVATION_STAGE_SKIP_DENIED"):
            chain.advance(**records, now=NOW)
        assert chain.current_stage == 0


def test_reopen_persists_receipts_nonces_rollback_reentry_and_denials(tmp_path: Path) -> None:
    keys = _keys()
    database = tmp_path / "activation.db"
    chain = ActivationChain(**IDENTITY, trust=_registry(keys), database=database)
    first = chain.advance(**_stage_records(keys, 1, None, "persist-1"), now=NOW)
    second = chain.advance(**_stage_records(keys, 2, first.receipt_digest, "persist-2"), now=NOW)
    chain.rollback(1)
    with pytest.raises(PermissionError, match="ACTIVATION_STAGE_SKIP_DENIED"):
        chain.advance(**_stage_records(keys, 3, first.receipt_digest, "skip"), now=NOW)

    reopened = ActivationChain(**IDENTITY, trust=_registry(keys), database=database)
    assert reopened.current_stage == 1
    assert len(reopened.history) == 2
    assert reopened.denials[-1].code == "ACTIVATION_STAGE_SKIP_DENIED"
    with pytest.raises(PermissionError, match="ACTIVATION_STAGE_SKIP_DENIED"):
        reopened.advance(**_stage_records(keys, 2, first.receipt_digest, "persist-2"), now=NOW)
    reentered = reopened.advance(**_stage_records(keys, 2, first.receipt_digest, "fresh-2"), now=NOW)
    assert reentered.stage == second.stage


def test_revoked_evidence_and_trust_epoch_rollback_deny() -> None:
    keys = _keys()
    registry = _registry(keys)
    registry.revoke("evidence")
    chain = ActivationChain(**IDENTITY, trust=registry)
    with pytest.raises(PermissionError, match="ACTIVATION_TRUST_REVOKED"):
        chain.advance(**_stage_records(keys, 1, None, "revoked"), now=NOW)
    with pytest.raises(PermissionError, match="ACTIVATION_TRUST_ROLLBACK_DENIED"):
        registry.rotate("evidence", TrustEntry.from_private_key(keys["evidence"], {"Evidence Custodian"}, 2))

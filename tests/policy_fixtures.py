from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.policy.loader import load_verified_policy
from hermes_kanban_workflow.policy.model import VerifiedPolicy
from hermes_kanban_workflow.policy.verifier import TrustRoot


def verified_policy(
    tmp_path: Path,
    *,
    policy_version: str = "1",
    now: datetime | None = None,
    rules: dict[str, Any] | None = None,
) -> VerifiedPolicy:
    checked_at = now or datetime.now(UTC)
    private_key = Ed25519PrivateKey.generate()
    document = {
        "schema_version": 1,
        "policy_id": "policy-1",
        "scope": "test",
        "issued_at": (checked_at - timedelta(minutes=1)).isoformat(),
        "expires_at": (checked_at + timedelta(minutes=5)).isoformat(),
        "trust_epoch": 1,
        "compatibility": {
            "host_version": "0.20.5",
            "plugin_version": "0.1.0",
            "executor_version": "1.0.0",
            "policy_version": policy_version,
        },
        "authority": {"effect_classes": ["read_only"]},
        "rules": rules if rules is not None else {"enforcement": "disabled"},
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    path = tmp_path / f"policy-{policy_version}.json"
    path.write_bytes(payload)
    root = TrustRoot.from_public_key("fixture-root", 1, private_key.public_key())
    return load_verified_policy(path, private_key.sign(payload), root, now=checked_at)

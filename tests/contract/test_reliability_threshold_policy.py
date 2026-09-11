from __future__ import annotations

import base64
import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.evaluation.metrics import (
    ReliabilityPolicyDenied,
    ReliabilityPolicyEvaluator,
    canonical_policy_bytes,
)

NOW = datetime(2026, 8, 29, 12, tzinfo=UTC)
SCENARIOS = (
    "idle", "normal load", "burst load", "sustained queue", "cross-product contention",
    "lease churn", "crash/replay", "partial effects", "failover", "artifact growth",
    "degraded dependencies",
)


def _signed_policy(**changes: Any) -> tuple[dict[str, Any], Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    document: dict[str, Any] = {
        "schema_version": 1,
        "policy_id": "reliability-test",
        "policy_version": 3,
        "issued_at": (NOW - timedelta(minutes=2)).isoformat(),
        "effective_at": (NOW - timedelta(minutes=1)).isoformat(),
        "expires_at": (NOW + timedelta(hours=1)).isoformat(),
        "signer_key_id": "fixture-key",
        "supported_host": "windows-11-x64",
        "workload_profile": "kanban-fixture-v1",
        "concurrency": 4,
        "queue_depth": 32,
        "resource_class": "fixture-small",
        "warm_cold_state": "warm",
        "measurement_window_seconds": 300,
        "percentile": 99.0,
        "maximum_error_rate": 0.01,
        "retention_window_days": 90,
        "evaluator_compatibility_version": "1.0.0",
        "aggregation": "fixed-window-p99",
        "scenario_fixtures": [
            {
                "name": name,
                "seed": index + 100,
                "clock": NOW.isoformat(),
                "workload": f"fixture:{index}",
                "aggregation": "fixed-window-p99",
                "retention_days": 90,
                "raw_evidence": f"fixture-evidence:{index}",
                "proof_scope": "repository-fixture-only",
            }
            for index, name in enumerate(SCENARIOS)
        ],
    }
    document.update(changes)
    document["signature"] = base64.b64encode(key.sign(canonical_policy_bytes(document))).decode()
    return document, key


def _verify(document: dict[str, Any], key: Ed25519PrivateKey) -> object:
    return ReliabilityPolicyEvaluator().verify(
        document,
        key.public_key(),
        now=NOW,
        expected_host="windows-11-x64",
        expected_workload="kanban-fixture-v1",
        evaluator_version="1.0.0",
        minimum_policy_version=2,
    )


def test_schema_requires_every_planned_reliability_field() -> None:
    schema = json.loads(Path("policies/reliability-threshold.schema.json").read_text())

    assert set(schema["required"]) >= {
        "workload_profile", "supported_host", "concurrency", "queue_depth", "resource_class",
        "warm_cold_state", "measurement_window_seconds", "percentile", "maximum_error_rate",
        "retention_window_days", "policy_version", "signature", "effective_at", "expires_at",
        "evaluator_compatibility_version", "scenario_fixtures",
    }


def test_canonical_signature_and_frozen_scenarios_are_verified() -> None:
    document, key = _signed_policy()

    policy = _verify(document, key)

    assert policy.policy_version == 3
    assert tuple(item.name for item in policy.scenarios) == SCENARIOS
    assert all(item.proof_scope == "repository-fixture-only" for item in policy.scenarios)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (lambda document: document.pop("signature"), "RELIABILITY_POLICY_UNSIGNED"),
        (lambda document: document.update(expires_at=(NOW - timedelta(seconds=1)).isoformat()), "RELIABILITY_POLICY_EXPIRED"),
        (lambda document: document.update(effective_at=(NOW + timedelta(seconds=1)).isoformat()), "RELIABILITY_POLICY_FUTURE"),
        (lambda document: document.update(maximum_error_rate=0.9), "RELIABILITY_POLICY_SIGNATURE_INVALID"),
        (lambda document: document.update(policy_version=1), "RELIABILITY_POLICY_ROLLBACK"),
        (lambda document: document.update(supported_host="other"), "RELIABILITY_POLICY_HOST_MISMATCH"),
        (lambda document: document.update(workload_profile="other"), "RELIABILITY_POLICY_WORKLOAD_MISMATCH"),
        (lambda document: document.update(evaluator_compatibility_version="2.0.0"), "RELIABILITY_POLICY_EVALUATOR_INCOMPATIBLE"),
    ],
)
def test_invalid_reliability_policies_fail_closed(mutation: Any, code: str) -> None:
    document, key = _signed_policy()
    mutation(document)
    if "signature" in document and code != "RELIABILITY_POLICY_SIGNATURE_INVALID":
        document["signature"] = base64.b64encode(key.sign(canonical_policy_bytes(document))).decode()

    with pytest.raises(ReliabilityPolicyDenied, match=code):
        _verify(document, key)


def test_caller_provided_trust_booleans_are_rejected() -> None:
    document, key = _signed_policy()

    with pytest.raises(TypeError):
        ReliabilityPolicyEvaluator().verify(
            document, key.public_key(), now=NOW, expected_host="windows-11-x64",
            expected_workload="kanban-fixture-v1", evaluator_version="1.0.0",
            minimum_policy_version=2, signature_valid=True, reconciled=True, owner_approved=True,
        )


def test_altered_scenario_raw_evidence_is_detected() -> None:
    document, key = _signed_policy()
    altered = copy.deepcopy(document)
    altered["scenario_fixtures"][0]["raw_evidence"] = "discarded"

    with pytest.raises(ReliabilityPolicyDenied, match="RELIABILITY_POLICY_SIGNATURE_INVALID"):
        _verify(altered, key)


def test_signed_policy_missing_required_scenario_is_denied() -> None:
    document, key = _signed_policy()
    document["scenario_fixtures"] = document["scenario_fixtures"][:-1]
    document["signature"] = base64.b64encode(key.sign(canonical_policy_bytes(document))).decode()

    with pytest.raises(ReliabilityPolicyDenied, match="RELIABILITY_SCENARIOS_INCOMPLETE"):
        _verify(document, key)


def test_signed_policy_with_discarded_raw_scenario_evidence_is_denied() -> None:
    document, key = _signed_policy()
    document["scenario_fixtures"][0]["raw_evidence"] = ""
    document["signature"] = base64.b64encode(key.sign(canonical_policy_bytes(document))).decode()

    with pytest.raises(ReliabilityPolicyDenied, match="RELIABILITY_RAW_EVIDENCE_REQUIRED"):
        _verify(document, key)


def test_signed_scenario_aggregation_must_match_policy() -> None:
    document, key = _signed_policy()
    document["scenario_fixtures"][0]["aggregation"] = "different-window"
    document["signature"] = base64.b64encode(key.sign(canonical_policy_bytes(document))).decode()

    with pytest.raises(ReliabilityPolicyDenied, match="RELIABILITY_SCENARIO_BINDING_INVALID"):
        _verify(document, key)


def test_signed_scenario_retention_must_match_policy() -> None:
    document, key = _signed_policy()
    document["scenario_fixtures"][0]["retention_days"] = 1
    document["signature"] = base64.b64encode(key.sign(canonical_policy_bytes(document))).decode()

    with pytest.raises(ReliabilityPolicyDenied, match="RELIABILITY_SCENARIO_BINDING_INVALID"):
        _verify(document, key)

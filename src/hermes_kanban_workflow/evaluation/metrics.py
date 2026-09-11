from __future__ import annotations

import base64
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import date, datetime
from math import sqrt
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ALL_DIMENSIONS = (
    "scope adherence",
    "correctness",
    "evidence quality",
    "normalized timeliness",
    "handoff completeness",
    "compliance",
    "rework",
    "recurrence",
    "escaped defects",
    "role-specific outcomes",
)


class EvaluationDenied(ValueError):
    pass


class ReliabilityPolicyDenied(ValueError):
    pass


@dataclass(frozen=True)
class ReliabilityScenario:
    name: str
    seed: int
    clock: str
    workload: str
    aggregation: str
    retention_days: int
    raw_evidence: str
    proof_scope: str


@dataclass(frozen=True)
class VerifiedReliabilityPolicy:
    policy_id: str
    policy_version: int
    supported_host: str
    workload_profile: str
    scenarios: tuple[ReliabilityScenario, ...]
    production_proof: bool = False


def canonical_policy_bytes(document: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()


class ReliabilityPolicyEvaluator:
    _SCENARIOS = (
        "idle",
        "normal load",
        "burst load",
        "sustained queue",
        "cross-product contention",
        "lease churn",
        "crash/replay",
        "partial effects",
        "failover",
        "artifact growth",
        "degraded dependencies",
    )
    _REQUIRED = frozenset(
        {
            "schema_version",
            "policy_id",
            "policy_version",
            "issued_at",
            "effective_at",
            "expires_at",
            "signer_key_id",
            "supported_host",
            "workload_profile",
            "concurrency",
            "queue_depth",
            "resource_class",
            "warm_cold_state",
            "measurement_window_seconds",
            "percentile",
            "maximum_error_rate",
            "retention_window_days",
            "evaluator_compatibility_version",
            "aggregation",
            "scenario_fixtures",
            "signature",
        }
    )

    def verify(
        self,
        document: dict[str, Any],
        public_key: Ed25519PublicKey,
        *,
        now: datetime,
        expected_host: str,
        expected_workload: str,
        evaluator_version: str,
        minimum_policy_version: int,
    ) -> VerifiedReliabilityPolicy:
        if "signature" not in document:
            raise ReliabilityPolicyDenied("RELIABILITY_POLICY_UNSIGNED")
        if not self._REQUIRED.issubset(document):
            raise ReliabilityPolicyDenied("RELIABILITY_POLICY_INCOMPLETE")
        try:
            signature = base64.b64decode(document["signature"], validate=True)
            public_key.verify(signature, canonical_policy_bytes(document))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise ReliabilityPolicyDenied("RELIABILITY_POLICY_SIGNATURE_INVALID") from exc

        effective_at = datetime.fromisoformat(str(document["effective_at"]))
        expires_at = datetime.fromisoformat(str(document["expires_at"]))
        if now < effective_at:
            raise ReliabilityPolicyDenied("RELIABILITY_POLICY_FUTURE")
        if now >= expires_at:
            raise ReliabilityPolicyDenied("RELIABILITY_POLICY_EXPIRED")
        if int(document["policy_version"]) < minimum_policy_version:
            raise ReliabilityPolicyDenied("RELIABILITY_POLICY_ROLLBACK")
        if document["supported_host"] != expected_host:
            raise ReliabilityPolicyDenied("RELIABILITY_POLICY_HOST_MISMATCH")
        if document["workload_profile"] != expected_workload:
            raise ReliabilityPolicyDenied("RELIABILITY_POLICY_WORKLOAD_MISMATCH")
        if document["evaluator_compatibility_version"] != evaluator_version:
            raise ReliabilityPolicyDenied("RELIABILITY_POLICY_EVALUATOR_INCOMPATIBLE")

        scenarios = tuple(ReliabilityScenario(**item) for item in document["scenario_fixtures"])
        if tuple(item.name for item in scenarios) != self._SCENARIOS:
            raise ReliabilityPolicyDenied("RELIABILITY_SCENARIOS_INCOMPLETE")
        if any(not item.raw_evidence for item in scenarios):
            raise ReliabilityPolicyDenied("RELIABILITY_RAW_EVIDENCE_REQUIRED")
        if any(
            item.aggregation != document["aggregation"]
            or item.retention_days != document["retention_window_days"]
            for item in scenarios
        ):
            raise ReliabilityPolicyDenied("RELIABILITY_SCENARIO_BINDING_INVALID")
        return VerifiedReliabilityPolicy(
            policy_id=str(document["policy_id"]),
            policy_version=int(document["policy_version"]),
            supported_host=str(document["supported_host"]),
            workload_profile=str(document["workload_profile"]),
            scenarios=scenarios,
        )


@dataclass(frozen=True)
class ImmutableEvidence:
    evidence_id: str
    digest: str
    observed_at: datetime
    retained: bool


@dataclass(frozen=True)
class MetricSample:
    role: str
    dimension: str
    value: float
    observed_at: datetime
    evidence: ImmutableEvidence


@dataclass(frozen=True)
class DailyException:
    role: str
    dimension: str
    value: float
    sample_size: int
    confidence: float
    evidence: tuple[ImmutableEvidence, ...]


@dataclass(frozen=True)
class ImprovementProposal:
    role: str
    dimension: str
    action: str
    status: str = "pending-authority-gate"


class EvaluationService:
    _FORBIDDEN = frozenset(
        {"punish", "replace", "dispatch", "grant authority", "change capabilities", "move cards"}
    )

    def __init__(
        self,
        *,
        exception_thresholds: dict[str, float],
        proposal_gate: Callable[[str, str, str], None] | None = None,
    ) -> None:
        self._thresholds = exception_thresholds
        self._proposal_gate = proposal_gate

    def daily_exceptions(
        self, samples: Iterable[MetricSample], *, day: date
    ) -> tuple[DailyException, ...]:
        groups: dict[tuple[str, str], list[MetricSample]] = {}
        for sample in samples:
            if sample.observed_at.date() == day and sample.dimension in ALL_DIMENSIONS:
                groups.setdefault((sample.role, sample.dimension), []).append(sample)
        result: list[DailyException] = []
        for (role, dimension), values in sorted(groups.items()):
            average = sum(item.value for item in values) / len(values)
            if average < self._thresholds.get(dimension, 0.0):
                result.append(
                    DailyException(
                        role,
                        dimension,
                        average,
                        len(values),
                        min(0.99, sqrt(len(values)) / (sqrt(len(values)) + 1.0)),
                        tuple(item.evidence for item in values),
                    )
                )
        return tuple(result)

    def propose_improvement(self, role: str, dimension: str, action: str) -> ImprovementProposal:
        if dimension not in ALL_DIMENSIONS or not action:
            raise EvaluationDenied("IMPROVEMENT_PROPOSAL_INVALID")
        if self._proposal_gate is None:
            raise EvaluationDenied("AUTHORITY_GATE_REQUIRED")
        self._proposal_gate(role, dimension, action)
        return ImprovementProposal(role, dimension, action)

    def perform(self, action: str) -> None:
        if action in self._FORBIDDEN:
            raise EvaluationDenied("EVALUATION_AUTHORITY_DENIED")
        raise EvaluationDenied("EVALUATION_ACTION_UNSUPPORTED")

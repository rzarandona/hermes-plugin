from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, timedelta
from math import sqrt

from .attribution import RootCause
from .metrics import ALL_DIMENSIONS, EvaluationDenied, ImmutableEvidence, MetricSample


@dataclass(frozen=True)
class WeeklyTrend:
    role: str
    dimension: str
    sample_size: int
    confidence: float
    trend: str
    root_cause: RootCause
    evidence: tuple[ImmutableEvidence, ...]


def build_weekly_trends(
    samples: Iterable[MetricSample], *, week_ending: date, attribution: RootCause
) -> tuple[WeeklyTrend, ...]:
    start = week_ending - timedelta(days=6)
    groups: dict[tuple[str, str], list[MetricSample]] = {}
    for sample in samples:
        if start <= sample.observed_at.date() <= week_ending and sample.dimension in ALL_DIMENSIONS:
            if not sample.evidence.retained:
                raise EvaluationDenied("RAW_EVIDENCE_DISCARDED")
            groups.setdefault((sample.role, sample.dimension), []).append(sample)
    result: list[WeeklyTrend] = []
    required_days = {start + timedelta(days=offset) for offset in range(7)}
    expected_pairs = {
        (role, dimension)
        for role, _dimension in groups
        for dimension in ALL_DIMENSIONS
    }
    if set(groups) != expected_pairs or any(
        {item.observed_at.date() for item in values} != required_days for values in groups.values()
    ):
        raise EvaluationDenied("MEASUREMENT_WINDOW_INCOMPLETE")
    for (role, dimension), values in sorted(groups.items()):
        values.sort(key=lambda item: item.observed_at)
        midpoint = max(1, len(values) // 2)
        early = sum(item.value for item in values[:midpoint]) / midpoint
        later_values = values[midpoint:] or values[:midpoint]
        later = sum(item.value for item in later_values) / len(later_values)
        delta = later - early
        trend = "stable" if abs(delta) < 0.01 else ("improving" if delta > 0 else "declining")
        result.append(
            WeeklyTrend(
                role,
                dimension,
                len(values),
                min(0.99, sqrt(len(values)) / (sqrt(len(values)) + 1.0)),
                trend,
                attribution,
                tuple(item.evidence for item in values),
            )
        )
    return tuple(result)

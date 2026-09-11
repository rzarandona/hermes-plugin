from __future__ import annotations

import argparse
import hashlib
import json
import random
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "conformance_cases.json"
TRACEABILITY = ROOT / "tests" / "fixtures" / "normative_traceability.json"
MATRIX = ROOT / "docs" / "conformance-matrix.md"
FAILURES = (
    "crash",
    "duplicate_delivery",
    "stale_epoch",
    "partial_effect",
    "queue_wake_up",
    "failover",
    "replay",
)
INJECTION_SELECTORS = {
    "crash": "tests/failure_injection/test_spec_conformance.py::test_crash_after_dispatch_before_receipt_reads_back_before_redispatch",
    "duplicate_delivery": "tests/failure_injection/test_spec_conformance.py::test_duplicate_provider_receipt_is_one_immutable_evidence_row",
    "stale_epoch": "tests/failure_injection/test_resource_scheduler.py::test_stale_worker_cannot_release_renewed_fence",
    "partial_effect": "tests/failure_injection/test_spec_conformance.py::test_contradictory_readback_requires_reconciliation",
    "queue_wake_up": "tests/failure_injection/test_resource_scheduler.py::test_duplicate_wake_dedupes_exact_release_but_denies_rebinding",
    "failover": "tests/failure_injection/test_holds_failover.py::test_active_passive_failover_has_one_winner_after_authoritative_reconciliation",
    "replay": "tests/failure_injection/test_resource_scheduler.py::test_lost_release_replay_repairs_acquired_wait_token",
}
BYPASS_PROBES = {
    8: "forbidden_recovery_executor_actions",
    14: "forged_approval",
    16: "leaked_secret",
    17: "material_operational_change",
    21: "direct_persistence_credentials_and_writes",
}


class SpecificationReviewRequired(ValueError):
    pass


def load_cases(path: Path = FIXTURE) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _test_exists(selector: str) -> bool:
    path_text, separator, name = selector.partition("::")
    if not separator or not path_text or not name:
        return False
    path = ROOT / path_text
    if not path.is_file():
        return False
    return f"def {name}(" in path.read_text(encoding="utf-8")


def validate_traceability(path: Path = TRACEABILITY) -> list[dict[str, str]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    raw = document.get("rules")
    if not isinstance(raw, list):
        raise SpecificationReviewRequired("NORMATIVE_TRACEABILITY_REQUIRED")
    rules = [item for item in raw if isinstance(item, dict)]
    expected_counts = (
        10, 20, 42, 27, 14, 17, 21, 6, 30, 16, 19,
        9, 8, 3, 3, 2, 21, 26, 12, 8, 1,
    )
    expected = [
        f"SECTION-{section:02d}-RULE-{ordinal:03d}"
        for section, count in enumerate(expected_counts, 1)
        for ordinal in range(1, count + 1)
    ] + [
        "AMENDMENT-SECTION-12-ARTIFACT-LOCATOR", "AMENDMENT-SECTION-18-GROUP-24"
    ]
    if (
        document.get("schema_version") != 2
        or not isinstance(document.get("operative_source_sha256"), str)
        or len(document["operative_source_sha256"]) != 64
        or [item.get("id") for item in rules] != expected
    ):
        raise SpecificationReviewRequired("UNMAPPED_NORMATIVE_RULE")
    for item in rules:
        if not all(
            isinstance(item.get(field), str) and item[field].strip()
            for field in (
                "source", "canonical_decision", "implementation", "test", "evidence"
            )
        ):
            raise SpecificationReviewRequired(f"UNMAPPED_NORMATIVE_RULE_{item.get('id')}")
        if not (ROOT / item["implementation"]).exists() or not _test_exists(item["test"]):
            raise SpecificationReviewRequired(f"UNMAPPED_NORMATIVE_RULE_{item['id']}")
    return rules  # type: ignore[return-value]


def validate(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    validate_traceability()
    raw_groups = catalog.get("groups")
    if not isinstance(raw_groups, list):
        raise SpecificationReviewRequired("CONFORMANCE_GROUPS_REQUIRED")
    groups = [group for group in raw_groups if isinstance(group, dict)]
    numbers = [group.get("group") for group in groups]
    if len(groups) != 25 or numbers != list(range(1, 26)):
        raise SpecificationReviewRequired("SPECIFICATION_REVIEW_REQUIRED_GROUP_COUNT")
    case_ids: set[str] = set()
    for group in groups:
        source = group.get("source")
        test = group.get("implementation_test")
        cases = group.get("cases")
        if not isinstance(source, str) or not source.strip():
            raise SpecificationReviewRequired(f"MISSING_CANONICAL_SOURCE_GROUP_{group['group']}")
        if not isinstance(test, str) or not _test_exists(test):
            raise SpecificationReviewRequired(f"MISSING_IMPLEMENTATION_TEST_GROUP_{group['group']}")
        if not isinstance(cases, list) or not cases:
            raise SpecificationReviewRequired(f"MISSING_STABLE_CASE_GROUP_{group['group']}")
        for case in cases:
            if not isinstance(case, dict):
                raise SpecificationReviewRequired("INVALID_CASE")
            case_id = case.get("id")
            outcome = case.get("outcome")
            case_test = case.get("implementation_test", test)
            if not isinstance(case_id, str) or not case_id or case_id in case_ids:
                raise SpecificationReviewRequired("INVALID_OR_DUPLICATE_CASE_ID")
            if not isinstance(outcome, str) or not outcome:
                raise SpecificationReviewRequired(f"MISSING_OUTCOME_{case_id}")
            if not isinstance(case_test, str) or not _test_exists(case_test):
                raise SpecificationReviewRequired(f"MISSING_IMPLEMENTATION_TEST_{case_id}")
            case_ids.add(case_id)
    artifact = next(group for group in groups if group["group"] == 24)["cases"]
    if not any(
        case.get("id") == "CONF-18-24-ARTIFACT-LOCATOR"
        and case.get("outcome") == "ARTIFACT_LOCATOR_UNSUPPORTED"
        for case in artifact
    ):
        raise SpecificationReviewRequired("GROUP_24_ARTIFACT_LOCATOR_CASE_REQUIRED")
    evidence = catalog.get("evidence_receipt")
    if evidence != {
        "immutable": True,
        "repository_fixture": True,
        "effect_executed": False,
        "production_proof": False,
    }:
        raise SpecificationReviewRequired("IMMUTABLE_FIXTURE_EVIDENCE_RECEIPT_REQUIRED")
    return groups


def _schedule(group: int, iteration: int) -> list[str]:
    seed_bytes = hashlib.sha256(f"wp14:{group}:{iteration}".encode()).digest()[:8]
    seed = int.from_bytes(seed_bytes)
    return random.Random(seed).sample(list(FAILURES), k=len(FAILURES))


def _snapshot_roots(roots: Sequence[Path]) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for root in roots:
        if not root.exists():
            snapshot[root.as_posix()] = "MISSING"
            continue
        digest = hashlib.sha256()
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            relative = path.relative_to(root).as_posix()
            digest.update(relative.encode())
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        snapshot[root.as_posix()] = digest.hexdigest()
    return snapshot


def execute(groups: list[dict[str, Any]], repeat: int, *, external_roots: Sequence[Path] = ()) -> dict[str, Any]:
    if repeat < 1:
        raise SpecificationReviewRequired("REPEAT_MUST_BE_POSITIVE")
    before = _snapshot_roots(external_roots)
    results: list[dict[str, Any]] = []
    unclassified = 0
    for group in groups:
        selectors = tuple(dict.fromkeys((group["implementation_test"], *(case.get("implementation_test", group["implementation_test"]) for case in group["cases"]))))
        raw_schedules = [
            _schedule(int(group["group"]), iteration) for iteration in range(repeat)
        ]
        injection_selectors = [
            INJECTION_SELECTORS[injection]
            for schedule in raw_schedules
            for injection in schedule
        ]
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", *selectors, *injection_selectors, "-q", "-W", "error", "-p", "no:cacheprovider"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env={**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        schedules = [
            {
                "seed": hashlib.sha256(f"wp14:{group['group']}:{iteration}".encode()).hexdigest()[:16],
                "schedule": schedule,
                "observations": [
                    {"injection": injection, "selector": INJECTION_SELECTORS[injection], "observed": completed.returncode == 0}
                    for injection in schedule
                ],
                "passed": completed.returncode == 0,
            }
            for iteration, schedule in enumerate(raw_schedules)
        ]
        passed = completed.returncode == 0
        if not passed:
            unclassified += 1
        results.append({
            "group": group["group"],
            "status": "passed" if passed else "failed",
            "runs": repeat,
            "cases": [{
                "id": case["id"],
                "expected_outcome": case["outcome"],
                "observed": {
                    "selector": case.get("implementation_test", group["implementation_test"]),
                    "selector_returncode": completed.returncode,
                    "schedule_runs": len(schedules),
                    "all_injections_observed": all(run["passed"] for run in schedules),
                },
            } for case in group["cases"]],
            "schedule_executions": schedules,
            "bypass_probe": BYPASS_PROBES.get(int(group["group"])),
            "evidence_receipt": {"source": group["source"], "implementation_test": group["implementation_test"], "immutable": True, "effect_executed": False, "production_proof": False},
            "stderr": completed.stderr[-2000:] if completed.returncode else "",
        })
    after = _snapshot_roots(external_roots)
    return {
        "schema_version": 2,
        "delivery_semantics": "at-least-once stable-ID delivery plus provider dedupe",
        "group_count": len(results),
        "repeat": repeat,
        "results": results,
        "unclassified_failures": unclassified,
        "external_state_boundary": "declared-fixture-roots" if external_roots else "explicit-empty-sandbox-boundary",
        "external_state_before": before,
        "external_state_after": after,
        "external_state_mutated": before != after,
    }


def render_matrix(groups: list[dict[str, Any]]) -> str:
    rules = validate_traceability()
    lines = [
        "# Normative Traceability and Section 18 Conformance Matrix",
        "",
        "Generated from immutable repository traceability fixtures. All Sections 1–21 and both",
        "owner-approved artifact-locator amendments map source → implementation → executable test → evidence.",
        "",
        "| Rule | Normative source | Canonical decision | Implementation | Executable test | Immutable evidence |",
        "|---|---|---|---|---|---|",
    ]
    for rule in rules:
        lines.append(
            f"| `{rule['id']}` | {rule['source']} | {rule['canonical_decision']} | "
            f"`{rule['implementation']}` | `{rule['test']}` | `{rule['evidence']}` |"
        )
    lines.extend([
        "",
        "## Section 18 — preserved 25-group matrix",
        "",
        "Repository fixtures are contract evidence only: `effect_executed=false`, `production_proof=false`.",
        "",
        "| Group | Normative rule | Canonical source | Stable cases | Implementation test | Evidence |",
        "|---:|---|---|---|---|---|",
    ])
    for group in groups:
        cases = "<br>".join(
            f"`{case['id']}` → `{case['outcome']}`" for case in group["cases"]
        )
        tests = "<br>".join(
            f"`{case.get('implementation_test', group['implementation_test'])}`"
            for case in group["cases"]
        )
        lines.append(
            f"| {group['group']} | {group['rule']} | {group['source']} | {cases} | {tests} | "
            "immutable repository receipt; no production proof |"
        )
    lines.extend(
        [
            "",
            (
                "A twenty-sixth group or unknown case is rejected as "
                "`SPECIFICATION_REVIEW_REQUIRED`; it is never added implicitly."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--all", action="store_true")
    selection.add_argument("--group", type=int)
    selection.add_argument("--case")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--generate-matrix", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        groups = validate(load_cases())
        selected = groups
        if args.group is not None:
            selected = [group for group in groups if group["group"] == args.group]
            if not selected:
                raise SpecificationReviewRequired("SPECIFICATION_REVIEW_REQUIRED_UNKNOWN_GROUP")
        elif args.case is not None:
            selected = [
                group
                for group in groups
                if any(case["id"] == args.case for case in group["cases"])
            ]
            if not selected:
                raise SpecificationReviewRequired("SPECIFICATION_REVIEW_REQUIRED_UNKNOWN_CASE")
        if args.generate_matrix:
            MATRIX.write_text(render_matrix(groups), encoding="utf-8", newline="\n")
        report = execute(selected, args.repeat)
    except SpecificationReviewRequired as error:
        print(
            json.dumps(
                {"status": "specification-review-required", "code": str(error)}, sort_keys=True
            )
        )
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["unclassified_failures"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

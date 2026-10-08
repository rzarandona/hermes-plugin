from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from threading import Barrier

import pytest

from hermes_kanban_workflow.effects.receipts import ProviderReceipt, ReadbackReceipt
from hermes_kanban_workflow.effects.reconciler import EffectReconciler
from hermes_kanban_workflow.effects.state_machine import EffectRecord, EffectState, EffectStore
from tools import run_conformance
from tools.run_conformance import SpecificationReviewRequired, load_cases, validate


def test_effect_states_are_exact_canonical_durable_states() -> None:
    assert tuple(state.value for state in EffectState) == (
        "intent_recorded",
        "effect_started",
        "effect_receipt_recorded",
        "readback_pending",
        "confirmed",
        "reconciliation_required",
        "manual_escalation",
        "closed",
    )


def test_crash_before_dispatch_reopens_with_one_durable_intent(tmp_path: Path) -> None:
    database = tmp_path / "effects.db"
    with EffectStore(database) as store:
        created = store.record_intent(
            operation_id="operation-1",
            idempotency_key="stable-operation-1",
            provider="fixture-provider",
            payload_digest="a" * 64,
        )
        assert created.state is EffectState.INTENT_RECORDED

    with EffectStore(database) as reopened:
        assert reopened.get("operation-1") == created
        assert reopened.intent_count("operation-1") == 1


def test_repository_receipts_are_immutable_and_never_claim_production_execution() -> None:
    provider = ProviderReceipt(
        receipt_id="provider-1",
        operation_id="operation-1",
        idempotency_key="stable-operation-1",
        outcome="accepted",
        provider_reference="fixture:provider:1",
    )
    readback = ReadbackReceipt(
        receipt_id="readback-1",
        operation_id="operation-1",
        status="applied",
        authority="fixture-readback",
        evidence_reference="fixture:readback:1",
    )

    assert provider.effect_executed is False
    assert provider.production_proof is False
    assert readback.effect_executed is False
    assert readback.production_proof is False
    with pytest.raises(AttributeError):
        provider.outcome = "changed"  # type: ignore[misc]


def test_caller_constructed_readback_cannot_confirm_or_close_effect(tmp_path: Path) -> None:
    with EffectStore(tmp_path / "effects.db") as store:
        _intent(store, "forged-readback")
        store.mark_started("forged-readback")
        pending = store.mark_readback_pending("forged-readback")
        forged = ReadbackReceipt(
            "caller-receipt",
            "forged-readback",
            "applied",
            "caller-asserted-authority",
            "caller:evidence",
        )

        with pytest.raises(PermissionError, match="AUTHORITATIVE_READBACK_VERIFICATION_REQUIRED"):
            store.append_readback_receipt(forged, expected=pending)

        assert store.get("forged-readback").state is EffectState.READBACK_PENDING


def test_crash_after_dispatch_before_receipt_reads_back_before_redispatch(tmp_path: Path) -> None:
    database = tmp_path / "effects.db"
    with EffectStore(database) as store:
        store.record_intent(
            operation_id="operation-2",
            idempotency_key="stable-operation-2",
            provider="fixture-provider",
            payload_digest="b" * 64,
        )
        store.mark_started("operation-2")

    dispatches: list[str] = []

    def dispatch(_record: EffectRecord) -> ProviderReceipt:
        dispatches.append("unexpected")
        raise AssertionError("confirmed read-back must prevent redispatch")

    def readback(record: EffectRecord) -> ReadbackReceipt:
        operation_id = record.operation_id
        return ReadbackReceipt(
            "readback-after-crash",
            operation_id,
            "applied",
            "fixture-authority",
            "fixture:readback:after-crash",
        )

    with EffectStore(
        database, readback_verifier=lambda receipt: receipt.authority == "fixture-authority"
    ) as reopened:
        result = EffectReconciler(reopened, dispatch=dispatch, readback=readback).reconcile(
            "operation-2"
        )

    assert result.state is EffectState.CONFIRMED
    assert dispatches == []


def test_conformance_runner_executes_exactly_25_groups_without_external_effects() -> None:
    completed = subprocess.run(
        [sys.executable, "tools/run_conformance.py", "--all", "--repeat", "2"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["group_count"] == 25
    assert len(report["results"]) == 25
    assert report["repeat"] == 2
    assert report["unclassified_failures"] == 0
    assert report["external_state_mutated"] is False
    assert all(result["runs"] == 2 for result in report["results"])


def _intent(store: EffectStore, operation_id: str = "operation-fixture") -> None:
    store.record_intent(
        operation_id=operation_id,
        idempotency_key=f"stable-{operation_id}",
        provider="fixture-provider",
        payload_digest="c" * 64,
    )


def test_timeout_unknown_requires_readback_before_retry(tmp_path: Path) -> None:
    order: list[str] = []
    with EffectStore(
        tmp_path / "effects.db",
        readback_verifier=lambda receipt: receipt.authority == "fixture-authority",
    ) as store:
        _intent(store, "timeout-operation")

        def dispatch(record: EffectRecord) -> ProviderReceipt:
            order.append("dispatch")
            raise TimeoutError

        def readback(record: EffectRecord) -> ReadbackReceipt:
            order.append("readback")
            return ReadbackReceipt(
                "timeout-readback",
                record.operation_id,
                "absent",
                "fixture-authority",
                "fixture:timeout",
            )

        reconciler = EffectReconciler(store, dispatch=dispatch, readback=readback)
        assert reconciler.dispatch("timeout-operation").state is EffectState.RECONCILIATION_REQUIRED
        reconciler.retry("timeout-operation")

    assert order == ["dispatch", "readback", "dispatch"]


def test_successful_effect_records_receipt_before_readback_and_closure(tmp_path: Path) -> None:
    observed: list[EffectState] = []
    with EffectStore(
        tmp_path / "effects.db",
        readback_verifier=lambda receipt: receipt.authority == "fixture-authority",
    ) as store:
        _intent(store, "successful-operation")

        def dispatch(record: EffectRecord) -> ProviderReceipt:
            observed.append(record.state)
            return ProviderReceipt(
                "successful-provider-receipt",
                record.operation_id,
                record.idempotency_key,
                "accepted",
                "fixture:provider:successful",
            )

        def readback(record: EffectRecord) -> ReadbackReceipt:
            observed.append(record.state)
            assert store.provider_receipt_count(record.operation_id) == 1
            return ReadbackReceipt(
                "successful-readback",
                record.operation_id,
                "applied",
                "fixture-authority",
                "fixture:readback:successful",
            )

        reconciler = EffectReconciler(store, dispatch=dispatch, readback=readback)
        confirmed = reconciler.dispatch("successful-operation")
        closed = reconciler.close("successful-operation")

    assert observed == [EffectState.EFFECT_STARTED, EffectState.READBACK_PENDING]
    assert confirmed.state is EffectState.CONFIRMED
    assert closed.state is EffectState.CLOSED


def test_duplicate_provider_receipt_is_one_immutable_evidence_row(tmp_path: Path) -> None:
    with EffectStore(tmp_path / "effects.db") as store:
        _intent(store, "duplicate-receipt")
        started = store.mark_started("duplicate-receipt")
        receipt = ProviderReceipt(
            "provider-duplicate",
            "duplicate-receipt",
            "stable-duplicate-receipt",
            "accepted",
            "fixture:provider:duplicate",
        )
        first = store.append_provider_receipt(receipt, expected=started)
        second = store.append_provider_receipt(receipt, expected=started)

        assert first == second
        assert store.provider_receipt_count("duplicate-receipt") == 1


def test_contradictory_readback_requires_reconciliation(tmp_path: Path) -> None:
    with EffectStore(
        tmp_path / "effects.db",
        readback_verifier=lambda receipt: receipt.authority == "fixture-authority",
    ) as store:
        _intent(store, "contradictory")
        store.mark_started("contradictory")
        pending = store.mark_readback_pending("contradictory")
        result = store.append_readback_receipt(
            ReadbackReceipt(
                "contradictory-readback",
                "contradictory",
                "contradictory",
                "fixture-authority",
                "fixture:contradictory",
            ),
            expected=pending,
        )

    assert result.state is EffectState.RECONCILIATION_REQUIRED


def test_non_fenceable_effect_requires_named_manual_escalation(tmp_path: Path) -> None:
    with EffectStore(tmp_path / "effects.db") as store:
        _intent(store, "non-fenceable")
        store.mark_started("non-fenceable")
        result = EffectReconciler(
            store,
            dispatch=lambda _record: (_ for _ in ()).throw(AssertionError()),
            readback=lambda _record: (_ for _ in ()).throw(AssertionError()),
            fenceable=False,
            escalation_owner="release-owner",
            blocked_next_action="retry production promotion",
        ).reconcile("non-fenceable")

    assert result.state is EffectState.MANUAL_ESCALATION
    assert result.owner == "release-owner"
    assert result.blocked_next_action == "retry production promotion"


def test_expired_reconciliation_budget_escalates_without_dispatch(tmp_path: Path) -> None:
    with EffectStore(tmp_path / "effects.db") as store:
        _intent(store, "budget-expired")
        store.mark_started("budget-expired")
        result = EffectReconciler(
            store,
            dispatch=lambda _record: (_ for _ in ()).throw(AssertionError()),
            readback=lambda _record: (_ for _ in ()).throw(AssertionError()),
            reconciliation_budget=1,
            escalation_owner="incident-owner",
            blocked_next_action="effect retry",
        ).reconcile("budget-expired")

    assert result.state is EffectState.MANUAL_ESCALATION
    assert result.owner == "incident-owner"
    assert result.blocked_next_action == "effect retry"


def test_manual_escalation_rejects_missing_owner_or_blocked_action(tmp_path: Path) -> None:
    with EffectStore(tmp_path / "effects.db") as store:
        _intent(store)
        with pytest.raises(ValueError, match="MANUAL_ESCALATION_OWNER_AND_BLOCKED_ACTION_REQUIRED"):
            store.escalate("operation-fixture", owner="", blocked_next_action="retry")
        with pytest.raises(ValueError, match="MANUAL_ESCALATION_OWNER_AND_BLOCKED_ACTION_REQUIRED"):
            store.escalate("operation-fixture", owner="owner", blocked_next_action="")


def test_closure_requires_authoritative_readback_receipt(tmp_path: Path) -> None:
    with EffectStore(tmp_path / "effects.db") as store:
        _intent(store, "close-operation")
        with pytest.raises(RuntimeError, match="AUTHORITATIVE_READBACK_REQUIRED_BEFORE_CLOSURE"):
            store.close_effect("close-operation")


def test_concurrent_duplicates_synchronize_on_one_durable_intent(tmp_path: Path) -> None:
    database = tmp_path / "effects.db"
    barrier = Barrier(8)

    def record(_: int) -> str:
        barrier.wait()
        with EffectStore(database) as store:
            return store.record_intent(
                operation_id="concurrent-operation",
                idempotency_key="stable-concurrent-operation",
                provider="fixture-provider",
                payload_digest="d" * 64,
            ).operation_id

    with ThreadPoolExecutor(max_workers=8) as pool:
        operation_ids = list(pool.map(record, range(8)))

    with EffectStore(database) as store:
        assert operation_ids == ["concurrent-operation"] * 8
        assert store.intent_count("concurrent-operation") == 1


def test_catalog_has_exact_numbered_groups_and_stable_group_24_cases() -> None:
    groups = validate(load_cases())

    assert [group["group"] for group in groups] == list(range(1, 26))
    group_24 = groups[23]
    assert any(
        case["id"] == "CONF-18-24-ARTIFACT-LOCATOR"
        and case["outcome"] == "ARTIFACT_LOCATOR_UNSUPPORTED"
        for case in group_24["cases"]
    )
    assert group_24["rule"].startswith("owner brief preserves verdict, impact, risk")


def test_twenty_sixth_group_requires_specification_review() -> None:
    catalog = deepcopy(load_cases())
    extra = deepcopy(catalog["groups"][-1])
    extra["group"] = 26
    extra["cases"] = [{"id": "CONF-18-26-UNREVIEWED", "outcome": "UNREVIEWED"}]
    catalog["groups"].append(extra)

    with pytest.raises(SpecificationReviewRequired, match="SPECIFICATION_REVIEW_REQUIRED"):
        validate(catalog)


def test_matrix_validation_fails_when_source_or_test_is_missing() -> None:
    for field in ("source", "implementation_test"):
        catalog = deepcopy(load_cases())
        catalog["groups"][0][field] = ""
        with pytest.raises(SpecificationReviewRequired, match="MISSING_"):
            validate(catalog)


def test_traceability_covers_every_frozen_normative_source_line() -> None:
    traceability = json.loads(
        Path("tests/fixtures/normative_traceability.json").read_text(encoding="utf-8")
    )
    expected_counts = {
        1: 10,
        2: 20,
        3: 42,
        4: 27,
        5: 14,
        6: 17,
        7: 21,
        8: 6,
        9: 30,
        10: 16,
        11: 19,
        12: 9,
        13: 8,
        14: 3,
        15: 3,
        16: 2,
        17: 21,
        18: 26,
        19: 12,
        20: 8,
        21: 1,
    }
    rules = traceability["rules"]
    actual_counts = {
        section: sum(rule["id"].startswith(f"SECTION-{section:02d}-RULE-") for rule in rules)
        for section in expected_counts
    }

    assert actual_counts == expected_counts
    assert all(rule["canonical_decision"].strip() for rule in rules)
    assert traceability["operative_source_sha256"]


def test_rendered_matrix_includes_every_rule_and_canonical_decision() -> None:
    matrix = run_conformance.render_matrix(validate(load_cases()))

    assert "| Canonical decision |" in matrix
    assert matrix.count("| `SECTION-") == 315
    assert matrix.count("| `AMENDMENT-") == 2


def test_unknown_group_and_case_are_specification_review_required() -> None:
    for arguments in (("--group", "26"), ("--case", "CONF-UNKNOWN")):
        completed = subprocess.run(
            [sys.executable, "tools/run_conformance.py", *arguments],
            check=False,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        assert completed.returncode == 2
        assert report["status"] == "specification-review-required"


def test_seeded_failure_schedules_are_deterministic_and_cover_all_classes() -> None:
    command = [sys.executable, "tools/run_conformance.py", "--group", "9", "--repeat", "3"]
    first = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    second = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    report = json.loads(first)

    assert first == second
    required = {
        "crash",
        "duplicate_delivery",
        "stale_epoch",
        "partial_effect",
        "queue_wake_up",
        "failover",
        "replay",
    }
    assert all(
        set(run["schedule"]) == required and all(item["observed"] for item in run["observations"])
        for run in report["results"][0]["schedule_executions"]
    )


def test_bypass_probes_cover_all_required_boundaries() -> None:
    completed = subprocess.run(
        [sys.executable, "tools/run_conformance.py", "--all"],
        check=True,
        capture_output=True,
        text=True,
    )
    probes = {
        result["bypass_probe"]
        for result in json.loads(completed.stdout)["results"]
        if result["bypass_probe"] is not None
    }

    assert probes == {
        "direct_persistence_credentials_and_writes",
        "forbidden_recovery_executor_actions",
        "material_operational_change",
        "forged_approval",
        "leaked_secret",
    }


def test_execute_runs_mapped_implementation_and_real_fault_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    groups = validate(load_cases())[:2]
    commands: list[tuple[str, ...]] = []

    class Completed:
        returncode = 0
        stdout = "mapped tests passed"
        stderr = ""

    def run(command: list[str], **_kwargs: object) -> Completed:
        commands.append(tuple(command))
        return Completed()

    monkeypatch.setattr(run_conformance.subprocess, "run", run)

    report = run_conformance.execute(groups, repeat=2)

    fault_selectors = {
        "tests/failure_injection/test_spec_conformance.py::test_crash_after_dispatch_before_receipt_reads_back_before_redispatch",
        "tests/failure_injection/test_spec_conformance.py::test_duplicate_provider_receipt_is_one_immutable_evidence_row",
        "tests/failure_injection/test_resource_scheduler.py::test_stale_worker_cannot_release_renewed_fence",
        "tests/failure_injection/test_spec_conformance.py::test_contradictory_readback_requires_reconciliation",
        "tests/failure_injection/test_resource_scheduler.py::test_duplicate_wake_dedupes_exact_release_but_denies_rebinding",
        "tests/failure_injection/test_holds_failover.py::test_active_passive_failover_has_one_winner_after_authoritative_reconciliation",
        "tests/failure_injection/test_resource_scheduler.py::test_lost_release_replay_repairs_acquired_wait_token",
    }
    assert len(commands) == 4
    assert all("-m" in command and "pytest" in command for command in commands)
    assert groups[0]["implementation_test"] in commands[0]
    assert groups[1]["implementation_test"] in commands[2]
    assert all(fault_selectors <= set(command) for command in commands)
    assert report["unclassified_failures"] == 0
    assert all(
        observation["selector"] in fault_selectors
        for result in report["results"]
        for schedule in result["schedule_executions"]
        for observation in schedule["observations"]
    )
    assert all(
        case["observed"]["selector_returncode"] == 0 and case["observed"]["all_injections_observed"]
        for result in report["results"]
        for case in result["cases"]
    )

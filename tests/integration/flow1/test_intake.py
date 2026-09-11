from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.flows.flow1 import (
    IntakeRequest,
    ProductBinding,
    handle_flow1_intake,
    reject_wrong_product,
)
from hermes_kanban_workflow.policy.loader import load_verified_policy
from hermes_kanban_workflow.policy.verifier import TrustRoot
from hermes_kanban_workflow.review.classifier import (
    ClassificationFacts,
    DeliveryProfile,
    classify_delivery_profile,
)


class _UninterpretableActionableContent:
    def __str__(self) -> str:
        raise AssertionError("actionable content was interpreted before product identity")

    def __repr__(self) -> str:
        raise AssertionError("actionable content was interpreted before product identity")


def test_wrong_product_is_rejected_before_any_card_or_forwarding() -> None:
    effects: list[str] = []
    request = IntakeRequest(
        request_id="request-1",
        product_id="other-product",
        project_id="project-1",
        workspace_id="workspace-1",
        dependency_product_ids=(),
        actionable_content="create and deploy everything",
    )
    binding = ProductBinding(
        product_id="correct-product",
        destination="kanban://correct-product/intake",
        project_ids=frozenset({"project-1"}),
        workspace_ids=frozenset({"workspace-1"}),
        dependency_product_ids=frozenset(),
    )

    receipt = reject_wrong_product(request, binding, effect_recorder=effects.append)

    assert receipt.command_type == "reject_wrong_product"
    assert receipt.correct_destination == "kanban://correct-product/intake"
    assert receipt.card_created is False
    assert receipt.forwarded is False
    assert effects == []


def test_wrong_product_identity_is_checked_before_actionable_content() -> None:
    request = IntakeRequest(
        request_id="request-uninterpreted",
        product_id="other-product",
        project_id="project-1",
        workspace_id="workspace-1",
        dependency_product_ids=(),
        actionable_content=_UninterpretableActionableContent(),
    )
    binding = ProductBinding(
        product_id="correct-product",
        destination="kanban://correct-product/intake",
        project_ids=frozenset({"project-1"}),
        workspace_ids=frozenset({"workspace-1"}),
        dependency_product_ids=frozenset(),
    )

    receipt = reject_wrong_product(request, binding)

    assert receipt.command_type == "reject_wrong_product"


def _facts() -> ClassificationFacts:
    return ClassificationFacts(
        product_id="product-1",
        project_id="project-1",
        workspace_id="workspace-1",
        mutates_product=False,
        modules=(),
        dependency_product_ids=(),
        migration=False,
        protected_subsystems=(),
        external_effect=False,
        deployment=False,
        material_configuration=False,
        uncertain_dependencies=False,
        design_unknown=False,
    )


def _verified_policy(
    tmp_path: Path,
    facts: ClassificationFacts,
    profile: DeliveryProfile,
    *,
    module_limit: int | None = None,
):
    now = datetime.now(UTC)
    private_key = Ed25519PrivateKey.generate()
    document = {
        "schema_version": 1,
        "policy_id": "classifier-policy",
        "scope": "flow1",
        "issued_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(minutes=5)).isoformat(),
        "trust_epoch": 1,
        "compatibility": {
            "host_version": "0.20.5",
            "plugin_version": "0.1.0",
            "executor_version": "1.0.0",
            "policy_version": "1",
        },
        "authority": {"effect_classes": ["read_only"]},
        "rules": {
            "classifier_rows": [
                {
                    "facts_digest": facts.digest,
                    "profile": profile.value,
                    "allowed_modules": list(facts.modules),
                    "module_limit": len(facts.modules) if module_limit is None else module_limit,
                }
            ]
        },
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    path = tmp_path / f"{profile.value}.json"
    path.write_bytes(payload)
    root = TrustRoot.from_public_key("classifier-root", 1, private_key.public_key())
    return load_verified_policy(path, private_key.sign(payload), root, now=now)


@pytest.mark.parametrize("profile", list(DeliveryProfile))
def test_exact_signed_policy_row_supports_each_normative_profile(
    tmp_path: Path, profile: DeliveryProfile
) -> None:
    facts = _facts()
    policy = _verified_policy(tmp_path, facts, profile)

    receipt = classify_delivery_profile(facts, policy, protected_registry=frozenset())

    assert receipt.profile is profile
    assert receipt.classification_status == "accepted_signed_row"
    assert receipt.policy_digest == policy.digest
    assert receipt.authority_granted is False


def test_missing_exact_signed_row_escalates_without_authority(tmp_path: Path) -> None:
    facts = _facts()
    different_facts = facts.model_copy(update={"project_id": "different-project"})
    policy = _verified_policy(tmp_path, different_facts, DeliveryProfile.RESEARCH_ONLY)

    receipt = classify_delivery_profile(facts, policy, protected_registry=frozenset())

    assert receipt.classification_status == "accountable_evidence_required"
    assert receipt.evidence_source == "accountable_pm_or_read_only_auditor"
    assert receipt.required_evidence_roles == ("accountable_pm", "read_only_auditor")
    assert receipt.authority_granted is False


@pytest.mark.parametrize(
    ("changes", "safer_profile"),
    [
        ({"migration": True}, DeliveryProfile.PROTECTED_OR_EFFECTFUL),
        ({"protected_subsystems": ("payments",)}, DeliveryProfile.PROTECTED_OR_EFFECTFUL),
        ({"external_effect": True}, DeliveryProfile.PROTECTED_OR_EFFECTFUL),
        ({"deployment": True}, DeliveryProfile.PROTECTED_OR_EFFECTFUL),
        ({"material_configuration": True}, DeliveryProfile.PROTECTED_OR_EFFECTFUL),
        ({"uncertain_dependencies": True}, DeliveryProfile.DESIGN_REQUIRED),
    ],
)
def test_risky_or_uncertain_facts_deny_signed_bounded_classification(
    tmp_path: Path, changes: dict[str, object], safer_profile: DeliveryProfile
) -> None:
    facts = _facts().model_copy(
        update={"mutates_product": True, "modules": ("module-a",), **changes}
    )
    policy = _verified_policy(tmp_path, facts, DeliveryProfile.BOUNDED_IMPLEMENTATION)

    receipt = classify_delivery_profile(
        facts, policy, protected_registry=frozenset({"payments"})
    )

    assert receipt.profile is safer_profile
    assert receipt.classification_status == "accountable_evidence_required"
    assert receipt.authority_granted is False


def test_any_uncertainty_escalates_even_with_an_exact_signed_row(tmp_path: Path) -> None:
    facts = _facts().model_copy(update={"uncertain_dependencies": True})
    policy = _verified_policy(tmp_path, facts, DeliveryProfile.DESIGN_REQUIRED)

    receipt = classify_delivery_profile(facts, policy, protected_registry=frozenset())

    assert receipt.classification_status == "accountable_evidence_required"
    assert receipt.evidence_source == "accountable_pm_or_read_only_auditor"
    assert receipt.authority_granted is False


def test_signed_module_limit_denies_oversized_bounded_slice(tmp_path: Path) -> None:
    facts = _facts().model_copy(
        update={"mutates_product": True, "modules": ("module-a", "module-b")}
    )
    policy = _verified_policy(
        tmp_path, facts, DeliveryProfile.BOUNDED_IMPLEMENTATION, module_limit=1
    )

    receipt = classify_delivery_profile(facts, policy, protected_registry=frozenset())

    assert receipt.profile is DeliveryProfile.DESIGN_REQUIRED
    assert receipt.classification_status == "accountable_evidence_required"
    assert receipt.authority_granted is False


def test_cross_product_binding_fuzz_fails_closed_before_effects(tmp_path: Path) -> None:
    effects: list[str] = []
    binding = ProductBinding(
        product_id="product-1",
        destination="kanban://product-1/intake",
        project_ids=frozenset({"project-1"}),
        workspace_ids=frozenset({"workspace-1"}),
        dependency_product_ids=frozenset({"product-1"}),
    )
    facts = _facts().model_copy(update={"dependency_product_ids": ("product-1",)})
    policy = _verified_policy(tmp_path, facts, DeliveryProfile.RESEARCH_ONLY)

    cases = [
        (project, workspace, dependencies, registry)
        for project in ("project-1", "other-project")
        for workspace in ("workspace-1", "other-workspace")
        for dependencies in (("product-1",), ("other-product",), ())
        for registry in (frozenset(), frozenset({"module-a"}))
        if (project, workspace, dependencies)
        != ("project-1", "workspace-1", ("product-1",))
    ]
    for index, (project, workspace, dependencies, registry) in enumerate(cases):
        request = IntakeRequest(
            request_id=f"request-{index}",
            product_id="product-1",
            project_id=project,
            workspace_id=workspace,
            dependency_product_ids=dependencies,
            actionable_content="must never be interpreted",
        )
        receipt = handle_flow1_intake(
            request,
            binding,
            facts,
            policy,
            protected_registry=registry,
            effect_recorder=effects.append,
        )

        assert receipt.command_type == "reject_wrong_product"
        assert receipt.card_created is False
        assert receipt.forwarded is False
        assert not hasattr(receipt, "granted_profile")

    assert len(cases) == 22
    assert effects == []

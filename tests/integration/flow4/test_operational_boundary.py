from __future__ import annotations

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hermes_kanban_workflow.flows.flow4 import (
    ChangeDimension,
    OperationalBoundary,
    OperationalCapabilityAuthority,
    OperationalRequest,
)


def test_material_change_routes_to_flow1_before_any_effect() -> None:
    capabilities = OperationalCapabilityAuthority(private_key=Ed25519PrivateKey.generate())
    boundary = OperationalBoundary(capability_authority=capabilities)
    request = OperationalRequest(
        request_id="request-1",
        name="expand_entitlement",
        service_id="svc",
        scope="entitlement:premium",
        reversible=True,
        change_dimensions=(ChangeDimension.ENTITLEMENT,),
        capability=None,
    )

    receipt = boundary.authorize(request)

    assert receipt.route == "flow1"
    assert receipt.flow2_after_authorization
    assert not receipt.effect_executed


def test_reconciliation_cannot_retroactively_authorize_material_change() -> None:
    capabilities = OperationalCapabilityAuthority(private_key=Ed25519PrivateKey.generate())
    boundary = OperationalBoundary(capability_authority=capabilities)
    request = OperationalRequest(
        request_id="request-2",
        name="change_schema",
        service_id="svc",
        scope="schema:orders",
        reversible=True,
        change_dimensions=(ChangeDimension.SCHEMA,),
        capability=None,
    )

    with pytest.raises(PermissionError, match="RECONCILIATION_CANNOT_AUTHORIZE"):
        boundary.reconcile_as_authorization(request, evidence_ref="post-incident:evidence")


@pytest.mark.parametrize(
    "dimension",
    [
        ChangeDimension.BEHAVIOR,
        ChangeDimension.SCOPE,
        ChangeDimension.ENTITLEMENT,
        ChangeDimension.SAFETY,
        ChangeDimension.DATA,
        ChangeDimension.SCHEMA,
        ChangeDimension.ARCHITECTURE,
        ChangeDimension.UX,
        ChangeDimension.POLICY,
    ],
)
def test_each_material_dimension_reenters_flow1(dimension: ChangeDimension) -> None:
    boundary = OperationalBoundary(
        capability_authority=OperationalCapabilityAuthority(
            private_key=Ed25519PrivateKey.generate()
        )
    )
    request = OperationalRequest(
        "material",
        "material_change",
        "svc",
        "service:svc",
        True,
        (dimension,),
        None,
    )

    assert boundary.authorize(request).route == "flow1"


def test_signed_exact_narrow_reversible_operation_is_recorded_without_effect() -> None:
    authority = OperationalCapabilityAuthority(private_key=Ed25519PrivateKey.generate())
    boundary = OperationalBoundary(capability_authority=authority)
    capability = authority.issue(
        name="restart_worker", service_id="svc", scope="worker:checkout-7"
    )
    request = OperationalRequest(
        "operational",
        "restart_worker",
        "svc",
        "worker:checkout-7",
        True,
        (ChangeDimension.MAINTENANCE,),
        capability,
    )

    receipt = boundary.authorize(request)

    assert receipt.route == "flow4"
    assert not receipt.effect_executed


def test_forged_or_scope_mismatched_operational_capability_is_denied() -> None:
    authority = OperationalCapabilityAuthority(private_key=Ed25519PrivateKey.generate())
    boundary = OperationalBoundary(capability_authority=authority)
    capability = authority.issue(name="scale", service_id="svc", scope="pool:a")
    request = OperationalRequest(
        "forged",
        "scale",
        "svc",
        "pool:a",
        True,
        (ChangeDimension.SCALING,),
        replace(capability, signature=b"forged"),
    )

    with pytest.raises(PermissionError, match="SIGNED_EXACT_OPERATIONAL_CAPABILITY_REQUIRED"):
        boundary.authorize(request)


def test_generic_operational_capability_cannot_authorize_owner_only_retirement() -> None:
    authority = OperationalCapabilityAuthority(private_key=Ed25519PrivateKey.generate())
    boundary = OperationalBoundary(capability_authority=authority)
    capability = authority.issue(
        name="retire_service", service_id="svc", scope="service:svc"
    )
    request = OperationalRequest(
        "retire",
        "retire_service",
        "svc",
        "service:svc",
        True,
        (ChangeDimension.RETIREMENT,),
        capability,
    )

    with pytest.raises(PermissionError, match="OWNER_RETIREMENT_APPROVAL_REQUIRED"):
        boundary.authorize(request)

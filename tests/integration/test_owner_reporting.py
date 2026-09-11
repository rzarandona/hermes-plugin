from __future__ import annotations

from dataclasses import FrozenInstanceError, fields

import pytest

from hermes_kanban_workflow.reporting.artifact_locator import (
    ArtifactActionReceipt,
    ArtifactDeliverable,
    ArtifactLocator,
    ArtifactLocatorCode,
    HostCapabilitySet,
)
from hermes_kanban_workflow.reporting.owner_brief import (
    OwnerBrief,
    VerificationSummary,
    build_owner_brief,
)
from hermes_kanban_workflow.reporting.technical_packet import (
    EvidenceAnnexItem,
    TechnicalPacket,
    TypedVerdict,
    route_to_pm,
)


def _packet(verdict: TypedVerdict = TypedVerdict.PASS) -> TechnicalPacket:
    return TechnicalPacket(
        packet_id="packet:42",
        verdict=verdict,
        accountability="gatekeeper:qa-1",
        evidence_annex=(
            EvidenceAnnexItem("evidence:1", "QA evidence", "artifact://evidence/1"),
        ),
    )


def test_technical_packet_is_immutable_and_preserves_typed_evidence_annex() -> None:
    packet = _packet()

    with pytest.raises(FrozenInstanceError):
        packet.verdict = TypedVerdict.FAIL  # type: ignore[misc]

    assert packet.evidence_annex[0].identity == "evidence:1"
    assert packet.verdict is TypedVerdict.PASS


def test_pm_route_adds_summary_without_changing_verdict_accountability_or_annex() -> None:
    packet = _packet(TypedVerdict.FAIL)

    route = route_to_pm(
        packet,
        technical_route="artifact://technical/packet-42",
        summary="Release failed; Owner must decide whether to remediate.",
    )

    assert route.packet is packet
    assert route.verdict is TypedVerdict.FAIL
    assert route.accountability == "gatekeeper:qa-1"
    assert route.evidence_identities == ("evidence:1",)
    assert route.technical_route == "artifact://technical/packet-42"


def test_owner_brief_has_exactly_six_owner_fields_and_retains_routing_truth() -> None:
    route = route_to_pm(
        _packet(TypedVerdict.FAIL),
        technical_route="artifact://technical/packet-42",
        summary="Verification failed.",
    )

    brief = build_owner_brief(
        route,
        requested_outcome="Ship the approved change",
        accomplished="Candidate was reviewed",
        product_impact="Release remains unavailable",
        verification_result="Required checks failed",
        remaining_risk="Users do not have the requested change",
        next_action="Owner chooses remediation or cancellation",
    )

    assert tuple(field.name for field in fields(OwnerBrief)) == (
        "requested_outcome",
        "accomplished",
        "product_impact",
        "verification",
        "remaining_risk",
        "next_action",
    )
    assert isinstance(brief.verification, VerificationSummary)
    assert brief.verification.verdict is TypedVerdict.FAIL
    assert brief.verification.accountability == "gatekeeper:qa-1"
    assert brief.verification.technical_packet_link == "artifact://technical/packet-42"
    assert tuple(brief.to_dict()) == tuple(field.name for field in fields(OwnerBrief))


def test_owner_brief_omits_incidental_technical_noise_unless_explicitly_requested() -> None:
    route = route_to_pm(
        _packet(),
        technical_route="artifact://technical/packet-42",
        summary="Passed.",
    )
    brief = build_owner_brief(
        route,
        requested_outcome="Improve checkout",
        accomplished="Checkout is ready",
        product_impact="Faster purchase flow",
        verification_result="All required checks passed",
        remaining_risk="None known",
        next_action="Approve release",
    )

    rendered = repr(brief.to_dict())
    for incidental in ("feature.py", "git diff", "sha256:", "pytest -q", "raw log"):
        assert incidental not in rendered


def test_failure_verdict_cannot_be_softened_by_owner_summary() -> None:
    route = route_to_pm(
        _packet(TypedVerdict.FAIL),
        technical_route="artifact://technical/packet-42",
        summary="Everything looks good.",
    )

    brief = build_owner_brief(
        route,
        requested_outcome="Release",
        accomplished="Review completed",
        product_impact="Release is blocked",
        verification_result="Looks good",
        remaining_risk="Verification failed",
        next_action="Remediate",
    )

    assert brief.verification.verdict is TypedVerdict.FAIL
    assert brief.verification.result.startswith("FAIL:")


class RecordingHost:
    def __init__(self, *, succeeded: bool = True, verified: bool = True) -> None:
        self.succeeded = succeeded
        self.verified = verified
        self.calls: list[tuple[str, str]] = []

    def invoke_artifact_action(self, action: str, locator: str) -> ArtifactActionReceipt:
        self.calls.append((action, locator))
        return ArtifactActionReceipt(action, locator, self.succeeded, self.verified)


def test_artifact_locator_opens_exact_deliverable_when_capability_is_declared_and_verified() -> None:
    deliverable = ArtifactDeliverable(
        identity="deliverable:release:42",
        label="Release evidence",
        canonical_locator="C:/evidence/release-42.json",
    )
    host = RecordingHost()
    capabilities = HostCapabilitySet(
        declared=frozenset({"open_artifact"}), verified=frozenset({"open_artifact"})
    )

    result = ArtifactLocator(host, capabilities).locate(deliverable)

    assert result.code is ArtifactLocatorCode.OPENED
    assert result.deliverable is deliverable
    assert host.calls == [("open_artifact", "C:/evidence/release-42.json")]


def test_explorer_action_is_used_only_when_declared_and_verified() -> None:
    deliverable = ArtifactDeliverable("d:1", "Packet", "C:/packets/1.json")
    host = RecordingHost()
    capabilities = HostCapabilitySet(
        declared=frozenset({"show_in_file_explorer"}),
        verified=frozenset({"show_in_file_explorer"}),
    )

    result = ArtifactLocator(host, capabilities).locate(deliverable)

    assert result.code is ArtifactLocatorCode.REVEALED
    assert host.calls == [("show_in_file_explorer", "C:/packets/1.json")]


@pytest.mark.parametrize(
    "capabilities",
    [
        HostCapabilitySet(frozenset(), frozenset()),
        HostCapabilitySet(frozenset({"open_artifact"}), frozenset()),
        HostCapabilitySet(frozenset(), frozenset({"open_artifact"})),
    ],
)
def test_missing_or_unverified_host_action_returns_typed_unsupported(
    capabilities: HostCapabilitySet,
) -> None:
    deliverable = ArtifactDeliverable("d:1", "Packet", "C:/packets/1.json")
    host = RecordingHost()

    result = ArtifactLocator(host, capabilities).locate(deliverable)

    assert result.code is ArtifactLocatorCode.UNSUPPORTED
    assert result.deliverable.canonical_locator == "C:/packets/1.json"
    assert result.manual_route.endswith("C:/packets/1.json")
    assert result.release_ready is False
    assert host.calls == []


def test_host_false_success_never_reports_locator_success() -> None:
    deliverable = ArtifactDeliverable("d:1", "Packet", "C:/packets/1.json")
    host = RecordingHost(succeeded=True, verified=False)
    capabilities = HostCapabilitySet(
        declared=frozenset({"open_artifact"}), verified=frozenset({"open_artifact"})
    )

    result = ArtifactLocator(host, capabilities).locate(deliverable)

    assert result.code is ArtifactLocatorCode.UNSUPPORTED
    assert result.release_ready is False


def test_unsupported_artifact_locator_is_retained_in_six_field_owner_brief() -> None:
    deliverable = ArtifactDeliverable("d:1", "Packet", "C:/packets/1.json")
    locator_result = ArtifactLocator(
        RecordingHost(), HostCapabilitySet(frozenset(), frozenset())
    ).locate(deliverable)
    route = route_to_pm(
        _packet(TypedVerdict.UNSUPPORTED),
        technical_route="artifact://technical/packet-42",
        summary="Artifact opening unsupported.",
    )

    brief = build_owner_brief(
        route,
        requested_outcome="Open deliverable",
        accomplished="Canonical locator recorded",
        product_impact="Automatic opening unavailable",
        verification_result="Host capability unavailable",
        remaining_risk="Manual navigation required",
        next_action="Use documented manual route",
        artifact_locators=(locator_result,),
    )

    assert brief.verification.artifact_locators[0].canonical_locator == "C:/packets/1.json"
    assert brief.verification.artifact_locators[0].code == "ARTIFACT_LOCATOR_UNSUPPORTED"

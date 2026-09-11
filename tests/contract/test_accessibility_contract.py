from __future__ import annotations

from dataclasses import replace

import pytest

from hermes_kanban_workflow.reporting.technical_packet import (
    ACCESSIBILITY_SURFACES,
    SUPPORTED_ENVIRONMENT,
    AccessibilityOutcomeCode,
    HostAccessibilityCapabilities,
    SupportedEnvironment,
    assess_accessibility_surface,
    assess_supported_environment,
)


def test_fixed_compatibility_matrix_is_encoded_exactly() -> None:
    environment = SUPPORTED_ENVIRONMENT

    assert environment == SupportedEnvironment(
        agent_version="0.20.5",
        desktop_version="0.17.0",
        source_commit="a251e87d826f4ef7c75a8927d5304e24cf43ef54",
        python_version="3.11",
        manifest_version="2",
        api_generation="1",
        windows_version="11 24H2",
        windows_build="26100",
        terminal_version="1.22",
        powershell_version="7.5",
        edge_version="140",
        chrome_version="140",
        narrator_build="26100",
        nvda_version="2025.1",
    )
    assert assess_supported_environment(environment).supported is True


@pytest.mark.parametrize(
    ("field_name", "unsupported_value"),
    [
        ("agent_version", "0.20.6"),
        ("desktop_version", "0.17.1"),
        ("source_commit", "deadbeef"),
        ("python_version", "3.14"),
        ("manifest_version", "3"),
        ("api_generation", "2"),
        ("windows_version", "11 23H2"),
        ("windows_build", "26101"),
        ("terminal_version", "1.23"),
        ("powershell_version", "7.6"),
        ("edge_version", "141"),
        ("chrome_version", "141"),
        ("narrator_build", "26101"),
        ("nvda_version", "2025.2"),
    ],
)
def test_every_unlisted_environment_returns_typed_unsupported(
    field_name: str, unsupported_value: str
) -> None:
    outcome = assess_supported_environment(
        replace(SUPPORTED_ENVIRONMENT, **{field_name: unsupported_value})
    )

    assert outcome.supported is False
    assert outcome.code == "ENVIRONMENT_UNSUPPORTED"
    assert field_name in outcome.mismatches


@pytest.mark.parametrize("python_version", ["3.11", "3.12", "3.13"])
def test_documented_python_range_is_supported(python_version: str) -> None:
    outcome = assess_supported_environment(
        replace(SUPPORTED_ENVIRONMENT, python_version=python_version)
    )

    assert outcome.supported is True


def test_every_named_plugin_surface_has_complete_automated_accessibility_contract() -> None:
    assert tuple(surface.surface for surface in ACCESSIBILITY_SURFACES) == (
        "hermes_owner_questions",
        "kanban_cards_and_status_details",
        "reviewer_qa_forms",
        "owner_briefs",
        "artifact_locator_actions",
        "operator_cli_output",
        "packaged_teaching_reference_html",
    )
    assert tuple(surface.keyboard_order for surface in ACCESSIBILITY_SURFACES) == tuple(range(1, 8))
    for surface in ACCESSIBILITY_SURFACES:
        assert surface.semantic_name
        assert surface.role
        assert surface.states == ("enabled", "disabled", "busy", "invalid")
        assert surface.keyboard_activation == ("Enter", "Space")
        assert surface.visible_focus is True
        assert surface.status_announcement in {"polite", "assertive"}
        assert surface.non_color_meaning is True
        assert surface.zoom_200_percent is True
        assert surface.narrow_layout_390px is True
        assert surface.table_containment is True
        assert surface.contrast_tokens == (
            "--color-text-high-contrast",
            "--color-focus-ring",
        )
        assert surface.reduced_motion is True


@pytest.mark.parametrize(
    "missing_capability",
    ["screen_reader", "focus", "open_artifact", "explorer", "notification"],
)
def test_missing_host_capability_is_typed_unsupported_with_fallback_and_blocks_release(
    missing_capability: str,
) -> None:
    values = {
        "screen_reader": True,
        "focus": True,
        "open_artifact": True,
        "explorer": True,
        "notification": True,
    }
    values[missing_capability] = False
    capabilities = HostAccessibilityCapabilities(**values)

    outcome = assess_accessibility_surface(
        ACCESSIBILITY_SURFACES[0], SUPPORTED_ENVIRONMENT, capabilities
    )

    assert outcome.code is AccessibilityOutcomeCode.CAPABILITY_UNSUPPORTED
    assert outcome.missing_capabilities == (missing_capability,)
    assert outcome.fallback
    assert outcome.release_ready is False


def test_supported_automated_contract_does_not_claim_manual_at_execution() -> None:
    capabilities = HostAccessibilityCapabilities(True, True, True, True, True)

    outcome = assess_accessibility_surface(
        ACCESSIBILITY_SURFACES[0], SUPPORTED_ENVIRONMENT, capabilities
    )

    assert outcome.code is AccessibilityOutcomeCode.READY
    assert outcome.release_ready is False
    assert "manual" not in outcome.code.value.lower()


def test_caller_capability_booleans_cannot_claim_manual_at_release_readiness() -> None:
    capabilities = HostAccessibilityCapabilities(True, True, True, True, True)

    outcome = assess_accessibility_surface(
        ACCESSIBILITY_SURFACES[0], SUPPORTED_ENVIRONMENT, capabilities
    )

    assert outcome.code is AccessibilityOutcomeCode.READY
    assert outcome.release_ready is False
    assert "manual" in outcome.fallback.lower()


def test_unlisted_environment_blocks_surface_readiness() -> None:
    capabilities = HostAccessibilityCapabilities(True, True, True, True, True)

    outcome = assess_accessibility_surface(
        ACCESSIBILITY_SURFACES[0],
        replace(SUPPORTED_ENVIRONMENT, chrome_version="141"),
        capabilities,
    )

    assert outcome.code is AccessibilityOutcomeCode.ENVIRONMENT_UNSUPPORTED
    assert outcome.release_ready is False
    assert outcome.fallback

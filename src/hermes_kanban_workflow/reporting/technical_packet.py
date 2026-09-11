from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum


class TypedVerdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class EvidenceAnnexItem:
    identity: str
    label: str
    canonical_locator: str


@dataclass(frozen=True, slots=True)
class TechnicalPacket:
    packet_id: str
    verdict: TypedVerdict
    accountability: str
    evidence_annex: tuple[EvidenceAnnexItem, ...]


@dataclass(frozen=True, slots=True)
class PMRoute:
    packet: TechnicalPacket
    technical_route: str
    concise_summary: str
    verdict: TypedVerdict
    accountability: str
    evidence_identities: tuple[str, ...]


def route_to_pm(packet: TechnicalPacket, *, technical_route: str, summary: str) -> PMRoute:
    return PMRoute(
        packet,
        technical_route,
        summary,
        packet.verdict,
        packet.accountability,
        tuple(item.identity for item in packet.evidence_annex),
    )


@dataclass(frozen=True, slots=True)
class SupportedEnvironment:
    agent_version: str
    desktop_version: str
    source_commit: str
    python_version: str
    manifest_version: str
    api_generation: str
    windows_version: str
    windows_build: str
    terminal_version: str
    powershell_version: str
    edge_version: str
    chrome_version: str
    narrator_build: str
    nvda_version: str


SUPPORTED_ENVIRONMENT = SupportedEnvironment(
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


@dataclass(frozen=True, slots=True)
class EnvironmentOutcome:
    supported: bool
    code: str
    mismatches: tuple[str, ...]


def assess_supported_environment(environment: SupportedEnvironment) -> EnvironmentOutcome:
    mismatches = tuple(
        field.name
        for field in fields(SupportedEnvironment)
        if field.name != "python_version"
        and getattr(environment, field.name) != getattr(SUPPORTED_ENVIRONMENT, field.name)
    )
    try:
        python_parts = tuple(int(part) for part in environment.python_version.split("."))
    except ValueError:
        python_parts = ()
    if python_parts not in ((3, 11), (3, 12), (3, 13)):
        mismatches += ("python_version",)
    return EnvironmentOutcome(
        supported=not mismatches,
        code="SUPPORTED" if not mismatches else "ENVIRONMENT_UNSUPPORTED",
        mismatches=mismatches,
    )


@dataclass(frozen=True, slots=True)
class AccessibilitySurfaceContract:
    surface: str
    semantic_name: str
    role: str
    states: tuple[str, ...]
    keyboard_order: int
    keyboard_activation: tuple[str, ...]
    visible_focus: bool
    status_announcement: str
    non_color_meaning: bool
    zoom_200_percent: bool
    narrow_layout_390px: bool
    table_containment: bool
    contrast_tokens: tuple[str, str]
    reduced_motion: bool


def _surface(name: str, order: int, role: str = "region") -> AccessibilitySurfaceContract:
    return AccessibilitySurfaceContract(
        surface=name,
        semantic_name=name.replace("_", " ").title(),
        role=role,
        states=("enabled", "disabled", "busy", "invalid"),
        keyboard_order=order,
        keyboard_activation=("Enter", "Space"),
        visible_focus=True,
        status_announcement="polite",
        non_color_meaning=True,
        zoom_200_percent=True,
        narrow_layout_390px=True,
        table_containment=True,
        contrast_tokens=("--color-text-high-contrast", "--color-focus-ring"),
        reduced_motion=True,
    )


ACCESSIBILITY_SURFACES = (
    _surface("hermes_owner_questions", 1, "form"),
    _surface("kanban_cards_and_status_details", 2, "group"),
    _surface("reviewer_qa_forms", 3, "form"),
    _surface("owner_briefs", 4, "article"),
    _surface("artifact_locator_actions", 5, "group"),
    _surface("operator_cli_output", 6, "log"),
    _surface("packaged_teaching_reference_html", 7, "document"),
)


class AccessibilityOutcomeCode(StrEnum):
    READY = "ACCESSIBILITY_CONTRACT_READY"
    ENVIRONMENT_UNSUPPORTED = "ENVIRONMENT_UNSUPPORTED"
    CAPABILITY_UNSUPPORTED = "ACCESSIBILITY_CAPABILITY_UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class HostAccessibilityCapabilities:
    screen_reader: bool
    focus: bool
    open_artifact: bool
    explorer: bool
    notification: bool


@dataclass(frozen=True, slots=True)
class AccessibilityOutcome:
    code: AccessibilityOutcomeCode
    surface: str
    missing_capabilities: tuple[str, ...]
    fallback: str
    release_ready: bool


def assess_accessibility_surface(
    surface: AccessibilitySurfaceContract,
    environment: SupportedEnvironment,
    capabilities: HostAccessibilityCapabilities,
) -> AccessibilityOutcome:
    environment_outcome = assess_supported_environment(environment)
    if not environment_outcome.supported:
        return AccessibilityOutcome(
            AccessibilityOutcomeCode.ENVIRONMENT_UNSUPPORTED,
            surface.surface,
            (),
            "Use the documented supported matrix; do not claim assistive-technology evidence.",
            False,
        )
    missing = tuple(
        field.name
        for field in fields(HostAccessibilityCapabilities)
        if not getattr(capabilities, field.name)
    )
    if missing:
        return AccessibilityOutcome(
            AccessibilityOutcomeCode.CAPABILITY_UNSUPPORTED,
            surface.surface,
            missing,
            "Use semantic text and the documented keyboard/manual artifact route; record unexecuted.",
            False,
        )
    return AccessibilityOutcome(
        AccessibilityOutcomeCode.READY,
        surface.surface,
        (),
        "Manual assistive-technology evidence remains required before release readiness.",
        False,
    )

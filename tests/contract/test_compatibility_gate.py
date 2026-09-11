from __future__ import annotations

from pathlib import Path

import pytest

from hermes_kanban_workflow.plugin import (
    HOST_CONTRACT,
    activate_enforcement,
    load_package,
    register_observe_only,
    run_preflight,
)
from hermes_kanban_workflow.policy.compatibility import (
    CompatibilityError,
    CompatibilityReceipt,
    assert_compatible,
)
from tests.policy_fixtures import verified_policy


def test_exact_supported_version_tuple_is_accepted() -> None:
    result = assert_compatible("0.20.5", "0.1.0", "1.0.0", "1")

    assert result.host_version == "0.20.5"
    assert result.plugin_version == "0.1.0"
    assert result.executor_version == "1.0.0"
    assert result.policy_version == "1"


@pytest.mark.parametrize(
    ("versions", "field"),
    [
        (("0.20.4", "0.1.0", "1.0.0", "1"), "host_version"),
        (("0.20.5", "0.1.1", "1.0.0", "1"), "plugin_version"),
        (("0.20.5", "0.1.0", "1.0.1", "1"), "executor_version"),
        (("0.20.5", "0.1.0", "1.0.0", "2"), "policy_version"),
    ],
)
def test_any_version_comparison_flip_fails_closed(
    versions: tuple[str, str, str, str], field: str
) -> None:
    with pytest.raises(CompatibilityError) as failure:
        assert_compatible(*versions)

    assert failure.value.code == "COMPATIBILITY_UNSUPPORTED"
    assert failure.value.mismatches == (field,)


def test_registration_rechecks_compatibility_before_host_callback() -> None:
    class Context:
        called = False

        def register_tool(self, **_: object) -> None:
            self.called = True

    context = Context()
    forged = CompatibilityReceipt("0.20.5", "0.1.0", "1.0.0", "2")

    with pytest.raises(CompatibilityError):
        register_observe_only(
            context,  # type: ignore[arg-type]
            load_package({"manifest_version": 2, "api_version": 1}),
            forged,
        )

    assert context.called is False


def test_preflight_denial_cannot_be_activated(tmp_path: Path) -> None:
    package = load_package({"manifest_version": 2, "api_version": 1})
    policy = verified_policy(tmp_path, policy_version="2")

    preflight = run_preflight(package, policy, HOST_CONTRACT)

    assert preflight.passed is False
    assert preflight.code == "COMPATIBILITY_UNSUPPORTED"
    with pytest.raises(TypeError):
        activate_enforcement(preflight, owner={"approved": True})  # type: ignore[call-arg,arg-type]


def test_preflight_rejects_forgeable_boolean_signature_metadata() -> None:
    package = load_package({"manifest_version": 2, "api_version": 1})
    forged = {
        "signed": True,
        "compatibility": {
            "host_version": "0.20.5",
            "plugin_version": "0.1.0",
            "executor_version": "1.0.0",
            "policy_version": "1",
        },
    }

    preflight = run_preflight(package, forged, HOST_CONTRACT)

    assert preflight.passed is False
    assert preflight.code == "POLICY_VERIFICATION_REQUIRED"


def test_verified_policy_still_requires_external_windows_profile(tmp_path: Path) -> None:
    package = load_package({"manifest_version": 2, "api_version": 1})

    preflight = run_preflight(package, verified_policy(tmp_path), HOST_CONTRACT)

    assert preflight.passed is False
    assert preflight.code == "EXTERNAL_WINDOWS_PROFILE_EVIDENCE_REQUIRED"

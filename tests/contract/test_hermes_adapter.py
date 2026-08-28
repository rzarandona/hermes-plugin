from dataclasses import replace
import unittest

from hermes_kanban_workflow.plugin import (
    HOST_CONTRACT,
    HostIdentity,
    OwnerDecision,
    activate_enforcement,
    load_package,
    register_observe_only,
    run_preflight,
)


class RecordingContext:
    def __init__(self) -> None:
        self.tools: list[tuple[str, object]] = []
        self.commands: list[tuple[str, object]] = []

    def register_tool(self, name: str, handler: object) -> None:
        self.tools.append((name, handler))

    def register_command(self, name: str, handler: object) -> None:
        self.commands.append((name, handler))


class HermesAdapterContractTests(unittest.TestCase):
    def test_load_is_inert_and_observe_only_has_no_mutating_commands(self) -> None:
        package = load_package({"manifest_version": 2, "api_version": 1})
        self.assertFalse(package.registered)
        ctx = RecordingContext()
        handle = register_observe_only(ctx, package)
        self.assertEqual(handle.mode, "observe-only")
        self.assertEqual([name for name, _ in ctx.tools], ["kanban_status"])
        self.assertEqual(ctx.commands, [])

    def test_preflight_is_exact_and_fail_closed(self) -> None:
        package = load_package({"manifest_version": 2, "api_version": 1})
        good = run_preflight(package, {"signed": True}, HOST_CONTRACT)
        self.assertTrue(good.passed)
        incompatible = replace(HOST_CONTRACT, desktop_version="0.17.1")
        denied = run_preflight(package, {"signed": True}, incompatible)
        self.assertEqual(denied.code, "HOST_COMPATIBILITY_UNSUPPORTED")

    def test_activation_needs_exact_current_owner_decision(self) -> None:
        package = load_package({"manifest_version": 2, "api_version": 1})
        preflight = run_preflight(package, {"signed": True}, HOST_CONTRACT)
        decision = OwnerDecision(
            stage=1, package_digest=package.digest, policy_digest=preflight.policy_digest
        )
        self.assertEqual(activate_enforcement(preflight, decision).stage, 1)
        with self.assertRaisesRegex(PermissionError, "ACTIVATION_ENTRY_DENIED"):
            activate_enforcement(preflight, replace(decision, stage=2))

    def test_host_contract_is_pinned_to_verified_local_installation(self) -> None:
        self.assertEqual(
            HOST_CONTRACT,
            HostIdentity(
                agent_version="0.20.5",
                desktop_version="0.17.0",
                source_commit="a251e87d826f4ef7c75a8927d5304e24cf43ef54",
                python_range=">=3.11,<3.14",
                manifest_version=2,
                api_version=1,
                os_name="Windows 11 24H2 x64",
                os_build=26100,
                filesystem="NTFS",
            ),
        )


if __name__ == "__main__":
    unittest.main()

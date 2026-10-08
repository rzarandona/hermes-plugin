import base64
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hermes_kanban_workflow.activation import ActivationChain, ActivationTrustRegistry
from hermes_kanban_workflow.plugin import (
    HOST_CONTRACT,
    HostIdentity,
    ServiceReadinessResponse,
    ServiceReadinessVerifier,
    load_package,
    register_observe_only,
    run_preflight,
)
from hermes_kanban_workflow.policy.compatibility import assert_compatible
from hermes_kanban_workflow.policy.model import VerifiedPolicy
from tests.policy_fixtures import verified_policy


class RecordingContext:
    def __init__(self) -> None:
        self.tools: list[tuple[str, dict[str, object]]] = []
        self.commands: list[tuple[str, dict[str, object]]] = []

    def register_tool(
        self,
        *,
        name: str,
        toolset: str,
        schema: dict[str, object],
        handler: object,
        **kwargs: object,
    ) -> None:
        self.tools.append(
            (name, {"toolset": toolset, "schema": schema, "handler": handler, **kwargs})
        )

    def register_command(
        self,
        *,
        name: str,
        handler: object,
        description: str = "",
        args_hint: str = "",
    ) -> None:
        self.commands.append(
            (
                name,
                {"handler": handler, "description": description, "args_hint": args_hint},
            )
        )


class HermesAdapterContractTests(unittest.TestCase):
    @staticmethod
    def signed_policy(now: datetime | None = None) -> VerifiedPolicy:
        with TemporaryDirectory() as directory:
            return verified_policy(Path(directory), now=now)

    def test_load_is_inert_and_observe_only_has_no_mutating_commands(self) -> None:
        package = load_package({"manifest_version": 2, "api_version": 1})
        self.assertFalse(package.registered)
        ctx = RecordingContext()
        handle = register_observe_only(
            ctx, package, assert_compatible("0.20.5", "0.1.0", "1.0.0", "1")
        )
        self.assertEqual(handle.mode, "observe-only")
        self.assertEqual([name for name, _ in ctx.tools], ["kanban_status"])
        self.assertEqual(ctx.commands, [])

    def test_preflight_is_exact_and_fail_closed(self) -> None:
        package = load_package({"manifest_version": 2, "api_version": 1})
        blocked = run_preflight(package, self.signed_policy(), HOST_CONTRACT)
        self.assertFalse(blocked.passed)
        self.assertEqual(blocked.code, "EXTERNAL_WINDOWS_PROFILE_EVIDENCE_REQUIRED")
        incompatible = replace(HOST_CONTRACT, desktop_version="0.17.1")
        denied = run_preflight(package, {"signed": True}, incompatible)
        self.assertEqual(denied.code, "HOST_COMPATIBILITY_UNSUPPORTED")

    def test_authenticated_service_readiness_is_exactly_bound_and_fixtures_cannot_pass(self) -> None:
        package = load_package({"manifest_version": 2, "api_version": 1})
        now = datetime(2026, 8, 29, tzinfo=UTC)
        policy = self.signed_policy(now)
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        host_digest = __import__("hashlib").sha256(
            json.dumps(HOST_CONTRACT.__dict__, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        payload = {
            "kind": "authenticated-service-readiness",
            "service_identity": "NT SERVICE\\HermesKanbanWriter",
            "client_identity": "hermes-kanban-workflow",
            "policy_digest": policy.digest,
            "policy_epoch": policy.document.trust_epoch,
            "host_digest": host_digest,
            "package_digest": package.digest,
            "nonce": "fresh-nonce",
            "expires_at": "2026-08-29T01:00:00+00:00",
        }
        signature = base64.b64encode(
            key.sign(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        ).decode()
        response = ServiceReadinessResponse(payload, signature)
        fixture = ServiceReadinessVerifier(
            public,
            service_identity="NT SERVICE\\HermesKanbanWriter",
            production_authority=False,
        )
        denied = run_preflight(
            package, policy, HOST_CONTRACT, now=now, readiness_response=response,
            readiness_verifier=fixture, nonce="fresh-nonce"
        )
        self.assertEqual(denied.code, "AUTHENTICATED_EXTERNAL_SERVICE_AUTHORITY_REQUIRED")
        authority = ServiceReadinessVerifier(
            public,
            service_identity="NT SERVICE\\HermesKanbanWriter",
            production_authority=True,
        )
        denied_caller_authority = run_preflight(
            package, policy, HOST_CONTRACT, now=now, readiness_response=response,
            readiness_verifier=authority, nonce="fresh-nonce"
        )
        self.assertFalse(denied_caller_authority.passed)
        self.assertEqual(
            denied_caller_authority.code,
            "AUTHENTICATED_EXTERNAL_SERVICE_AUTHORITY_REQUIRED",
        )

    def test_lifecycle_api_names_are_distinct_from_host_registration(self) -> None:
        import hermes_kanban_workflow.plugin as lifecycle

        names = {
            name
            for name in dir(lifecycle)
            if name in {"load_package", "register_observe_only", "run_preflight", "activate_enforcement"}
        }
        self.assertEqual(
            names,
            {"load_package", "register_observe_only", "run_preflight", "activate_enforcement"},
        )

    def test_public_activation_rejects_caller_created_chain_without_state_change(self) -> None:
        from hermes_kanban_workflow.plugin import activate_enforcement

        chain = ActivationChain(
            "pkg", "policy", "host", "0.1.0", ActivationTrustRegistry({}, minimum_epoch=1)
        )
        with self.assertRaisesRegex(
            PermissionError, "AUTHENTICATED_SERVICE_ACTIVATION_REQUIRED"
        ):
            activate_enforcement(
                chain,
                entry={},
                passed={},
                review={},
                owner={},
                now=datetime(2026, 8, 29, tzinfo=UTC),
            )
        self.assertEqual(chain.current_stage, 0)
        self.assertEqual(chain.denials, [])

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

    def test_generation_one_adapter_uses_supported_keyword_signatures(self) -> None:
        from hermes_kanban_workflow.adapters.hermes_host import HermesPluginContextPort

        ctx = RecordingContext()
        from hermes_kanban_workflow.observe import OBSERVE_SOURCE_COMMIT, Observer

        with TemporaryDirectory() as directory:
            observer = Observer(Path(directory), Path(directory) / "absent.db", OBSERVE_SOURCE_COMMIT)
            HermesPluginContextPort(ctx, observer=observer).register_package_commands()

        self.assertEqual([name for name, _ in ctx.tools], ["kanban_status"])
        self.assertEqual(ctx.tools[0][1]["toolset"], "kanban-workflow")
        schema = ctx.tools[0][1]["schema"]
        self.assertIsInstance(schema, dict)
        self.assertEqual(schema["parameters"]["type"], "object")  # type: ignore[index]
        self.assertEqual(
            [name for name, _ in ctx.commands],
            ["kanban_workflow", "kanban_preflight", "kanban_request_activation"],
        )

    def test_manifest_declares_configuration_and_fail_closed_host_contract(self) -> None:
        manifest = Path("plugin.yaml").read_text(encoding="utf-8")
        self.assertIn("manifest_version: 2", manifest)
        self.assertIn("api_version: 1", manifest)
        self.assertIn("config_schema:", manifest)
        self.assertIn("default: observe_only", manifest)
        self.assertIn('python_entrypoint: "__init__:register"', manifest)
        self.assertIn("persistence: guarded_service_only", manifest)

    def test_manifest_top_level_fields_are_recognized_by_pinned_hermes_parser(self) -> None:
        provenance = json.loads(
            Path("vendor/hermes-agent-0.20.5-manifest-v2.json").read_text(encoding="utf-8")
        )
        self.assertEqual(provenance["hermes_agent_version"], "0.20.5")
        self.assertEqual(
            provenance["source_commit"], "a251e87d826f4ef7c75a8927d5304e24cf43ef54"
        )
        known_fields = set(provenance["known_manifest_fields"])
        manifest = yaml.safe_load(Path("plugin.yaml").read_text(encoding="utf-8"))
        self.assertIsInstance(manifest, dict)
        self.assertEqual(set(manifest) - known_fields, set())

    def test_dashboard_and_desktop_surfaces_are_scoped_and_opt_in(self) -> None:
        dashboard_manifest = Path("dashboard/manifest.json").read_text(encoding="utf-8")
        dashboard_api = Path("dashboard/plugin_api.py").read_text(encoding="utf-8")
        desktop = Path("desktop/plugin.js").read_text(encoding="utf-8")

        self.assertIn('"api": "plugin_api.py"', dashboard_manifest)
        self.assertNotIn('"backend"', dashboard_manifest)
        self.assertIn('prefix="/api/plugins/hermes-kanban-workflow"', dashboard_api)
        self.assertIn("defaultEnabled: false", desktop)
        self.assertIn("export default {", desktop)
        self.assertIn("ctx.rest('/status'", desktop)
        self.assertNotIn("ctx.rest.get", desktop)
        self.assertNotIn("extends HermesPlugin", desktop)


if __name__ == "__main__":
    unittest.main()

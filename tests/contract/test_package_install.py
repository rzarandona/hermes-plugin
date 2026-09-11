from __future__ import annotations

import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile

import yaml

from hermes_kanban_workflow.activation import ActivationReceipt
from hermes_kanban_workflow.config import (
    PackageState,
    UpgradeManager,
    VerifiedUpgradeEvidence,
    inspect_plugin_bundle,
    resolve_discovery_source,
)


def _state(path: Path, version: str, trust_epoch: int) -> PackageState:
    return PackageState(version, sha256(path.read_bytes()).hexdigest(), "policy-1", f"trust-{trust_epoch}", trust_epoch, path)


def test_project_local_plugin_is_denied_without_explicit_host_opt_in(tmp_path: Path) -> None:
    project_plugin = tmp_path / ".hermes" / "plugins" / "hermes-kanban-workflow"
    project_plugin.mkdir(parents=True)
    result = resolve_discovery_source(project_plugin, hermes_home=tmp_path / "user-home")
    assert not result.allowed
    assert result.code == "PROJECT_LOCAL_ACTIVATION_DENIED"


def test_upgrade_rejects_caller_booleans_and_forged_records(tmp_path: Path) -> None:
    active_file = tmp_path / "active.whl"
    candidate_file = tmp_path / "candidate.whl"
    active_file.write_bytes(b"active")
    candidate_file.write_bytes(b"candidate")
    active = _state(active_file, "0.1.0", 2)
    candidate = _state(candidate_file, "0.1.1", 3)
    manager = UpgradeManager(active, history=("event-a",), package_verifier=lambda _: False, activation_reader=lambda: None)
    assert manager.stage({"candidate": candidate, "compatible": True}).code == "VERIFIED_UPGRADE_EVIDENCE_REQUIRED"
    forged = VerifiedUpgradeEvidence(candidate, "host", "compat", "policy-1", candidate.package_digest, "n", "caller", True)
    assert manager.stage(forged).code == "VERIFIED_UPGRADE_EVIDENCE_REQUIRED"
    assert manager.promote(activation_chain_complete=True).code == "VERIFIED_ACTIVATION_READBACK_REQUIRED"
    assert manager.active == active


def test_verified_upgrade_requires_bytes_trust_epoch_and_complete_activation_readback(tmp_path: Path) -> None:
    active_file = tmp_path / "active.whl"
    candidate_file = tmp_path / "candidate.whl"
    active_file.write_bytes(b"active")
    candidate_file.write_bytes(b"candidate")
    active = _state(active_file, "0.1.0", 2)
    candidate = _state(candidate_file, "0.1.1", 3)
    receipt = ActivationReceipt(10, "receipt", "predecessor", candidate.package_digest, "policy-1", "host", "0.1.1")
    manager = UpgradeManager(active, history=("event-a", "event-b"), package_verifier=lambda evidence: evidence.authority == "fixture-authority", activation_reader=lambda: receipt)
    evidence = VerifiedUpgradeEvidence(candidate, "host", "compat", "policy-1", candidate.package_digest, "nonce", "fixture-authority", True)
    assert manager.stage(evidence).code == "UPGRADE_STAGED"
    assert manager.promote().code == "UPGRADE_PROMOTED"
    assert manager.history == ("event-a", "event-b")
    assert manager.rollback().code == "LAST_KNOWN_COMPATIBLE_RESTORED"
    assert manager.active == active


def test_rollback_rejects_changed_last_known_package_bytes(tmp_path: Path) -> None:
    active_file = tmp_path / "active.whl"
    candidate_file = tmp_path / "candidate.whl"
    active_file.write_bytes(b"active")
    candidate_file.write_bytes(b"candidate")
    active = _state(active_file, "0.1.0", 2)
    candidate = _state(candidate_file, "0.1.1", 3)
    receipt = ActivationReceipt(10, "receipt", None, candidate.package_digest, "policy-1", "host", "0.1.1")
    manager = UpgradeManager(active, history=("event",), package_verifier=lambda _: True, activation_reader=lambda: receipt)
    evidence = VerifiedUpgradeEvidence(candidate, "host", "compat", "policy-1", candidate.package_digest, "nonce", "authority", True)
    assert manager.stage(evidence).allowed
    assert manager.promote().allowed
    active_file.write_bytes(b"tampered")
    assert manager.rollback().code == "ROLLBACK_PACKAGE_IDENTITY_DENIED"


def test_fresh_wheel_install_discovers_real_entry_points_runs_cli_and_inspects_bundle(tmp_path: Path) -> None:
    dist = tmp_path / "dist"
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(dist)], check=True, capture_output=True, text=True)
    wheel = next(dist.glob("*.whl"))
    with ZipFile(wheel) as archive:
        entry_points = archive.read(next(name for name in archive.namelist() if name.endswith(".dist-info/entry_points.txt"))).decode()
        assert "[hermes_agent.plugins]" in entry_points
        assert "hermes-kanban-workflow = hermes_kanban_workflow.adapters.hermes_host:register" in entry_points
        assert "[console_scripts]" in entry_points

    venv = tmp_path / "isolated"
    subprocess.run(["uv", "venv", str(venv)], check=True, capture_output=True, text=True)
    python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    subprocess.run(["uv", "pip", "install", "--python", str(python), str(wheel)], check=True, capture_output=True, text=True)
    probe = subprocess.run([str(python), "-c", "import json,importlib.metadata as m; d=m.distribution('hermes-kanban-workflow'); print(json.dumps(sorted((e.group,e.name,e.value) for e in d.entry_points)))"], check=True, capture_output=True, text=True)
    discovered = json.loads(probe.stdout)
    assert ["hermes_agent.plugins", "hermes-kanban-workflow", "hermes_kanban_workflow.adapters.hermes_host:register"] in discovered
    cli = subprocess.run([str(venv / ("Scripts/hermes-kanban-workflow.exe" if os.name == "nt" else "bin/hermes-kanban-workflow")), "status"], check=True, capture_output=True, text=True)
    assert json.loads(cli.stdout)["activation_authorized"] is False

    bundle = tmp_path / "verification-root" / "plugin.zip"
    subprocess.run([sys.executable, "tools/build_release.py", "--output", str(bundle), "--verification-root", str(tmp_path / "verification-root")], check=True, capture_output=True, text=True)
    report = inspect_plugin_bundle(bundle)
    assert report.valid
    with ZipFile(bundle) as archive:
        manifest = yaml.safe_load(archive.read("hermes-kanban-workflow/plugin.yaml"))
        dashboard = json.loads(archive.read("hermes-kanban-workflow/dashboard/manifest.json"))
        provenance = json.loads(
            archive.read("hermes-kanban-workflow/vendor/hermes-agent-0.20.5-manifest-v2.json")
        )
        assert manifest["manifest_version"] == 2
        assert dashboard["enabledByDefault"] is False
        assert provenance["source_commit"] == "a251e87d826f4ef7c75a8927d5304e24cf43ef54"

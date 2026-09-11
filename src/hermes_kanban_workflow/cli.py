"""Dependency-light inspection CLI; it cannot install or activate enforcement."""

from __future__ import annotations

import argparse
import json

from hermes_kanban_workflow.config import (
    AGENT_VERSION,
    API_VERSION,
    DESKTOP_VERSION,
    MANIFEST_VERSION,
    PYTHON_RANGE,
    SOURCE_COMMIT,
)


def main() -> int:
    parser = argparse.ArgumentParser(prog="hermes-kanban-workflow")
    parser.add_argument("command", choices=("status", "preflight-info"))
    args = parser.parse_args()
    if args.command == "status":
        payload = {
            "implementation": "repository-contract-ready",
            "release_ready": False,
            "installed": False,
            "agent_stage": 0,
            "desktop_stage": 0,
            "activation_authorized": False,
            "blocker": "INDEPENDENT_AUDIT_AND_EXTERNAL_EVIDENCE_REQUIRED",
        }
    else:
        payload = {
            "agent_version": AGENT_VERSION,
            "desktop_version": DESKTOP_VERSION,
            "source_commit": SOURCE_COMMIT,
            "python": PYTHON_RANGE,
            "manifest_version": MANIFEST_VERSION,
            "api_version": API_VERSION,
            "enforcement": "authenticated-ten-stage-owner-gated",
        }
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

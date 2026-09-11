"""Validate pre-collected Windows profile evidence without changing machine state.

This script deliberately does not execute sc.exe, icacls, PowerShell, service
installation, ACL mutation, DPAPI-NG provisioning, or any other applying action.
The input JSON must be produced by the separately authorized clean-VM procedure.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from hermes_kanban_workflow.command.windows_profile import (
    WindowsProfileEvidence,
    WindowsProfileVerifier,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, help="pre-collected profile evidence JSON")
    args = parser.parse_args()
    evidence = WindowsProfileEvidence.model_validate_json(args.evidence.read_bytes())
    receipt = WindowsProfileVerifier().verify(evidence)
    print(json.dumps(receipt.model_dump(mode="json"), sort_keys=True, indent=2))
    return 0 if receipt.enforcement_eligible else 2


if __name__ == "__main__":
    raise SystemExit(main())

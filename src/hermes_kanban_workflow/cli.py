"""Dependency-light development CLI. It cannot activate enforcement."""

from __future__ import annotations

import argparse
import json


def main() -> int:
    parser = argparse.ArgumentParser(prog="hermes-kanban-workflow")
    parser.add_argument("command", choices=("status", "preflight-info"))
    args = parser.parse_args()
    if args.command == "status":
        print(json.dumps({"implementation": "in-progress", "installed": False, "activated": False}))
    else:
        print(json.dumps({"required_host": "Hermes Agent 0.20.5 / Desktop 0.17.0", "enforcement": "owner-gated"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


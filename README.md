# Hermes Kanban Workflow Plugin

A fail-closed standalone package pinned to Hermes Agent 0.20.5, Desktop 0.17.0, source `a251e87d826f4ef7c75a8927d5304e24cf43ef54`, manifest v2/API generation 1, and Python >=3.11,<3.14.

**Release state:** development package built for inspection only. Installation, profile modification, registration, migration, secret provisioning, activation, production access, deployment, and retirement are unauthorized.

## Architecture

The Hermes Agent and Desktop halves are separately disabled unless an exact authenticated activation stage authorizes them. Hermes in-process code is not a security sandbox and owns no durable mutation credential. Durable mutation belongs only to the separately authenticated guarded writer service. Combined-process mode is observe-only.

Plugin-owned lifecycle APIs are exactly:

- `load_package`
- `register_observe_only`
- `run_preflight`
- `activate_enforcement`

They are distinct from Hermes native `register(ctx)`. The companion skill is advisory and has no state authority.

## Inspection commands

```powershell
python -m hermes_kanban_workflow.cli status
python -m hermes_kanban_workflow.cli preflight-info
```

## Reproducible isolated build (no install)

From an isolated temporary checkout/build environment:

```powershell
uv build --wheel --out-dir dist
.venv\Scripts\python.exe tools\build_release.py
```

The second command creates a deterministic unified plugin archive and regenerates `release/package-inventory.json` and `release/checksums.txt`. Inspect the wheel or archive directly; do not install it into Hermes or any profile.

## Verification

```powershell
.venv\Scripts\python.exe -m pytest -W error -q
.venv\Scripts\python.exe tools\run_conformance.py --all --repeat 20
.venv\Scripts\ruff.exe check .
.venv\Scripts\mypy.exe
```

See the Operator Guide, Role Guide, Recovery and Rollback Runbook, Known Limitations, evidence locators, and owner brief. Repository fixtures prove verifier behavior only; they are not clean-host, assistive-technology, external-effect, independent-review, or Owner evidence.
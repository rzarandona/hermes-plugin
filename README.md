<p align="center">
	<img src="docs/assets/hermes-agent-logo.png" alt="Hermes Agent logo" width="160" />
</p>

<h1 align="center">Hermes Kanban Workflow Plugin</h1>

<p align="center"><strong>Fail-closed workflow controls for Hermes Kanban.</strong></p>

<p align="center">
	A standalone Python plugin that provides observable, policy-gated Kanban workflow controls for Hermes Agent and Desktop.
</p>

<p align="center">
	<img src="https://img.shields.io/badge/Python-3.11--3.13-3776AB?logo=python&logoColor=white" alt="Python 3.11 to 3.13" />
	<img src="https://img.shields.io/badge/Hermes%20Agent-0.20.5-24292F" alt="Hermes Agent 0.20.5" />
	<img src="https://img.shields.io/badge/Hermes%20Desktop-0.17.0-24292F" alt="Hermes Desktop 0.17.0" />
	<img src="https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white" alt="FastAPI 0.110 or later" />
	<img src="https://img.shields.io/badge/Pydantic-2%2B-E92063?logo=pydantic&logoColor=white" alt="Pydantic 2" />
</p>

---

## Overview

This standalone package targets Hermes Agent 0.20.5 and Hermes Desktop 0.17.0
at source `a251e87d826f4ef7c75a8927d5304e24cf43ef54`. It uses manifest version
2 and API generation 1, and supports Python 3.11 through 3.13.

**Release state:** development package built for inspection only. Installation, profile modification, registration, migration, secret provisioning, activation, production access, deployment, and retirement are unauthorized.

## Tech Stack

### Platform

| Area | Technology |
| --- | --- |
| Language and runtime | Python 3.11-3.13 |
| Host integration | Hermes Agent 0.20.5, Hermes Desktop 0.17.0, manifest v2, API generation 1 |
| Plugin model | Standalone Hermes plugin with an observe-only default mode |
| Packaging | Hatchling, `uv`, wheel distribution, deterministic unified plugin archive |
| Configuration | YAML plugin manifest and Pydantic configuration schema |
| Security model | Fail-closed activation, signed monotonic ten-stage activation chain, guarded writer service for durable mutation |

### Runtime Dependencies

| Package | Requirement | Purpose |
| --- | --- | --- |
| `cryptography` | >=42 | Cryptographic controls used by the plugin. |
| `fastapi` | >=0.110 | API framework for plugin service interfaces. |
| `pydantic` | >=2,<3 | Typed validation and configuration models. |
| `typer` | >=0.12 | Command-line interface framework. |

### Development and Quality Dependencies

| Package | Requirement | Purpose |
| --- | --- | --- |
| `hatchling` | build backend | Python wheel build backend. |
| `hypothesis` | >=6 | Property-based testing. |
| `mypy` | >=1.11 | Strict static type checking. |
| `pytest` | >=8 | Test runner. |
| `pytest-asyncio` | >=0.23 | Async test support. |
| `pyyaml` | >=6.0.3 | YAML parsing for development tooling. |
| `ruff` | >=0.6 | Linting and formatting checks. |

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

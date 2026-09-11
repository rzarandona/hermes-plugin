# WP15 Owner Brief

Status: BLOCKED — implementation-completion review, installation, and activation are unauthorized.

Owner: Product Secretary (brief preparation); acceptance authority remains the exact Owner.

## Exact artifacts

1. Wheel: `dist/hermes_kanban_workflow-0.1.0-py3-none-any.whl` (identity in `release/package-inventory.json`).
2. Unified plugin bundle: `dist/hermes-kanban-workflow-plugin.zip`.
3. Policy bundle: `policies/pilot-policy.json` plus `policies/pilot-policy.sig` (development fixture, not production trust).
4. Package inventory: `release/package-inventory.json`.
5. Checksums: `release/checksums.txt`.
6. Audit verdict: `release/audit-verdict.json` — `UNEXECUTED`, not PASS.
7. Conformance and traceability: `docs/conformance-matrix.md`, `tests/fixtures/conformance_cases.json`, and `tests/fixtures/normative_traceability.json` (Sections 1–21, both amendments, preserved 25-group matrix).
8. Automated isolated-package evidence: `tests/contract/test_package_install.py` builds a fresh temporary wheel, installs it into an isolated temporary environment with no Hermes/profile install, discovers real plugin/CLI entry points, executes `status`, and parses the shipped bundle manifests/provenance.
9. Known limitations: `docs/known-limitations.md`.
10. Direct evidence locators: `release/evidence-locators.json`, all 14 completion rows represented.

## Decision posture

Repository tests and rehearsal fixtures do not prove WP5 clean-host service/ACL/DPAPI-NG/IPC, manual assistive-technology evidence, production trust/effects, actual independent review, or Owner acceptance. Those rows remain BLOCKED. No installation, profile modification, Agent/Desktop enablement, migration, secret provisioning, enforcement activation, production release, deployment, or retirement is authorized by this brief.
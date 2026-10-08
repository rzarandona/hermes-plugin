# Operator Guide

## Observation switch

Rein Hermes Kanban Plugin provides a native read tool and the human-operated
`/kanban_workflow on|off|status` command. On enables status counts only; Off stops
board reads immediately. The choice persists in the captured profile's state
directory across fresh processes and restarts. Missing or malformed state is Off.
Changing the host source or using a dirty/unsupported host blocks observation.
This switch never enables workers, Asana writes, enforcement or PROD deployment.
`/kanban_preflight` reports live observation compatibility and the missing
enforcement authority; `/kanban_request_activation` continues to deny enforcement.

The independent controller is `python tools/observe_control.py status` with
explicit profile/host options when operating outside Hermes; see `--help`.

Owner: Operations
Status: repository rehearsal only; installation and activation unauthorized.

## Supported packaged commands

Run from an isolated source checkout or isolated wheel virtual environment only:

```powershell
python -m hermes_kanban_workflow.cli status
python -m hermes_kanban_workflow.cli preflight-info
```

`status` reports package implementation state and keeps Agent/Desktop enforcement disabled. `preflight-info` prints the frozen Agent 0.20.5, Desktop 0.17.0, source commit, Python, manifest, and API requirements. Neither command installs, registers, migrates, activates, or contacts an external service.

## Lifecycle procedure

1. **Load:** call `load_package(manifest_mapping)` only after verifying bundle checksums. Loading is inert.
2. **Observe-only registration:** call `register_observe_only(ctx, package, compatibility_receipt)`. It may register only `kanban_status`; it has no mutation command or persistence credential.
3. **Preflight:** call `run_preflight(package, verified_policy, exact_host, ...)`. Missing authenticated clean-host service evidence is expected to return a typed denial. Repository fixtures cannot enable enforcement.
4. **Enforcement request:** `activate_enforcement` is not an operator shortcut. It requires the next stage of an authenticated `ActivationChain`, four current signatures, exact predecessor and identity, independent review, and exact Owner decision.
5. **Health:** inspect status, denial ledger, guarded-service health, policy expiry/revocation, evidence retention, and Agent/Desktop stage values separately.
6. **Holds:** stop dispatch, preserve exact membership, and resume members only as fresh eligible attempts after authority read-back.
7. **Evidence:** retain immutable receipt digests and use `release/evidence-locators.json`; never relabel a repository fixture as manual/external evidence.
8. **Uninstall preparation:** kill/revoke capabilities, reconcile unknown effects, export required evidence, preserve holds/ledger, and obtain a separate Owner uninstall decision. This package performs no uninstall.
9. **Failure routing:** security or trust failure → Security; ledger/effect uncertainty → Recovery and Effects; release mismatch → Release Gatekeeper; owner decision ambiguity → Owner. Fail closed.

No screenshot is shipped as proof. Manual screenshots, when independently produced, must bind host/version/case/time and immutable evidence digest.

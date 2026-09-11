# Recovery and Rollback Runbook

Owner: Recovery and Release
Status: rehearsal fixture only; no external recovery was executed.

## Universal first response

1. Freeze new effects and separately disable Agent/Desktop capabilities.
2. Preserve ledger, denial records, policy/trust state, package inventory, receipts, leases, holds, and logs.
3. Read back authoritative external state; never retry while effect state is unknown.
4. Name incident commander, Recovery reviewer, Effects reviewer, Gatekeeper, and Owner route.

## Scenarios

### Plugin failure
Unregister observers, revoke effect capabilities, keep guarded writer stopped, preserve evidence, and return to the last safe stage. Kill criteria: crash loop, mutation path, secret exposure, evidence loss, or unbounded alerts.

### Ledger recovery
Restore only from verified backup, validate append-only chain/schema/migrations, reconcile every intent/provider/read-back triple, advance fencing, and resume exact held members as fresh eligible attempts. Never edit SQLite directly.

### Policy rollback
Require a signed, unrevoked policy whose epoch is not below the trust floor. Bind package/host/version. Rollback cannot activate; forward movement must freshly re-enter every intervening activation stage.

### Trust-root rotation or revocation
Revoke compromised key, raise minimum trust epoch, preserve revocation evidence, re-sign nothing retroactively, invalidate staged packages/approvals, and require fresh evidence. Rolled-back keys and signatures are denied.

### Control-plane failover
Fence the old writer, prove passive eligibility and sole-writer profile externally, reconcile queue/leases/effects, then permit fresh attempts only. Combined-process mode remains observe-only.

### Unknown external effect
Record durable UNKNOWN state, stop retries and closure, obtain provider receipt plus authoritative read-back, and route unresolved state to named manual Effects responder and Owner.

### Manual escalation
Provide exact case, package/policy/host digests, stage, predecessor, effect state, evidence gaps, safe fallback, and requested decision. General approval is invalid.

## Rollback and re-entry
Rollback may target only an earlier recorded safe stage. Agent/Desktop halves are disabled according to that stage. Any subsequent forward transition requires new nonces, current unrevoked entry/pass evidence, eligible independent review, exact predecessor, and a new Owner decision for each stage—no shortcut.

## Repository rehearsal record
The automated activation and recovery tests exercise fixture signatures and deterministic state only. They prove verifier behavior, not clean-host ACLs, production identity, external effects, manual accessibility, independent audit, or Owner acceptance. Accountable rehearsal owners: Recovery and Release; evidence review: Gatekeeper.
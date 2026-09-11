# Security

## Boundary

Hermes Python/Desktop plugins execute in-process and are not a security sandbox. They may validate and observe, but cannot prove sole-writer isolation against hostile co-resident code. Enforcement requires an authenticated out-of-process guarded writer with OS identity/ACL isolation. The unresolved clean-Windows WP5 profile remains BLOCKED.

## Fail-closed rules

- No mutation credential, production trust root, or real secret may exist in Hermes, Desktop, prompts, cards, logs, evidence, repositories, or shared environments.
- Exact package, policy, host, source, Python, manifest/API, trust epoch, stage, predecessor, current entry/pass evidence, independent review, and stage-named Owner decision are mandatory.
- Caller booleans, JSON, typed receipts, and repository signatures cannot manufacture external or production authority.
- Direct skip/repeat, changed payload, replayed nonce, expiry, missing predecessor, revoked key, trust rollback, conflict, or forged signature deny before registration/effect and create an auditable denial.
- Rollback only targets an earlier safe stage; every forward stage then requires fresh re-entry.
- Unknown external effect blocks retry and closure pending authoritative read-back/manual escalation.
- Agent and Desktop halves remain separately disabled unless the exact stage authorizes each.

## Reporting and response

Report suspected bypass, secret exposure, signature/trust compromise, unauthorized mutation, evidence loss, or reconciliation failure to Security and the Gatekeeper. Freeze effects, preserve evidence, revoke relevant capability/key, advance fencing, and follow `docs/recovery-rollback-runbook.md`. Never repair the ledger directly.

Package/test success grants no installation or activation authority.
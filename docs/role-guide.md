# Role Guide

Owner: Product Governance
Status: repository contract; no role receives production authority from this document.

| Role | Allowed commands/duties | Forbidden actions | Evidence duty | Escalation owner | Outcome test |
|---|---|---|---|---|---|
| Operator | `status`, `preflight-info`, preserve evidence, request gates | install, activate, direct DB edits, infer approval | retain exact receipts/denials | Operations | typed status/denial |
| Product Secretary | observe/classify/monitor and assemble lossless brief | mutate product state or act as Owner | authenticated observation packet | Owner | no mutation path |
| Watchdog / Classifier reviewer | review stage-1 classifier evidence | share Owner credential or review own work | signed eligible review | Gatekeeper | independence verified |
| Project PM | route Flow 1 and own project scope | bypass six-choice gate or cross-product routing | exact routing receipts | Owner | wrong-product denied |
| Recovery / Effects reviewer | assess R0/R1, reconciliation, rollback | broaden scope, retry unknown effect | read-back and budget receipts | Gatekeeper | unknown effect escalates |
| Build / Release reviewer | verify artifact identity, lanes, provenance | production promotion without exact approval | immutable candidate digest | Release Gatekeeper | rebuild invalidates binding |
| Security reviewer | verify identity, trust, sole-writer boundary | create external PASS from fixture | authenticated external evidence | Owner | forged authority denied |
| Independent Auditor | audit immutable scope/evidence when eligible | accept caller JSON/boolean, conflict, self-review | signed verdict, findings/P2/expiry | Gatekeeper | exact digest accepted only |
| Gatekeeper | consolidate eligible evidence and sign acknowledgement | manufacture reviewer/Owner authority | acknowledgement bound to verdict digest | Owner | altered scope denied |
| Operational Owner | handoff, support, narrow operations, retirement duties | silently broaden commands | signed handoff/operations evidence | Owner | unlisted operation denied |
| Evidence Custodian | retention, locator, archive and disposition evidence | alter or delete held evidence | immutable digest/index | Legal/Compliance | hold blocks deletion |
| Owner | exact stage/release/retirement decisions | reusable/general approval | stage-named, expiring signed decision | Owner | wrong/replayed stage denied |

Conflicts, aliases, shared/reused credential families, stale eligibility epochs, and reviewer=Owner produce typed independence/capability denial. Role documentation is advisory; authenticated registries and verifier read-back are authoritative.
# Audit remediation, 8 October 2026

This update repairs the source defects found in the full-plugin audit and adds
native observation support for the current tested Hermes source. It does not
claim autonomous enforcement or production qualification.

## Native integration

The unified bundle uses package-relative imports rather than depending on a
process-wide import-path change. Tools use Hermes's native function schema and
dictionary argument; commands accept raw text and return strings. Observation
captures the profile and Hermes-resolved Kanban board at registration, including
the selected/pinned board. Its native surface needs only the Python standard
library; the full model package retains its declared project dependencies.

`/kanban_workflow on|off|status` controls observation only. It defaults to Off,
persists across fresh processes, checks the exact clean host source and avoids
board reads when disabled. It queries a copied SQLite DB/WAL snapshot, avoiding
source SHM writes. The GUI/CLI controller is included in the unified archive.

Actual Hermes Agent 0.21.5 source
`08165d58931841cee713468ae89032af7c57060a`, Python 3.11.16, was exercised in a
scratch profile: normal loading, status dispatch, all three commands, On/Off,
selected-board counts and state persistence across fresh processes. This is
process-restart evidence; the PC was not physically restarted for testing.

## Durable safety

Command identity is reserved before effect callbacks; changed-payload reuse is
rejected first and uncertain callbacks cannot silently replay. Effect admission
enforces state and attempt budgets before callbacks, and unknown/contradictory
readback cannot authorize a retry. Wake dispatch admission is durable, recovered
wakes revalidate current authority and exact lease/fence, and callback uncertainty
requires reconciliation. Artifact signatures authenticate the complete descriptor;
ephemeral signer verification cannot confer production proof.

Regressions include all nine original audit probes, bounded concurrent callers,
process exits after command/effect admission, wake recovery before admission and
authority/lease changes. Independent review additionally exercises active callback
versus retry, distinct release IDs consuming one queue token, and public ledger
append after an uncertain command. Passing the original probes alone is not
treated as sufficient acceptance.

## Build evidence

Text archive bytes and checksums use canonical LF; binary assets retain exact
bytes. Mandatory package inputs must exist before an archive is written. Full
dist/index generation requires a built wheel; inspection archives may be built
separately. Generated inventory/checksum files use explicit LF bytes on Windows.

Each requested conformance repetition runs in a fresh subprocess and retains its
own outcome. Results explicitly say `isolated-ordered-fixture-tests` and
`worker_interleavings_proven=false`. Ordered fixture execution is not proof of
real worker crash/failover interleavings or external effects.

## Remaining enforcement prerequisites

Full autonomous task execution remains unavailable. The repository does not
provide a qualified authenticated Windows writer service, production signer and
provider authority, or the external Windows/activation evidence required by its
enforcement contract. Existing preflight/activation denials are retained. Fixture
keys, caller flags and local tests must not substitute for those prerequisites.

Uncertain command/wake outcomes deliberately block without automatic retry. A
future writer integration needs an authoritative reconciliation interface; direct
database repair or identity deletion is not an acceptable recovery mechanism.

The original external operative specification was unavailable to the audit.
External acceptance, accessibility and real provider behavior remain unqualified.
The release verdict remains development-only. No installed profile, worker,
external task or production deployment was changed by this source remediation.

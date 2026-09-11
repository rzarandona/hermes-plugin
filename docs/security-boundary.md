# WP5 Security Boundary

## Status and boundary

WP5 repository code is **not installed or activated**. Enforcing topology requires a separately
installed Windows service named `HermesKanbanWriter` running as
`NT SERVICE\HermesKanbanWriter`. The Hermes Agent plugin, Desktop renderer, Watchdog,
Recovery Executor, workers, and any other combined Python/JavaScript process are untrusted
clients. Python imports, object identities, strings, and module-private tokens are not security
boundaries.

Durable workflow mutation belongs only inside the authenticated service process. That process
alone owns the private `%ProgramData%\HermesKanbanWorkflow` state root, SQLite database/WAL/SHM
paths, storage handles, and persistence/DPAPI-NG material. Host/plugin configuration receives
only a local IPC endpoint and public service identity. It must never receive a database path,
Ledger object, storage credential, plaintext secret, or DPAPI-NG unprotect authority.

The checked-in AF_PIPE harness is explicitly **FIXTURE EVIDENCE**. It proves real separate-process
request/receipt behavior and Python's authenticated `multiprocessing.connection` handshake on
this development host. Its temporary database path is created inside the child process and is
not returned. Its symmetric fixture IPC key is test-only and is not the production Windows
identity/ACL design.

## Enforcement preflight

Combined-process mode defaults to `combined-observe-only`; it is never enforcement-ready.
`run_preflight()` never treats a directly supplied profile receipt as host authorization. Missing
or fixture evidence returns `EXTERNAL_WINDOWS_PROFILE_EVIDENCE_REQUIRED`; even a receipt carrying
eligible-looking fields returns `AUTHENTICATED_SERVICE_READINESS_REQUIRED`. A public Python model
is forgeable inside the untrusted plugin process. A future authorized installation must obtain
readiness through authenticated service IPC bound to the service SID and fresh nonce, and the
service must independently validate the OS/hardware-backed attestation before accepting effects.
Caller-supplied `os_backed`/`receipts_signed` booleans are insufficient.
In-memory/fake runner evidence may pass verifier logic, but must carry the label
`FIXTURE EVIDENCE - NOT CLEAN-VM EVIDENCE` and can never become enforcement-eligible.

The sole-writer claim depends on external OS controls, not the repository's historical
`writer_identity` diagnostic string. A caller can import `Ledger` and write a database it owns,
but cannot thereby obtain the service's undisclosed protected database path, service token,
ACL permission, or DPAPI-NG authority. Any topology that distributes those assets is invalid.

## Frozen Windows profile and non-applying verifier

The only supported profile is Windows 11 24H2 x64 build 26100 on NTFS. The required service
account is `NT SERVICE\HermesKanbanWriter`; its resolved service SID is installation-specific.
Only that SID and SYSTEM (`S-1-5-18`) may have write rights. Administrators may have read-only
recovery inspection rights; local administrators remain explicitly inside the trusted computing
base because they can take ownership.

`scripts/verify_windows_profile.py` is intentionally non-applying. It only reads pre-collected
JSON and validates it with `WindowsProfileVerifier`; it does not call `sc.exe`, `icacls`,
PowerShell, DPAPI APIs, service APIs, or ACL APIs. The evidence collector, signed fixture, and
clean-VM execution require separate Owner authorization outside this repository.

The input must evidence all frozen steps:

1. A valid signed writer binary identity, SHA-256 digest, publisher, service name, automatic
   delayed start, and account from the signed package manifest.
2. The resolved SID for `HermesKanbanWriter`, bound to the service account and every later
   receipt.
3. Protected NTFS owner/ACL state for state root, DB, WAL, SHM, policy cache, and DPAPI-NG
   ciphertext, with no inherited or unexpected write principal.
4. Byte-exact normalized SDDL after substituting the resolved service SID; write principals must
   be exactly service SID plus SYSTEM.
5. A positive service-token transaction: create, append receipt, WAL checkpoint, reopen, replay.
6. Access-denied receipts for Hermes Desktop, Watchdog, Recovery Executor, worker, and an
   unprivileged local process for open/create/rename/replace/hard-link/symlink/copy/WAL/SHM and
   DPAPI-NG unprotect.
7. An IPC identity receipt bound to the service SID and signed client executable, plus denial of
   forged token, wrong process SID, replayed handshake, and stale epoch.
8. A non-destructive uninstall rehearsal receipt proving executable authority can be removed
   while retained evidence remains governed separately.

## Authentication, credentials, and rotation

Production IPC must authenticate OS principal/process identity, bind the handshake to a nonce,
client executable signature, policy/authority epoch, and service SID, and reject replay. Caller
strings such as `"HermesKanbanWriter"`, copied tokens, actor fields, or plugin module names are
never authentication. Command authorization then atomically checks the complete canonical
envelope, authenticated actor/role/product/project/target and optional bindings, capability,
policy, authority/fencing epochs, lease, expiry, effect class, reason, hold/disable state, and
precondition. Disable, hold, capability, lease, policy, and fencing state are reloaded immediately
before an effect callback.

Persistence secrets are DPAPI-NG ciphertext protected to the service SID. Rotation creates new
ciphertext/capability versions inside the service, advances policy/authority epochs, verifies a
read-back transaction, then retires the predecessor. Plaintext, old keys, database paths, and
broker credentials must not enter host environments, plugin configuration, logs, prompts,
receipts, or project files.

## Incident assumptions

Unexpected ACL/owner/SDDL, service identity drift, failed DPAPI-NG denial, IPC identity mismatch,
credential/path disclosure, replay, stale epoch, direct-write attempt, or unsigned client is a
security incident. The response is fail closed: disable enforcement, stop accepting effects,
preserve append-only evidence, rotate affected IPC/persistence material, re-establish the exact
profile on a clean host, and require new Owner/security review before re-entry. Product mutation
still returns through Flow 1; incident response cannot expand authority.

## External evidence blocker

No Windows service was installed; no ACL was applied or changed; no service SID or DPAPI-NG
secret was provisioned; no `sc.exe`/`icacls` command was invoked; and no clean Windows 11 24H2
build 26100 NTFS VM run occurred in WP5 repository work. Therefore completion-row 3 remains
**BLOCKED / NOT PASS** until an independent security reviewer receives signed receipts for all
eight frozen steps from the authorized clean VM. Repository tests and fixture evidence must not
be cited as that external pass.

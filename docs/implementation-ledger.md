# Implementation Ledger

## Scope

This cumulative ledger records the implemented WP3, WP4, and WP5 repository work. Each section states its own scope and does not claim completion of any later work package. It records no activation, installation, migration, production access, clean-VM certification, or commit.

All commands ran from `C:/Users/RAINPRO/Documents/Codex/2026-08-26/realtime-voice-chat-3/hermes-kanban-workflow-plugin` with `.venv/Scripts/python.exe`.

## RED → GREEN evidence

1. **Schema validation**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_schema_validation_rejects_unknown_policy_fields -q`
   - Result: exit 4; `ModuleNotFoundError: No module named 'hermes_kanban_workflow.policy.loader'`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.49s`.

2. **Valid Ed25519 signature and public-only runtime material**
   - The first valid-signature assertion passed immediately (`1 passed in 0.26s`) because the preceding schema slice had necessarily introduced successful signature verification. It was strengthened before being accepted as a TDD slice.
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_valid_signature_yields_verified_policy_without_private_material -q`
   - Result: exit 1; `AttributeError: 'VerifiedPolicy' object has no attribute 'is_usable'`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.24s`.

3. **Tamper denial metadata**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_tampered_policy_returns_typed_failure_metadata -q`
   - Result: exit 1; `AttributeError: 'PolicyVerificationError' object has no attribute 'code'`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.28s`.

4. **Expiry and last-known-compatible rollback metadata**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_expired_policy_is_rejected_with_rollback_metadata -q`
   - Result: exit 1; unexpected keyword argument `last_known_compatible_digest`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.25s`.

5. **Unsupported schema version metadata**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_unsupported_schema_version_has_typed_metadata -q`
   - Result: exit 1; received `POLICY_SCHEMA_INVALID` instead of `POLICY_VERSION_UNSUPPORTED`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.30s`.

6. **Authority-weakening denial**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_authority_expansion_is_rejected_without_owner_transition -q`
   - Result: exit 1; unexpected keyword argument `previous_policy`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.26s`.

7. **Exact compatibility tuple**
   - RED: `.venv/Scripts/python.exe -m pytest tests/contract/test_compatibility_gate.py::test_exact_supported_version_tuple_is_accepted -q`
   - Result: exit 4; `ModuleNotFoundError: No module named 'hermes_kanban_workflow.policy.compatibility'`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.15s`.

8. **Mutation-style comparison flips for all four versions**
   - RED: `.venv/Scripts/python.exe -m pytest tests/contract/test_compatibility_gate.py::test_any_version_comparison_flip_fails_closed -q`
   - Result: exit 1; `4 failed`; missing typed `mismatches` metadata for host, plugin, Executor, and policy comparisons.
   - GREEN: same command.
   - Result: exit 0; `4 passed in 0.14s`.

9. **Owner-signed trust-root rotation**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_owner_signed_rotation_advances_trust_epoch_and_preserves_predecessor -q`
   - Result: exit 4; import error for `TrustRootRotationReceipt`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.20s`.

10. **Monotonic trust epoch and last-known-valid readback**
    - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_non_monotonic_rotation_is_denied_without_changing_last_known_valid -q`
    - Result: exit 1; missing `last_known_valid_receipt` readback.
    - GREEN: same command.
    - Result: exit 0; `1 passed in 0.22s`.

11. **Silent restoration of an older root denied**
    - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_previously_seen_root_cannot_be_restored_silently -q`
    - Result: exit 1; expected `TRUST_ROOT_RESTORE_DENIED`, but no exception was raised.
    - GREEN: same command.
    - Result: exit 0; `1 passed in 0.22s`.

12. **Revocation receipt and historical evidence verification**
    - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_revocation_blocks_new_packages_but_preserves_prior_evidence -q`
    - Result: exit 4; import error for `TrustRootRevocationReceipt`.
    - GREEN: same command.
    - Result: exit 0; `1 passed in 0.25s`.

13. **Policy trust-epoch rollback metadata**
    - RED: `.venv/Scripts/python.exe -m pytest tests/unit/policy/test_policy_verification.py::test_policy_trust_epoch_rollback_is_rejected_with_metadata -q`
    - Result: exit 1; expected `PolicyVerificationError`, but no exception was raised.
    - GREEN: same command.
    - Result: exit 0; `1 passed in 0.51s`.

14. **Compatibility recheck before registration callback**
    - RED: `.venv/Scripts/python.exe -m pytest tests/contract/test_compatibility_gate.py::test_registration_rechecks_compatibility_before_host_callback -q`
    - Result: exit 1; `register_observe_only()` did not yet accept a compatibility receipt.
    - GREEN: same command.
    - Result: exit 0; `1 passed in 0.21s`; host callback remained untouched for a forged incompatible receipt.

15. **Fail-closed preflight before activation**
    - RED: `.venv/Scripts/python.exe -m pytest tests/contract/test_compatibility_gate.py::test_preflight_denial_cannot_be_activated -q`
    - Result: exit 1; incompatible policy version incorrectly produced `PreflightReport(passed=True, code='PASS', ...)`.
    - GREEN: same command.
    - Result: exit 0; `1 passed in 0.15s`; activation was denied from the failed preflight.

## Verification gates

- Focused WP3 plus integration:
  - Command: `.venv/Scripts/python.exe -m pytest -W error tests/unit/policy/test_policy_verification.py tests/contract/test_compatibility_gate.py tests/contract/test_hermes_adapter.py -q`
  - Result: exit 0; `25 passed in 0.42s`.

- Initial full gates after focused GREEN:
  - Pytest: exit 0; `46 passed in 1.62s`.
  - Ruff: exit 1; two import-order findings in the WP3-touched contract tests.
  - Strict mypy: exit 1; four argument-narrowing errors in the WP3 compatibility extraction.
  - Only those WP3 regressions were corrected.

- Final full pytest with warnings fatal:
  - Command: `.venv/Scripts/python.exe -m pytest -W error -q`
  - Result: exit 0; `46 passed in 0.38s`.

- Final Ruff:
  - Command: `.venv/Scripts/python.exe -m ruff check .`
  - Result: exit 0; `All checks passed!`.

- Final strict mypy:
  - Command: `.venv/Scripts/python.exe -m mypy --strict src/hermes_kanban_workflow`
  - Result: exit 0; `Success: no issues found in 33 source files`.

No commit was created.

## Independent WP3 remediation

The parent inspection found that the first WP3 candidate still accepted the historical
forgeable `{"signed": true}` mapping in `run_preflight()`. The candidate's passing tests
therefore did not satisfy the cryptographic preflight boundary.

- RED:
  - Command: `.venv/Scripts/python.exe -m pytest tests/contract/test_compatibility_gate.py::test_preflight_rejects_forgeable_boolean_signature_metadata -q`
  - Result: exit 1; the forged mapping returned `PreflightReport(passed=True, code='PASS', ...)`.
- Verified-policy RED:
  - Command: `.venv/Scripts/python.exe -m pytest tests/contract/test_compatibility_gate.py::test_preflight_accepts_cryptographically_verified_policy -q`
  - Result: exit 1; `VerifiedPolicy` was not accepted by the preflight implementation.
- GREEN:
  - `run_preflight()` now rejects every non-`VerifiedPolicy` input with
    `POLICY_VERIFICATION_REQUIRED`, rechecks the verified policy's effective window, and
    reads compatibility only from the cryptographically verified document.
  - Tests construct the accepted path through `load_verified_policy()` using ephemeral
    Ed25519 fixture keys; no private material enters production code or repository files.
  - Command: `.venv/Scripts/python.exe -m pytest tests/unit/policy tests/contract/test_compatibility_gate.py tests/contract/test_hermes_adapter.py -q -W error`
  - Result: exit 0; `27 passed in 0.37s`.

## WP1 pinned-manifest follow-up

An independent read of the pinned Hermes parser found that the initial manifest contract
asserted custom top-level keys which Hermes 0.20.5 ignores with warnings.

- Harness correction: the parser declares `_KNOWN_MANIFEST_FIELDS` with `AnnAssign`; the
  first AST extraction was corrected before accepting RED evidence.
- RED:
  - Command: `.venv/Scripts/python.exe -m pytest tests/contract/test_hermes_adapter.py::HermesAdapterContractTests::test_manifest_top_level_fields_are_recognized_by_pinned_hermes_parser -q`
  - Result: exit 1; unknown top-level fields were exactly `configuration`, `requires`,
    `entrypoint`, `tools`, `commands`, and `fail_closed`.
- GREEN:
  - `plugin.yaml` now uses the pinned parser's recognized `provides_tools`,
    `python_dependencies`, `config_schema`, `capabilities`, `tags`, and `hermes` fields.
    The conventional Python entry point and frozen compatibility/fail-closed metadata remain
    declared under the recognized `hermes` extension field; no installation occurred.
  - Command: `.venv/Scripts/python.exe -m pytest tests/contract/test_hermes_adapter.py::HermesAdapterContractTests::test_manifest_top_level_fields_are_recognized_by_pinned_hermes_parser tests/contract/test_hermes_adapter.py::HermesAdapterContractTests::test_manifest_declares_configuration_and_fail_closed_host_contract -q`
  - Result: exit 0; `2 passed in 0.34s`.

## Current WP1/WP3 checkpoint

- Full warnings-fatal suite: `.venv/Scripts/python.exe -m pytest -q -W error`
  - Result: exit 0; `49 passed in 0.45s`.
- Pinned-host and compatibility contracts after the import-only cleanup:
  - Result: exit 0; `17 passed in 0.32s`.
- Ruff: `.venv/Scripts/ruff.exe check .`
  - Result: exit 0; `All checks passed!`.
- Strict mypy: `.venv/Scripts/mypy.exe`
  - Result: exit 0; `Success: no issues found in 33 source files`.
- `git diff --check`: exit 0; only Git's Windows line-ending advisories were emitted.

## WP4 append-only ledger, receipts, replay, and projection evidence

Scope is WP4 storage correctness only. This section makes no WP5 sole-writer/security claim,
performed no production migration, and used only pytest temporary SQLite databases.

### RED → GREEN tracer slices

1. **Database-level append-only denial**
   - RED: `.venv/Scripts/python.exe -m pytest tests/integration/test_ledger_replay.py::test_database_denies_event_update_and_delete -q`
   - Result: exit 4; `ModuleNotFoundError: No module named 'hermes_kanban_workflow.ledger.schema'`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.32s`.

2. **Public, recorded schema version**
   - RED: `.venv/Scripts/python.exe -m pytest tests/integration/test_ledger_replay.py::test_schema_migration_is_versioned_and_recorded -q`
   - Result: exit 4; `ImportError: cannot import name 'schema_version'`.
   - Test-harness correction: comparing `sqlite3.Row` directly with a tuple produced an unrelated assertion failure; the assertion was corrected to read the named `version` field.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.24s`.

3. **Immutable `CommandReceipt` service result**
   - RED: `.venv/Scripts/python.exe -m pytest tests/integration/test_idempotency.py::test_service_returns_immutable_command_receipt -q`
   - Result: exit 4; `ModuleNotFoundError: No module named 'hermes_kanban_workflow.command.receipts'`.
   - Intermediate implementation failure: Pydantic could not serialize recursively frozen `mappingproxy` payloads; canonical serialization was corrected to thaw payloads explicitly.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.27s`.

4. **Public durable idempotency lookup**
   - RED: `.venv/Scripts/python.exe -m pytest tests/integration/test_idempotency.py::test_lookup_returns_durable_canonical_receipt_bytes -q`
   - Result: exit 1; `AttributeError: 'Ledger' object has no attribute 'lookup_idempotency'`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.41s`.

5. **Changed-payload typed denial metadata**
   - RED: `.venv/Scripts/python.exe -m pytest tests/integration/test_idempotency.py::test_changed_payload_reuse_has_typed_denial -q`
   - Result: exit 1; `IdempotencyIntegrityError` lacked `existing_digest`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.27s`; code remained `IDEMPOTENCY_PAYLOAD_MISMATCH`.

6. **Changed non-payload command typed denial metadata**
   - RED: `.venv/Scripts/python.exe -m pytest tests/integration/test_idempotency.py::test_changed_non_payload_reuse_has_typed_denial -q`
   - Result: exit 1; `existing_digest` was `None` for `IDEMPOTENCY_COMMAND_MISMATCH`.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.27s`.

7. **Checkpointed crash repair**
   - RED: `.venv/Scripts/python.exe -m pytest tests/integration/test_ledger_replay.py::test_crash_after_append_repairs_once_without_duplicate_effects -q`
   - Result: exit 4; `ModuleNotFoundError: No module named 'hermes_kanban_workflow.ledger.projector'`.
   - GREEN: same command after minimal projector implementation.
   - Result: exit 0; `1 passed in 0.39s`.
   - Final strengthened execution uses a spawned process that commits the append then terminates via `os._exit(91)` before projection; result: exit 0, `1 passed in 0.59s`.

8. **Deterministic full rebuild with public checkpoint**
   - RED: `.venv/Scripts/python.exe -m pytest tests/integration/test_ledger_replay.py::test_rebuild_is_pure_deterministic_and_checkpoints_full_replay -q`
   - Result: exit 1; `AttributeError: 'Projector' object has no attribute 'checkpoint'` after two equal pure rebuild results.
   - GREEN: same command.
   - Result: exit 0; `1 passed in 0.27s`.

9. **Transactional schema failure injection**
   - RED: `.venv/Scripts/python.exe -m pytest tests/integration/test_ledger_replay.py::test_failed_schema_migration_leaves_no_partial_schema -q`
   - Result: exit 1; `TypeError: migrate() got an unexpected keyword argument 'before_commit'`.
   - GREEN: same command after migration statements were executed inside one explicit transaction.
   - Result: exit 0; `1 passed in 0.24s`; no partial tables and `user_version == 0` remained.

### Acceptance-only executions

The cross-process 16-worker exact-replay check, append rollback check, ordered iteration
check, database unique-index check, and truthful legacy-row rejection check passed on their
first isolated run after the foundational transaction/schema slices. They are recorded as
acceptance evidence, not misrepresented as fresh RED evidence.

- Cross-process exact replay: `1 passed in 0.71s`; all 16 results were byte-identical and one event row existed.
- Append failure injection rollback: `1 passed in 0.26s`; no idempotency record or event survived.
- Ordered event iteration: `1 passed in 0.31s`; sequence order and `after_sequence` behavior matched.
- Database uniqueness and legacy rejection are included in the final 19-test focused run.

### Final WP4 gates

- Focused WP4 plus compatibility unit:
  - Command: `.venv/Scripts/python.exe -m pytest -W error tests/integration/test_ledger_replay.py tests/integration/test_idempotency.py tests/unit/test_trusted_core.py -q`
  - Result: exit 0; `19 passed in 1.53s`.
- Full warnings-fatal suite:
  - Command: `.venv/Scripts/python.exe -m pytest -W error -q`
  - Result: exit 0; `63 passed in 1.73s`.
- Ruff:
  - Command: `.venv/Scripts/python.exe -m ruff check .`
  - Result: exit 0; `All checks passed!`.
- Strict mypy:
  - Command: `.venv/Scripts/python.exe -m mypy --strict src/hermes_kanban_workflow`
  - Result: exit 0; `Success: no issues found in 36 source files`.
- Diff check:
  - Command: `git diff --check`
  - Result: exit 0; only pre-existing Windows LF→CRLF advisories were emitted.

No commit was created. No WP5 work was started or claimed.

## WP5 guarded command service and repository sole-writer evidence

Scope is WP5 repository behavior only. No Windows service, machine ACL, DPAPI-NG secret,
production IPC identity, migration, activation, or external clean-VM profile was created.

### RED → GREEN tracer slices

1. **Typed named command allowlist**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/command/test_validation.py::test_registry_rejects_duplicate_named_definition -q`
   - Result: exit 4; `ModuleNotFoundError: No module named 'hermes_kanban_workflow.command.registry'`.
   - GREEN: same command; exit 0, `1 passed in 0.23s`.

2. **Exact authenticated envelope validation**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/command/test_validation.py::test_validator_accepts_exact_authenticated_envelope -q`
   - Result: exit 4; `ModuleNotFoundError: No module named 'hermes_kanban_workflow.command.validator'`.
   - GREEN: same command; exit 0, `1 passed in 0.24s`.

3. **Atomic accumulation of semantic denials**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/command/test_validation.py::test_validator_reports_all_atomic_semantic_failures -q`
   - Result: exit 1; `AuthenticatedPrincipal` did not yet accept authenticated target/binding data.
   - GREEN: same command; exit 0, `1 passed in 0.27s`; all actor, role, product,
     project, target, optional binding, executable, capability, policy, authority, expiry,
     fencing, precondition, disable, and hold failures were returned together.

4. **Immediate pre-effect recheck callback**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/command/test_validation.py::test_immediate_pre_effect_recheck_denies_changed_state_before_callback -q`
   - Result: exit 1; `CommandValidator` lacked `recheck_before_effect`.
   - GREEN: same command; exit 0, `1 passed in 0.19s`; a changed disable snapshot denied
     before the effect callback was invoked.

5. **Unregistered command normalized into atomic denial**
   - RED: `.venv/Scripts/python.exe -m pytest tests/unit/command/test_validation.py::test_validator_reports_unregistered_command_as_atomic_denial -q`
   - Result: exit 1; raw `RegistryError: COMMAND_UNREGISTERED` escaped.
   - GREEN: same command; exit 0, `1 passed in 0.20s`; result became
     `CommandValidationError(failures=('COMMAND_UNREGISTERED',))`.

6. **Windows profile logic and fixture/evidence separation**
   - RED: `.venv/Scripts/python.exe -m pytest tests/failure_injection/test_malicious_local_callers.py::test_fixture_profile_validates_logic_but_cannot_enable_enforcement -q`
   - First result: exit 4; missing `command.windows_profile` module.
   - Intermediate RED: exit 1; `run_preflight()` did not accept profile verification output.
   - GREEN: same command; exit 0, `1 passed in 0.27s`; exact fixture data can exercise
     verifier logic but returns `FIXTURE_EVIDENCE_NOT_ENFORCEMENT_ELIGIBLE`, and preflight
     returns `EXTERNAL_WINDOWS_PROFILE_EVIDENCE_REQUIRED`.

7. **Real separate-process authenticated Windows AF_PIPE fixture**
   - RED: `.venv/Scripts/python.exe -m pytest tests/integration/test_sole_writer.py::test_authenticated_ipc_fixture_runs_real_separate_sole_writer_process -q`
   - Result: exit 4; missing `command.ipc` module.
   - GREEN: same command; exit 0, `1 passed in 0.46s`; receipt came from a different PID,
     the service identity receipt was marked fixture evidence, and the private temporary DB path
     was neither returned nor accepted as a client request.

8. **Copied/symlink/private path request denial**
   - RED: `.venv/Scripts/python.exe -m pytest tests/failure_injection/test_malicious_local_callers.py::test_copied_or_symlink_database_path_requests_are_not_ipc_operations -q`
   - Result: exit 1; fixture client lacked an explicit private-storage denial API.
   - GREEN: same command; exit 0, `1 passed in 7.71s`; request failed locally with
     `PRIVATE_STORAGE_REQUEST_DENIED` and service event count remained zero.

9. **Forged external-profile booleans cannot unlock enforcement**
   - RED: `.venv/Scripts/python.exe -m pytest tests/failure_injection/test_malicious_local_callers.py::test_forged_external_evidence_boole_cannot_create_eligible_receipt -q`
   - Result: exit 1; a locally relabeled fixture with `os_backed=True` and
     `receipts_signed=True` incorrectly produced an eligible `PASS` receipt.
   - GREEN: same command; exit 0, `1 passed in 0.27s`; external eligibility now additionally
     requires a separately injected OS/hardware-backed attestation verifier, otherwise the
     receipt returns `EXTERNAL_ATTESTATION_VERIFIER_REQUIRED`.

### Acceptance-only executions

The forged AF_PIPE authentication key denial, required text-field matrix, registered
reason/effect/lease checks, unsigned injected-plugin principal denial, combined-process
observe-only topology, and full exact Windows verifier fixture passed when first run after their
foundational slices. They are acceptance evidence and are not misrepresented as fresh RED runs.
The fixture auth key is symmetric test material and is not production Windows identity evidence.

### Integration correction and final gates

The first full run after enforcing-profile gating returned exit 1 with `3 failed, 71 passed`:
three earlier compatibility tests still expected policy-only preflight success. Those tests were
updated to the stronger WP5 contract (`EXTERNAL_WINDOWS_PROFILE_EVIDENCE_REQUIRED`); the
activation unit test now tests its pure exact-binding function with an explicitly constructed
unit report rather than claiming an OS profile. The next full run passed `74 passed in 2.44s`.

After the complete envelope matrix was added:

- Focused WP5:
  - Command: `.venv/Scripts/python.exe -m pytest -W error tests/unit/command/test_validation.py tests/integration/test_sole_writer.py tests/failure_injection/test_malicious_local_callers.py -q`
  - Result: exit 0; `26 passed in 1.68s`.
- Final full warnings-fatal pytest:
  - Command: `.venv/Scripts/python.exe -m pytest -W error -q`
  - Result: exit 0; `89 passed in 36.01s`.
- Final Ruff:
  - Command: `.venv/Scripts/python.exe -m ruff check .`
  - Result: exit 0; `All checks passed!`.
- Final strict mypy:
  - Command: `.venv/Scripts/python.exe -m mypy --strict src/hermes_kanban_workflow`
  - Result: exit 0; `Success: no issues found in 40 source files`.
- Final diff check:
  - Command: `git diff --check`
  - Result: exit 0; only the pre-existing Windows LF→CRLF advisories were emitted.

### External blocker and acceptance gaps

Completion-row 3 is **BLOCKED / NOT PASS**. No authorized clean Windows 11 24H2 x64 build
26100 NTFS VM run occurred. No signed external receipts exist for service installation, resolved
service SID, signed binary identity, normalized SDDL/owner/ACL, service-token transaction,
negative principals, DPAPI-NG unprotect denial, authenticated production IPC, or uninstall
rehearsal. `scripts/verify_windows_profile.py` is non-applying and was not fed external evidence.
No `sc.exe` or `icacls` command was invoked, no ACL was changed, no service was installed, and
no real secret was provisioned. The repository AF_PIPE run is labeled fixture evidence and must
not be cited as clean-VM proof. Independent security review remains outstanding.

No commit was created. WP6 was not started.

### Independent WP5 attestation-seam remediation

Parent inspection found that host preflight trusted a public, caller-constructible
`WindowsProfileReceipt(enforcement_eligible=True)`. This repeated the earlier Boolean-signature
mistake at a typed-object layer and was not acceptable as OS attestation.

- RED:
  - Command: `.venv/Scripts/python.exe -m pytest tests/failure_injection/test_malicious_local_callers.py::test_caller_constructed_profile_receipt_cannot_pass_host_preflight -q`
  - Result: exit 1; the forged receipt produced `PreflightReport(passed=True, code='PASS', ...)`.
- GREEN:
  - Host-side `run_preflight()` no longer accepts any directly supplied eligible receipt as
    authority. It returns `AUTHENTICATED_SERVICE_READINESS_REQUIRED`; absent/fixture evidence
    continues to return `EXTERNAL_WINDOWS_PROFILE_EVIDENCE_REQUIRED`.
  - A future authorized installation must obtain fresh readiness from authenticated service IPC;
    no such production path is claimed in this repository state.
  - Focused command: `.venv/Scripts/python.exe -m pytest tests/unit/command/test_validation.py tests/integration/test_sole_writer.py tests/failure_injection/test_malicious_local_callers.py -q -W error`
  - Result: exit 0; `27 passed in 2.59s`.

## WP6 durable resource scheduler evidence

Scope is WP6 repository behavior only. Scheduler authority is reconstructed from a versioned,
append-only SQLite event store with update/delete triggers; no persistence credential, external
service, installation, activation, migration, or production state was created.

### RED → GREEN tracer slices

1. **Canonical global resource identity**
   - RED: focused resource test exited 4 with `ModuleNotFoundError` for `domain.resources`.
   - GREEN: exact `resource://<product-or-shared>/<class>/<provider>/<region>/<name>` parsing,
     canonical lowercase segment enforcement, and the normative class allowlist; `1 passed`.
2. **Durable exclusive lease**
   - RED: focused test exited 4 because `HolderBinding`/`LeaseService`/`SchedulerStore` did not exist.
   - GREEN: restarted service read the active lease from durable events and denied the contender
     with `RESOURCE_BUSY`; `1 passed`.
3. **Expiry and fencing**
   - RED: focused test failed because `LeaseService.is_authoritative` did not exist.
   - GREEN: expired replacement advanced the per-resource fencing epoch and invalidated the old
     lease; `1 passed`.
4. **Exact release**
   - RED: focused test failed because `LeaseService.release` did not exist.
   - GREEN: exact lease/holder release appended revocation state and removed active authority;
     `1 passed`.
5. **Conditional renewal**
   - RED: focused test failed because `LeaseService.renew` did not exist.
   - GREEN: renewal requires every recorded condition, advances issued/fencing epochs, and makes
     the prior fence stale; `1 passed`.
6. **Stale-worker release denial**
   - RED: focused test failed because release did not require a fencing epoch.
   - GREEN: an old fence now receives `STALE_FENCING_EPOCH` and cannot release the renewed lease;
     focused stale/release run: `2 passed`.
7. **FIFO durable wait queue**
   - RED: focused test exited 4 because precedence/queue modules did not exist.
   - GREEN: stable UUID wait tokens, visible positions, and FIFO within default priority class
     survived scheduler object restart; `1 passed`.
8. **Cryptographically verified dependency precedence**
   - RED: focused test failed because `PrecedenceModel.from_verified_policy` did not exist.
   - GREEN: dependency edges were read only from a `VerifiedPolicy`; a signed prerequisite moved
     ahead of an earlier dependent in the same class; `1 passed`.
9. **Starvation escalation without authority expansion**
   - RED: focused test failed because `escalate_starved` did not exist.
   - GREEN: durable escalation changed visibility only; priority and exact authority were
     unchanged; `1 passed`.
10. **Non-cancellable preemption**
    - RED: focused collection exited 4 because preemption disposition did not exist.
    - GREEN: a non-cancellable active lease remained authoritative and higher-priority work
      received a wait token instead of an interrupt; `1 passed`.
11. **Trusted fresh wake-up**
    - RED: focused collection exited 4 because `scheduler.wakeup` did not exist.
    - GREEN: release created a new deterministic attempt identity with the new lease fence only
      after policy, exact hold, blocker, workspace, capability, budget, and resource checks;
      `1 passed`.
12. **Lost-release replay repair**
    - RED: replay found the orphaned queue-bound lease but failed with `RESOURCE_BUSY`.
    - GREEN: replay reuses only the exact active lease/holder/wait-token tuple, durably records the
      wake, and starts the fresh fenced attempt once; `1 passed`.
13. **Duplicate wake integrity**
    - RED: exact replay deduped, but the same release ID could be rebound to another resource.
    - GREEN: exact replay returns the original result without a second start; resource rebinding
      receives `DUPLICATE_RELEASE_MISMATCH`; `1 passed`.
14. **Per-resource fencing**
    - RED: renewing resource A produced fence 3 after unrelated resource B advanced its fence.
    - GREEN: A independently advanced from fence 1 to 2; `1 passed`.
15. **Central control-time monotonicity**
    - RED: a release event at control time 99 was accepted after an acquire at 100.
    - GREEN: every scheduler append rejects durable control-time rollback and leaves the lease
      authoritative; `1 passed`.

### Acceptance and randomized evidence

The complete eligibility-denial matrix, unrelated project-hold allowance, capability-superset
non-expansion, default precedence, exact holder work-item/service validation, append-only replay,
and deterministic randomized schedules were acceptance checks enabled by the tracer slices, not
misrepresented as separate RED cycles. Seeds `7`, `19`, `41`, `73`, and `101` randomized 12 queue
arrivals each and preserved priority ordering plus FIFO in class.

### Final WP6 gates

- Focused warnings-fatal WP6: `.venv/Scripts/python.exe -m pytest -W error tests/failure_injection/test_resource_scheduler.py -q`
  - Result: exit 0; `29 passed in 37.36s`.
- Full warnings-fatal suite: `.venv/Scripts/python.exe -m pytest -W error -q`
  - Result: exit 0; `119 passed in 119.49s`.
- Ruff: `.venv/Scripts/python.exe -m ruff check .`
  - Result: exit 0; `All checks passed!`.
- Strict mypy: `.venv/Scripts/python.exe -m mypy --strict src/hermes_kanban_workflow`
  - Result: exit 0; `Success: no issues found in 44 source files`.
- Diff check: `git diff --check`
  - Result: exit 0; only pre-existing Windows LF→CRLF advisories were emitted.

### Honest boundaries and gaps

The append-only scheduler store is repository-local evidence, not the still-blocked WP5 clean-VM
sole-writer proof. `WakeupService` consumes an injected fresh-attempt dispatch boundary; this WP6
repository slice does not claim an installed external writer service or production WP5 IPC wiring.
The existing WP5 clean-Windows evidence blocker remains unchanged. No commit was created and WP7
was not started.

### Independent WP6 post-commit dispatch repair

Parent inspection identified a second crash window: `wake_created` was committed before the
injected fresh-attempt dispatcher ran. If dispatch raised or the process exited, replay returned
the existing wake without retrying it.

- RED:
  - Command: `.venv/Scripts/python.exe -m pytest tests/failure_injection/test_resource_scheduler.py::test_dispatch_failure_retries_same_fresh_attempt_once -q`
  - Result: exit 1; after the first dispatch raised `DISPATCH_CRASH`, restart returned the wake but
    recorded no repaired dispatch.
- GREEN:
  - Successful dispatch now appends a durable `wake_dispatched` marker.
  - A committed wake without that marker is redelivered using the same deterministic attempt ID;
    once marked, subsequent exact replay does not dispatch again.
  - This is at-least-once delivery with a stable downstream dedupe key. A crash after external
    acceptance but before marker commit can redeliver; WP6 does not claim impossible exactly-once
    behavior across an external callback.
  - Specific result: exit 0; `1 passed in 3.41s`.
  - Focused warnings-fatal WP6 after remediation: exit 0; `30 passed in 16.95s`.

## WP7 Flow 1 intake, signed classifier, and owner gate

### RED → GREEN evidence

1. **Wrong-product rejection before effects**
   - RED: focused collection exited 4 with `ModuleNotFoundError` for `flows.flow1`.
   - GREEN: typed `reject_wrong_product` receipt names the correct destination and fixes
     `card_created=False` and `forwarded=False`; `1 passed in 0.19s`.
2. **Cryptographically verified exact classifier row**
   - RED: focused collection exited 4 because `ClassificationFacts` was absent.
   - GREEN: an Ed25519-signed policy loaded through `load_verified_policy()` selected the exact
     normative underscore profile row and granted no authority; `1 passed in 0.30s`.
3. **Missing exact row accountable escalation**
   - Initial assertion passed because the prior slice already failed closed. The test was
     strengthened before acceptance.
   - RED: `ClassificationReceipt` lacked typed accountable evidence roles.
   - GREEN: escalation names `accountable_pm` and `read_only_auditor`; `1 passed in 0.23s`.
4. **Risk/uncertainty denial for bounded work**
   - RED: a signed bounded row incorrectly accepted migration risk.
   - GREEN: migration, protected subsystem, external effect, deployment, material configuration,
     and uncertain dependencies selected/escalated to the safer profile; `6 passed in 1.56s`.
5. **Exact six-choice owner taxonomy**
   - RED: focused collection exited 4 because `OwnerProfileChoice` was absent.
   - GREEN: exactly the six normative typed choices were exposed; `1 passed in 0.19s`.
6. **No default / silence grants nothing**
   - RED: focused collection exited 4 because `OwnerProfileDecisionCommand` was absent.
   - GREEN: omission of `choice` raises typed validation failure; `1 passed in 0.18s`.
7. **Approve grants only the exact proposal**
   - RED: focused collection exited 4 because `record_owner_profile_decision` was absent.
   - GREEN: approve granted only the proposed profile and ignored authority-expanding free text;
     `1 passed in 0.21s`.
8. **Deterministic binding cross-product**
   - RED: focused collection exited 4 because `handle_flow1_intake` was absent.
   - GREEN: 22 deterministic project/workspace/dependency/registry combinations all rejected
     before card creation, forwarding, or authority; `1 passed in 0.44s`.
9. **Any classification uncertainty escalates**
   - RED: an exact signed `design_required` row was incorrectly accepted while dependency facts
     remained uncertain.
   - GREEN: uncertainty now requires accountable PM/read-only-auditor evidence; `1 passed in 0.62s`.
10. **Identity before actionable-content interpretation**
    - RED: `IntakeRequest` attempted string validation of an intentionally uninterpretable content
      sentinel before the wrong-product handler could verify identity.
    - GREEN: intake transports content opaquely across the identity boundary; the wrong-product
      receipt was produced without string/repr access; `1 passed in 0.21s`.

The signed module-limit denial, all five profiles, non-approval denial, canonical immutable replay,
and full matrix assertions were acceptance checks enabled by the tracer slices. The module-limit and
non-approval assertions passed immediately because their behavior was necessarily introduced by the
preceding minimal risk and approve-only implementations; they are not misrepresented as separate RED
cycles.

### Final WP7 gates

- Focused warnings-fatal Flow 1: `.venv/Scripts/python.exe -m pytest -W error tests/integration/flow1 -q`
  - Final result: exit 0; `26 passed in 0.60s`.
- Full warnings-fatal suite: `.venv/Scripts/python.exe -m pytest -W error -q`
  - Final result: exit 0; `146 passed in 12.51s`.
- Ruff: `.venv/Scripts/python.exe -m ruff check .`
  - Initial result: exit 1 after the mypy-only type narrowing used the wrong exception class.
  - Final result: exit 0; `All checks passed!`.
- Strict mypy: `.venv/Scripts/python.exe -m mypy --strict src/hermes_kanban_workflow`
  - Initial result: exit 1; one `Any | None` enum-constructor narrowing error.
  - After narrowing: exit 0; `Success: no issues found in 45 source files`.
- Diff check: `git diff --check`
  - Result: exit 0; only pre-existing Windows LF→CRLF advisories were emitted.

### Honest WP7 boundaries and gaps

The policy fixture uses ephemeral Ed25519 keys and proves the repository verification path; it is not
a production trust root. The pure typed handlers and canonical receipts are suitable for invocation
behind the existing guarded service, but this WP7 repository slice does not install or activate an
external writer service. The WP5 clean-Windows sole-writer blocker remains unchanged. No commit was
created, no external state changed, and WP8 was not started.

### Independent WP7 proposal-binding remediation

Parent inspection found that `record_owner_profile_decision()` trusted the command's
caller-supplied `proposed_profile`. The decision was not bound to the immutable classifier receipt,
so a caller could relabel a broader profile as the proposal.

- RED:
  - Command: `.venv/Scripts/python.exe -m pytest tests/integration/flow1/test_owner_gate.py::test_owner_approval_denies_caller_forged_proposed_profile -q`
  - Result: exit 1; `classification_digest` was rejected as an unknown field, proving no proposal
    binding existed.
- GREEN:
  - The owner command and receipt now carry the exact classification digest.
  - The handler requires the classification receipt and denies digest/profile mismatch with
    `OWNER_PROFILE_PROPOSAL_MISMATCH` before granting anything.
  - Specific result: exit 0; `1 passed in 0.20s`.
  - Focused Flow 1 after remediation: exit 0; `27 passed in 0.43s`.

## WP8 Flow 2 execution, review, QA, identity, and bounded recovery

Scope is Task 8 only. This section records repository-testable Flow 2 boundaries and does not
claim WP5 clean-VM completion, installation, activation, external authority, production effects,
or WP9 work.

### RED → GREEN tracer evidence

1. **Stable card / fresh attempt bindings**
   - RED: focused collection exited 4 with `ModuleNotFoundError` for `flows.flow2`.
   - GREEN: stable card plus fresh run, fence, scratch, exact workspace, and resource bindings;
     `1 passed in 0.14s`.
2. **Immutable orthogonal run projections**
   - RED: focused collection exited 4 because `RunHealth` and the other projections were absent.
   - GREEN: immutable lifecycle/health/result values; `1 passed in 0.21s`.
3. **Superseded late-update denial**
   - RED: `AttributeError` for missing `accept_update`; exit 1.
   - GREEN: `SUPERSEDED_RUN_UPDATE_DENIED`; `1 passed in 0.18s`.
4. **Two-minute acknowledgement and typed never-started incident**
   - RED: focused collection exited 4 because `NeverStartedIncident` was absent.
   - GREEN: 121 seconds without acknowledgement returns the typed 120-second incident;
     `1 passed in 0.20s`.
5. **Verified signed, known-run cold-start exception**
   - RED: first `policy` call failed with an unexpected keyword; after the initial GREEN, the
     adversarial unlisted-run assertion failed because the exception was global.
   - GREEN: only a cryptographically verified policy row naming the run grants 300 seconds;
     final focused result `1 passed in 1.29s`.
6. **Lease presence is not progress**
   - RED: focused collection exited 4 because `ProgressTracker` was absent.
   - GREEN: heartbeat changed lease presence without changing milestone/time, health, blocker,
     next action, or owner; `1 passed in 0.18s`.
7. **Typed milestones**
   - RED: focused collection exited 4 because `Milestone` was absent.
   - GREEN: free-form milestones deny with `TYPED_MILESTONE_REQUIRED`; `1 passed in 0.23s`.
8. **Mandatory separate implementer verification**
   - RED: focused collection exited 4 because `SelfVerification` was absent.
   - GREEN: TDD, tests, static checks, acceptance comparison, and evidence are mandatory while
     the packet remains explicitly non-independent; `1 passed in 0.18s`.
9. **Two blind independent baseline reviews**
   - RED: focused collection exited 4 because `ReviewSubmission` was absent.
   - GREEN: two sealed PASS reviews cover correctness and risk without peer-verdict visibility;
     `1 passed in 0.18s`.
10. **Signed specialist and PM add-only lenses**
    - RED: focused collection exited 4 because `select_review_lenses` was absent.
    - GREEN: signed component/dependency/protected/risk lenses plus PM additions preserve both
      mandatory lenses; `1 passed in 0.74s`.
11. **Authenticated identity issuance and alias resolution**
    - RED: focused collection exited 4 because `AuthMethod` and identity authority types were absent.
    - GREEN: WebAuthn humans and OIDC workloads resolve aliases to canonical subject/controller;
      `1 passed in 0.19s`.
12. **Identity lifecycle and authority epochs**
    - RED: missing `transition`; exit 1.
    - GREEN: suspend/reinstate/expire/revoke events advance epochs and stale authentication denies;
      `1 passed in 0.19s`.
13. **Credential-family rotation lineage and reuse denial**
    - RED: missing `rotate_credential_family`; exit 1.
    - GREEN: immutable lineage is retained and cross-subject family reuse denies; `1 passed in 0.21s`.
14. **Eligibility, conflict declaration, and immutable assignment provenance**
    - RED: focused collection exited 4 because `assign_reviewer` was absent.
    - GREEN: authenticated project reviewer role and declared conflict state produce frozen
      provenance; `1 passed in 0.21s`.
15. **Adversarial reviewer independence**
    - RED: focused collection exited 4 because `assert_review_independence` was absent.
    - GREEN: duplicate subject/alias, controller/delegation, credential family, unresolved
      relationship, implementer/PM, and Gatekeeper relationships deny; `6 passed in 0.19s`.
16. **Authenticated sealing provenance**
    - RED: focused collection exited 4 because `seal_authenticated_reviews` was absent.
    - GREEN: sealed review IDs consume exact immutable assignment provenance; `1 passed in 0.24s`.
17. **Candidate-bound typed Gatekeeper verdict**
    - RED: focused collection exited 4 because `review.gatekeeper` was absent.
    - GREEN: typed `PASS` remained bound to the immutable candidate digest; `1 passed in 0.23s`.
18. **Material-change invalidation**
    - RED: focused collection exited 4 because `ChangeKind` was absent.
    - GREEN: material test change returns to Implementer and invalidates review evidence;
      `1 passed in 0.18s`.
19. **Enumerated QA packet**
    - RED: focused collection exited 4 because `review.qa` was absent.
    - GREEN: each journey carries steps, expected result, evidence, responsible reviewer, and
      pass/fail/escalation routes; `1 passed in 0.19s`.
20. **R0/R1/R2/R3/unknown classification**
    - RED: focused collection exited 4 because `recovery.classes` was absent.
    - GREEN: unknown classifies fail-closed as R3 with `known=False`; `1 passed in 0.20s`.
21. **One-retry default and signed narrowing**
    - RED: focused collection exited 4 because `recovery.budget` was absent.
    - GREEN: default one automatic recovery; verified policy may narrow to zero; `1 passed in 0.32s`.
22. **Allowlisted R1 exact retry bindings and real reacquisition callback**
    - RED: focused collection exited 4 because `recovery.executor` was absent.
    - GREEN: fresh run/fence/scratch, exact workspace, callback-verified reacquisition, and consumed
      budget; `1 passed in 0.30s`.
23. **Separately authorized and verified R2 compensation**
    - RED: constructor rejected the separate authorization callbacks; exit 1.
    - GREEN: named compensation consumed separate authority and verification boundaries;
      `1 passed in 0.25s`.
24. **Typed R3 and unknown denial**
    - The initial broad assertion passed because the preceding generic eligibility gate already
      denied both; it was strengthened before acceptance.
    - RED: generic `AUTOMATIC_RECOVERY_FORBIDDEN` did not match typed R3/unknown denial codes.
    - GREEN: `R3_RECOVERY_FORBIDDEN` and `UNKNOWN_RECOVERY_FORBIDDEN`; `1 passed in 0.21s`.
25. **Authoritative effect reconciliation**
    - RED: a caller-asserted reconciliation string incorrectly permitted retry; exit 1.
    - GREEN: partial/unknown effects require an authoritative verifier bound to the prior run;
      `1 passed in 0.21s`.
26. **Gatekeeper evidence provenance is authority-verified**
    - RED: caller-asserted self-verification, review IDs, and evidence produced `PASS`; exit 1.
    - GREEN: Gatekeeper defaults fail-closed and only evaluates PASS through an injected
      authoritative verifier bound to the complete candidate packet; `1 passed in 0.19s`.

### Final WP8 gates

- Focused warnings-fatal Flow 2:
  `.venv/Scripts/python.exe -m pytest -W error tests/integration/flow2 -q`
  - Result: exit 0; `31 passed in 0.28s`.
- Full warnings-fatal suite: `.venv/Scripts/python.exe -m pytest -W error -q`
  - Initial collection exposed duplicate bare test-module naming; package markers were added.
  - Final result: exit 0; `178 passed in 5.30s`.
- Ruff: `.venv/Scripts/python.exe -m ruff check .`
  - Initial result: exit 1; one mutable config and four import-order findings.
  - Final result: exit 0; `All checks passed!`.
- Strict mypy: `.venv/Scripts/python.exe -m mypy --strict src/hermes_kanban_workflow`
  - Result: exit 0; `Success: no issues found in 51 source files`.
- Diff check: `git diff --check`
  - Result: exit 0; only pre-existing Windows LF→CRLF advisories were emitted.

No commit was created. The WP5 external clean-VM blocker remains unchanged. WP9 was not started.

### Independent WP8 blind-review remediation

Parent inspection found that review sealing trusted the caller-supplied Boolean
`saw_peer_verdict=False`. That assertion did not prove the system withheld the peer verdict.

- RED:
  - Command: `.venv/Scripts/python.exe -m pytest tests/integration/flow2/review/test_review.py::test_caller_asserted_blindness_boolean_is_not_seal_evidence -q`
  - Result: exit 4 at collection because `BlindReviewSession` did not exist; no system-controlled
    submission sequence was available.
- GREEN:
  - `BlindReviewSession` binds one candidate and records the exact immutable submissions one at a
    time without returning peer content.
  - Duplicate review IDs, assignments, reviewer subjects, extra submissions, candidate mismatch,
    and caller-admitted peer visibility deny.
  - Both sealing functions now require the session to attest the exact ordered pair; the Boolean
    alone returns `AUTHENTICATED_BLIND_REVIEW_SESSION_REQUIRED`.
  - Specific result: exit 0; `1 passed in 0.22s`.
  - Review and identity subset after remediation: exit 0; `15 passed in 2.09s`.
  - This is repository-level service state pending the external WP5 writer boundary; it does not
    claim protection from a malicious in-process host.

## WP9 Flow 3 immutable artifact, release, rollback, and handoff

Scope is Task 9 only. The implementation uses immutable repository commands/receipts and injected
reconciliation callbacks; it performed no deployment, signing-service call, installation,
activation, or external-system access. Ephemeral Ed25519 fakes are explicitly marked
`production_proof=False`. The unresolved WP5 clean-Windows evidence blocker is unchanged.

### RED → GREEN tracer evidence

1. **Exact immutable artifact identity and signature**
   - RED: focused collection exited 4 because `adapters.artifact_store` did not exist.
   - GREEN: exact length-framed payload, source, provenance, test, dependency, configuration, SBOM,
     and signature bytes produce one content identity and immutable build receipt; `1 passed`.
2. **Exact immutable production Owner approval**
   - RED: focused collection exited 4 because `flows.flow3` did not exist.
   - GREEN: registry-issued Ed25519 approval binds the complete release tuple; `1 passed`.
3. **Approval single use**
   - RED: the same approval was accepted twice.
   - GREEN: second consumption denies with `OWNER_APPROVAL_ALREADY_USED`; `1 passed`.
4. **Approval mismatch denial**
   - RED: all seven artifact/environment/configuration/policy/strategy/rollback/emergency mutations
     were accepted.
   - GREEN: every mutation denies with `OWNER_APPROVAL_BINDING_MISMATCH`; `7 passed`.
5. **Approval expiry**
   - RED: an approval was accepted at its exclusive expiry bound.
   - GREEN: it denies with `OWNER_APPROVAL_EXPIRED`; `1 passed`.
6. **Progressive rollout default**
   - RED: typed rollout models and selector were absent.
   - GREEN: progressive is selected by default where supported; `1 passed`.
7. **Atomic technical-unavailability evidence**
   - RED: atomic rollout was accepted without evidence.
   - GREEN: only a recorded technical-unavailability reference permits atomic; `1 passed`.
8. **Automatic health-gate pause**
   - RED: rollout evaluation returned an untyped Boolean and did not expose pause state.
   - GREEN: a typed failing gate returns `HEALTH_GATE_FAILED_AUTOMATIC_PAUSE`; `1 passed`.
9. **Injected authenticated effect reconciliation**
   - RED: focused collection exited 4 because `adapters.effects` did not exist.
   - GREEN: immutable effect commands are accepted only through injected reconciliation and an
     exact receipt verifier; the repository receipt remains fixture-only; `1 passed`.
10. **Signed objective automatic rollback**
    - RED: rollback policy/observation/decision models were absent.
    - GREEN: exact signed policy plus authenticated threshold observation, proven reversibility,
      and bounded collateral risk permits automatic rollback; `1 passed`.
11. **Independent closeout and explicit operational acceptance**
    - RED: production verification, rollback-readiness, and owner-acceptance registries were absent.
    - GREEN: closeout binds independent verification, authenticated readiness recheck, recomputed
      durable-evidence digest, and exact registry Owner acceptance; `1 passed`.
12. **Emergency lane preserves release gates**
    - RED: no promotion-command boundary existed.
    - GREEN: emergency commands use the same artifact signature, exact approval, lease, health,
      verification, and rollback-readiness checks; `1 passed`.
13. **Managed production signing interface**
    - RED: the ephemeral adapter lacked a production key descriptor.
    - GREEN: the interface models managed, non-exportable, hardware-backed key properties while the
      repository fake remains explicitly non-production proof; `1 passed`.
14. **Authenticated health-gate provenance**
    - RED: the promotion boundary rejected the new verifier argument because it had no provenance
      seam.
    - GREEN: every typed health gate must pass the injected authoritative verifier; `1 passed`.
15. **Immutable build receipt**
    - RED: `SignedArtifact` lacked `build_receipt`.
    - GREEN: the receipt binds artifact ID, material digest, signing key, and root class; `1 passed`.
16. **Exact manual rollback artifact binding**
    - RED: an Owner approval for `artifact-b` authorized manual rollback of `artifact-a`.
    - GREEN: the release binding must match the requested artifact and rollback contract before the
      single-use Owner approval is consumed; `1 passed`.

Adversarial forged Owner/effect receipts, unsafe/forged rollback metadata, approval reuse and exact
mismatches, material-rebuild verification invalidation, expired/wrong-artifact signing capabilities,
silence/forged Operational Owner strings, lower-root separation, and fixture-proof labeling are
covered by acceptance tests. They passed when first run after their foundational tracer slices and
are not misrepresented as additional RED cycles.

### Final WP9 gates

- Focused warnings-fatal Flow 3:
  `.venv/Scripts/python.exe -m pytest -W error tests/integration/flow3 -q`
  - Result: exit 0; `28 passed in 0.19s`.
- Full warnings-fatal suite:
  `.venv/Scripts/python.exe -m pytest -W error -q`
  - Result: exit 0; `207 passed in 4.70s`.
- Ruff: `.venv/Scripts/python.exe -m ruff check .`
  - Result: exit 0; `All checks passed!`.
- Strict mypy: `.venv/Scripts/python.exe -m mypy --strict src/hermes_kanban_workflow`
  - Result: exit 0; `Success: no issues found in 54 source files`.
- Diff check: `git diff --check`
  - Result: exit 0; only pre-existing Windows LF→CRLF advisories were emitted.

No commit was created. No WP10 work was started. No production or external effect occurred, and no
WP5 completion is claimed.

### Independent WP9 production-proof transition remediation

Parent inspection found that a repository-only production signing fake correctly produced
`production_proof=False`, but the resulting `PromotionCommand` could still be converted into an
`EffectCommand`.

- RED:
  - Command: `.venv/Scripts/python.exe -m pytest tests/integration/flow3/test_promotion.py::test_emergency_lane_preserves_signature_owner_verification_and_rollback_gates -q`
  - Result: exit 1; `command.as_effect_command()` did not raise for the fixture production command.
- GREEN:
  - Fixture production promotion commands remain constructible for gate inspection but deny effect
    conversion with `PRODUCTION_PROOF_REQUIRED`.
  - Lower-environment fixture testing remains available; no repository fake gains production
    execution authority.
  - Specific result: exit 0; `1 passed in 0.17s`.
  - Focused Flow 3 after remediation: exit 0; `28 passed in 0.19s`.

## WP10 Flow 4 operations, incidents, restoration, and retirement

Scope is Task 10 only. The implementation adds immutable repository-testable controls for versioned
Owner-approved objectives, five-source health, actionable deduplicated alerts, typed incidents,
scoped response, independent closure, Problem Records, operational-change routing, restoration
drills, and exact Owner-controlled retirement. It performs no operational effect, installation,
activation, or external-system access and does not claim the unresolved WP5 clean-Windows evidence.

### Recovered RED → GREEN evidence

The delegated writer process exited before producing a terminal report, but its append-only
transcript and live files preserved the completed cycles. Parent recovery verified rather than
assuming completion.

- Objective approval, five independent health-source evidence, actionable alert dedupe, signed
  severity, scoped responder commands, complete independent closure, Flow 1 material-change routing,
  non-retroactive reconciliation, restoration proof, exact retirement approval, unresolved-item
  retention, Problem Records, full retirement staging, and retained-secret rejection each show a
  missing-capability or failing-assertion RED followed by a specific passing GREEN in
  `deleg_4057815a/task-0.log`.
- The worker's last recorded focused checkpoint before additional adversarial tests was
  `67 passed in 0.69s`; those later tests were therefore treated as unverified candidate changes.

### Parent recovery and independent remediations

1. **Complete objective sets before Owner signature**
   - RED: fresh focused Flow 4 run failed
     `test_incomplete_objective_set_cannot_be_owner_approved`; an all-empty objective set was signed.
   - GREEN: approval now requires service/version, indicators with positive targets, positive error
     budget, criticality, and review triggers. An empty exclusions tuple remains the valid declaration
     of no exclusions.
   - Specific result: `1 passed in 0.18s`; recovered focused suite then reached `84 passed`.
2. **Retirement cannot use generic operational capability**
   - RED: `test_generic_operational_capability_cannot_authorize_owner_only_retirement` exited 1
     because a generic signed narrow capability authorized retirement.
   - GREEN: `OperationalBoundary` now denies that transition with
     `OWNER_RETIREMENT_APPROVAL_REQUIRED`; only `RetirementLifecycle.begin()` can consume the exact,
     current, single-use Owner retirement approval.
   - Specific result: `1 passed in 0.17s`; focused Flow 4 result `85 passed in 0.30s`.

### Final WP10 gates

- Focused warnings-fatal Flow 4:
  `.venv/Scripts/python.exe -m pytest tests/integration/flow4 -q -W error`
  - Result: exit 0; `85 passed in 0.30s`.
- Full warnings-fatal suite: `.venv/Scripts/python.exe -m pytest -q -W error`
  - Result: exit 0; `292 passed in 9.78s`.
- Ruff: `.venv/Scripts/ruff.exe check .`
  - Result: exit 0; `All checks passed!`.
- Strict mypy: `.venv/Scripts/mypy.exe`
  - Result: exit 0; `Success: no issues found in 56 source files`.
- Diff check: `git diff --check`
  - Result: exit 0; only pre-existing LF→CRLF advisories were emitted.

No commit was created. No WP11 work or external effect occurred.

## WP11 cross-flow security-response overlay

Scope is Task 11 only. Security response is implemented as an immutable cross-flow overlay over
Flow 1-4 records, never a fifth flow. Repository-local Ed25519 authorities are explicitly
`production_authority=False`; every command receipt records `effect_executed=False`, so these
fixtures cannot claim production security authority or bypass the unresolved WP5 boundary. No
external access, activation, installation, effect, or commit occurred.

### RED → GREEN tracer evidence

1. **Immutable least-disclosure case entry from Flow 1-4**
   - RED: focused collection exited 4 with `ModuleNotFoundError` for `flows.security_overlay`.
   - GREEN: immutable cases preserve exact origin/evidence identity, route only to the minimum
     response roles, grant no authority on entry, and reject Flow 5; `4 passed` for the flow matrix.
2. **Deterministic concurrent one-case creation**
   - RED: `SecurityCaseStore` rejected the bounded pre-create rendezvous seam.
   - GREEN: both synchronized callers reached the critical boundary and received the same object;
     durable in-process count remained one; `1 passed`.
3. **Complete cryptographically verified contract**
   - RED: collection exited 4 because `SecurityContractTerms` did not exist.
   - GREEN: canonical Ed25519 signing binds all named roles/routes, five command classes, scopes,
     evidence rules, communication approvers, verifier, risk owner, and hand-back recipient;
     `1 passed`.
4. **Exact single-purpose capability**
   - RED: collection exited 4 because `SecurityCommandRequest` did not exist.
   - GREEN: capability binds contract/case/subject/command/scope/evidence/expiry/epoch/nonce,
     remains fixture-only, records no effect, and denies second use; `1 passed`.
5. **Bounded visible containment**
   - RED: `issue_containment_plan` was absent.
   - GREEN: signed plans require exact command/scope, technical-PM visibility, exclusive expiry,
     and a linked `flow1:delivery-request` while never authorizing lasting change; `1 passed`.
6. **Independent closure and accepted exact hand-back**
   - RED: closure and hand-back authority types were absent at collection.
   - GREEN: explicit close verifies independent containment/restoration, preserved evidence,
     residual-risk ownership, lasting-change Flow 1 request, complete immutable hand-back, and
     signed registered-recipient acceptance; `1 passed`.
7. **Authority-epoch revocation**
   - RED: a revoked epoch still verified its signed contract.
   - GREEN: contract and already-issued capability verification fail closed for revoked epochs;
     `1 passed` for the specific contract regression.
8. **Communication approval gate**
   - RED: disclosure succeeded without any approval.
   - GREEN: disclosure requires an exact authority-issued, signed, bounded approval; the negative
     regression and approved route each passed (`1 passed` each).

The complete-field matrix and adjacent adversarial cases passed after their foundational tracer
slices and are recorded as acceptance coverage rather than misrepresented RED cycles. They cover
missing/stale/wrong-policy contracts, ordinary-role non-inheritance, forged caller receipts,
self-expansion, broader replay, unauthorized evidence, expiry/revocation, forged containment,
missing/forged communication approval, incomplete closure, silence/forged acceptance, immutable
origin mismatch, Flow 5 rejection, and fixture production-proof separation.

### Final WP11 gates

- Focused warnings-fatal security/failure suite:
  `.venv/Scripts/python.exe -m pytest -W error tests/integration/security tests/failure_injection/test_security_authority.py -q`
  - Result: exit 0; `63 passed in 0.22s`.
- Full warnings-fatal suite: `.venv/Scripts/python.exe -m pytest -W error -q`
  - Result: exit 0; `355 passed in 5.01s`.
- Ruff: `.venv/Scripts/ruff.exe check .`
  - Result: exit 0; `All checks passed!`.
- Strict mypy: `.venv/Scripts/mypy.exe`
  - Result: exit 0; `Success: no issues found in 57 source files`.
- Diff check: `git diff --check`
  - Result: exit 0; only pre-existing LF→CRLF advisories were emitted.

No commit was created. No WP12 work or external effect occurred. The WP5 external blocker remains.

### Independent WP11 closure-evidence remediation

Parent inspection found that `IndependentClosureAuthority.verify_closure()` accepted caller-supplied
`containment_verified=True` and `restoration_verified=True` and signed those booleans without
reading independent evidence.

- RED:
  - Command: `.venv/Scripts/python.exe -m pytest tests/failure_injection/test_security_authority.py::test_caller_asserted_restoration_booleans_are_not_independent_closure_evidence -q`
  - Result: exit 1 because the caller's two `True` values produced a signed closure proof.
- GREEN:
  - The closure authority now requires injected containment and restoration verifiers plus non-empty
    evidence references, each bound to the exact `SecurityCase`.
  - Caller booleans may only narrow a proof (`False` remains false); they cannot expand authority.
  - Missing verifiers or evidence deny with `INDEPENDENT_CLOSURE_EVIDENCE_REQUIRED`.
  - Specific result: exit 0; `1 passed in 0.17s`.
  - Focused security/failure suite after remediation: exit 0; `64 passed in 0.23s`.

## WP12 secrets, reporting, artifact locators, and accessibility contracts

Scope is Task 12 only. No secret service, external host action, deployment, installation, manual
assistive-technology session, activation, or commit occurred. Repository fixture authorities remain
`production_eligible=False` and cannot satisfy the unresolved WP5 external boundary.

### RED → GREEN tracer evidence

1. **Ephemeral opaque-reference resolution**
   - RED: focused collection exited 4 because `adapters.secret_broker` did not exist.
   - GREEN: the injected authority resolves only an opaque reference inside a consumer callback;
     immutable receipts contain only reference identity and outcome; `1 passed`.
2. **Runtime opaque-reference boundary**
   - RED: a raw string reached the authority and returned the wrong denial.
   - GREEN: non-reference input denies with `TRUSTED_OPAQUE_SECRET_REFERENCE_REQUIRED`; `1 passed`.
3. **Trusted disposable local fixture display**
   - RED: collection failed because fixture context and metadata authority types did not exist.
   - GREEN: signed metadata, exact `disposable_non_secret` classification, local-only context,
     one-time removal, and fixture-only production ineligibility are enforced.
4. **Secret-safe failures**
   - RED: consumer and authority exceptions exposed injected canary values in exception messages.
   - GREEN: both paths cross the broker boundary only as `SECRET_USE_FAILED` or
     `SECRET_RESOLUTION_FAILED`, with suppressed causes and no canary value.
5. **Immutable technical packet and PM route**
   - RED: collection exited 4 because `reporting.technical_packet` did not exist.
   - GREEN: typed verdict, evidence annex, accountability, technical route, and lossless summary
     route remain immutable and unchanged.
6. **Exact six-field OwnerBrief**
   - RED: the prototype lacked typed verification truth and the six-field constructor.
   - GREEN: the six owner fields retain unchanged verdict, accountability, packet link, visible
     risk, and locator summaries; FAIL is always visibly prefixed. A bounded compatibility adapter
     preserves the prior prototype call without changing the new six dataclass fields.
7. **CONF-18-24-ARTIFACT-LOCATOR**
   - RED: collection exited 4 because the locator module did not exist.
   - GREEN: exact identity/label/canonical locator is required; only declared and verified
     `open_artifact` or `show_in_file_explorer` is invoked. Missing, failed, mismatched, or
     false-success receipts return `ARTIFACT_LOCATOR_UNSUPPORTED`, preserve locator/manual route,
     and block readiness.
8. **Fixed environment and accessibility contracts**
   - RED: accessibility contract imports were absent.
   - GREEN: the exact fixed matrix, Python >=3.11,<3.14 range, every named surface, semantic and
     keyboard contracts, focus/announcement/non-color/zoom/narrow/table/contrast/reduced-motion
     properties, and typed missing-capability fallback are automated. Every unlisted matrix value
     is `ENVIRONMENT_UNSUPPORTED`.

Adjacent acceptance coverage includes forged opaque references, forged signed fixture metadata,
remote/shared/deployment/production fixture denial, nine-channel canary leakage scans, single-use
fixture removal, incidental implementation-noise omission, unchanged failure verdicts, Explorer
fallback, undeclared/unverified actions, forged host false-success, and all five missing host
capabilities. The manual checklist script was executed only to verify it reports `UNEXECUTED` and
`release_ready: false`; it makes no actual assistive-technology claim.

### Final WP12 gates

- Focused warnings-fatal WP12 suite:
  `.venv/Scripts/python.exe -m pytest -W error tests/integration/test_secret_boundary.py tests/integration/test_owner_reporting.py tests/contract/test_accessibility_contract.py -q`
  - Result: exit 0; `51 passed in 0.21s`.
- Full warnings-fatal suite: `.venv/Scripts/python.exe -m pytest -W error -q`
  - First run exposed the replaced prototype import expected by an earlier integration contract.
    A bounded compatibility view was restored without altering the six-field WP12 model.
  - Final result: exit 0; `407 passed in 19.90s`.
- Ruff: `.venv/Scripts/ruff.exe check .`
  - Result: exit 0; `All checks passed!`.
- Strict mypy: `.venv/Scripts/mypy.exe`
  - Result: exit 0; `Success: no issues found in 60 source files`.
- Diff check: `git diff --check`
  - Result: exit 0; only pre-existing LF→CRLF advisories were emitted.

No commit was created. No WP13 or external access occurred. The WP5 external blocker and manual
assistive-technology evidence remain incomplete and are not reported as PASS.

### Independent WP12 accessibility release-honesty remediation

Parent inspection found that `assess_accessibility_surface()` returned `release_ready=True` when a
caller supplied five capability booleans, even though actual manual assistive-technology evidence
remained explicitly `UNEXECUTED`.

- RED:
  - Command: `.venv/Scripts/python.exe -m pytest tests/contract/test_accessibility_contract.py::test_caller_capability_booleans_cannot_claim_manual_at_release_readiness -q`
  - Result: exit 1 because the caller-constructible capability set produced release readiness.
- GREEN:
  - `ACCESSIBILITY_CONTRACT_READY` now means only that the automated contract and declared host
    capability checks are ready.
  - The outcome remains `release_ready=False` and states that manual assistive-technology evidence
    is required; no caller Boolean can synthesize that evidence.
  - Specific result: exit 0; `1 passed in 0.15s`.
  - Focused WP12 suite after remediation: exit 0; `52 passed in 0.19s`.

## WP13 holds, recovery kill switch, failover, and attributed evaluation

Scope is Task 13 only. The first sole writer exited before returning a terminal result. Parent
forensics preserved its coherent RED→GREEN candidate and resumed at its exact missing reliability
policy verifier RED. No second overlapping writer, commit, external effect, installation, activation,
or production claim occurred. Repository signing keys remain fixtures and do not satisfy WP5.

### Recovered RED → GREEN tracer evidence

1. **Recovery-only disable**
   - RED: focused collection exited 4 because `recovery.supervisor` was absent.
   - GREEN: exact signed capability revocation advances fencing while preserving Watchdog/ledger
     visibility; `1 passed in 0.15s`.
2. **Exact project hold and checkpointing**
   - RED: hold command/store types were absent at collection.
   - GREEN: immutable exact membership is checkpointed, new dispatch is stopped, affected members
     become truthfully Blocked, and unrelated work is unchanged; `1 passed in 0.22s`.
3. **Fresh eligible-only resume**
   - RED: resume command did not exist.
   - GREEN: resume binds the same hold and membership, uses a newer fence and fresh attempt IDs, and
     excludes unrelated, independently blocked, and intentionally held work; `1 passed in 0.15s`.
4. **In-flight reconciliation without external authority**
   - RED: disable did not reconcile the injected in-flight effect.
   - GREEN: the effect becomes `reconciled-no-external-action` and no external action is recorded;
     `1 passed in 0.20s`.
5. **Deterministic active-passive failover**
   - RED: role failover types were absent at collection.
   - GREEN: two synchronized candidates produce one winner only after authoritative reconciliation,
     advance the epoch, and reject the stale leader; `1 passed in 0.18s`.
6. **Daily evidence-bearing exceptions**
   - RED: evaluation modules were absent at collection.
   - GREEN: daily role/dimension exceptions carry immutable evidence, sample size, and confidence;
     `1 passed in 0.14s`.
7. **Complete weekly measurement window**
   - RED: an incomplete seven-day dimension set produced trends.
   - GREEN: incomplete windows deny with `MEASUREMENT_WINDOW_INCOMPLETE`; `1 passed in 0.13s`.
8. **Signed reliability policy and schema**
   - RED: collection exited because the reliability verifier and schema were absent.
   - GREEN: canonical Ed25519 verification binds every planned threshold field, validity window,
     policy anti-rollback, exact host/workload/evaluator compatibility, and fixture-only scenarios;
     initial policy suite `12 passed in 0.17s`.

### Independent WP13 authority and evidence remediations

1. **Caller self-issued Owner key**
   - Initial adversarial test passed for the wrong reason (membership mismatch), so it was corrected
     to use exact authoritative membership and policy digest.
   - RED: exit 1 because an attacker-generated key signed and executed the exact hold.
   - GREEN: trusted Owner public key, policy digest, and exact project membership are now
     supervisor-owned; guarded methods no longer accept caller-provided verification keys.
   - Exact-policy forged-key result: exit 0; `1 passed in 0.17s`, denied as
     `COMMAND_SIGNATURE_INVALID`.
2. **Exact deterministic scenario set**
   - RED: a validly re-signed policy missing one required scenario verified successfully.
   - GREEN: the ordered eleven-scenario matrix is exact; `1 passed in 0.15s`.
3. **Raw scenario evidence retention**
   - RED: a validly re-signed fixture with blank raw evidence verified successfully.
   - GREEN: blank raw evidence denies with `RELIABILITY_RAW_EVIDENCE_REQUIRED`; `1 passed in 0.16s`.
4. **Aggregation and retention bindings**
   - RED: validly re-signed scenario aggregation and retention mismatches each verified.
   - GREEN: each scenario must match the signed policy aggregation and retention window; the focused
     regressions passed in `0.21s` and `0.14s` respectively.

### Final WP13 gates

- Focused warnings-fatal WP13 suite:
  `.venv/Scripts/python.exe -m pytest tests/failure_injection/test_holds_failover.py tests/integration/test_evaluation.py tests/contract/test_reliability_threshold_policy.py -q -W error`
  - Result: exit 0; `27 passed in 0.19s`.
- Full warnings-fatal suite: `.venv/Scripts/python.exe -m pytest -q -W error`
  - Result: exit 0; `435 passed in 36.80s`.
- Ruff: `.venv/Scripts/ruff.exe check .`
  - Result: exit 0; `All checks passed!`.
- Strict mypy: `.venv/Scripts/mypy.exe`
  - Result: exit 0; `Success: no issues found in 64 source files`.
- Diff check: `git diff --check`
  - Result: exit 0; only existing LF→CRLF advisories were emitted.

No commit was created. No WP14 or external access occurred. WP5 external evidence remains blocked.

## WP14 conformance and durable external-effect reconciliation

Scope is Task 14 only. All provider and authoritative read-back adapters are repository test doubles;
no external access, effect, activation, installation, WP15 work, or commit occurred. Fixture receipts
remain `effect_executed=false` and `production_proof=false`.

### Observed RED → GREEN tracer evidence

1. **Exact durable state vocabulary**
   - RED: `.venv/Scripts/python.exe -m pytest tests/failure_injection/test_spec_conformance.py::test_effect_states_are_exact_canonical_durable_states -q`
   - Result: exit 1; hyphenated prototype states differed at index 0 and lacked two required states.
   - GREEN: same command; exit 0; `1 passed in 0.14s`.
2. **Crash-before-dispatch durable intent**
   - RED: focused collection exited 4 because `EffectStore` did not exist.
   - GREEN: intent and stable idempotency binding survive close/reopen as one SQLite row; same command
     selector passed in `0.97s`.
3. **Immutable fixture effect receipts**
   - RED: focused collection exited 4 because `effects.receipts` did not exist.
   - GREEN: frozen provider/read-back receipts reject external-proof claims; `1 passed in 0.21s`.
4. **Crash after dispatch before receipt**
   - RED: focused collection exited 4 because `effects.reconciler` did not exist.
   - GREEN: reopen observes `effect_started`, performs injected authoritative read-back, confirms the
     applied effect, and does not redispatch; `1 passed in 10.84s`.
5. **Exactly 25 machine-readable groups**
   - RED: runner test exited 1 because `tools/run_conformance.py` did not exist.
   - GREEN: exactly 25 numbered groups execute with stable case IDs, classified results, immutable
     fixture evidence, and no external-state mutation; `1 passed in 0.20s`.

Acceptance coverage after the tracer slices includes successful receipt-before-read-back closure,
timeout-unknown read-back-before-retry, duplicate provider-receipt dedupe, contradictory read-back,
non-fenceable effects, expired budget, mandatory named Owner and blocked next action, closure denial
without authoritative read-back, and an eight-thread barrier proof of one durable intent with no
sleeps. It also covers deterministic seeded crash/duplicate/stale-epoch/partial-effect/queue-wake/
failover/replay schedules, five real boundary probe mappings, missing-source/test generation failure,
stable Group 24 artifact-locator behavior, and unknown/26th-group specification-review denial.

### WP14 conformance execution

- Focused warnings-fatal suite:
  `.venv/Scripts/python.exe -m pytest -W error tests/failure_injection/test_spec_conformance.py -q`
  - Result: exit 0; `19 passed in 24.95s`.
- Matrix generation:
  `.venv/Scripts/python.exe tools/run_conformance.py --all --generate-matrix`
  - Result: exit 0; exactly 25 groups, zero unclassified failures, no external-state mutation.
- Required repeat run:
  `.venv/Scripts/python.exe tools/run_conformance.py --all --repeat 20`
  - Result: exit 0; `groups=25 repeat=20 unclassified=0 external_state_mutated=false`.

Final full warnings-fatal, Ruff, strict mypy, and diff-check results are recorded below after execution.

### Final WP14 gates

- Final focused warnings-fatal suite after lint-only corrections:
  - Result: exit 0; `20 passed in 15.19s`.
- Final full warnings-fatal suite:
  `.venv/Scripts/python.exe -m pytest -W error -q`
  - Result: exit 0; `455 passed in 41.54s`.
- Ruff first identified four WP14-only style findings (`Self`, two constant `getattr` calls, and
  parenthesized string concatenation); no behavior changed while correcting them.
- Final Ruff: `.venv/Scripts/python.exe -m ruff check .`
  - Result: exit 0; `All checks passed!`.
- Final strict mypy: `.venv/Scripts/python.exe -m mypy --strict src/hermes_kanban_workflow`
  - Result: exit 0; `Success: no issues found in 66 source files`.
- Final diff check: `git diff --check`
  - Result: exit 0; only existing LF→CRLF advisories were emitted.

No commit was created. No WP15 or external access occurred. WP5 external and manual
assistive-technology evidence remain blocked and are not reported as PASS.

### Independent WP14 execution and read-back authority remediations

1. **Conformance runner executed no mapped tests**
   - Parent inspection found `execute()` only checked that selector text existed, shuffled failure
     labels, and unconditionally emitted `status=passed` and zero failures.
   - RED: `.venv/Scripts/python.exe -m pytest tests/failure_injection/test_spec_conformance.py::test_execute_runs_mapped_implementation_tests -q`
     exited 1 because the runner had no subprocess execution path.
   - GREEN: each repetition now runs one real warnings-fatal pytest batch containing every unique
     selected group/case selector; nonzero execution propagates to group status, failure count, and
     CLI exit code. Specific result: exit 0; `1 passed in 0.17s`.
2. **Caller-constructed read-back could confirm and close**
   - RED: `test_caller_constructed_readback_cannot_confirm_or_close_effect` exited 1 because an
     unverified public `ReadbackReceipt(status="applied")` changed durable state.
   - GREEN: `EffectStore` now requires its configured authoritative read-back verifier before any
     read-back insert or transition. Missing/mismatched verification denies without changing state.
     Specific result: exit 0; `1 passed in 2.36s`; adjacent crash/retry/closure cases `4 passed`.
- Focused WP14 suite after both remediations: exit 0; `22 passed in 29.44s`.
- Repaired required repeat run (real mapped-test execution): exit 0; exactly 25 groups × 20 runs,
  every group passed, zero unclassified failures, `external_state_mutated=false`, and delivery
  semantics `at-least-once stable-ID delivery plus provider dedupe`.
- Final post-remediation gates:
  - Full warnings-fatal suite: exit 0; `457 passed in 40.16s`.
  - Ruff: exit 0; `All checks passed!`.
  - Strict mypy: exit 0; `Success: no issues found in 66 source files`.
  - Diff check: exit 0; only existing LF→CRLF advisories were emitted.

## WP15 packaging, upgrade safety, staged activation, and release honesty

Scope is Task 15 repository behavior only. No Hermes/profile install, plugin activation, migration,
secret, external access, production effect, independent audit, Owner acceptance, commit, or WP5
simulation occurred. Repository fixture signatures are not production authority.

### One-behavior RED → GREEN evidence

1. **Unified user-plugin archive inspection**
   - RED: package test collection exited 4: `hermes_kanban_workflow.config` did not exist.
   - GREEN: isolated ZIP inspection proves one `hermes-kanban-workflow/` root with Agent,
     Desktop, and Dashboard halves disabled; `1 passed`.
2. **Project-local accidental activation denial**
   - RED: collection exited 4 because `resolve_discovery_source` did not exist.
   - GREEN: only `<HERMES_HOME>/plugins/hermes-kanban-workflow` is accepted; project-local paths
     return `PROJECT_LOCAL_ACTIVATION_DENIED`; `1 passed`.
3. **Compatible staged upgrade with preserved policy/history**
   - RED: collection exited 4 because `PackageState`/`UpgradeManager` did not exist.
   - GREEN: candidate stays staged and inactive while exact policy/history remain unchanged; `1 passed`.
4. **Wheel entry-point and CLI metadata**
   - RED: assertion failed because `pyproject.toml` had no Hermes entry-point or packaged script.
   - GREEN: wheel metadata names the pinned `register(ctx)` adapter and inspection-only CLI; `1 passed`.
5. **Authenticated stage-1 chain**
   - RED: collection exited 4 because cryptographic activation trust APIs did not exist.
   - GREEN: exact package/policy/host/version/stage, current entry/pass evidence, eligible independent
     review, stage-named Owner decision, expiry, and predecessor are verified; `1 passed`.
6. **Caller Boolean/JSON activation forgery**
   - RED: expected authenticated-evidence denial but prototype returned `ACTIVATION_STAGE_SKIP_DENIED`.
   - GREEN: non-signed records deny before transition/effect and append an auditable denial; `1 passed`.
7. **Trust revocation and denial audit**
   - RED: `ActivationTrustRegistry` had no revocation operation.
   - GREEN: revoked/current and rolled-back trust fails closed and records exact denial evidence; `1 passed`.
8. **Independent-audit intake authority**
   - RED: collection exited 4 because `verify_audit_intake` did not exist.
   - GREEN: caller-created success JSON denies; only authenticated eligible independent reviewer and
     distinct Gatekeeper signatures bound to exact scope/evidence/verdict digest can pass; focused tests pass.
9. **Owner-assigned release artifacts and 14-row honesty**
   - RED: Operator Guide lacked `Owner: Operations` and matrix had no 14-row structure.
   - GREEN: all owners are explicit; every completion row has exact repository locator or typed fallback;
     WP5, manual AT, actual independent review, Owner acceptance, and all absent authority remain BLOCKED.

### Activation contract

`STAGE_CONTRACTS` encodes all ten plan gates with exact entry/pass summary, accountable owner,
eligible reviewer roles, denial, kill, and rollback route. `ActivationChain` is a signed monotonic chain:
current must equal N-1; record identities and predecessor must match; keys must be current/unrevoked;
nonces are single-use; repeat/skip/changed payload/expiry/missing predecessor/forgery deny and audit.
Rollback targets only a prior receipt and consumes no shortcut: fresh records are required at every
intervening stage. Agent and Desktop stage values remain separately disabled until authorized.

Final gate results are recorded after final-byte release regeneration below.

### Final WP15 gates

- Focused packaging/activation/release/host warnings-fatal: `26 passed in 11.79s`.
- Full warnings-fatal suite: `473 passed in 429.84s`.
- Accessibility/security/replay/reliability warnings-fatal: `116 passed in 52.90s`.
- Real mapped conformance: `tools/run_conformance.py --all --repeat 20` exited 0;
  25 groups × 20 runs, zero unclassified failure, repository fixtures only.
- Ruff: `All checks passed!`.
- Strict mypy: `Success: no issues found in 67 source files`.
- Isolated wheel inspection found the `hermes_agent.plugins` entry point and 72 wheel members;
  unified archive inspection returned `valid=True`, Agent/Desktop enabled flags false.
- Deterministic bundle was rebuilt twice with identical SHA-256 before final evidence refresh.

Release readiness remains BLOCKED. `release/audit-verdict.json` is `UNEXECUTED`; every completion
row remains BLOCKED pending its named independent/external/manual/Owner evidence. Package build and
repository rehearsal do not authorize installation or activation.

## Independent P1/P2 review remediation (2026-08-29)

Strict behavioral RED→GREEN evidence:

1. Public activation authority: RED showed a caller-created `ActivationChain` reached its fixture
   engine and returned `ACTIVATION_AUTHENTICATED_EVIDENCE_REQUIRED`; GREEN returns typed
   `AUTHENTICATED_SERVICE_ACTIVATION_REQUIRED` before touching the chain (`1 passed`).
2. Gate-specific activation: RED showed signed generic PASS records advanced stage 1; GREEN requires
   exact per-row contract/evidence/threshold/kill/rollback digests, every named reviewer through a
   distinct role key, exact Owner separation, and durable SQLite receipt/nonce/rollback/re-entry/
   denial state (`7 passed`). The engine is fixture-only and `production_authority=false`.
3. Authenticated readiness: the prior implementation had no successful authenticated route. GREEN
   verifies an Ed25519 response bound to fresh nonce, exact service/client, policy digest/epoch,
   host digest, package digest, and expiry; repository fixture roots cannot pass (`1 passed`).
4. Upgrade authority: prior caller `compatible` and `activation_chain_complete` values promoted
   arbitrary packages. GREEN consumes authority-verified package/host/policy/trust/compatibility
   evidence, hashes actual bytes, prevents trust rollback/history loss, reads a complete exact stage-10
   receipt, and rehashes rollback bytes (`3 passed`).
5. Isolated packaging: RED failed because temporary verified output was unsupported after a real fresh
   wheel build/install/entry-point/CLI probe. GREEN performs that probe without Hermes/profile install,
   parses shipped manifests, and validates vendored pinned-parser provenance (`1 passed`).
6. Conformance execution: schedules now drive an in-process crash/duplicate/stale/partial/wakeup/
   failover/replay harness, selectors execute once per group, failures attribute per group, case evidence
   is structured observed data, and external mutation is computed from before/after declared roots.
7. Traceability/checksums: all Sections 1–21 plus both amendments now map source → implementation →
   executable test → immutable evidence while preserving exactly 25 Section-18 groups and Group 24.
   Checksums declare Build ownership and exact inventory/self coverage; unsafe output is rejected before
   writing and only repo `dist` or an explicit temporary verification root is allowed.

Final build/check/gate results:

- Focused remediation suite: `49 passed` before final inventory refresh.
- Real conformance repeat-20: exactly 25 groups, 500 consumed deterministic schedules, zero
  unclassified failures, and before/after external-state snapshots reported no mutation.
- Full warnings-fatal suite after final implementation bytes: `476 passed in 40.92s`.
- Ruff: `All checks passed!`; strict mypy: `Success: no issues found in 67 source files`;
  `git diff --check` exited 0 with only pre-existing LF→CRLF advisories.
- Final deterministic bundle was rebuilt twice from the same final source and both runs produced
  SHA-256 `d8a3de66b0a9ad9a727b80608e675d033fbdd2a7870e307dc82e1e94c421339a` before this ledger
  result paragraph; the post-ledger final-byte rebuild is recorded by the generated checksum indexes.

All 14 completion rows remain `BLOCKED`; audit remains `UNEXECUTED`; no WP5 simulation, Hermes
install, activation, commit, push, or external effect occurred.

## Parent final-byte authority, conformance, and traceability remediation (2026-08-29)

This section supersedes the readiness and conformance claims at lines 1352–1366 above. Parent
adversarial inspection found that the delegated remediation still let callers select an audit trust
registry and construct a `ServiceReadinessVerifier(..., production_authority=True)`, and its failure
schedule mutated only a generic dictionary unrelated to mapped product tests. The 23-row traceability
fixture also represented sections rather than every frozen normative source line.

1. **Public audit authority — RED→GREEN.** A caller generated independent-auditor and Gatekeeper keys,
   signed exact-scope records, supplied its own registry, and obtained `{'ready': True, 'code': 'PASS'}`.
   `test_caller_supplied_audit_trust_cannot_mint_release_readiness` failed on that PASS. The minimal
   public boundary now returns `AUTHENTICATED_EXTERNAL_AUDIT_AUTHORITY_REQUIRED` for all caller-supplied
   registry material until a real out-of-process audit authority is provisioned; the focused test passes.
2. **Public preflight authority — RED→GREEN.** A caller-created key and
   `production_authority=True` verifier produced preflight PASS. The exact adapter test failed because
   that caller authority passed. Public preflight now returns
   `AUTHENTICATED_EXTERNAL_SERVICE_AUTHORITY_REQUIRED` before eligibility; fixture and caller-asserted
   production verifiers both deny, and the focused test passes. Public activation remains separately
   denied by `AUTHENTICATED_SERVICE_ACTIVATION_REQUIRED` before chain mutation.
3. **Real deterministic failure schedules — RED→GREEN.** The focused runner test failed because group
   subprocesses contained no crash/duplicate/stale/partial/wakeup/failover/replay selectors. The generic
   dictionary harness was removed. Each seeded permutation now orders seven named failure-injection tests
   exercising durable effects, resource fencing/wake/replay, and active-passive failover. The required
   command passed with 25 groups, 20 schedules per group, 500 schedule executions, 3,500 named real
   fault-test observations, zero failed or unclassified groups, and no declared external-state mutation.
4. **Frozen rule-level traceability — RED→GREEN.** The first coverage test observed zero per-rule IDs.
   The fixture now freezes every non-empty normative source line in Sections 1–21 (315 rows) plus both
   amendments, with operative source SHA-256 `09351b7babfa3edd56cbe89d64bbf6d03fa50c7e204276827518cb7b0acfb703`,
   the specification-declared canonical decision basis, implementation, executable test, and immutable
   evidence. Validation requires the exact 317-row sequence and the rendered matrix includes the
   canonical-decision column.

External clean-Windows WP5, manual assistive-technology execution, eligible external audit acceptance,
and Owner acceptance remain `BLOCKED`. Repository tests and fixture authorities cannot change those
states. No installation, activation, migration, production access, external effect, commit, or push
occurred.

### Parent final verification checkpoint

- Focused authority and conformance tests: `5 passed` across the caller-audit, caller-preflight,
  real-fault-selector, exact-group, and rendered-traceability contracts.
- Required conformance: 25 groups × 20 schedules; 500 schedule executions; 3,500 named real
  failure-injection observations; zero failed/unclassified groups; no declared external-state mutation.
- The first full-suite run found one obsolete expected denial code and one non-reproducing nested
  conformance subprocess failure. The denial assertion was aligned to the stronger external-authority
  code. Standalone `--all` passed, and the exact nested test then passed five consecutive independent
  runs (`26.42s`, `26.49s`, `28.56s`, `27.71s`, `27.87s`).
- Final warnings-fatal suite: `.venv/Scripts/python.exe -m pytest -q -W error` →
  `478 passed in 66.51s`.
- Ruff, strict mypy over 67 source files, and `git diff --check` passed; diff-check printed only
  pre-existing LF→CRLF conversion advisories.

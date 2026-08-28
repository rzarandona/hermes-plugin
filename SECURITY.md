# Security boundary

- The out-of-process Guarded Command Service is the sole durable writer.
- Hermes Python and renderer plugins are in-process extensions and are not security boundaries.
- Enforced operation requires Windows Service `HermesKanbanWriter` under `NT SERVICE\HermesKanbanWriter`, private NTFS ACLs, authenticated IPC, and DPAPI-NG brokerage.
- Real secrets are prohibited from prompts, cards, logs, evidence, repositories, and shared environments.
- Local administrators remain part of the trusted computing base on the pilot Windows profile.
- Installation, activation, deployment, migration, production access, and secret provisioning require separate owner authorization.

Report suspected bypasses as security incidents; do not attempt direct database repair.


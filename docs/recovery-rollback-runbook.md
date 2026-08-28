# Recovery and rollback runbook

1. Disable the affected authority; keep observation and evidence running.
2. Fence the stale epoch and reject outstanding commands.
3. Reconcile ledger intent, provider receipts, and authoritative target state.
4. If an external effect remains unknown, block retry and route to the named manual responder.
5. Roll back policy or package only to the last verified trust state; forward movement re-enters every intervening activation gate.
6. Project holds resume only exact recorded members as fresh eligible attempts.
7. Record independent restoration evidence before closure.


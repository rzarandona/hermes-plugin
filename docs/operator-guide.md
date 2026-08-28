# Operator guide

This source package is not an installed or active control plane. Operators may inspect package metadata, run tests, call inert `load_package`, use `register_observe_only`, and run preflight. They must not call enforcement without an exact, current Owner decision and predecessor-bound activation receipt.

If status is unknown, stop state-changing work, preserve evidence, and escalate. Never edit the SQLite database directly.


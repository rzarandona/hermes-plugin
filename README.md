# Hermes Kanban Workflow Plugin

Standalone, fail-closed workflow-control plugin targeting Hermes Agent 0.20.5 and Hermes Desktop 0.17.0. The package is under implementation and is **not installed or activated**.

The Hermes-facing Python and Desktop adapters are convenience surfaces only. Durable mutation belongs exclusively to the separately supervised `HermesKanbanWriter` service identity.

## Development verification

Run the local dependency-free baseline suite:

```powershell
$env:PYTHONPATH='src;.'
python -m unittest discover -s tests -p 'test_*.py' -v
```

Full release verification additionally requires the pinned clean Windows profile and the development dependencies declared in `pyproject.toml`.


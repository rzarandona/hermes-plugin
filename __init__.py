"""Hermes manifest-v2 entry point."""

def register(ctx: object) -> None:
    """Register only typed, non-persistent host entry points."""
    from .hermes_kanban_workflow.adapters.hermes_host import register as register_host

    register_host(ctx)


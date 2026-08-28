"""Hermes manifest-v2 entry point."""

from hermes_kanban_workflow.adapters.hermes_host import HermesPluginContextPort


def register(ctx: object) -> None:
    """Register only typed, non-persistent host entry points."""
    HermesPluginContextPort(ctx).register_package_commands()


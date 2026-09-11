"""Thin adapter for the verified generation-1 Hermes PluginContext."""

from __future__ import annotations

from typing import Any


def register(ctx: Any) -> None:
    """Pinned generation-1 entry point; registers inert host surfaces only."""
    HermesPluginContextPort(ctx).register_package_commands()


class HermesPluginContextPort:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def register_package_commands(self) -> None:
        self._ctx.register_tool(
            name="kanban_status",
            toolset="kanban-workflow",
            schema={"type": "object", "properties": {}, "additionalProperties": False},
            handler=self.status,
            description="Read workflow plugin status without durable mutation.",
        )
        self._ctx.register_command(
            name="kanban_preflight",
            handler=self.preflight,
            description="Describe the explicit offline preflight inputs.",
        )
        self._ctx.register_command(
            name="kanban_request_activation",
            handler=self.request_activation,
            description="Describe the owner decision required for activation.",
        )

    @staticmethod
    def status() -> dict[str, str]:
        return {"mode": "loaded", "enforcement": "disabled"}

    @staticmethod
    def preflight() -> dict[str, str]:
        return {"status": "requires-explicit-input"}

    @staticmethod
    def request_activation() -> dict[str, str]:
        return {"status": "owner-decision-required"}

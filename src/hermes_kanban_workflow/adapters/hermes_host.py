"""Thin adapter for the verified generation-1 Hermes PluginContext."""

from __future__ import annotations

from typing import Any


class HermesPluginContextPort:
    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def register_package_commands(self) -> None:
        self._ctx.register_tool("kanban_status", self.status)
        self._ctx.register_command("kanban_preflight", self.preflight)
        self._ctx.register_command("kanban_request_activation", self.request_activation)

    @staticmethod
    def status() -> dict[str, str]:
        return {"mode": "loaded", "enforcement": "disabled"}

    @staticmethod
    def preflight() -> dict[str, str]:
        return {"status": "requires-explicit-input"}

    @staticmethod
    def request_activation() -> dict[str, str]:
        return {"status": "owner-decision-required"}


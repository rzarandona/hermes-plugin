"""Native observation adapter; authenticated external enforcement remains separate."""

from __future__ import annotations

import json
from typing import Any

from ..observe import Observer, runtime_observer
from ..observe import register as register_observation


def register(ctx: Any) -> None:
    """Register the observation surfaces using native callback signatures."""
    HermesPluginContextPort(ctx).register_package_commands()


class HermesPluginContextPort:
    def __init__(self, ctx: Any, *, observer: Observer | None = None) -> None:
        self._ctx = ctx
        self._observer = observer

    def register_package_commands(self) -> None:
        self._observer = self._observer or runtime_observer()
        register_observation(self._ctx, self._observer)
        self._ctx.register_command(
            name="kanban_preflight",
            handler=self.preflight,
            description="Read live observation compatibility and enforcement prerequisites.",
        )
        self._ctx.register_command(
            name="kanban_request_activation",
            handler=self.request_activation,
            description="Describe the authenticated external authority required for enforcement.",
        )

    def preflight(self, raw_args: str = "", **kwargs: object) -> str:
        if raw_args.strip():
            return json.dumps({"error": "NO_ARGUMENTS_ACCEPTED"})
        assert self._observer is not None
        status = self._observer.status()
        return json.dumps({
            "observation_compatible": status["compatible"], "enabled": status["enabled"],
            "enforcement": "disabled", "code": "AUTHENTICATED_SERVICE_ACTIVATION_REQUIRED",
        }, sort_keys=True)

    @staticmethod
    def request_activation(raw_args: str = "", **kwargs: object) -> str:
        return json.dumps({
            "enforcement": "disabled", "code": "AUTHENTICATED_SERVICE_ACTIVATION_REQUIRED",
        }, sort_keys=True)

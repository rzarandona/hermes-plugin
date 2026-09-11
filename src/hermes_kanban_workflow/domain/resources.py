from __future__ import annotations

import re
from dataclasses import dataclass

_RESOURCE_CLASSES = frozenset(
    {
        "workspace",
        "build-lane",
        "release-lane",
        "emergency-release-lane",
        "test-device",
        "database",
        "migration-lock",
        "runtime",
        "maintenance-window",
        "restore-target",
        "incident-containment",
        "retirement-target",
    }
)
_SEGMENT = re.compile(r"[a-z0-9]+(?:[.-][a-z0-9]+)*")


@dataclass(frozen=True, slots=True)
class ResourceUri:
    scope: str
    resource_class: str
    provider: str
    region: str
    name: str

    @classmethod
    def parse(cls, value: str) -> ResourceUri:
        prefix = "resource://"
        if not value.startswith(prefix):
            raise ValueError("RESOURCE_URI_NON_CANONICAL")
        parts = value[len(prefix) :].split("/")
        if len(parts) != 5 or any(_SEGMENT.fullmatch(part) is None for part in parts):
            raise ValueError("RESOURCE_URI_NON_CANONICAL")
        scope, resource_class, provider, region, name = parts
        if resource_class not in _RESOURCE_CLASSES:
            raise ValueError("RESOURCE_URI_CLASS_INVALID")
        parsed = cls(scope, resource_class, provider, region, name)
        if str(parsed) != value:
            raise ValueError("RESOURCE_URI_NON_CANONICAL")
        return parsed

    def __str__(self) -> str:
        return (
            f"resource://{self.scope}/{self.resource_class}/"
            f"{self.provider}/{self.region}/{self.name}"
        )

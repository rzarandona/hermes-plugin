from __future__ import annotations

from dataclasses import dataclass

SUPPORTED_VERSION_TUPLE = ("0.20.5", "0.1.0", "1.0.0", "1")
_VERSION_FIELDS = ("host_version", "plugin_version", "executor_version", "policy_version")


class CompatibilityError(PermissionError):
    def __init__(self, received: tuple[str, str, str, str]) -> None:
        super().__init__("COMPATIBILITY_UNSUPPORTED")
        self.code = "COMPATIBILITY_UNSUPPORTED"
        self.received = received
        self.supported = SUPPORTED_VERSION_TUPLE
        self.mismatches = tuple(
            field
            for field, actual, expected in zip(
                _VERSION_FIELDS, received, SUPPORTED_VERSION_TUPLE, strict=True
            )
            if actual != expected
        )


@dataclass(frozen=True)
class CompatibilityReceipt:
    host_version: str
    plugin_version: str
    executor_version: str
    policy_version: str


def assert_compatible(
    host_version: str,
    plugin_version: str,
    executor_version: str,
    policy_version: str,
) -> CompatibilityReceipt:
    received = (host_version, plugin_version, executor_version, policy_version)
    if received != SUPPORTED_VERSION_TUPLE:
        raise CompatibilityError(received)
    return CompatibilityReceipt(*received)

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


@dataclass(frozen=True)
class Lease:
    resource_id: str
    holder_id: str
    fencing_epoch: int
    expires_at: datetime


class LeaseRegistry:
    def __init__(self, ttl: timedelta = timedelta(minutes=5)) -> None:
        self._ttl = ttl
        self._leases: dict[str, Lease] = {}
        self._epochs: dict[str, int] = {}

    def acquire(self, resource_id: str, holder_id: str, *, replace_expired: bool = False, now: datetime | None = None) -> Lease:
        at = now or datetime.now(timezone.utc)
        current = self._leases.get(resource_id)
        if current and current.expires_at > at:
            raise PermissionError("RESOURCE_BUSY")
        if current and not replace_expired:
            raise PermissionError("EXPIRED_LEASE_REQUIRES_EXPLICIT_REPLACEMENT")
        epoch = self._epochs.get(resource_id, 0) + 1
        lease = Lease(resource_id, holder_id, epoch, at + self._ttl)
        self._epochs[resource_id] = epoch
        self._leases[resource_id] = lease
        return lease

    def is_authoritative(self, lease: Lease) -> bool:
        return self._leases.get(lease.resource_id) == lease


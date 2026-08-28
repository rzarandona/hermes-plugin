"""Read-only dashboard router; durable writes never terminate here."""

try:
    from fastapi import APIRouter
except ImportError:  # pragma: no cover - fail-closed packaging diagnostic
    APIRouter = None  # type: ignore[assignment,misc]

if APIRouter is None:
    router = None
else:
    router = APIRouter(prefix="/api/plugins/hermes-kanban-workflow")

    @router.get("/status")
    def status() -> dict[str, str]:
        return {"enforcement": "disabled", "persistence": "guarded-service-only"}


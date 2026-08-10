"""Health check endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter

from mock_oidc.models import HealthResponse

if TYPE_CHECKING:
    from mock_oidc.store import OIDCStore


def create_health_router(store: OIDCStore) -> APIRouter:
    """Create health check router."""
    r = APIRouter()

    @r.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        stats = store.stats()
        return HealthResponse(
            clients=stats["clients"],
            users=stats["users"],
        )

    return r

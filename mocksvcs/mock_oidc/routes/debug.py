"""Debug endpoints for inspecting and resetting mock OIDC state."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter

if TYPE_CHECKING:
    from mock_oidc.store import OIDCStore


def create_debug_router(store: OIDCStore) -> APIRouter:
    """Create debug router for store inspection and reset."""
    r = APIRouter()

    @r.get("/debug/store")
    async def debug_store() -> dict[str, Any]:
        """Return aggregate statistics about the OIDC store."""
        return store.stats()

    @r.delete("/debug/store")
    async def debug_reset() -> dict[str, Any]:
        """Reset all data (clients, users, codes, tokens) and re-seed defaults."""
        return store.clear()

    @r.get("/debug/tokens")
    async def debug_tokens() -> list[dict[str, Any]]:
        """List all issued access tokens (truncated for safety)."""
        return store.list_tokens()

    return r

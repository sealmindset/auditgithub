"""Mock user management CRUD endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException, status

from mock_oidc.models import UserCreate, UserUpdate

if TYPE_CHECKING:
    from mock_oidc.store import OIDCStore


def create_users_router(store: OIDCStore) -> APIRouter:
    """Create user management router."""
    r = APIRouter()

    @r.get("/users")
    async def list_users() -> list[dict[str, Any]]:
        """List all mock users."""
        return store.list_users()

    @r.get("/users/{sub}")
    async def get_user(sub: str) -> dict[str, Any]:
        """Get a specific user by sub."""
        user = store.get_user(sub)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {sub}",
            )
        return user

    @r.post("/users", status_code=status.HTTP_201_CREATED)
    async def create_user(body: UserCreate) -> dict[str, Any]:
        """Create a new mock user."""
        return store.create_user(body.model_dump(exclude_none=True))

    @r.put("/users/{sub}")
    async def update_user(sub: str, body: UserUpdate) -> dict[str, Any]:
        """Update an existing user."""
        data = body.model_dump(exclude_none=True)
        result = store.update_user(sub, data)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {sub}",
            )
        return result

    @r.delete("/users/{sub}")
    async def delete_user(sub: str) -> dict[str, str]:
        """Delete a user."""
        if not store.delete_user(sub):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User not found: {sub}",
            )
        return {"status": "deleted", "sub": sub}

    return r

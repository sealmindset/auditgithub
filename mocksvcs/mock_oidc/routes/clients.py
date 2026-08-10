"""Client registration CRUD endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException, status

from mock_oidc.models import ClientCreate, ClientUpdate

if TYPE_CHECKING:
    from mock_oidc.store import OIDCStore


def create_clients_router(store: OIDCStore) -> APIRouter:
    """Create client management router."""
    r = APIRouter()

    @r.get("/clients")
    async def list_clients() -> list[dict[str, Any]]:
        """List all registered clients."""
        return store.list_clients()

    @r.get("/clients/{client_id}")
    async def get_client(client_id: str) -> dict[str, Any]:
        """Get a specific client by ID."""
        client = store.get_client(client_id)
        if client is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Client not found: {client_id}",
            )
        return client

    @r.post("/clients", status_code=status.HTTP_201_CREATED)
    async def create_client(body: ClientCreate) -> dict[str, Any]:
        """Register a new client."""
        data = body.model_dump(exclude_none=True)
        return store.create_client(data)

    @r.put("/clients/{client_id}")
    async def update_client(client_id: str, body: ClientUpdate) -> dict[str, Any]:
        """Update an existing client."""
        data = body.model_dump(exclude_none=True)
        result = store.update_client(client_id, data)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Client not found: {client_id}",
            )
        return result

    @r.delete("/clients/{client_id}")
    async def delete_client(client_id: str) -> dict[str, str]:
        """Delete a client."""
        if not store.delete_client(client_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Client not found: {client_id}",
            )
        return {"status": "deleted", "client_id": client_id}

    return r

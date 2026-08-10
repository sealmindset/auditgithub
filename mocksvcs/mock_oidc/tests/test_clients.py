"""Tests for the client CRUD endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_clients_returns_default(client: AsyncClient) -> None:
    resp = await client.get("/clients")
    assert resp.status_code == 200
    clients = resp.json()
    assert len(clients) == 1
    assert clients[0]["client_id"] == "mock-oidc-client"


@pytest.mark.asyncio
async def test_get_client(client: AsyncClient) -> None:
    resp = await client.get("/clients/mock-oidc-client")
    assert resp.status_code == 200
    data = resp.json()
    assert data["client_id"] == "mock-oidc-client"
    assert "redirect_uris" in data


@pytest.mark.asyncio
async def test_get_client_not_found(client: AsyncClient) -> None:
    resp = await client.get("/clients/nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_client(client: AsyncClient) -> None:
    resp = await client.post(
        "/clients",
        json={
            "client_id": "new-client",
            "client_secret": "new-secret",
            "redirect_uris": ["http://localhost:9000/callback"],
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["client_id"] == "new-client"

    # Verify it's listed
    resp2 = await client.get("/clients")
    assert len(resp2.json()) == 2


@pytest.mark.asyncio
async def test_update_client(client: AsyncClient) -> None:
    resp = await client.put(
        "/clients/mock-oidc-client",
        json={"scope": "openid"},
    )
    assert resp.status_code == 200
    assert resp.json()["scope"] == "openid"
    # client_id should remain unchanged
    assert resp.json()["client_id"] == "mock-oidc-client"


@pytest.mark.asyncio
async def test_delete_client(client: AsyncClient) -> None:
    resp = await client.delete("/clients/mock-oidc-client")
    assert resp.status_code == 200

    resp2 = await client.get("/clients/mock-oidc-client")
    assert resp2.status_code == 404

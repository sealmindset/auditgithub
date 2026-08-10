"""Tests for the user CRUD endpoints."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_users_returns_defaults(client: AsyncClient) -> None:
    resp = await client.get("/users")
    assert resp.status_code == 200
    users = resp.json()
    assert len(users) == 3
    subs = {u["sub"] for u in users}
    assert subs == {"mock-admin", "mock-analyst", "mock-user"}


@pytest.mark.asyncio
async def test_get_user(client: AsyncClient) -> None:
    resp = await client.get("/users/mock-admin")
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "admin@zapper.local"
    assert data["name"] == "Mock Admin"


@pytest.mark.asyncio
async def test_get_user_not_found(client: AsyncClient) -> None:
    resp = await client.get("/users/nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_user(client: AsyncClient) -> None:
    resp = await client.post(
        "/users",
        json={
            "sub": "new-user",
            "email": "new@test.com",
            "name": "New User",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["sub"] == "new-user"
    assert data["email"] == "new@test.com"

    # Verify listed
    resp2 = await client.get("/users")
    assert len(resp2.json()) == 4


@pytest.mark.asyncio
async def test_update_user(client: AsyncClient) -> None:
    resp = await client.put(
        "/users/mock-admin",
        json={"name": "Updated Admin"},
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "Updated Admin"
    assert resp.json()["sub"] == "mock-admin"  # sub immutable


@pytest.mark.asyncio
async def test_delete_user(client: AsyncClient) -> None:
    resp = await client.delete("/users/mock-admin")
    assert resp.status_code == 200

    resp2 = await client.get("/users/mock-admin")
    assert resp2.status_code == 404

    # Should now have 2 users
    resp3 = await client.get("/users")
    assert len(resp3.json()) == 2

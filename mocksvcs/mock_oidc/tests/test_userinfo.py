"""Tests for the userinfo endpoint."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from mock_oidc.main import store


@pytest.mark.asyncio
async def test_userinfo_returns_claims(client: AsyncClient) -> None:
    # Issue a token
    code = store.create_auth_code(
        client_id="mock-oidc-client",
        sub="mock-admin",
        redirect_uri="http://localhost:3000/api/auth/callback",
    )
    resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "mock-oidc-client",
        },
    )
    access_token = resp.json()["access_token"]

    # Call userinfo
    resp2 = await client.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert resp2.status_code == 200
    data = resp2.json()
    assert data["sub"] == "mock-admin"
    assert data["email"] == "admin@zapper.local"
    assert data["name"] == "Mock Admin"


@pytest.mark.asyncio
async def test_userinfo_missing_auth_header(client: AsyncClient) -> None:
    resp = await client.get("/userinfo")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_userinfo_invalid_token(client: AsyncClient) -> None:
    resp = await client.get(
        "/userinfo",
        headers={"Authorization": "Bearer invalid-token"},
    )
    assert resp.status_code == 401

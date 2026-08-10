"""Tests for the token endpoint (exchange, introspect, revoke)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from mock_oidc.main import key_pair, store


def _create_auth_code(
    client_id: str = "mock-oidc-client",
    sub: str = "mock-admin",
    redirect_uri: str = "http://localhost:3000/api/auth/callback",
) -> str:
    """Helper to create a valid auth code."""
    return store.create_auth_code(
        client_id=client_id,
        sub=sub,
        redirect_uri=redirect_uri,
    )


@pytest.mark.asyncio
async def test_token_exchange_authorization_code(client: AsyncClient) -> None:
    code = _create_auth_code()
    resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "http://localhost:3000/api/auth/callback",
            "client_id": "mock-oidc-client",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "id_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] > 0


@pytest.mark.asyncio
async def test_token_exchange_id_token_is_valid_jwt(client: AsyncClient) -> None:
    code = _create_auth_code()
    resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "mock-oidc-client",
        },
    )
    data = resp.json()
    claims = key_pair.decode_jwt(data["id_token"])
    assert claims["sub"] == "mock-admin"
    assert claims["email"] == "admin@zapper.local"
    assert claims["aud"] == "mock-oidc-client"


@pytest.mark.asyncio
async def test_token_exchange_invalid_code(client: AsyncClient) -> None:
    resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "invalid-code",
            "client_id": "mock-oidc-client",
        },
    )
    assert resp.status_code == 400
    assert "Invalid or expired" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_token_exchange_code_single_use(client: AsyncClient) -> None:
    """Auth codes should be consumed on first use."""
    code = _create_auth_code()

    # First use succeeds
    resp1 = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "mock-oidc-client",
        },
    )
    assert resp1.status_code == 200

    # Second use fails
    resp2 = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "mock-oidc-client",
        },
    )
    assert resp2.status_code == 400


@pytest.mark.asyncio
async def test_token_refresh(client: AsyncClient) -> None:
    """Refresh tokens should issue new access + refresh tokens."""
    code = _create_auth_code()
    resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "mock-oidc-client",
        },
    )
    refresh_token = resp.json()["refresh_token"]

    resp2 = await client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": "mock-oidc-client",
        },
    )
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert "access_token" in data2
    assert "refresh_token" in data2
    # New refresh token should differ from original
    assert data2["refresh_token"] != refresh_token


@pytest.mark.asyncio
async def test_token_unsupported_grant_type(client: AsyncClient) -> None:
    resp = await client.post(
        "/token",
        data={"grant_type": "client_credentials"},
    )
    assert resp.status_code == 400
    assert "Unsupported grant_type" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_token_introspect_active(client: AsyncClient) -> None:
    code = _create_auth_code()
    resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "mock-oidc-client",
        },
    )
    access_token = resp.json()["access_token"]

    resp2 = await client.post(
        "/token/introspect",
        data={"token": access_token},
    )
    assert resp2.status_code == 200
    data = resp2.json()
    assert data["active"] is True
    assert data["sub"] == "mock-admin"


@pytest.mark.asyncio
async def test_token_introspect_invalid(client: AsyncClient) -> None:
    resp = await client.post(
        "/token/introspect",
        data={"token": "invalid-token"},
    )
    assert resp.status_code == 200
    assert resp.json()["active"] is False


@pytest.mark.asyncio
async def test_token_revoke(client: AsyncClient) -> None:
    code = _create_auth_code()
    resp = await client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "mock-oidc-client",
        },
    )
    access_token = resp.json()["access_token"]

    # Revoke
    resp2 = await client.post(
        "/token/revoke",
        data={"token": access_token},
    )
    assert resp2.status_code == 200

    # Introspect should show inactive
    resp3 = await client.post(
        "/token/introspect",
        data={"token": access_token},
    )
    assert resp3.json()["active"] is False

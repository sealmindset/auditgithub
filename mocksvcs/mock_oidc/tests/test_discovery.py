"""Tests for the OIDC discovery endpoint."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_discovery_returns_required_fields(client: AsyncClient) -> None:
    resp = await client.get("/.well-known/openid-configuration")
    assert resp.status_code == 200
    data = resp.json()

    # Required OIDC discovery fields
    assert "issuer" in data
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "userinfo_endpoint" in data
    assert "jwks_uri" in data
    assert "response_types_supported" in data
    assert "id_token_signing_alg_values_supported" in data


@pytest.mark.asyncio
async def test_discovery_split_urls(client: AsyncClient) -> None:
    """Authorization endpoint should use external URL, token endpoint should use internal."""
    resp = await client.get("/.well-known/openid-configuration")
    data = resp.json()

    # Browser-facing (external)
    assert "localhost:3007" in data["authorization_endpoint"]
    assert "localhost:3007" in data["end_session_endpoint"]

    # Container-facing (internal)
    assert "mock-oidc:10090" in data["token_endpoint"]
    assert "mock-oidc:10090" in data["userinfo_endpoint"]
    assert "mock-oidc:10090" in data["jwks_uri"]


@pytest.mark.asyncio
async def test_discovery_supported_scopes(client: AsyncClient) -> None:
    resp = await client.get("/.well-known/openid-configuration")
    data = resp.json()
    assert "openid" in data["scopes_supported"]
    assert "profile" in data["scopes_supported"]
    assert "email" in data["scopes_supported"]


@pytest.mark.asyncio
async def test_discovery_supported_grant_types(client: AsyncClient) -> None:
    resp = await client.get("/.well-known/openid-configuration")
    data = resp.json()
    assert "authorization_code" in data["grant_types_supported"]
    assert "refresh_token" in data["grant_types_supported"]

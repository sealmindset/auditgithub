"""Tests for the authorization endpoint."""

from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_authorize_renders_user_picker(client: AsyncClient) -> None:
    resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "mock-oidc-client",
            "redirect_uri": "http://localhost:3000/api/auth/callback",
            "scope": "openid profile email",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    body = resp.text
    assert "Mock OIDC Login" in body
    assert "Mock Admin" in body
    assert "Mock Analyst" in body
    assert "Mock User" in body


@pytest.mark.asyncio
async def test_authorize_login_hint_auto_redirect(client: AsyncClient) -> None:
    resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "mock-oidc-client",
            "redirect_uri": "http://localhost:3000/api/auth/callback",
            "login_hint": "mock-admin",
            "state": "test-state",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "http://localhost:3000/api/auth/callback" in location
    assert "code=" in location
    assert "state=test-state" in location


@pytest.mark.asyncio
async def test_authorize_unknown_client(client: AsyncClient) -> None:
    resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "nonexistent",
            "redirect_uri": "http://localhost:3000/callback",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "Unknown client_id" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_authorize_unsupported_response_type(client: AsyncClient) -> None:
    resp = await client.get(
        "/authorize",
        params={
            "response_type": "token",
            "client_id": "mock-oidc-client",
            "redirect_uri": "http://localhost:3000/callback",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "Unsupported response_type" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_authorize_login_hint_unknown_user(client: AsyncClient) -> None:
    """Unknown login_hint should fall through to user picker."""
    resp = await client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "mock-oidc-client",
            "redirect_uri": "http://localhost:3000/api/auth/callback",
            "login_hint": "nonexistent-user",
        },
        follow_redirects=False,
    )
    # Falls through to HTML user picker
    assert resp.status_code == 200
    assert "Mock OIDC Login" in resp.text


@pytest.mark.asyncio
async def test_authorize_select_form_post(client: AsyncClient) -> None:
    resp = await client.post(
        "/authorize/select",
        data={
            "sub": "mock-admin",
            "client_id": "mock-oidc-client",
            "redirect_uri": "http://localhost:3000/api/auth/callback",
            "scope": "openid profile email",
            "state": "form-state",
            "nonce": "form-nonce",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "code=" in location
    assert "state=form-state" in location

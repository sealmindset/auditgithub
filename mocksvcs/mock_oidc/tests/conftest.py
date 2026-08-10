"""Shared fixtures for mock OIDC tests."""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from mock_oidc.main import app, key_pair, store


@pytest.fixture(autouse=True)
def _reset_store():
    """Reset the OIDC store before each test."""
    store.clear()
    yield


@pytest_asyncio.fixture
async def client() -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

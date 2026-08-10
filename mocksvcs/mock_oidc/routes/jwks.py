"""JWKS endpoint — exposes the RSA public key for token verification."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter

if TYPE_CHECKING:
    from mock_oidc.crypto import KeyPair


def create_jwks_router(key_pair: KeyPair) -> APIRouter:
    """Create JWKS router."""
    r = APIRouter()

    @r.get("/jwks")
    async def jwks() -> dict[str, Any]:
        """Return the JSON Web Key Set (JWKS) for token verification."""
        return key_pair.jwks()

    return r

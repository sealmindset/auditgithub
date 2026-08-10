"""UserInfo endpoint — returns claims for the authenticated user."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException, Request, status

if TYPE_CHECKING:
    from mock_oidc.store import OIDCStore


def create_userinfo_router(store: OIDCStore) -> APIRouter:
    """Create userinfo router."""
    r = APIRouter()

    @r.get("/userinfo")
    async def userinfo(request: Request) -> dict[str, Any]:
        """Return user claims for the Bearer token in the Authorization header."""
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid Authorization header",
            )

        access_token = auth_header[7:]
        token_info = store.get_token_info(access_token)
        if token_info is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired access token",
            )

        user = store.get_user(token_info["sub"])
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        return {
            "sub": user["sub"],
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "email_verified": user.get("email_verified", True),
            "preferred_username": user.get("preferred_username", ""),
        }

    return r

"""Token endpoint — exchange auth code for tokens, introspect, revoke."""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Form, HTTPException, status

from mock_oidc.config import settings
from mock_oidc.models import TokenIntrospectResponse, TokenResponse

if TYPE_CHECKING:
    from mock_oidc.crypto import KeyPair
    from mock_oidc.store import OIDCStore


def create_token_router(store: OIDCStore, key_pair: KeyPair) -> APIRouter:
    """Create token router for code exchange, introspection, and revocation."""
    r = APIRouter()

    @r.post("/token", response_model=TokenResponse)
    async def token_exchange(
        grant_type: str = Form(...),
        code: str = Form(""),
        redirect_uri: str = Form(""),
        client_id: str = Form(""),
        client_secret: str = Form(""),
        refresh_token: str = Form(""),
        scope: str = Form(""),
        code_verifier: str = Form(""),
    ) -> TokenResponse:
        """Exchange an authorization code or refresh token for access/ID tokens."""
        if grant_type == "authorization_code":
            return _handle_auth_code(
                code=code,
                redirect_uri=redirect_uri,
                client_id=client_id,
                client_secret=client_secret,
                code_verifier=code_verifier,
            )
        elif grant_type == "refresh_token":
            return _handle_refresh_token(
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported grant_type: {grant_type}",
            )

    def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
        """Verify PKCE code_verifier against stored code_challenge."""
        if method == "S256":
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
            return computed == code_challenge
        elif method == "plain":
            return code_verifier == code_challenge
        return False

    def _handle_auth_code(
        code: str,
        redirect_uri: str,
        client_id: str,
        client_secret: str,
        code_verifier: str = "",
    ) -> TokenResponse:
        if not code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing authorization code",
            )

        auth_data = store.consume_auth_code(code)
        if auth_data is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired authorization code",
            )

        # Validate PKCE if code_challenge was provided during authorization
        stored_challenge = auth_data.get("code_challenge", "")
        stored_method = auth_data.get("code_challenge_method", "")
        if stored_challenge:
            if not code_verifier:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="PKCE code_verifier required but not provided",
                )
            if not _verify_pkce(code_verifier, stored_challenge, stored_method):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="PKCE verification failed: code_verifier does not match code_challenge",
                )

        # Validate client
        if client_id and client_id != auth_data["client_id"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="client_id mismatch",
            )
        effective_client_id = client_id or auth_data["client_id"]

        client = store.get_client(effective_client_id)
        if client is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Unknown client",
            )

        # Validate client secret if required
        if settings.require_client_secret:
            if client_secret != client["client_secret"]:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid client credentials",
                )

        user = store.get_user(auth_data["sub"])
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not found",
            )

        return _issue_tokens(
            sub=user["sub"],
            client_id=effective_client_id,
            scope=auth_data["scope"],
            nonce=auth_data.get("nonce", ""),
            user=user,
        )

    def _handle_refresh_token(
        refresh_token: str,
        client_id: str,
        client_secret: str,
        scope: str,
    ) -> TokenResponse:
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing refresh_token",
            )

        token_data = store.consume_refresh_token(refresh_token)
        if token_data is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired refresh token",
            )

        user = store.get_user(token_data["sub"])
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User not found",
            )

        effective_scope = scope or token_data["scope"]
        return _issue_tokens(
            sub=user["sub"],
            client_id=token_data["client_id"],
            scope=effective_scope,
            nonce="",
            user=user,
        )

    def _issue_tokens(
        sub: str,
        client_id: str,
        scope: str,
        nonce: str,
        user: dict[str, Any],
    ) -> TokenResponse:
        """Generate access token, ID token, and refresh token."""
        issuer = settings.internal_base_url.rstrip("/")

        # Access token (opaque)
        access_token = secrets.token_urlsafe(48)
        store.store_token(
            access_token=access_token,
            sub=sub,
            client_id=client_id,
            scope=scope,
        )

        # ID token (JWT)
        id_claims: dict[str, Any] = {
            "iss": issuer,
            "sub": sub,
            "aud": client_id,
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "email_verified": user.get("email_verified", True),
            "preferred_username": user.get("preferred_username", ""),
        }
        if nonce:
            id_claims["nonce"] = nonce
        id_token = key_pair.sign_jwt(id_claims, expires_in=settings.id_token_lifetime)

        # Refresh token
        new_refresh_token = secrets.token_urlsafe(48)
        store.store_refresh_token(
            refresh_token=new_refresh_token,
            sub=sub,
            client_id=client_id,
            scope=scope,
        )

        return TokenResponse(
            access_token=access_token,
            expires_in=settings.access_token_lifetime,
            refresh_token=new_refresh_token,
            id_token=id_token,
            scope=scope,
        )

    @r.post("/token/introspect", response_model=TokenIntrospectResponse)
    async def introspect(
        token: str = Form(...),
        client_id: str = Form(""),
        client_secret: str = Form(""),
    ) -> TokenIntrospectResponse:
        """Token introspection (RFC 7662)."""
        info = store.get_token_info(token)
        if info is None:
            return TokenIntrospectResponse(active=False)

        return TokenIntrospectResponse(
            active=True,
            sub=info["sub"],
            client_id=info["client_id"],
            scope=info["scope"],
            token_type=info["token_type"],
            exp=int(info["expires_at"]),
        )

    @r.post("/token/revoke")
    async def revoke(
        token: str = Form(...),
        client_id: str = Form(""),
        client_secret: str = Form(""),
    ) -> dict[str, str]:
        """Token revocation (RFC 7009). Always returns 200."""
        store.revoke_token(token)
        return {"status": "ok"}

    return r

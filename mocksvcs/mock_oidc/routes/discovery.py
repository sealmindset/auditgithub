"""OpenID Connect Discovery endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import APIRouter

from mock_oidc.config import settings

if TYPE_CHECKING:
    from mock_oidc.store import OIDCStore


def create_discovery_router(store: OIDCStore) -> APIRouter:
    """Create discovery router."""
    r = APIRouter()

    @r.get("/.well-known/openid-configuration")
    async def openid_configuration() -> dict[str, Any]:
        """Return the OIDC discovery document with split URLs.

        Browser-facing endpoints use external_base_url (localhost).
        Backend-facing endpoints use internal_base_url (Docker network).
        """
        ext = settings.external_base_url.rstrip("/")
        internal = settings.internal_base_url.rstrip("/")

        return {
            "issuer": internal,
            # Browser-facing (redirects)
            "authorization_endpoint": f"{ext}/authorize",
            "end_session_endpoint": f"{ext}/logout",
            # Backend-facing (server-to-server)
            "token_endpoint": f"{internal}/token",
            "userinfo_endpoint": f"{internal}/userinfo",
            "jwks_uri": f"{internal}/jwks",
            "introspection_endpoint": f"{internal}/token/introspect",
            "revocation_endpoint": f"{internal}/token/revoke",
            "registration_endpoint": f"{internal}/clients",
            # Standard metadata
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid", "profile", "email"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "claims_supported": [
                "sub",
                "name",
                "email",
                "email_verified",
                "preferred_username",
                "iss",
                "aud",
                "exp",
                "iat",
                "nonce",
            ],
            "code_challenge_methods_supported": ["S256", "plain"],
        }

    return r

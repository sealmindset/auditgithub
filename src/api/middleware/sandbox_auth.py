"""
Sandbox Authentication Middleware

Simplified API key-only authentication for the sandbox environment.
Replaces the production AuthenticationMiddleware when SANDBOX_MODE=true.

Keys are stored as SHA-256 hashes in the sandbox_api_keys table and
the plaintext values are publicly displayed on the sandbox landing page.
"""

import hashlib
import os

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from loguru import logger


class SandboxAuthMiddleware(BaseHTTPMiddleware):
    """
    API-key-only authentication for the sandbox environment.

    Public paths are allowed without authentication.
    All other paths require a valid X-API-Key header (or api_key query param).
    """

    PUBLIC_PREFIXES = [
        "/",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/health",
        "/api/sandbox/keys",
        "/favicon.ico",
        "/static",
    ]

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Allow public paths
        if self._is_public(path):
            request.state.sandbox_key_name = None
            request.state.sandbox_key_role = None
            request.state.user_role = "viewer"
            return await call_next(request)

        # Extract API key from header or query param
        api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")

        if not api_key:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "detail": "Sandbox API key required. GET /api/sandbox/keys to see available keys.",
                },
            )

        # Lookup key by SHA-256 hash
        key_record = await self._lookup_key(api_key)
        if not key_record:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Invalid sandbox API key."},
            )

        # Attach sandbox identity to request state
        request.state.sandbox_key_name = key_record["name"]
        request.state.sandbox_key_role = key_record["role"]
        request.state.user_role = key_record["role"]

        logger.bind(
            sandbox_key=key_record["name"],
            role=key_record["role"],
            path=path,
        ).debug("Sandbox request authenticated")

        return await call_next(request)

    # ------------------------------------------------------------------
    def _is_public(self, path: str) -> bool:
        # Exact match for root
        if path == "/":
            return True
        for prefix in self.PUBLIC_PREFIXES:
            if prefix != "/" and path.startswith(prefix):
                return True
        return False

    async def _lookup_key(self, raw_key: str) -> dict | None:
        from src.api.database import SessionLocal
        from src.api.models import SandboxApiKey

        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        db = SessionLocal()
        try:
            record = (
                db.query(SandboxApiKey)
                .filter(SandboxApiKey.key_hash == key_hash, SandboxApiKey.is_active.is_(True))
                .first()
            )
            if record:
                return {"name": record.name, "role": record.role}
            return None
        except Exception as e:
            logger.warning(f"Sandbox key lookup failed: {e}")
            return None
        finally:
            db.close()

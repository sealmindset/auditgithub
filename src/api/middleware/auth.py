"""
Authentication Middleware

Global authentication enforcement for the entire application.
Redirects unauthenticated users to login page when AUTH_REQUIRED=true.
"""
import os
from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import RedirectResponse, JSONResponse
from loguru import logger


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Global authentication middleware.

    Enforces AUTH_REQUIRED setting:
    - If AUTH_REQUIRED=false (dev mode): Allow all requests
    - If AUTH_REQUIRED=true (prod mode): Check session, redirect to /login if not authenticated

    Public endpoints (no auth required):
    - /auth/* - Authentication endpoints
    - /invite/* - Invitation acceptance pages
    - /api/docs - API documentation
    - /api/redoc - API documentation
    - /api/openapi.json - API schema
    - /api/invitations/validate/{token} - Public invitation validation
    - /static/* - Static files
    - /_next/* - Next.js static files
    """

    # Public endpoints that don't require authentication
    PUBLIC_PREFIXES = [
        "/auth/",
        "/invite/",
        "/health",
        "/api/docs",
        "/api/redoc",
        "/api/openapi.json",
        "/static/",
        "/_next/",
    ]

    # Public API endpoints (exact matches)
    PUBLIC_API_ENDPOINTS = [
        "/api/invitations/validate/",  # Public invitation validation
    ]

    async def dispatch(self, request: Request, call_next):
        """
        Check authentication before processing request.

        Args:
            request: FastAPI request object
            call_next: Next middleware in chain

        Returns:
            Response from next middleware or redirect to login
        """
        # Check if auth is required
        auth_required = os.getenv("AUTH_REQUIRED", "false").lower() == "true"

        if not auth_required:
            # Dev mode - allow all requests
            logger.debug(f"AUTH_REQUIRED=false, allowing request to {request.url.path}")
            return await call_next(request)

        # Check if endpoint is public
        if self._is_public_endpoint(request.url.path):
            logger.debug(f"Public endpoint: {request.url.path}")
            return await call_next(request)

        # Check if user is authenticated
        user_data = request.session.get('user')

        if not user_data:
            # User not authenticated
            logger.info(f"Unauthenticated request to {request.url.path}")

            # Return 401 JSON for all API requests (frontend is a separate app)
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "detail": "Authentication required",
                    "login_url": "/login"
                }
            )

        # User is authenticated - proceed with request
        return await call_next(request)

    def _is_public_endpoint(self, path: str) -> bool:
        """
        Check if endpoint is public (doesn't require authentication).

        Args:
            path: Request path

        Returns:
            True if endpoint is public, False otherwise
        """
        # Check prefix matches
        for prefix in self.PUBLIC_PREFIXES:
            if path.startswith(prefix):
                return True

        # Check exact matches for API endpoints
        for endpoint in self.PUBLIC_API_ENDPOINTS:
            if path.startswith(endpoint):
                return True

        return False

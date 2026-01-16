"""
FastAPI security dependencies for authentication.

Provides dependency injection functions for protected routes with support for:
- Session-based authentication (cookies, for browser apps)
- Token-based authentication (Bearer tokens, for API clients)
"""

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from src.auth.models import User
from src.auth.middleware import security, validate_jwt_token
from jose import JWTError
import logging

logger = logging.getLogger(__name__)


async def get_current_user_from_session(request: Request) -> User:
    """
    Extract current user from session (cookie-based auth) with expiry enforcement.

    Args:
        request: FastAPI request object

    Returns:
        User: Authenticated user from session

    Raises:
        HTTPException 401: If user is not authenticated or session expired

    Usage:
        @router.get("/protected")
        async def protected_route(user: User = Depends(get_current_user_from_session)):
            return {"user": user.email}

    Security:
        - Session-based auth is simpler for browser apps
        - Session data set during OAuth callback flow
        - Enforces dual timeout (absolute + idle)
        - Checks session metadata for expiry
        - WWW-Authenticate header required by RFC 6750
    """
    # Get user data from session
    user_data = request.session.get('user')

    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check session metadata for expiry
    session_id = request.cookies.get('session')  # Starlette session cookie
    if session_id:
        from src.auth.session import get_session_metadata, update_last_activity, delete_session
        from src.auth.config import settings

        metadata = get_session_metadata(session_id)

        if not metadata:
            # Session metadata missing - treat as expired
            request.session.clear()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session expired (metadata not found)",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Check expiry
        is_expired, reason = metadata.is_expired(
            settings.session_absolute_timeout_hours,
            settings.session_idle_timeout_minutes
        )

        if is_expired:
            # Clear session and raise 401
            request.session.clear()
            delete_session(session_id)

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Session expired ({reason} timeout)",
                headers={"WWW-Authenticate": "Bearer"}
            )

        # Update last activity (async to avoid blocking request)
        update_last_activity(session_id)

    # Return User model
    return User(**user_data)


async def get_current_user_from_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    """
    Extract current user from Bearer token (token-based auth).

    Args:
        request: FastAPI request object (for storing jti/exp in state)
        credentials: HTTP Authorization credentials (Bearer token)

    Returns:
        User: Authenticated user from validated token

    Raises:
        HTTPException 401: If token is invalid, missing, or blacklisted

    Usage:
        @router.get("/api/data")
        async def api_endpoint(user: User = Depends(get_current_user_from_token)):
            return {"data": "protected", "user": user.email}

    Security:
        - Token-based auth is standard for API clients
        - Tries both OIDC providers (entra, okta) and self-signed tokens
        - Checks token blacklist for revoked tokens
        - Stores jti and exp in request.state for revocation endpoint
        - WWW-Authenticate header required by RFC 6750
        - Does not expose validation errors to prevent information leakage
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = credentials.credentials

    # First try validating as self-signed token (from our /auth/refresh endpoint)
    import os
    from jose import jwt
    from src.auth.tokens import is_token_blacklisted

    secret_key = os.getenv("JWT_SECRET_KEY")
    if secret_key:
        try:
            # Try decoding as self-signed token
            claims = jwt.decode(token, secret_key, algorithms=["HS256"])

            # Check if token is blacklisted
            jti = claims.get("jti")
            if jti and is_token_blacklisted(jti):
                logger.warning(f"Attempted to use blacklisted token (jti: {jti})")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked",
                    headers={"WWW-Authenticate": "Bearer"}
                )

            # Store jti and exp in request.state for revocation endpoint
            if jti:
                request.state.token_jti = jti
                request.state.token_exp = claims.get("exp", 0)
                request.state.user_sub = claims.get("sub", "")

            # Extract user info from claims
            user = User(
                email=claims.get('email', ''),
                name=claims.get('name', ''),
                sub=claims['sub'],  # Required claim
                provider=claims.get('provider', 'self-signed')
            )

            logger.debug(f"Self-signed token validated successfully")
            return user

        except JWTError:
            # Not a self-signed token, continue to OIDC providers
            logger.debug("Token is not self-signed, trying OIDC providers")
            pass

    # Try validating with each OIDC provider
    # We don't know which IdP issued the token without parsing claims first
    for provider in ["entra", "okta"]:
        try:
            # Validate token with this provider
            claims = await validate_jwt_token(token, provider)

            # Extract user info from claims
            user = User(
                email=claims.get('email', ''),
                name=claims.get('name', ''),
                sub=claims['sub'],  # Required claim
                provider=provider
            )

            logger.debug(f"Token validated successfully with provider {provider}")
            return user

        except HTTPException as e:
            # If this is not a validation error, re-raise immediately
            if e.status_code != status.HTTP_401_UNAUTHORIZED:
                raise

            # Otherwise, continue to next provider
            logger.debug(f"Token validation failed with {provider}, trying next provider")
            continue

        except JWTError as e:
            # JWT validation failed, try next provider
            logger.debug(f"JWT error with {provider}: {e}")
            continue

    # No provider could validate the token
    logger.warning("Token validation failed with all providers")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token",
        headers={"WWW-Authenticate": "Bearer"}
    )


async def get_current_user_with_bypass(request: Request) -> User:
    """
    Get current user with AUTH_DISABLED bypass support.

    If AUTH_DISABLED environment variable is set to 'true', returns a mock admin user.
    Otherwise, uses normal session-based authentication.
    """
    import os

    # Check if authentication is disabled
    auth_disabled = os.getenv("AUTH_DISABLED", "false").lower() == "true"

    if auth_disabled:
        # Return a mock admin user when auth is disabled
        logger.debug("AUTH_DISABLED is true, returning mock admin user")
        return User(
            email="admin@localhost",
            name="Admin User (Auth Disabled)",
            sub="auth-disabled-admin",
            provider="bypass"
        )

    # Normal authentication flow
    return await get_current_user_from_session(request)


# Default to session-based auth with AUTH_DISABLED bypass
# Most endpoints will use cookies (browser-based auth)
# API clients can explicitly use get_current_user_from_token
get_current_user = get_current_user_with_bypass

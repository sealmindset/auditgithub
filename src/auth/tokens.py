"""
Token management for refresh tokens and access tokens.

Implements:
- Refresh token generation with HS256 signing (7-day lifetime)
- Refresh token rotation (one-time use) with Redis tracking
- Token revocation with Redis blacklist
- Access token generation for API authentication
"""

from datetime import datetime, timedelta
from typing import Optional, Tuple
import uuid
import json
import redis
from jose import jwt, JWTError
from fastapi import HTTPException, status
import logging

logger = logging.getLogger(__name__)

# Redis client for token storage and blacklisting
# Use environment variable or default to localhost
import os
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

redis_client = redis.Redis.from_url(
    REDIS_URL,
    decode_responses=True  # Return strings instead of bytes
)


def generate_refresh_token(
    user_sub: str,
    tenant_id: str,
    email: str = "",
    name: str = "",
    provider: str = ""
) -> str:
    """
    Generate a signed refresh token with 7-day lifetime.

    Args:
        user_sub: User's unique identifier (from OIDC provider)
        tenant_id: Tenant UUID
        email: User's email address
        name: User's display name
        provider: OIDC provider ("entra" or "okta")

    Returns:
        str: Signed JWT refresh token

    Security:
        - Uses HS256 signing (symmetric key - we control these tokens)
        - Includes jti (JWT ID) for rotation tracking
        - Stores jti in Redis for one-time use enforcement
    """
    from src.auth.config import settings

    jti = str(uuid.uuid4())
    now = datetime.utcnow()
    exp = now + timedelta(days=7)  # 7-day lifetime

    claims = {
        "sub": user_sub,
        "tenant_id": tenant_id,
        "email": email,
        "name": name,
        "provider": provider,
        "type": "refresh",
        "jti": jti,
        "iat": now,
        "exp": exp
    }

    # Sign token with JWT_SECRET_KEY
    secret_key = os.getenv("JWT_SECRET_KEY")
    if not secret_key:
        raise ValueError("JWT_SECRET_KEY environment variable not set")

    token = jwt.encode(claims, secret_key, algorithm="HS256")

    # Store jti in Redis for rotation tracking (7-day TTL)
    redis_client.setex(f"refresh:{jti}", 7 * 24 * 3600, "1")

    logger.info(f"Generated refresh token for user {user_sub} (jti: {jti})")
    return token


def generate_access_token(
    user_sub: str,
    tenant_id: str,
    email: str = "",
    name: str = ""
) -> str:
    """
    Generate a signed access token with 1-hour lifetime.

    Args:
        user_sub: User's unique identifier
        tenant_id: Tenant UUID
        email: User's email address
        name: User's display name

    Returns:
        str: Signed JWT access token

    Security:
        - Short-lived (1 hour) for security
        - Uses HS256 signing (we control these tokens)
        - Includes jti for revocation capability
    """
    jti = str(uuid.uuid4())
    now = datetime.utcnow()
    exp = now + timedelta(hours=1)  # 1-hour lifetime

    claims = {
        "sub": user_sub,
        "tenant_id": tenant_id,
        "email": email,
        "name": name,
        "type": "access",
        "jti": jti,
        "iat": now,
        "exp": exp
    }

    # Sign token with JWT_SECRET_KEY
    secret_key = os.getenv("JWT_SECRET_KEY")
    if not secret_key:
        raise ValueError("JWT_SECRET_KEY environment variable not set")

    token = jwt.encode(claims, secret_key, algorithm="HS256")

    logger.debug(f"Generated access token for user {user_sub} (jti: {jti})")
    return token


def rotate_refresh_token(old_token: str) -> Tuple[str, dict]:
    """
    Rotate a refresh token (one-time use).

    Validates the old token, checks blacklist and rotation tracker,
    then generates a new refresh token and invalidates the old one.

    Args:
        old_token: Previous refresh token

    Returns:
        (new_token, user_claims): New refresh token and validated claims

    Raises:
        HTTPException 401: If token is invalid, expired, blacklisted, or already used

    Security:
        - Enforces one-time use (checks refresh:{jti} exists in Redis)
        - Checks blacklist (prevents revoked token reuse)
        - Deletes old jti from rotation tracker after successful validation
        - Rotation prevents token reuse attacks
    """
    secret_key = os.getenv("JWT_SECRET_KEY")
    if not secret_key:
        raise ValueError("JWT_SECRET_KEY environment variable not set")

    try:
        # Validate token signature and expiry
        claims = jwt.decode(old_token, secret_key, algorithms=["HS256"])

        # Verify token type
        if claims.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type (expected refresh token)"
            )

        jti = claims.get("jti")
        if not jti:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing jti claim"
            )

        # Check if token is blacklisted
        if is_token_blacklisted(jti):
            logger.warning(f"Attempted to use blacklisted refresh token (jti: {jti})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has been revoked"
            )

        # Check if token is in rotation tracker (one-time use)
        if not redis_client.exists(f"refresh:{jti}"):
            logger.warning(f"Attempted to reuse refresh token (jti: {jti})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has already been used"
            )

        # Extract user claims
        user_sub = claims.get("sub")
        tenant_id = claims.get("tenant_id")
        email = claims.get("email", "")
        name = claims.get("name", "")
        provider = claims.get("provider", "")

        # Delete old jti from rotation tracker (one-time use enforcement)
        redis_client.delete(f"refresh:{jti}")

        # Generate new refresh token
        new_token = generate_refresh_token(
            user_sub=user_sub,
            tenant_id=tenant_id,
            email=email,
            name=name,
            provider=provider
        )

        logger.info(f"Rotated refresh token for user {user_sub} (old jti: {jti})")

        return (new_token, claims)

    except JWTError as e:
        logger.warning(f"Invalid refresh token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid refresh token: {str(e)}"
        )


def revoke_token(jti: str, exp: int):
    """
    Revoke a token by adding its JTI to the blacklist.

    Args:
        jti: Token JTI (unique identifier)
        exp: Token expiry timestamp (Unix time)

    Security:
        - Blacklist entry expires at token's natural expiry time
        - Uses Redis SETEX for automatic cleanup (no manual maintenance)
        - Instant revocation across all API instances
    """
    now = int(datetime.utcnow().timestamp())
    ttl = exp - now

    if ttl > 0:
        redis_client.setex(f"blacklist:{jti}", ttl, "1")
        logger.info(f"Revoked token (jti: {jti}, TTL: {ttl}s)")
    else:
        logger.debug(f"Token already expired (jti: {jti}), skipping blacklist")


def is_token_blacklisted(jti: str) -> bool:
    """
    Check if a token JTI is blacklisted.

    Args:
        jti: Token JTI to check

    Returns:
        bool: True if blacklisted, False otherwise
    """
    return redis_client.exists(f"blacklist:{jti}") > 0

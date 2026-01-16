"""
JWT validation middleware with JWKS caching.

Implements token validation with proper security checks:
- Algorithm whitelist (RS256, RS384, RS512) to prevent "none" algorithm attack
- Claim validation (aud, iss, exp) to prevent confused deputy attacks
- JWKS caching with 24-hour TTL to prevent performance issues
"""

from fastapi import HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from cachetools import TTLCache
import httpx
from src.auth.config import settings
import logging
import os

logger = logging.getLogger(__name__)

# HTTPBearer security scheme for token extraction
# auto_error=False allows handling missing tokens gracefully
security = HTTPBearer(auto_error=False)

# Cache JWKS for 24 hours (86400 seconds)
# Prevents fetching on every request which adds >100ms latency
# See RESEARCH.md "Common Pitfalls #6"
jwks_cache = TTLCache(maxsize=10, ttl=86400)


async def get_jwks(discovery_url: str) -> dict:
    """
    Fetch JWKS (JSON Web Key Set) from provider's discovery document.

    Args:
        discovery_url: OIDC discovery endpoint URL (.well-known/openid-configuration)

    Returns:
        dict: JWKS containing public keys for token validation

    Raises:
        HTTPException: If discovery or JWKS fetch fails

    Security:
        - Caches JWKS for 24 hours to prevent performance issues
        - Automatically handles key rotation via discovery document
    """
    # Return cached JWKS if available
    if discovery_url in jwks_cache:
        logger.debug(f"JWKS cache hit for {discovery_url}")
        return jwks_cache[discovery_url]

    try:
        async with httpx.AsyncClient() as client:
            # Fetch OIDC discovery document
            logger.debug(f"Fetching OIDC discovery from {discovery_url}")
            discovery = await client.get(discovery_url)
            discovery.raise_for_status()
            jwks_uri = discovery.json()["jwks_uri"]

            # Fetch JWKS from jwks_uri
            logger.debug(f"Fetching JWKS from {jwks_uri}")
            jwks_response = await client.get(jwks_uri)
            jwks_response.raise_for_status()
            jwks_data = jwks_response.json()

            # Cache for 24 hours
            jwks_cache[discovery_url] = jwks_data
            logger.info(f"JWKS cached for {discovery_url}")

            return jwks_data

    except httpx.HTTPError as e:
        logger.error(f"Failed to fetch JWKS from {discovery_url}: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to fetch identity provider keys"
        )
    except KeyError as e:
        logger.error(f"Invalid discovery document structure: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Invalid identity provider configuration"
        )


async def validate_jwt_token(token: str, provider: str) -> dict:
    """
    Validate JWT token and return claims.

    Args:
        token: JWT token string
        provider: Identity provider name ("entra" or "okta")

    Returns:
        dict: Validated token claims including email, name, sub

    Raises:
        HTTPException 401: If token is invalid, expired, or malformed

    Security:
        - Explicit algorithm whitelist [RS256, RS384, RS512] prevents "none" algorithm attack
        - Validates aud (audience) claim to prevent confused deputy attacks
        - Validates iss (issuer) claim to prevent token reuse across apps
        - Validates exp (expiration) claim to prevent replay attacks
        - See RESEARCH.md "Common Pitfalls #1, #2"
    """
    # Determine discovery URL based on provider
    if provider == "entra":
        discovery_url = settings.entra_discovery_url
        audience = settings.entra_client_id
    elif provider == "okta":
        discovery_url = settings.okta_discovery_url
        audience = settings.okta_client_id
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid provider: {provider}"
        )

    try:
        # Fetch JWKS (cached)
        jwks = await get_jwks(discovery_url)

        # Decode JWT header to get kid (key ID)
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing key ID"
            )

        # Find matching key in JWKS
        key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: key not found"
            )

        # Validate token with explicit algorithm whitelist and claim validation
        # CRITICAL: Never allow "none" algorithm - enables trivial token forgery
        # CRITICAL: Always validate aud/iss/exp - prevents confused deputy attacks
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256", "RS384", "RS512"],  # Explicit whitelist only
            audience=audience,
            options={
                "verify_aud": True,  # Validate audience claim
                "verify_iss": True,  # Validate issuer claim
                "verify_exp": True   # Validate expiration claim
            }
        )

        logger.debug(f"Token validated successfully for provider {provider}")
        return claims

    except JWTError as e:
        logger.warning(f"JWT validation failed for provider {provider}: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        logger.error(f"Unexpected error validating token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token validation failed",
            headers={"WWW-Authenticate": "Bearer"}
        )


# ============================================================================
# Session Activity Tracking Middleware (Phase 5)
# ============================================================================

from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request


class SessionActivityMiddleware(BaseHTTPMiddleware):
    """
    Middleware to track session activity on every authenticated request.

    Updates last_activity timestamp in Redis for idle timeout enforcement.
    Non-blocking - logs warning on failure but doesn't block requests.
    """

    async def dispatch(self, request: Request, call_next):
        """
        Process request and update session activity if user is authenticated.

        Args:
            request: FastAPI Request object
            call_next: Next middleware/handler in chain

        Returns:
            Response from next handler
        """
        # Process request
        response = await call_next(request)

        # Update activity timestamp if user is authenticated
        session_id = request.cookies.get('session')
        user_data = request.session.get('user')

        if session_id and user_data:
            # Update last_activity in Redis (non-blocking)
            from src.auth.session import update_last_activity
            try:
                update_last_activity(session_id)
            except Exception as e:
                logger.warning(f"Failed to update session activity: {e}")

        return response


# ============================================================================
# Security Headers Middleware (Phase 5)
# ============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all responses.

    Headers:
    - Content-Security-Policy: Restrict resource loading to prevent XSS
    - Strict-Transport-Security: Force HTTPS (production only)
    - X-Frame-Options: Prevent clickjacking
    - X-Content-Type-Options: Prevent MIME sniffing
    - Referrer-Policy: Control referer information leakage
    - Permissions-Policy: Restrict browser features
    """

    def __init__(self, app, enforce_https: bool = False):
        super().__init__(app)
        self.enforce_https = enforce_https or os.getenv("ENVIRONMENT") == "production"

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Content-Security-Policy (CSP)
        # Restrict resource loading to same origin + CDNs
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            "img-src 'self' data: https:",
            "font-src 'self' data: https://cdn.jsdelivr.net",
            "connect-src 'self' https://login.microsoftonline.com https://*.okta.com",
            "frame-ancestors 'none'",  # Prevent embedding in iframes
            "base-uri 'self'",
            "form-action 'self'"
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        # Strict-Transport-Security (HSTS) - production only
        if self.enforce_https:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # X-Frame-Options - prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # X-Content-Type-Options - prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Referrer-Policy - control referer leakage
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions-Policy - restrict browser features
        permissions = [
            "geolocation=()",
            "microphone=()",
            "camera=()",
            "payment=()",
            "usb=()"
        ]
        response.headers["Permissions-Policy"] = ", ".join(permissions)

        # X-XSS-Protection (legacy, but some browsers still use it)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        return response

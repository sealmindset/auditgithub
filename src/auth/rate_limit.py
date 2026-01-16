"""
Rate limiting middleware for API protection.

Uses Redis-backed sliding window algorithm for distributed rate limiting.
Supports per-user and per-IP limits with endpoint-specific overrides.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request
import logging

logger = logging.getLogger(__name__)

# Import Redis client from tokens module
from src.auth.tokens import redis_client


def get_user_identifier(request: Request) -> str:
    """
    Get identifier for rate limiting (user sub or IP address).

    Priority:
    1. User sub (from session or token) - for authenticated requests
    2. IP address - for unauthenticated requests

    Args:
        request: FastAPI Request object

    Returns:
        str: Rate limit identifier (e.g., "user:abc123" or "ip:127.0.0.1")
    """
    # Check if user is authenticated via session
    user_data = request.session.get('user')
    if user_data and 'sub' in user_data:
        return f"user:{user_data['sub']}"

    # Check for token-based auth (if available in request.state)
    if hasattr(request.state, 'user_sub'):
        return f"user:{request.state.user_sub}"

    # Fall back to IP address
    return f"ip:{get_remote_address(request)}"


# Create limiter with Redis storage
limiter = Limiter(
    key_func=get_user_identifier,
    storage_uri=None,  # Will use redis_client directly via storage_options
    storage_options={"connection": redis_client},
    default_limits=["100/minute"],  # Default: 100 requests/minute per user
    headers_enabled=True  # Include X-RateLimit-* headers in response
)


# Override limits for specific endpoints
ENDPOINT_LIMITS = {
    "/auth/login": "5/minute",         # Prevent brute force
    "/auth/register": "3/minute",      # Prevent spam
    "/auth/refresh": "10/minute",      # Limit token refresh
    "/auth/reset-password": "3/minute" # Prevent abuse
}


def get_endpoint_limit(request: Request) -> str:
    """
    Get rate limit for specific endpoint or return default.

    Args:
        request: FastAPI Request object

    Returns:
        str: Rate limit string (e.g., "5/minute")
    """
    # Extract path without query parameters
    path = request.url.path

    # Check for endpoint-specific override
    for endpoint_path, limit in ENDPOINT_LIMITS.items():
        if path.startswith(endpoint_path):
            return limit

    # Return default limit
    return "100/minute"

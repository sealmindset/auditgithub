"""
API key authentication and authorization.

Validates API keys from the X-API-Key header, enforces rate limiting via Redis,
resolves effective permissions (intersection of owner + key overrides), and
provides tool/repository scope checking.
"""

import hashlib
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from src.api.database import SessionLocal
from src.api.models import ApiKey, User as DBUser
from src.api.constants.tool_categories import TOOL_CATEGORIES
from src.auth.models import User

import logging

logger = logging.getLogger(__name__)


async def validate_api_key(request: Request) -> Optional[User]:
    """
    Extract and validate API key from X-API-Key header.

    Returns the owning User (auth model) if valid, None if no API key header present.
    Raises HTTPException if key is present but invalid.

    On success, sets request.state attributes:
      - auth_method = "api_key"
      - api_key_id = key UUID
      - api_key_tool_categories = allowed categories or None
      - api_key_tools = allowed tools or None
      - api_key_repository_ids = allowed repo IDs or None
      - effective_permissions = resolved permission list
      - db_user = the owning DBUser
    """
    api_key_header = request.headers.get("X-API-Key")
    if not api_key_header:
        return None

    # Hash the provided key
    key_hash = hashlib.sha256(api_key_header.encode()).hexdigest()

    # Look up in database
    db = SessionLocal()
    try:
        api_key = db.query(ApiKey).filter(ApiKey.key_hash == key_hash).first()

        if not api_key:
            logger.warning("API key authentication failed: key not found")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "X-API-Key"},
            )

        # Check if active
        if not api_key.is_active:
            logger.warning(f"API key authentication failed: key revoked ({api_key.key_prefix})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has been revoked",
                headers={"WWW-Authenticate": "X-API-Key"},
            )

        # Check expiration
        if api_key.expires_at and api_key.expires_at < datetime.now(timezone.utc):
            logger.warning(f"API key authentication failed: key expired ({api_key.key_prefix})")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired",
                headers={"WWW-Authenticate": "X-API-Key"},
            )

        # Check organization context matches (if org context is set)
        org_id = getattr(request.state, 'org_id', None)
        if org_id and str(api_key.organization_id) != org_id:
            logger.warning(f"API key org mismatch: key org={api_key.organization_id}, request org={org_id}")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="API key does not belong to this organization",
            )

        # Check rate limit
        rate_allowed = check_api_key_rate_limit(str(api_key.id), api_key.rate_limit_per_hour)
        if not rate_allowed:
            logger.warning(f"API key rate limit exceeded: {api_key.key_prefix}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded ({api_key.rate_limit_per_hour}/hr)",
                headers={"Retry-After": "60"},
            )

        # Fetch the owning user
        owner = db.query(DBUser).filter(DBUser.id == api_key.user_id).first()
        if not owner or not owner.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key owner account is inactive",
            )

        # Resolve effective permissions
        owner_permissions = _get_owner_permissions(owner)
        effective = resolve_effective_permissions(owner_permissions, api_key.permission_overrides)

        # Set request state for downstream middleware/handlers
        request.state.auth_method = "api_key"
        request.state.api_key_id = api_key.id
        request.state.api_key_tool_categories = api_key.allowed_tool_categories
        request.state.api_key_tools = api_key.allowed_tools
        request.state.api_key_repository_ids = api_key.allowed_repository_ids
        request.state.effective_permissions = effective
        request.state.db_user = owner

        # Update last_used_at and last_used_ip (non-blocking update)
        api_key.last_used_at = datetime.now(timezone.utc)
        api_key.last_used_ip = request.client.host if request.client else None
        db.commit()

        # Build auth User model for compatibility with existing code
        user = User(
            email=owner.email or "",
            name=owner.full_name or owner.username or "",
            sub=str(owner.id),
            provider="api_key",
        )

        logger.debug(f"API key authenticated: {api_key.key_prefix} as {owner.email}")
        return user

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API key validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key validation failed",
        )
    finally:
        db.close()


def check_api_key_rate_limit(key_id: str, limit: int) -> bool:
    """
    Check API key rate limit using Redis sliding window counter.
    Key: apikey_rate:{key_id}, Window: 1 hour.
    Returns True if within limit, False if exceeded.
    """
    try:
        from src.auth.tokens import redis_client

        redis_key = f"apikey_rate:{key_id}"
        current = redis_client.incr(redis_key)
        if current == 1:
            redis_client.expire(redis_key, 3600)  # 1 hour window
        return current <= limit
    except Exception as e:
        # If Redis is down, allow the request (fail-open for availability)
        logger.warning(f"Rate limit check failed (allowing request): {e}")
        return True


def resolve_effective_permissions(
    owner_permissions: List[str],
    key_permission_overrides: Optional[List[str]],
) -> List[str]:
    """
    Compute effective permissions for an API key.

    If key has permission_overrides, return the intersection with owner_permissions.
    Otherwise, return all owner_permissions.
    Keys can never escalate beyond the owner's permissions.
    """
    if key_permission_overrides is None:
        return owner_permissions
    return [p for p in key_permission_overrides if p in owner_permissions]


def is_tool_allowed(
    tool_name: str,
    key_allowed_categories: Optional[List[str]],
    key_allowed_tools: Optional[List[str]],
) -> bool:
    """
    Check if a specific tool is allowed by an API key's scope.
    Priority: allowed_tools (explicit) > allowed_tool_categories > None (all allowed).
    """
    # No restrictions = all tools allowed
    if key_allowed_categories is None and key_allowed_tools is None:
        return True
    # Explicit tool allowlist takes precedence
    if key_allowed_tools is not None and tool_name in key_allowed_tools:
        return True
    # Check category membership
    if key_allowed_categories is not None:
        for category, config in TOOL_CATEGORIES.items():
            if category in key_allowed_categories and tool_name in config["tools"]:
                return True
    # If tools list is set but tool not in it, and categories don't cover it
    return False


def is_repository_allowed(
    repository_id: str,
    key_allowed_repository_ids: Optional[List[str]],
) -> bool:
    """
    Check if a specific repository is allowed by an API key's scope.
    None = all repos the owner has access to.
    """
    if key_allowed_repository_ids is None:
        return True
    return str(repository_id) in key_allowed_repository_ids


def _get_owner_permissions(owner: DBUser) -> List[str]:
    """
    Get the permission list for a user based on their role.
    Maps to the same RBAC structure used by the rest of the system.
    """
    role_permissions = {
        'super_admin': ['*'],
        'admin': ['*'],
        'manager': ['findings:read', 'findings:write', 'scans:read', 'scans:execute', 'repos:read', 'repos:write'],
        'analyst': ['findings:read', 'findings:write', 'scans:read', 'scans:execute', 'repos:read'],
        'developer': ['findings:read', 'scans:read', 'scans:execute', 'repos:read'],
        'user': ['findings:read', 'repos:read'],
    }
    return role_permissions.get(owner.role, ['findings:read', 'repos:read'])

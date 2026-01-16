"""
Redis caching for RBAC permission lookups.

Provides caching layer for get_user_permissions() results with 5-minute TTL
and pub/sub invalidation when role assignments change.
"""

import redis
import json
import logging
import os
from typing import Optional, List

logger = logging.getLogger(__name__)

# Redis client initialization
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

# Initialize Redis client with error handling
try:
    redis_client = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=0,
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5
    )
    # Test connection
    redis_client.ping()
    logger.info(f"Redis client connected to {REDIS_HOST}:{REDIS_PORT}")
except Exception as e:
    logger.warning(f"Redis connection failed: {e}. Caching will be disabled.")
    redis_client = None

# Cache TTL: 5 minutes (300 seconds)
PERMISSION_CACHE_TTL = 300


async def get_cached_permissions(user_sub: str, tenant_id: str) -> Optional[List[str]]:
    """
    Get cached permissions for a user in a tenant.

    Args:
        user_sub: User's subject claim
        tenant_id: Tenant/organization ID

    Returns:
        List of permission strings if cached, None if not cached or error

    Cache key format: permissions:{user_sub}:{tenant_id}
    """
    if not redis_client:
        return None

    try:
        key = f"permissions:{user_sub}:{tenant_id}"
        cached = redis_client.get(key)

        if cached:
            permissions = json.loads(cached)
            logger.debug(f"Cache hit for {user_sub} in tenant {tenant_id}: {permissions}")
            return permissions

        logger.debug(f"Cache miss for {user_sub} in tenant {tenant_id}")
        return None

    except Exception as e:
        logger.error(f"Error reading from cache: {e}")
        return None


async def set_cached_permissions(user_sub: str, tenant_id: str, permissions: List[str]) -> None:
    """
    Cache permissions for a user in a tenant with TTL.

    Args:
        user_sub: User's subject claim
        tenant_id: Tenant/organization ID
        permissions: List of permission strings to cache

    Cache TTL: 5 minutes (balances performance vs staleness)
    """
    if not redis_client:
        return

    try:
        key = f"permissions:{user_sub}:{tenant_id}"
        value = json.dumps(permissions)
        redis_client.setex(key, PERMISSION_CACHE_TTL, value)
        logger.debug(f"Cached permissions for {user_sub} in tenant {tenant_id} (TTL={PERMISSION_CACHE_TTL}s)")

    except Exception as e:
        logger.error(f"Error writing to cache: {e}")


async def invalidate_user_permissions(user_sub: str, tenant_id: Optional[str] = None) -> None:
    """
    Invalidate cached permissions for a user.

    Call this when:
    - User's role assignment changes
    - Role's permissions are modified
    - User is removed from tenant

    Args:
        user_sub: User's subject claim
        tenant_id: Tenant ID to invalidate (optional)
                  If None, invalidates all tenants for this user

    Examples:
        # Invalidate single tenant
        await invalidate_user_permissions("user123", "tenant456")

        # Invalidate all tenants for user
        await invalidate_user_permissions("user123")
    """
    if not redis_client:
        return

    try:
        if tenant_id:
            # Invalidate single tenant
            key = f"permissions:{user_sub}:{tenant_id}"
            deleted = redis_client.delete(key)
            if deleted:
                logger.info(f"Invalidated cache for {user_sub} in tenant {tenant_id}")
        else:
            # Invalidate all tenants for user (pattern delete)
            pattern = f"permissions:{user_sub}:*"
            cursor = 0
            deleted_count = 0

            while True:
                cursor, keys = redis_client.scan(cursor, match=pattern, count=100)
                if keys:
                    deleted_count += redis_client.delete(*keys)
                if cursor == 0:
                    break

            logger.info(f"Invalidated {deleted_count} cache entries for {user_sub} (all tenants)")

    except Exception as e:
        logger.error(f"Error invalidating cache: {e}")


async def publish_permission_invalidation(user_sub: str, tenant_id: Optional[str] = None) -> None:
    """
    Publish permission invalidation event to Redis pub/sub.

    Use this in distributed environments where multiple API instances
    need to be notified of permission changes.

    Args:
        user_sub: User's subject claim
        tenant_id: Tenant ID (optional)

    Message format: {"user_sub": "...", "tenant_id": "..."}
    """
    if not redis_client:
        return

    try:
        message = json.dumps({
            "user_sub": user_sub,
            "tenant_id": tenant_id
        })
        redis_client.publish("permission_invalidation", message)
        logger.debug(f"Published invalidation event for {user_sub} (tenant={tenant_id})")

    except Exception as e:
        logger.error(f"Error publishing invalidation event: {e}")


async def invalidate_role_permissions(role_id: str, tenant_id: Optional[str] = None) -> None:
    """
    Invalidate cached permissions for all users with a specific role.

    Call this when a role's permissions are modified.

    This is a more expensive operation as it requires:
    1. Query all UserRole records with role_id
    2. Invalidate cache for each user

    Args:
        role_id: Role UUID
        tenant_id: Tenant ID to limit invalidation (optional)

    Note: This function requires database access and should be called
    from within a route handler or background task with session access.
    """
    if not redis_client:
        return

    try:
        # This will be implemented when called from a context with DB access
        # For now, log the request
        logger.info(f"Role permission invalidation requested for role {role_id} (tenant={tenant_id})")
        logger.warning("invalidate_role_permissions requires database access - implement in route handler")

    except Exception as e:
        logger.error(f"Error invalidating role permissions: {e}")


def is_cache_available() -> bool:
    """
    Check if Redis cache is available.

    Returns:
        True if Redis is connected, False otherwise
    """
    if not redis_client:
        return False

    try:
        redis_client.ping()
        return True
    except Exception:
        return False

"""
Permission evaluation logic for RBAC system.

Provides functions for evaluating user permissions with tenant filtering,
wildcard support, and role hierarchy checks with Redis caching.
"""

from typing import List, Optional
from sqlalchemy.orm import Session
from src.rbac.models import Role, Permission, RolePermission, UserRole
from src.auth.models import User
from src.rbac.cache import get_cached_permissions, set_cached_permissions
import logging

logger = logging.getLogger(__name__)


async def get_user_role(user_sub: str, tenant_id: str, session: Session) -> Optional[Role]:
    """
    Get user's role in a specific tenant.

    Args:
        user_sub: User's subject claim (from OIDC token)
        tenant_id: Tenant/organization ID
        session: Database session

    Returns:
        Role object if user has a role in the tenant, None otherwise

    Security:
        CRITICAL - Always filters by tenant_id to prevent cross-tenant access
    """
    user_role = session.query(UserRole).filter(
        UserRole.user_sub == user_sub,
        UserRole.tenant_id == tenant_id
    ).first()

    if not user_role:
        logger.debug(f"No role found for user {user_sub} in tenant {tenant_id}")
        return None

    # Join with Role to get full role details
    role = session.query(Role).filter(Role.id == user_role.role_id).first()
    return role


async def get_role_permissions(role_id: str, session: Session) -> List[Permission]:
    """
    Get all permissions assigned to a role.

    Args:
        role_id: Role UUID
        session: Database session

    Returns:
        List of Permission objects assigned to the role
    """
    permissions = session.query(Permission).join(
        RolePermission
    ).filter(
        RolePermission.role_id == role_id
    ).all()

    return permissions


async def get_user_permissions(user: User, tenant_id: str, session: Session) -> List[str]:
    """
    Get all permissions for a user in a specific tenant with Redis caching.

    Caching strategy:
    - Check cache first (5-minute TTL)
    - If miss, query database and cache result
    - Cache provides >100ms latency improvement per request

    Args:
        user: Authenticated user
        tenant_id: Tenant/organization ID
        session: Database session

    Returns:
        List of permission names in "resource:action" format
        Example: ["findings:read", "findings:write", "scans:execute", "*:*"]

    Security:
        - Returns empty list if user has no role in tenant
        - Always filters by tenant_id to prevent cross-tenant access
        - Supports wildcard permissions (*:* for super admin)
        - Cache invalidated when role assignments change
    """
    # Check cache first
    cached_perms = await get_cached_permissions(user.sub, tenant_id)
    if cached_perms is not None:
        logger.debug(f"Cache hit for {user.email} in tenant {tenant_id}")
        return cached_perms

    # Cache miss - fetch from database
    logger.debug(f"Cache miss for {user.email} in tenant {tenant_id}, querying database")

    # Get user's role in this tenant
    role = await get_user_role(user.sub, tenant_id, session)

    if not role:
        logger.debug(f"User {user.email} has no role in tenant {tenant_id}")
        # Cache empty result to avoid repeated database queries
        await set_cached_permissions(user.sub, tenant_id, [])
        return []

    # Get permissions for the role
    permissions = await get_role_permissions(role.id, session)

    # Return permission names in resource:action format
    permission_names = [f"{p.resource}:{p.action}" for p in permissions]

    logger.debug(f"User {user.email} permissions in tenant {tenant_id}: {permission_names}")

    # Cache the result
    await set_cached_permissions(user.sub, tenant_id, permission_names)

    return permission_names


def has_permission(user_permissions: List[str], required_permission: str) -> bool:
    """
    Check if user has a required permission, including wildcard matching.

    Wildcard rules:
    - "*:*" matches any permission (super admin)
    - "resource:*" matches any action on that resource
    - Exact match required otherwise

    Args:
        user_permissions: List of user's permissions
        required_permission: Required permission in "resource:action" format

    Returns:
        True if user has the permission, False otherwise

    Examples:
        has_permission(["*:*"], "findings:read") -> True
        has_permission(["findings:*"], "findings:read") -> True
        has_permission(["findings:read"], "findings:write") -> False
    """
    # Check for super admin wildcard
    if "*:*" in user_permissions:
        return True

    # Check for exact match
    if required_permission in user_permissions:
        return True

    # Check for resource wildcard (e.g., "findings:*")
    resource = required_permission.split(":")[0]
    resource_wildcard = f"{resource}:*"
    if resource_wildcard in user_permissions:
        return True

    return False


def has_role_level(user_role_level: int, required_level: int) -> bool:
    """
    Check if user's role level meets required level.

    Role hierarchy: Lower level number = higher privilege
    - 1 = Super Admin
    - 2 = Admin
    - 3 = Analyst
    - 4 = Manager
    - 5 = User

    Args:
        user_role_level: User's role level
        required_level: Required minimum role level

    Returns:
        True if user's level is sufficient (<=), False otherwise

    Examples:
        has_role_level(2, 3) -> True (Admin level=2 can access Analyst level=3 resource)
        has_role_level(4, 3) -> False (Manager level=4 cannot access Analyst level=3 resource)
    """
    return user_role_level <= required_level

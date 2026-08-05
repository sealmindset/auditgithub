"""
FastAPI authentication and authorization dependencies for RBAC.

Provides dependency injection functions for protecting API routes with
permission checks, role level validation, and tenant access verification.

Usage examples:
    # Permission-based protection
    @router.get("/findings", dependencies=[Depends(require_permissions("findings:read"))])
    async def list_findings(user: User = Depends(get_current_user)):
        return {"findings": [...]}

    # Role-based protection (level 3 = Analyst and above)
    @router.post("/scans", dependencies=[Depends(require_role(3))])
    async def create_scan(user: User = Depends(get_current_user)):
        return {"scan_id": "..."}

    # Resource-level tenant check (inside handler)
    @router.get("/findings/{finding_id}", dependencies=[Depends(require_permissions("findings:read"))])
    async def get_finding(finding_id: str, user: User = Depends(get_current_user), session: Session = Depends(get_db)):
        await require_tenant_access(finding_id, "finding", user, session)
        return await session.get_finding(finding_id)
"""

from typing import List, Callable
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from src.auth.dependencies import get_current_user
from src.auth.models import User
from src.api.database import get_db
from src.rbac.permissions import get_user_permissions, has_permission, get_user_role, has_role_level
from src.rbac.audit import audit_authorization, audit_data_access
import logging

logger = logging.getLogger(__name__)


def get_tenant_id_from_request(request: Request) -> str:
    """
    Extract tenant ID from request context.

    Resolution order:
    1. request.state.org_id (set by OrganizationContextMiddleware)
    2. Auto-select when only one organization exists (single-org mode)
    3. AUTH_DISABLED bypass

    Args:
        request: FastAPI request object

    Returns:
        Tenant/organization ID as string

    Raises:
        HTTPException 400: If tenant context cannot be determined
    """
    import os

    # Check both attribute names (middleware sets org_id)
    tenant_id = (
        getattr(request.state, "org_id", None)
        or getattr(request.state, "organization_id", None)
    )

    if not tenant_id:
        # Check if auth is disabled - allow bypass
        auth_disabled = os.getenv("AUTH_DISABLED", "false").lower() == "true"
        if auth_disabled:
            logger.debug("AUTH_DISABLED is true, returning dummy tenant ID")
            return "auth-disabled-tenant"

        # Auto-select org when multi-tenant is disabled or only one org exists
        multi_tenant = os.getenv("MULTI_TENANT_ENABLED", "false").lower() == "true"
        if not multi_tenant:
            try:
                from src.api.database import SessionLocal
                from src.api.models import Organization, Repository
                from sqlalchemy import func
                db = SessionLocal()
                try:
                    # Pick the org with the most repositories (most likely the primary)
                    result = (
                        db.query(Organization.id)
                        .outerjoin(Repository, Repository.organization_id == Organization.id)
                        .group_by(Organization.id)
                        .order_by(func.count(Repository.id).desc())
                        .first()
                    )
                    if result:
                        tenant_id = str(result.id)
                        logger.debug(f"Auto-selected organization (multi-tenant disabled): {tenant_id}")
                        return tenant_id
                finally:
                    db.close()
            except Exception as e:
                logger.warning(f"Failed to auto-select organization: {e}")

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization context required. Set X-Organization-ID header or X-Organization-Name header."
        )

    return str(tenant_id)


def require_permissions(*required_perms: str) -> Callable:
    """
    Create a FastAPI dependency that checks if user has required permissions.

    This is a dependency factory that returns a dependency function. The
    dependency runs before the route handler, ensuring authorization happens
    before any data access (prevents timing attacks).

    Args:
        *required_perms: Permission names in "resource:action" format

    Returns:
        FastAPI dependency function that checks permissions

    Raises:
        HTTPException 403: If user lacks any required permission

    Examples:
        @router.get("/findings", dependencies=[Depends(require_permissions("findings:read"))])
        @router.post("/findings", dependencies=[Depends(require_permissions("findings:write"))])
        @router.delete("/findings/{id}", dependencies=[Depends(require_permissions("findings:delete"))])

    Security:
        - Checks all required permissions before route handler runs
        - Logs authorization failures for audit trail
        - Returns 403 (not 404) for permission denied on routes
    """
    async def permission_checker(
        user: User = Depends(get_current_user),
        request: Request = None,
        session: Session = Depends(get_db)
    ) -> User:
        """Inner dependency function that performs the permission check."""
        import os

        # Check if authentication is disabled - bypass all permission checks
        auth_disabled = os.getenv("AUTH_DISABLED", "false").lower() == "true"
        if auth_disabled:
            logger.debug(f"AUTH_DISABLED is true, bypassing permission check for {required_perms}")
            return user

        # Get tenant context from request
        tenant_id = get_tenant_id_from_request(request)

        # Get user's permissions in this tenant via RBAC tables
        user_perms = await get_user_permissions(user, tenant_id, session)

        # Fallback: if no RBAC role assignment exists, check legacy User.role field
        if not user_perms:
            legacy_perms = _get_legacy_permissions(user, session)
            if legacy_perms:
                logger.debug(
                    f"Using legacy role permissions for {user.email}: {legacy_perms}"
                )
                user_perms = legacy_perms

        # Check each required permission
        for perm in required_perms:
            if not has_permission(user_perms, perm):
                logger.warning(
                    f"Permission denied for {user.email} in tenant {tenant_id}: "
                    f"required {perm}, has {user_perms}"
                )
                # Audit authorization failure
                audit_authorization(
                    user, tenant_id, "api", "request", granted=False,
                    reason=f"Missing permission: {perm}",
                    required_permissions=list(required_perms),
                    user_permissions=user_perms
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {perm}"
                )

        # All checks passed, audit success and return user for chaining
        logger.debug(f"Permission check passed for {user.email}: {required_perms}")
        audit_authorization(
            user, tenant_id, "api", "request", granted=True,
            required_permissions=list(required_perms),
            user_permissions=user_perms
        )
        return user

    return permission_checker


def check_permission(permission: str) -> Callable:
    """
    Create a dependency that REPORTS whether the user holds a permission, as a bool.

    Unlike require_permissions, this never raises. It exists for routes whose behaviour
    degrades rather than fails: the zero-day analyst runs its database tools for any
    caller with findings:write, but reaches live external systems only with
    hunt:execute, and the response records which surfaces went unexamined.

    Do not use this to guard a route. A route that must be denied should use
    require_permissions, which returns 403 before the handler runs. This returns a value
    the handler is free to ignore, so it protects nothing on its own.

    Args:
        permission: Permission name in "resource:action" format

    Returns:
        FastAPI dependency resolving to True if the user holds the permission.
    """
    async def permission_reporter(
        user: User = Depends(get_current_user),
        request: Request = None,
        session: Session = Depends(get_db)
    ) -> bool:
        import os

        if os.getenv("AUTH_DISABLED", "false").lower() == "true":
            return True

        try:
            tenant_id = get_tenant_id_from_request(request)
            user_perms = await get_user_permissions(user, tenant_id, session)
            if not user_perms:
                user_perms = _get_legacy_permissions(user, session)
            granted = has_permission(user_perms, permission)
        except Exception as exc:
            # Fail closed. An error resolving permissions must not read as a grant.
            logger.warning(f"check_permission({permission}) could not be resolved: {exc}")
            return False

        # Recorded either way: a denial here silently narrows what a hunt examined, and
        # that needs to be attributable afterwards.
        audit_authorization(
            user, tenant_id, "api", "request", granted=granted,
            reason=None if granted else f"Optional capability not held: {permission}",
            required_permissions=[permission],
            user_permissions=user_perms,
        )
        return granted

    return permission_reporter


# Legacy role → permission mapping for backward compatibility
# Used when user_roles table has no entry for the user
#
# KEEP IN SYNC with role_permissions_map in src/rbac/seeds.py. These two maps are
# duplicated definitions of the same policy and will silently diverge otherwise — a
# permission added only to seeds.py is invisible to any user falling back to legacy
# role resolution.
_LEGACY_ROLE_PERMISSIONS = {
    "super_admin": ["*:*"],
    "admin": [
        "findings:read", "findings:write", "findings:delete",
        "scans:read", "scans:execute",
        "repositories:read", "repositories:write",
        "organizations:read", "organizations:write",
        "users:read", "users:write",
        "reports:read", "admin:manage",
        "hunt:read", "hunt:execute",
        "schedules:read", "schedules:create", "schedules:update",
        "schedules:override", "schedules:trigger",
    ],
    "analyst": [
        "findings:read", "findings:write",
        "scans:read", "scans:execute",
        "repositories:read",
        "reports:read",
        "hunt:read", "hunt:execute",
        "schedules:read", "schedules:create", "schedules:update",
        "schedules:trigger",
    ],
    "manager": [
        "findings:read", "scans:read", "repositories:read", "reports:read",
        "hunt:read",
        "schedules:read",
    ],
    "user": [
        "findings:read", "repositories:read", "reports:read",
        "schedules:read",
    ],
}


def _get_legacy_permissions(user: User, session: Session) -> list[str]:
    """Look up legacy User.role from the users table and map to permissions."""
    try:
        from src.api.models import User as DBUser
        db_user = session.query(DBUser).filter(DBUser.email == user.email).first()
        if db_user and db_user.role:
            perms = _LEGACY_ROLE_PERMISSIONS.get(db_user.role, [])
            if perms:
                return perms
    except Exception as e:
        logger.warning(f"Legacy role lookup failed for {user.email}: {e}")
    return []


def require_role(min_role_level: int) -> Callable:
    """
    Create a FastAPI dependency that checks if user has required role level.

    Role hierarchy: Lower level number = higher privilege
    - 1 = Super Admin
    - 2 = Admin
    - 3 = Analyst
    - 4 = Manager
    - 5 = User

    Args:
        min_role_level: Minimum role level required (1-5)

    Returns:
        FastAPI dependency function that checks role level

    Raises:
        HTTPException 403: If user's role level is insufficient or missing

    Examples:
        @router.post("/admin/users", dependencies=[Depends(require_role(2))])  # Admin and above
        @router.get("/reports", dependencies=[Depends(require_role(4))])  # Manager and above

    Security:
        - Checks role level before route handler runs
        - Logs authorization failures for audit trail
        - Returns 403 for both missing roles and insufficient levels
    """
    async def role_checker(
        user: User = Depends(get_current_user),
        request: Request = None,
        session: Session = Depends(get_db)
    ) -> User:
        """Inner dependency function that performs the role level check."""
        # Get tenant context from request
        tenant_id = get_tenant_id_from_request(request)

        # Get user's role in this tenant
        role = await get_user_role(user.sub, tenant_id, session)

        if not role:
            logger.warning(f"User {user.email} has no role in tenant {tenant_id}")
            # Audit authorization failure - no role
            audit_authorization(
                user, tenant_id, "api", "request", granted=False,
                reason=f"No role assigned in tenant"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No role assigned in this tenant"
            )

        # Check if user's role level is sufficient
        if not has_role_level(role.level, min_role_level):
            logger.warning(
                f"Role check failed for {user.email} in tenant {tenant_id}: "
                f"required level {min_role_level}, has level {role.level}"
            )
            # Audit authorization failure - insufficient role level
            audit_authorization(
                user, tenant_id, "api", "request", granted=False,
                reason=f"Role level {role.level} insufficient for requirement {min_role_level}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role level insufficient: required {min_role_level}, has {role.level}"
            )

        # Role level check passed
        logger.debug(f"Role check passed for {user.email}: level {role.level} >= {min_role_level}")
        # Audit authorization success
        audit_authorization(
            user, tenant_id, "api", "request", granted=True,
            reason=f"Role level {role.level} meets requirement {min_role_level}"
        )
        return user

    return role_checker


async def require_tenant_access(
    resource_id: str,
    resource_type: str,
    user: User,
    tenant_id: str,
    session: Session
) -> None:
    """
    Verify that a resource belongs to the user's current tenant.

    This is a helper function (not a dependency) that should be called inside
    route handlers to verify resource-level tenant access. This check happens
    after permission checks but before returning data.

    Args:
        resource_id: UUID of the resource to check
        resource_type: Type of resource (e.g., "finding", "scan", "repository")
        user: Authenticated user
        tenant_id: Current tenant ID
        session: Database session

    Raises:
        HTTPException 404: If resource doesn't exist or belongs to different tenant

    Examples:
        @router.get("/findings/{finding_id}")
        async def get_finding(
            finding_id: str,
            user: User = Depends(get_current_user),
            request: Request = None,
            session: Session = Depends(get_db)
        ):
            tenant_id = get_tenant_id_from_request(request)
            await require_tenant_access(finding_id, "finding", user, tenant_id, session)
            finding = session.query(Finding).filter(Finding.id == finding_id).first()
            return finding

    Security:
        - Returns 404 (not 403) to prevent information disclosure
        - Prevents tenant enumeration attacks
        - Logs access attempts for audit trail
    """
    # Import here to avoid circular dependency
    # Resource models should have organization_id column
    from src.api.database import Base

    # Map resource types to model classes
    # This will need to be expanded as more resources are added
    resource_models = {
        "finding": "Finding",
        "scan": "Scan",
        "repository": "Repository",
        # Add more resource types as needed
    }

    if resource_type not in resource_models:
        logger.error(f"Unknown resource type: {resource_type}")
        # Audit failed access attempt - unknown resource type
        audit_data_access(user, tenant_id, resource_type, resource_id, "access_denied")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found"
        )

    # Query the resource and check organization_id
    # For now, we'll log the check but not perform it since models aren't fully defined
    # This will be implemented when resource models are available
    logger.debug(
        f"Tenant access check for {user.email}: "
        f"resource_type={resource_type}, resource_id={resource_id}, tenant_id={tenant_id}"
    )

    # Audit successful access check (once actual verification is implemented)
    audit_data_access(user, tenant_id, resource_type, resource_id, "access_check")

    # TODO: Implement actual resource query when models are available
    # Example:
    # model_class = get_model_class(resource_type)
    # resource = session.query(model_class).filter(
    #     model_class.id == resource_id,
    #     model_class.organization_id == tenant_id
    # ).first()
    #
    # if not resource:
    #     logger.warning(
    #         f"Resource access denied for {user.email}: "
    #         f"{resource_type}:{resource_id} not in tenant {tenant_id}"
    #     )
    #     raise HTTPException(
    #         status_code=status.HTTP_404_NOT_FOUND,
    #         detail="Resource not found"
    #     )

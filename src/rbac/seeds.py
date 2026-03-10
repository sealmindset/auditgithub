"""
RBAC seed data for default roles and permissions.

Seeds the database with 5 default roles and their associated permissions.
Designed to be idempotent - safe to run multiple times without duplicates.

Usage:
    from src.rbac.seeds import seed_rbac_data
    from src.api.database import SessionLocal

    session = SessionLocal()
    seed_rbac_data(session)
    session.close()
"""

from sqlalchemy.orm import Session
from sqlalchemy import select
from src.rbac.models import Role, Permission, RolePermission
import logging

logger = logging.getLogger(__name__)


def seed_rbac_data(session: Session) -> None:
    """
    Seed database with default RBAC roles and permissions.

    Creates:
    - 5 roles (super_admin, admin, analyst, manager, user)
    - ~13 permissions covering core resources
    - Role-permission mappings based on hierarchy

    Idempotent: Uses merge() to avoid duplicate entries on re-runs.

    Args:
        session: SQLAlchemy database session
    """
    logger.info("Starting RBAC seed data initialization...")

    # =============================================================================
    # Define Roles
    # =============================================================================
    roles_data = [
        {
            "name": "super_admin",
            "display_name": "Super Administrator",
            "description": "Full system access across all tenants",
            "level": 1
        },
        {
            "name": "admin",
            "display_name": "Administrator",
            "description": "Tenant administrator with full access to tenant resources",
            "level": 2
        },
        {
            "name": "analyst",
            "display_name": "Security Analyst",
            "description": "Security analyst with read/write access to findings and scans",
            "level": 3
        },
        {
            "name": "manager",
            "display_name": "Manager",
            "description": "Manager with read-only access to reports and dashboards",
            "level": 4
        },
        {
            "name": "user",
            "display_name": "User",
            "description": "Basic user with limited read-only access",
            "level": 5
        }
    ]

    # Create or update roles
    roles = {}
    for role_data in roles_data:
        # Check if role exists
        existing_role = session.execute(
            select(Role).where(Role.name == role_data["name"])
        ).scalar_one_or_none()

        if existing_role:
            # Update existing role
            for key, value in role_data.items():
                setattr(existing_role, key, value)
            role = existing_role
            logger.info(f"Updated existing role: {role_data['name']}")
        else:
            # Create new role
            role = Role(**role_data)
            session.add(role)
            logger.info(f"Created new role: {role_data['name']}")

        roles[role_data["name"]] = role

    session.flush()  # Flush to get role IDs

    # =============================================================================
    # Define Permissions
    # =============================================================================
    permissions_data = [
        # Super admin wildcard
        {"name": "*:*", "resource": "*", "action": "*", "description": "Full system access (super admin only)"},

        # Findings permissions
        {"name": "findings:read", "resource": "findings", "action": "read", "description": "View security findings"},
        {"name": "findings:write", "resource": "findings", "action": "write", "description": "Create and update findings"},
        {"name": "findings:delete", "resource": "findings", "action": "delete", "description": "Delete findings"},

        # Scans permissions
        {"name": "scans:read", "resource": "scans", "action": "read", "description": "View scan results"},
        {"name": "scans:execute", "resource": "scans", "action": "execute", "description": "Trigger security scans"},

        # Repositories permissions
        {"name": "repositories:read", "resource": "repositories", "action": "read", "description": "View repositories"},
        {"name": "repositories:write", "resource": "repositories", "action": "write", "description": "Add/update repositories"},

        # Organizations permissions
        {"name": "organizations:read", "resource": "organizations", "action": "read", "description": "View organizations"},
        {"name": "organizations:write", "resource": "organizations", "action": "write", "description": "Manage organizations"},

        # Users permissions
        {"name": "users:read", "resource": "users", "action": "read", "description": "View users"},
        {"name": "users:write", "resource": "users", "action": "write", "description": "Manage users"},

        # Reports permissions
        {"name": "reports:read", "resource": "reports", "action": "read", "description": "View reports"},

        # Schedules permissions
        {"name": "schedules:read", "resource": "schedules", "action": "read", "description": "View scan schedules"},
        {"name": "schedules:create", "resource": "schedules", "action": "create", "description": "Create scan schedules"},
        {"name": "schedules:update", "resource": "schedules", "action": "update", "description": "Update scan schedules"},
        {"name": "schedules:override", "resource": "schedules", "action": "override", "description": "Lock/unlock schedule overrides"},
        {"name": "schedules:trigger", "resource": "schedules", "action": "trigger", "description": "Trigger immediate scans"},
    ]

    # Create or update permissions
    permissions = {}
    for perm_data in permissions_data:
        # Check if permission exists
        existing_perm = session.execute(
            select(Permission).where(Permission.name == perm_data["name"])
        ).scalar_one_or_none()

        if existing_perm:
            # Update existing permission
            for key, value in perm_data.items():
                setattr(existing_perm, key, value)
            permission = existing_perm
            logger.info(f"Updated existing permission: {perm_data['name']}")
        else:
            # Create new permission
            permission = Permission(**perm_data)
            session.add(permission)
            logger.info(f"Created new permission: {perm_data['name']}")

        permissions[perm_data["name"]] = permission

    session.flush()  # Flush to get permission IDs

    # =============================================================================
    # Define Role-Permission Mappings
    # =============================================================================
    role_permissions_map = {
        "super_admin": [
            "*:*"  # Super admin has wildcard access to everything
        ],
        "admin": [
            # Admin has all permissions except super admin wildcard
            "findings:read", "findings:write", "findings:delete",
            "scans:read", "scans:execute",
            "repositories:read", "repositories:write",
            "organizations:read", "organizations:write",
            "users:read", "users:write",
            "reports:read",
            "schedules:read", "schedules:create", "schedules:update",
            "schedules:override", "schedules:trigger",
        ],
        "analyst": [
            # Analyst can read/write findings and scans
            "findings:read", "findings:write",
            "scans:read", "scans:execute",
            "repositories:read",
            "reports:read",
            "schedules:read", "schedules:create", "schedules:update",
            "schedules:trigger",
        ],
        "manager": [
            # Manager has read-only access
            "findings:read",
            "scans:read",
            "repositories:read",
            "reports:read",
            "schedules:read",
        ],
        "user": [
            # Basic user has minimal read access
            "findings:read",
            "repositories:read",
            "reports:read",
            "schedules:read",
        ]
    }

    # Assign permissions to roles
    for role_name, permission_names in role_permissions_map.items():
        role = roles[role_name]

        for perm_name in permission_names:
            permission = permissions[perm_name]

            # Check if role-permission mapping already exists
            existing_mapping = session.execute(
                select(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == permission.id
                )
            ).scalar_one_or_none()

            if not existing_mapping:
                role_permission = RolePermission(
                    role_id=role.id,
                    permission_id=permission.id
                )
                session.add(role_permission)
                logger.info(f"Assigned permission '{perm_name}' to role '{role_name}'")

    # Commit all changes
    session.commit()

    # Flush permission cache so users pick up new permissions immediately
    try:
        from src.rbac.cache import redis_client
        if redis_client:
            cursor = 0
            while True:
                cursor, keys = redis_client.scan(cursor, match="permissions:*", count=100)
                if keys:
                    redis_client.delete(*keys)
                if cursor == 0:
                    break
            logger.info("Flushed permission cache after RBAC seed")
    except Exception as e:
        logger.debug(f"Could not flush permission cache (non-critical): {e}")

    # Log summary
    roles_count = len(roles_data)
    permissions_count = len(permissions_data)
    logger.info(f"RBAC seed complete: {roles_count} roles, {permissions_count} permissions")

    # Verify and log role-permission counts
    for role_name, role in roles.items():
        perm_count = len(role_permissions_map[role_name])
        logger.info(f"  - {role_name}: {perm_count} permissions")


def init_rbac_if_needed(session: Session) -> None:
    """
    Initialize RBAC data if roles table is empty, and ensure new
    permissions are added to existing installations.

    Convenience function that checks if RBAC is already initialized
    before running seed_rbac_data(). Always runs seed_rbac_data()
    since it is idempotent and handles adding new permissions.

    Args:
        session: SQLAlchemy database session
    """
    # Always run seed — it's idempotent and will add any missing
    # permissions/role-mappings without duplicating existing ones.
    seed_rbac_data(session)

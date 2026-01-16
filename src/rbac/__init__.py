"""
RBAC (Role-Based Access Control) module.

Provides role and permission management for the AuditGH platform.
Implements a 5-tier role hierarchy with tenant-scoped user assignments.
"""

from src.rbac.models import Role, Permission, RolePermission, UserRole
from src.rbac.seeds import seed_rbac_data, init_rbac_if_needed
from src.rbac.dependencies import require_permissions, require_role, require_tenant_access
from src.rbac.audit import (
    audit_authorization,
    audit_data_access,
    audit_data_modification,
    audit_admin_action,
    audit_role_assignment
)

__all__ = [
    "Role",
    "Permission",
    "RolePermission",
    "UserRole",
    "seed_rbac_data",
    "init_rbac_if_needed",
    "require_permissions",
    "require_role",
    "require_tenant_access",
    "audit_authorization",
    "audit_data_access",
    "audit_data_modification",
    "audit_admin_action",
    "audit_role_assignment",
]

"""
RBAC (Role-Based Access Control) SQLAlchemy models.

Provides a 5-tier role hierarchy with tenant-scoped user role assignments:
- Super Admin (level 1): Full system access across all tenants
- Admin (level 2): Tenant administrator with full tenant access
- Analyst (level 3): Security analyst with read/write access to findings and scans
- Manager (level 4): Manager with read-only access to reports and dashboards
- User (level 5): Basic user with limited read-only access

Models:
- Role: Global role definitions with hierarchy levels
- Permission: Global permission definitions (resource:action format)
- RolePermission: Many-to-many relationship between roles and permissions
- UserRole: Tenant-scoped user role assignments (CRITICAL: includes tenant_id)
"""

from sqlalchemy import Column, String, Integer, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func, text
from src.api.database import Base


class Role(Base):
    """
    Global role definition with level-based hierarchy.

    Roles are global definitions - not tenant-scoped. The tenant scoping
    happens at the UserRole level where users are assigned roles per tenant.

    Fields:
        id: UUID primary key
        name: Unique role name (e.g., "super_admin", "admin", "analyst")
        display_name: Human-readable name (e.g., "Super Administrator")
        description: Role description explaining privileges
        level: Integer hierarchy level (1=Super Admin, 2=Admin, 3=Analyst, 4=Manager, 5=User)
        created_at: Timestamp when role was created
    """
    __tablename__ = "roles"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    name = Column(String(50), unique=True, nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    description = Column(String(255))
    level = Column(Integer, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")
    user_roles = relationship("UserRole", back_populates="role")

    def __repr__(self):
        return f"<Role(name='{self.name}', level={self.level})>"


class Permission(Base):
    """
    Global permission definition using resource:action naming convention.

    Permissions are global definitions that can be assigned to roles.
    Format: resource:action (e.g., "findings:read", "scans:execute")
    Supports wildcards: "findings:*" (all actions on findings), "*:*" (super admin)

    Fields:
        id: UUID primary key
        name: Unique permission name in resource:action format
        resource: Resource being accessed (e.g., "findings", "scans", "*")
        action: Action being performed (e.g., "read", "write", "execute", "*")
        description: Permission description
        created_at: Timestamp when permission was created
    """
    __tablename__ = "permissions"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    name = Column(String(100), unique=True, nullable=False, index=True)
    resource = Column(String(50), nullable=False)
    action = Column(String(50), nullable=False)
    description = Column(String(255))
    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    roles = relationship("RolePermission", back_populates="permission")

    # Unique constraint on resource + action combination
    __table_args__ = (
        UniqueConstraint('resource', 'action', name='uq_permission_resource_action'),
    )

    def __repr__(self):
        return f"<Permission(name='{self.name}')>"


class RolePermission(Base):
    """
    Many-to-many join table between roles and permissions.

    Associates permissions with roles. Multiple permissions can be assigned
    to a role, and the same permission can be assigned to multiple roles.

    Fields:
        id: UUID primary key
        role_id: Foreign key to roles table
        permission_id: Foreign key to permissions table
        created_at: Timestamp when association was created
    """
    __tablename__ = "role_permissions"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    permission_id = Column(UUID(as_uuid=True), ForeignKey("permissions.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    # Relationships
    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")

    # Unique constraint to prevent duplicate role-permission assignments
    __table_args__ = (
        UniqueConstraint('role_id', 'permission_id', name='uq_role_permission'),
    )

    def __repr__(self):
        return f"<RolePermission(role_id={self.role_id}, permission_id={self.permission_id})>"


class UserRole(Base):
    """
    Tenant-scoped user role assignment.

    CRITICAL: This is where tenant isolation happens. Users are assigned roles
    per tenant, meaning a user can be an admin in Tenant A but only a user in
    Tenant B. The tenant_id column is essential for multi-tenant security.

    Design rationale:
    - user_sub instead of user_id because User model is Pydantic (not ORM)
    - user_sub matches the 'sub' claim from OIDC JWT tokens
    - tenant_id ensures role assignments are scoped per tenant
    - UniqueConstraint on user_sub + tenant_id ensures one role per user per tenant

    Fields:
        id: UUID primary key
        user_sub: OIDC 'sub' claim identifying the user
        tenant_id: Foreign key to organizations table (tenant scoping)
        role_id: Foreign key to roles table
        created_at: Timestamp when assignment was created
        updated_at: Timestamp when assignment was last updated
    """
    __tablename__ = "user_roles"

    id = Column(UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    user_sub = Column(String(255), nullable=False, index=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    role_id = Column(UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Relationships
    role = relationship("Role", back_populates="user_roles")
    organization = relationship("Organization", backref="user_roles")

    # Unique constraint: one role per user per tenant
    __table_args__ = (
        UniqueConstraint('user_sub', 'tenant_id', name='uq_user_tenant_role'),
    )

    def __repr__(self):
        return f"<UserRole(user_sub='{self.user_sub}', tenant_id={self.tenant_id}, role_id={self.role_id})>"

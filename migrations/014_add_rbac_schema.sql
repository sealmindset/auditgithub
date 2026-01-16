-- Migration: 014_add_rbac_schema.sql
-- Description: Add RBAC (Role-Based Access Control) schema with 5-tier role hierarchy
-- Date: 2026-01-12
-- Phase: 3.1 - RBAC System

-- =============================================================================
-- Roles Table
-- =============================================================================
-- Global role definitions with level-based hierarchy.
-- Roles are not tenant-scoped - they are global definitions.
-- Tenant scoping happens at UserRole level.

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Role identity
    name VARCHAR(50) NOT NULL UNIQUE,                 -- e.g., 'super_admin', 'admin', 'analyst'
    display_name VARCHAR(100) NOT NULL,               -- e.g., 'Super Administrator'
    description VARCHAR(255),                         -- Role description

    -- Hierarchy level (1=highest, 5=lowest)
    -- 1=Super Admin, 2=Admin, 3=Analyst, 4=Manager, 5=User
    level INTEGER NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for common queries
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_level ON roles(level);

-- =============================================================================
-- Permissions Table
-- =============================================================================
-- Global permission definitions using resource:action naming convention.
-- Examples: "findings:read", "scans:execute", "*:*" (super admin wildcard)

CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Permission identity (resource:action format)
    name VARCHAR(100) NOT NULL UNIQUE,                -- e.g., 'findings:read', 'scans:execute'
    resource VARCHAR(50) NOT NULL,                    -- e.g., 'findings', 'scans', '*'
    action VARCHAR(50) NOT NULL,                      -- e.g., 'read', 'write', 'execute', '*'
    description VARCHAR(255),                         -- Permission description

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),

    -- Unique constraint on resource + action combination
    CONSTRAINT uq_permission_resource_action UNIQUE (resource, action)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_permissions_name ON permissions(name);
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource);

-- =============================================================================
-- Role-Permission Mapping Table (Join Table)
-- =============================================================================
-- Many-to-many relationship between roles and permissions.
-- Defines which permissions each role has.

CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Foreign keys
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),

    -- Unique constraint to prevent duplicate assignments
    CONSTRAINT uq_role_permission UNIQUE (role_id, permission_id)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_permission ON role_permissions(permission_id);

-- =============================================================================
-- User-Role Mapping Table (TENANT-SCOPED)
-- =============================================================================
-- User role assignments scoped to tenants.
-- CRITICAL: This is where tenant isolation happens.
-- A user can have different roles in different tenants.
--
-- Design notes:
-- - user_sub (not user_id) because User model is Pydantic (JWT claims), not ORM
-- - user_sub matches OIDC 'sub' claim from JWT tokens
-- - tenant_id (organization_id) provides tenant isolation
-- - One role per user per tenant (enforced by unique constraint)

CREATE TABLE IF NOT EXISTS user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- User identity (OIDC 'sub' claim)
    user_sub VARCHAR(255) NOT NULL,                   -- e.g., '00u1234567890abcdef' from Okta/Entra

    -- Tenant scoping (CRITICAL for multi-tenancy)
    tenant_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Role assignment
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- Unique constraint: one role per user per tenant
    CONSTRAINT uq_user_tenant_role UNIQUE (user_sub, tenant_id)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_user_roles_user_sub ON user_roles(user_sub);
CREATE INDEX IF NOT EXISTS idx_user_roles_tenant ON user_roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_tenant ON user_roles(user_sub, tenant_id);

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE roles IS 'Global role definitions with level-based hierarchy (1=Super Admin to 5=User)';
COMMENT ON TABLE permissions IS 'Global permission definitions using resource:action format (e.g., findings:read)';
COMMENT ON TABLE role_permissions IS 'Many-to-many mapping between roles and permissions';
COMMENT ON TABLE user_roles IS 'Tenant-scoped user role assignments (CRITICAL: includes tenant_id for isolation)';

COMMENT ON COLUMN roles.level IS 'Hierarchy level: 1=Super Admin, 2=Admin, 3=Analyst, 4=Manager, 5=User';
COMMENT ON COLUMN permissions.name IS 'Permission in resource:action format (e.g., findings:read, *:* for super admin)';
COMMENT ON COLUMN user_roles.user_sub IS 'OIDC sub claim from JWT token (not user_id as User is Pydantic model)';
COMMENT ON COLUMN user_roles.tenant_id IS 'Organization ID for tenant scoping (users can have different roles per tenant)';

-- =============================================================================
-- End of Migration
-- =============================================================================

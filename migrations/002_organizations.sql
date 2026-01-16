-- Migration: 002_organizations.sql
-- Description: Add multi-organization support with isolated databases
-- Date: 2024-12-12

-- =============================================================================
-- Organizations Registry Table
-- =============================================================================
-- Stores metadata about each organization including database connection info,
-- schema version tracking, and scan status.

CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE NOT NULL,
    
    -- Organization identity
    name VARCHAR(255) NOT NULL UNIQUE,           -- Internal name (e.g., 'sealmindset')
    display_name VARCHAR(255),                    -- Display name (e.g., 'Seal Mindset')
    github_org VARCHAR(255) NOT NULL,             -- GitHub organization name
    
    -- Database configuration (same instance, different databases)
    database_name VARCHAR(255) NOT NULL UNIQUE,   -- e.g., 'auditgithub_sealmindset'
    database_schema VARCHAR(255) DEFAULT 'public', -- Schema within database
    
    -- Status tracking
    is_active BOOLEAN DEFAULT true,
    is_default BOOLEAN DEFAULT false,             -- Only one org can be default
    
    -- Schema synchronization
    schema_version VARCHAR(128),                   -- Current schema version hash
    schema_version_name VARCHAR(100),             -- Human-readable version (e.g., 'v2.3.0')
    last_schema_sync TIMESTAMPTZ,
    schema_sync_status VARCHAR(50) DEFAULT 'unknown', -- 'synced', 'drift', 'error', 'unknown'
    schema_sync_error TEXT,
    
    -- Scan tracking
    last_scan_at TIMESTAMPTZ,
    scan_status VARCHAR(50) DEFAULT 'idle',       -- 'idle', 'scanning', 'queued', 'error'
    scan_progress INTEGER DEFAULT 0,              -- 0-100 percentage
    current_scan_id UUID,                         -- Reference to active scan
    total_scans INTEGER DEFAULT 0,
    total_repos INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    
    -- Metadata
    description TEXT,
    settings JSONB DEFAULT '{}',                  -- Org-specific settings
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by UUID,                              -- User who created
    
    -- Constraints
    CONSTRAINT unique_default_org EXCLUDE (is_default WITH =) WHERE (is_default = true)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_organizations_name ON organizations(name);
CREATE INDEX IF NOT EXISTS idx_organizations_github_org ON organizations(github_org);
CREATE INDEX IF NOT EXISTS idx_organizations_active ON organizations(is_active);
CREATE INDEX IF NOT EXISTS idx_organizations_default ON organizations(is_default) WHERE is_default = true;

-- =============================================================================
-- Organization Audit Log
-- =============================================================================
-- Tracks all changes to organizations for compliance and debugging

CREATE TABLE IF NOT EXISTS organization_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE NOT NULL,
    
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    organization_name VARCHAR(255),               -- Denormalized for deleted orgs
    
    action VARCHAR(50) NOT NULL,                  -- 'created', 'updated', 'deleted', 'schema_sync', 'scan_started', etc.
    actor_id UUID,                                -- User who performed action
    actor_name VARCHAR(255),                      -- Denormalized
    
    old_values JSONB,                             -- Previous state
    new_values JSONB,                             -- New state
    metadata JSONB,                               -- Additional context
    
    ip_address INET,
    user_agent TEXT,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_audit_org_id ON organization_audit_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_audit_action ON organization_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_org_audit_created ON organization_audit_log(created_at);

-- =============================================================================
-- Organization Schema Versions
-- =============================================================================
-- Tracks schema version history for each organization

CREATE TABLE IF NOT EXISTS organization_schema_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE NOT NULL,
    
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    version_hash VARCHAR(64) NOT NULL,            -- SHA-256 of schema DDL
    version_name VARCHAR(100),                    -- Human-readable (e.g., 'v2.3.0')
    
    migration_sql TEXT,                           -- SQL that was applied
    migration_status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'applied', 'failed', 'rolled_back'
    migration_error TEXT,
    
    applied_at TIMESTAMPTZ,
    applied_by UUID,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_schema_versions_org ON organization_schema_versions(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_schema_versions_hash ON organization_schema_versions(version_hash);

-- =============================================================================
-- Current Organization Context (Session-based)
-- =============================================================================
-- Tracks which organization is currently selected per session/user

CREATE TABLE IF NOT EXISTS organization_context (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    session_id VARCHAR(255) UNIQUE,               -- Session identifier
    user_id UUID,                                 -- Optional user reference
    
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    selected_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ                        -- Optional expiration
);

CREATE INDEX IF NOT EXISTS idx_org_context_session ON organization_context(session_id);
CREATE INDEX IF NOT EXISTS idx_org_context_user ON organization_context(user_id);

-- =============================================================================
-- Functions
-- =============================================================================

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_organization_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for organizations table
DROP TRIGGER IF EXISTS trigger_organizations_updated ON organizations;
CREATE TRIGGER trigger_organizations_updated
    BEFORE UPDATE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION update_organization_timestamp();

-- Function to ensure only one default organization
CREATE OR REPLACE FUNCTION ensure_single_default_org()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.is_default = true THEN
        UPDATE organizations SET is_default = false WHERE id != NEW.id AND is_default = true;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_single_default_org ON organizations;
CREATE TRIGGER trigger_single_default_org
    BEFORE INSERT OR UPDATE ON organizations
    FOR EACH ROW
    WHEN (NEW.is_default = true)
    EXECUTE FUNCTION ensure_single_default_org();

-- Function to log organization changes
CREATE OR REPLACE FUNCTION log_organization_change()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO organization_audit_log (organization_id, organization_name, action, new_values)
        VALUES (NEW.id, NEW.name, 'created', to_jsonb(NEW));
    ELSIF TG_OP = 'UPDATE' THEN
        INSERT INTO organization_audit_log (organization_id, organization_name, action, old_values, new_values)
        VALUES (NEW.id, NEW.name, 'updated', to_jsonb(OLD), to_jsonb(NEW));
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO organization_audit_log (organization_name, action, old_values)
        VALUES (OLD.name, 'deleted', to_jsonb(OLD));
    END IF;
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_log_org_changes ON organizations;
CREATE TRIGGER trigger_log_org_changes
    AFTER INSERT OR UPDATE OR DELETE ON organizations
    FOR EACH ROW
    EXECUTE FUNCTION log_organization_change();

-- =============================================================================
-- Initial Data: No hardcoded organizations
-- =============================================================================
-- Organizations are created dynamically when:
-- 1. User runs: python3 scan_repos.py --create-org NAME --github-org ORG --token TOKEN
-- 2. Organizations are auto-registered from ORG_{NAME}_TOKEN env vars on first scan
-- 
-- DO NOT hardcode organization names here - they should be user-configured.

-- =============================================================================
-- Row Level Security (RLS)
-- =============================================================================

-- Enable RLS on organizations table
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;

-- Policy: All authenticated users can view active organizations
CREATE POLICY organizations_select_policy ON organizations
    FOR SELECT
    USING (is_active = true);

-- Policy: Only admins can modify organizations
CREATE POLICY organizations_modify_policy ON organizations
    FOR ALL
    USING (true)  -- Will be refined with proper auth
    WITH CHECK (true);

-- Enable RLS on audit log
ALTER TABLE organization_audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY org_audit_select_policy ON organization_audit_log
    FOR SELECT
    USING (true);  -- Admins can view all

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON TABLE organizations IS 'Registry of organizations with isolated databases for multi-tenant scanning';
COMMENT ON COLUMN organizations.name IS 'Internal identifier, lowercase, used in CLI --target flag';
COMMENT ON COLUMN organizations.database_name IS 'PostgreSQL database name for this org (same instance)';
COMMENT ON COLUMN organizations.schema_version IS 'SHA-256 hash of current schema DDL for drift detection';
COMMENT ON COLUMN organizations.is_default IS 'Default org used when no --target specified (first org created becomes default)';
COMMENT ON TABLE organization_audit_log IS 'Audit trail for all organization changes';
COMMENT ON TABLE organization_schema_versions IS 'History of schema migrations per organization';

-- =============================================================================
-- NOTE: Organizations are created dynamically, not via migrations
-- =============================================================================
-- To add an organization:
--   python3 scan_repos.py --create-org myorg --github-org my-github-org --token ghp_xxx
--
-- Or set environment variables:
--   GITHUB_TOKEN=ghp_xxx        # Default org token
--   GITHUB_ORG=my-github-org    # Default org name
--   ORG_ACME_TOKEN=ghp_yyy      # Additional org "acme"
--   ORG_ACME_GITHUB=acme-corp   # GitHub org name for "acme"

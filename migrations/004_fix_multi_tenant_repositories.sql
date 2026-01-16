-- Migration: 004_fix_multi_tenant_repositories.sql
-- Description: Add organization_id to repositories and all related tables for proper multi-tenant scoping
-- Date: 2025-12-13
-- CRITICAL FIX: Ensures all data is properly scoped to organizations

-- =============================================================================
-- STEP 1: Add organization_id to repositories table
-- =============================================================================

-- Add organization_id column to repositories
ALTER TABLE repositories 
ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Create indexes for organization scoping
CREATE INDEX IF NOT EXISTS idx_repositories_org_id ON repositories(organization_id);
CREATE INDEX IF NOT EXISTS idx_repositories_org_name ON repositories(organization_id, name);

-- Drop the old unique constraint on name (repos can have same name in different orgs)
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_name_key;

-- Add new unique constraint: name must be unique within an organization
ALTER TABLE repositories 
ADD CONSTRAINT unique_repo_name_per_org UNIQUE (organization_id, name);

-- =============================================================================
-- STEP 2: Add organization_id to scan_runs table
-- =============================================================================

ALTER TABLE scan_runs 
ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_scan_runs_org_id ON scan_runs(organization_id);

-- =============================================================================
-- STEP 3: Add organization_id to findings table
-- =============================================================================

ALTER TABLE findings 
ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_findings_org_id ON findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_findings_org_repo ON findings(organization_id, repository_id);

-- =============================================================================
-- STEP 4: Add organization_id to contributors table
-- =============================================================================

ALTER TABLE contributors 
ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_contributors_org_id ON contributors(organization_id);

-- =============================================================================
-- STEP 5: Add organization_id to language_stats table
-- =============================================================================

ALTER TABLE language_stats 
ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_language_stats_org_id ON language_stats(organization_id);

-- =============================================================================
-- STEP 6: Add organization_id to dependencies table
-- =============================================================================

ALTER TABLE dependencies 
ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_dependencies_org_id ON dependencies(organization_id);

-- =============================================================================
-- STEP 7: Add organization_id to api_endpoints table
-- =============================================================================

ALTER TABLE api_endpoints 
ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_api_endpoints_org_id ON api_endpoints(organization_id);

-- =============================================================================
-- STEP 8: Add organization_id to openapi_specs table
-- =============================================================================

ALTER TABLE openapi_specs 
ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_openapi_specs_org_id ON openapi_specs(organization_id);

-- =============================================================================
-- STEP 9: Add organization_id to file_commits table
-- =============================================================================

ALTER TABLE file_commits 
ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_file_commits_org_id ON file_commits(organization_id);

-- =============================================================================
-- STEP 10: Migrate existing data to default organization (if any exists)
-- =============================================================================
-- This migrates orphaned data (organization_id IS NULL) to the default org.
-- Only runs if there's existing data AND a default organization.

DO $$
DECLARE
    default_org_id UUID;
    default_org_name VARCHAR;
BEGIN
    -- Get the default organization (whichever is marked as default)
    SELECT id, name INTO default_org_id, default_org_name 
    FROM organizations 
    WHERE is_default = true 
    LIMIT 1;
    
    IF default_org_id IS NULL THEN
        RAISE NOTICE 'No default organization found - orphaned data will remain unassigned until an org is created';
        RETURN;
    END IF;
    
    RAISE NOTICE 'Migrating orphaned data to default organization: % (%)', default_org_id, default_org_name;
    
    -- Update repositories
    UPDATE repositories SET organization_id = default_org_id WHERE organization_id IS NULL;
    RAISE NOTICE 'Updated repositories';
    
    -- Update scan_runs
    UPDATE scan_runs SET organization_id = default_org_id WHERE organization_id IS NULL;
    RAISE NOTICE 'Updated scan_runs';
    
    -- Update findings
    UPDATE findings SET organization_id = default_org_id WHERE organization_id IS NULL;
    RAISE NOTICE 'Updated findings';
    
    -- Update contributors (if table exists)
    BEGIN
        UPDATE contributors SET organization_id = default_org_id WHERE organization_id IS NULL;
        RAISE NOTICE 'Updated contributors';
    EXCEPTION WHEN undefined_table THEN
        RAISE NOTICE 'contributors table does not exist, skipping';
    END;
    
    -- Update language_stats (if table exists)
    BEGIN
        UPDATE language_stats SET organization_id = default_org_id WHERE organization_id IS NULL;
        RAISE NOTICE 'Updated language_stats';
    EXCEPTION WHEN undefined_table THEN
        RAISE NOTICE 'language_stats table does not exist, skipping';
    END;
    
    -- Update dependencies (if table exists)
    BEGIN
        UPDATE dependencies SET organization_id = default_org_id WHERE organization_id IS NULL;
        RAISE NOTICE 'Updated dependencies';
    EXCEPTION WHEN undefined_table THEN
        RAISE NOTICE 'dependencies table does not exist, skipping';
    END;
    
    -- Update api_endpoints (if table exists)
    BEGIN
        UPDATE api_endpoints SET organization_id = default_org_id WHERE organization_id IS NULL;
        RAISE NOTICE 'Updated api_endpoints';
    EXCEPTION WHEN undefined_table THEN
        RAISE NOTICE 'api_endpoints table does not exist, skipping';
    END;
    
    -- Update openapi_specs (if table exists)
    BEGIN
        UPDATE openapi_specs SET organization_id = default_org_id WHERE organization_id IS NULL;
        RAISE NOTICE 'Updated openapi_specs';
    EXCEPTION WHEN undefined_table THEN
        RAISE NOTICE 'openapi_specs table does not exist, skipping';
    END;
    
    -- Update file_commits (if table exists)
    BEGIN
        UPDATE file_commits SET organization_id = default_org_id WHERE organization_id IS NULL;
        RAISE NOTICE 'Updated file_commits';
    EXCEPTION WHEN undefined_table THEN
        RAISE NOTICE 'file_commits table does not exist, skipping';
    END;
    
    -- Update credential_url_test_results (if table exists)
    BEGIN
        UPDATE credential_url_test_results SET organization_id = default_org_id WHERE organization_id IS NULL;
        RAISE NOTICE 'Updated credential_url_test_results';
    EXCEPTION WHEN undefined_table THEN
        RAISE NOTICE 'credential_url_test_results table does not exist, skipping';
    END;
    
    -- Update credential_url_test_status (if table exists)
    BEGIN
        UPDATE credential_url_test_status SET organization_id = default_org_id WHERE organization_id IS NULL;
        RAISE NOTICE 'Updated credential_url_test_status';
    EXCEPTION WHEN undefined_table THEN
        RAISE NOTICE 'credential_url_test_status table does not exist, skipping';
    END;
    
    RAISE NOTICE 'Data migration complete!';
END $$;

-- =============================================================================
-- STEP 11: Update organization stats (for all orgs)
-- =============================================================================

-- Update total_repos count for all organizations
UPDATE organizations o
SET total_repos = (
    SELECT COUNT(*) FROM repositories r WHERE r.organization_id = o.id
);

-- Update total_findings count for all organizations
UPDATE organizations o
SET total_findings = (
    SELECT COUNT(*) FROM findings f WHERE f.organization_id = o.id
);

-- =============================================================================
-- NOTE: Organizations are NOT pre-created in migrations
-- =============================================================================
-- Organizations are created dynamically via:
--   1. CLI: python3 scan_repos.py --create-org NAME --github-org ORG --token TOKEN
--   2. Auto-registration from ORG_{NAME}_TOKEN environment variables
--
-- The first organization created becomes the default (is_default = true).

-- =============================================================================
-- Comments
-- =============================================================================

COMMENT ON COLUMN repositories.organization_id IS 'Organization this repository belongs to (multi-tenant scope)';
COMMENT ON COLUMN scan_runs.organization_id IS 'Organization this scan belongs to (multi-tenant scope)';
COMMENT ON COLUMN findings.organization_id IS 'Organization this finding belongs to (multi-tenant scope)';
COMMENT ON COLUMN contributors.organization_id IS 'Organization this contributor belongs to (multi-tenant scope)';
COMMENT ON COLUMN language_stats.organization_id IS 'Organization this language stat belongs to (multi-tenant scope)';
COMMENT ON COLUMN dependencies.organization_id IS 'Organization this dependency belongs to (multi-tenant scope)';
COMMENT ON COLUMN api_endpoints.organization_id IS 'Organization this API endpoint belongs to (multi-tenant scope)';
COMMENT ON COLUMN openapi_specs.organization_id IS 'Organization this OpenAPI spec belongs to (multi-tenant scope)';
COMMENT ON COLUMN file_commits.organization_id IS 'Organization this file commit belongs to (multi-tenant scope)';

-- =============================================================================
-- Verification queries (run manually to verify)
-- =============================================================================

-- SELECT 'repositories' as table_name, COUNT(*) as total, COUNT(organization_id) as with_org FROM repositories
-- UNION ALL SELECT 'scan_runs', COUNT(*), COUNT(organization_id) FROM scan_runs
-- UNION ALL SELECT 'findings', COUNT(*), COUNT(organization_id) FROM findings
-- UNION ALL SELECT 'contributors', COUNT(*), COUNT(organization_id) FROM contributors
-- UNION ALL SELECT 'language_stats', COUNT(*), COUNT(organization_id) FROM language_stats
-- UNION ALL SELECT 'dependencies', COUNT(*), COUNT(organization_id) FROM dependencies
-- UNION ALL SELECT 'api_endpoints', COUNT(*), COUNT(organization_id) FROM api_endpoints
-- UNION ALL SELECT 'openapi_specs', COUNT(*), COUNT(organization_id) FROM openapi_specs
-- UNION ALL SELECT 'file_commits', COUNT(*), COUNT(organization_id) FROM file_commits;

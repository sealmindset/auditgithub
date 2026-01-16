-- =============================================================================
-- Migration 006: Ensure All Tables Exist
-- =============================================================================
-- This migration ensures all required tables and columns exist.
-- Safe to run multiple times (uses IF NOT EXISTS / IF EXISTS).
-- Run after all other migrations to fix any missing schema elements.
--
-- NOTE: No transaction wrapper - each statement runs independently so
-- partial failures don't block subsequent statements.
-- =============================================================================

-- =============================================================================
-- 1. ENSURE ORGANIZATIONS TABLE HAS ALL COLUMNS
-- =============================================================================

ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS database_schema VARCHAR(100) DEFAULT 'public',
ADD COLUMN IF NOT EXISTS schema_version VARCHAR(128),
ADD COLUMN IF NOT EXISTS schema_version_name VARCHAR(100) DEFAULT 'v1.0.0',
ADD COLUMN IF NOT EXISTS last_schema_sync TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS schema_sync_status VARCHAR(50) DEFAULT 'synced',
ADD COLUMN IF NOT EXISTS schema_sync_error TEXT,
ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS scan_status VARCHAR(50) DEFAULT 'idle',
ADD COLUMN IF NOT EXISTS scan_progress INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS current_scan_id UUID,
ADD COLUMN IF NOT EXISTS total_scans INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_repos INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_findings INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS description TEXT,
ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS created_by UUID;

-- =============================================================================
-- 2. ORGANIZATION AUDIT LOG (from migration 002)
-- =============================================================================

CREATE TABLE IF NOT EXISTS organization_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE NOT NULL,
    
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    organization_name VARCHAR(255),
    
    action VARCHAR(50) NOT NULL,
    actor_id UUID,
    actor_name VARCHAR(255),
    
    old_values JSONB,
    new_values JSONB,
    metadata JSONB,
    
    ip_address INET,
    user_agent TEXT,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_audit_org_id ON organization_audit_log(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_audit_action ON organization_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_org_audit_created ON organization_audit_log(created_at);

-- =============================================================================
-- 3. ORGANIZATION SCHEMA VERSIONS (from migration 002)
-- =============================================================================

CREATE TABLE IF NOT EXISTS organization_schema_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE NOT NULL,
    
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    version_hash VARCHAR(64) NOT NULL,
    version_name VARCHAR(100),
    
    migration_sql TEXT,
    migration_status VARCHAR(50) DEFAULT 'pending',
    migration_error TEXT,
    
    applied_at TIMESTAMPTZ,
    applied_by UUID,
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_schema_versions_org ON organization_schema_versions(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_schema_versions_hash ON organization_schema_versions(version_hash);

-- =============================================================================
-- 4. ORGANIZATION CONTEXT (from migration 002)
-- =============================================================================

CREATE TABLE IF NOT EXISTS organization_context (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    session_id VARCHAR(255) UNIQUE,
    user_id UUID,
    
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    
    selected_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_org_context_session ON organization_context(session_id);
CREATE INDEX IF NOT EXISTS idx_org_context_user ON organization_context(user_id);

-- =============================================================================
-- 5. MOBILE APPS TABLE (from migration 005)
-- =============================================================================

CREATE TABLE IF NOT EXISTS mobile_apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    
    app_name VARCHAR(255),
    package_name VARCHAR(255),
    bundle_id VARCHAR(255),
    platform VARCHAR(20) NOT NULL,
    
    version_name VARCHAR(50),
    version_code INTEGER,
    min_sdk_version INTEGER,
    target_sdk_version INTEGER,
    
    app_type VARCHAR(50),
    file_path TEXT,
    file_hash VARCHAR(64),
    file_size_bytes BIGINT,
    
    is_signed BOOLEAN,
    signature_algorithm VARCHAR(100),
    certificate_issuer TEXT,
    certificate_subject TEXT,
    certificate_expires_at TIMESTAMP,
    
    permissions JSONB,
    dangerous_permissions JSONB,
    entitlements JSONB,
    
    is_debuggable BOOLEAN DEFAULT false,
    allows_backup BOOLEAN DEFAULT true,
    has_exported_components BOOLEAN DEFAULT false,
    uses_cleartext_traffic BOOLEAN DEFAULT false,
    
    last_scanned_at TIMESTAMP,
    scan_run_id UUID REFERENCES scan_runs(id),
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mobile_apps_org ON mobile_apps(organization_id);
CREATE INDEX IF NOT EXISTS idx_mobile_apps_repo ON mobile_apps(repository_id);
CREATE INDEX IF NOT EXISTS idx_mobile_apps_platform ON mobile_apps(platform);
CREATE INDEX IF NOT EXISTS idx_mobile_apps_package ON mobile_apps(package_name);

-- =============================================================================
-- 6. MOBILE SECURITY FINDINGS TABLE (from migration 005)
-- =============================================================================

CREATE TABLE IF NOT EXISTS mobile_security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    mobile_app_id UUID REFERENCES mobile_apps(id) ON DELETE CASCADE,
    
    mobsf_rule_id VARCHAR(100),
    mobsf_category VARCHAR(100),
    analysis_type VARCHAR(20),
    
    component_type VARCHAR(50),
    component_name VARCHAR(255),
    is_exported BOOLEAN,
    
    binary_analysis_type VARCHAR(50),
    library_name VARCHAR(255),
    
    domain VARCHAR(255),
    ip_address VARCHAR(45),
    is_hardcoded_url BOOLEAN,
    uses_http BOOLEAN,
    
    crypto_algorithm VARCHAR(100),
    is_weak_crypto BOOLEAN,
    key_size INTEGER,
    
    api_endpoint TEXT,
    api_key_exposed BOOLEAN,
    
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mobile_findings_org ON mobile_security_findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_mobile_findings_finding ON mobile_security_findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_mobile_findings_app ON mobile_security_findings(mobile_app_id);
CREATE INDEX IF NOT EXISTS idx_mobile_findings_category ON mobile_security_findings(mobsf_category);

-- =============================================================================
-- 7. GO SECURITY FINDINGS TABLE (from migration 005)
-- =============================================================================

CREATE TABLE IF NOT EXISTS go_security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    
    gosec_rule_id VARCHAR(20),
    gosec_rule_name VARCHAR(100),
    gosec_cwe_id VARCHAR(20),
    
    linter_name VARCHAR(50),
    linter_severity VARCHAR(20),
    
    function_name VARCHAR(255),
    package_name VARCHAR(255),
    go_version VARCHAR(20),
    
    issue_confidence VARCHAR(20),
    issue_what TEXT,
    issue_why TEXT,
    
    is_sql_injection BOOLEAN DEFAULT false,
    is_command_injection BOOLEAN DEFAULT false,
    is_path_traversal BOOLEAN DEFAULT false,
    is_hardcoded_credential BOOLEAN DEFAULT false,
    is_weak_crypto BOOLEAN DEFAULT false,
    is_insecure_random BOOLEAN DEFAULT false,
    is_ssrf BOOLEAN DEFAULT false,
    is_unsafe_reflection BOOLEAN DEFAULT false,
    
    taint_source VARCHAR(255),
    taint_sink VARCHAR(255),
    
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_go_findings_org ON go_security_findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_go_findings_finding ON go_security_findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_go_findings_repo ON go_security_findings(repository_id);
CREATE INDEX IF NOT EXISTS idx_go_findings_rule ON go_security_findings(gosec_rule_id);
CREATE INDEX IF NOT EXISTS idx_go_findings_linter ON go_security_findings(linter_name);

-- =============================================================================
-- 8. SCANNER CONFIGS TABLE (from migration 005)
-- =============================================================================

CREATE TABLE IF NOT EXISTS scanner_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    scanner_name VARCHAR(50) NOT NULL,
    is_enabled BOOLEAN DEFAULT true,
    
    config JSONB,
    custom_rules JSONB,
    excluded_rules JSONB,
    severity_threshold VARCHAR(20),
    
    timeout_seconds INTEGER DEFAULT 600,
    max_file_size_mb INTEGER DEFAULT 100,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    UNIQUE(organization_id, scanner_name)
);

CREATE INDEX IF NOT EXISTS idx_scanner_configs_org ON scanner_configs(organization_id);

-- =============================================================================
-- 9. ADD MISSING COLUMNS TO FINDINGS (from migration 005)
-- =============================================================================

ALTER TABLE findings ADD COLUMN IF NOT EXISTS mobile_app_id UUID REFERENCES mobile_apps(id);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_mobile_finding BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_go_finding BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS gosec_rule_id VARCHAR(20);

CREATE INDEX IF NOT EXISTS idx_findings_mobile_app ON findings(mobile_app_id);
CREATE INDEX IF NOT EXISTS idx_findings_is_mobile ON findings(is_mobile_finding) WHERE is_mobile_finding = true;
CREATE INDEX IF NOT EXISTS idx_findings_is_go ON findings(is_go_finding) WHERE is_go_finding = true;

-- =============================================================================
-- 10. ADD MISSING COLUMNS TO REPOSITORIES (from migration 005)
-- =============================================================================

ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_go_code BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_android_code BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_ios_code BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_mobile_app BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS go_module_path VARCHAR(255);

CREATE INDEX IF NOT EXISTS idx_repos_has_go ON repositories(has_go_code) WHERE has_go_code = true;
CREATE INDEX IF NOT EXISTS idx_repos_has_mobile ON repositories(has_mobile_app) WHERE has_mobile_app = true;

-- =============================================================================
-- 11. ADD MISSING COLUMNS TO REPOSITORIES (from various migrations)
-- =============================================================================

ALTER TABLE repositories ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'private';
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS is_private BOOLEAN DEFAULT true;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS is_fork BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS pushed_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS github_created_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS github_updated_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS stargazers_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS forks_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS open_issues_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS watchers_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS size_kb INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS topics JSONB;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS license_name VARCHAR(100);
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS failure_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS last_failure_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS last_failure_reason VARCHAR;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS architecture_report TEXT;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS architecture_diagram TEXT;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS architecture_preprocessed TEXT;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_wiki BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_pages BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_discussions BOOLEAN DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_repositories_org_id ON repositories(organization_id);
CREATE INDEX IF NOT EXISTS idx_repositories_org_name ON repositories(organization_id, name);

-- =============================================================================
-- 12. ADD MISSING COLUMNS TO FINDINGS (from various migrations)
-- =============================================================================

ALTER TABLE findings ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_verified_by_scanner BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_validated_active BOOLEAN;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_message VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validated_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS investigation_status VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS investigation_started_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS investigation_resolved_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_score INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_factors JSONB;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS snooze_reason VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_started_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_completed_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_triage_recommendation VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_triage_confidence NUMERIC(3,2);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_triage_reasoning TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS duplicate_group_id UUID;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_primary_in_group BOOLEAN DEFAULT true;

CREATE INDEX IF NOT EXISTS idx_findings_org_id ON findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_findings_org_repo ON findings(organization_id, repository_id);

-- =============================================================================
-- 13. ADD MISSING COLUMNS TO SCAN_RUNS
-- =============================================================================

ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_scan_runs_org_id ON scan_runs(organization_id);

-- =============================================================================
-- 14. ADD MISSING COLUMNS TO OTHER TABLES
-- =============================================================================

ALTER TABLE contributors ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE language_stats ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE dependencies ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE api_endpoints ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE openapi_specs ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;
ALTER TABLE file_commits ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_contributors_org_id ON contributors(organization_id);
CREATE INDEX IF NOT EXISTS idx_language_stats_org_id ON language_stats(organization_id);
CREATE INDEX IF NOT EXISTS idx_dependencies_org_id ON dependencies(organization_id);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_org_id ON api_endpoints(organization_id);
CREATE INDEX IF NOT EXISTS idx_openapi_specs_org_id ON openapi_specs(organization_id);
CREATE INDEX IF NOT EXISTS idx_file_commits_org_id ON file_commits(organization_id);

-- =============================================================================
-- 15. ADD MISSING COLUMNS TO REMEDIATIONS
-- =============================================================================

ALTER TABLE remediations ADD COLUMN IF NOT EXISTS finding_id UUID REFERENCES findings(id);
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS diff TEXT;
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS confidence NUMERIC(3,2);

CREATE INDEX IF NOT EXISTS idx_remediations_finding_id ON remediations(finding_id);

-- =============================================================================
-- 16. CONTRIBUTOR PROFILES (from setup/contributor_profiles.sql)
-- =============================================================================

CREATE TABLE IF NOT EXISTS contributor_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name VARCHAR NOT NULL,
    primary_email VARCHAR UNIQUE,
    primary_github_username VARCHAR,
    entra_id_object_id VARCHAR UNIQUE,
    entra_id_upn VARCHAR,
    entra_id_employee_id VARCHAR,
    entra_id_job_title VARCHAR,
    entra_id_department VARCHAR,
    entra_id_manager_upn VARCHAR,
    employment_status VARCHAR DEFAULT 'unknown',
    employment_verified_at TIMESTAMP,
    employment_start_date TIMESTAMP,
    employment_end_date TIMESTAMP,
    total_repos INTEGER DEFAULT 0,
    total_commits INTEGER DEFAULT 0,
    last_activity_at TIMESTAMP,
    first_activity_at TIMESTAMP,
    risk_score INTEGER DEFAULT 0,
    is_stale BOOLEAN DEFAULT FALSE,
    has_elevated_access BOOLEAN DEFAULT FALSE,
    files_with_findings INTEGER DEFAULT 0,
    critical_files_count INTEGER DEFAULT 0,
    ai_identity_confidence NUMERIC(3, 2),
    ai_summary TEXT,
    is_verified BOOLEAN DEFAULT FALSE,
    verified_by UUID REFERENCES users(id),
    verified_at TIMESTAMP,
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contributor_profiles_primary_email ON contributor_profiles(primary_email);
CREATE INDEX IF NOT EXISTS idx_contributor_profiles_entra_id ON contributor_profiles(entra_id_object_id);
CREATE INDEX IF NOT EXISTS idx_contributor_profiles_employment_status ON contributor_profiles(employment_status);

-- =============================================================================
-- 17. CONTRIBUTOR ALIASES
-- =============================================================================

CREATE TABLE IF NOT EXISTS contributor_aliases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES contributor_profiles(id) ON DELETE CASCADE,
    alias_type VARCHAR NOT NULL,
    alias_value VARCHAR NOT NULL,
    is_primary BOOLEAN DEFAULT FALSE,
    source VARCHAR,
    first_seen_at TIMESTAMP,
    last_seen_at TIMESTAMP,
    confidence NUMERIC(3, 2),
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(alias_type, alias_value)
);

CREATE INDEX IF NOT EXISTS idx_contributor_aliases_profile ON contributor_aliases(profile_id);
CREATE INDEX IF NOT EXISTS idx_contributor_aliases_value ON contributor_aliases(alias_value);

-- =============================================================================
-- 18. CONTRIBUTORS TABLE ENHANCEMENTS
-- =============================================================================

CREATE TABLE IF NOT EXISTS contributors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    profile_id UUID REFERENCES contributor_profiles(id),
    name VARCHAR(255),
    email VARCHAR(255),
    github_username VARCHAR(255),
    commits INTEGER DEFAULT 0,
    commit_percentage NUMERIC(5, 2),
    additions INTEGER DEFAULT 0,
    deletions INTEGER DEFAULT 0,
    first_commit_at TIMESTAMP,
    last_commit_at TIMESTAMP,
    files_contributed JSONB DEFAULT '[]',
    folders_contributed JSONB DEFAULT '[]',
    risk_score INTEGER DEFAULT 0,
    ai_summary TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contributors_org_id ON contributors(organization_id);
CREATE INDEX IF NOT EXISTS idx_contributors_repo ON contributors(repository_id);
CREATE INDEX IF NOT EXISTS idx_contributors_profile ON contributors(profile_id);
CREATE INDEX IF NOT EXISTS idx_contributors_repo_risk ON contributors(repository_id, risk_score DESC);

-- =============================================================================
-- 19. LANGUAGE STATS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS language_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    language VARCHAR(100),
    bytes BIGINT DEFAULT 0,
    percentage NUMERIC(5, 2),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_language_stats_org_id ON language_stats(organization_id);
CREATE INDEX IF NOT EXISTS idx_language_stats_repo ON language_stats(repository_id);

-- =============================================================================
-- 20. DEPENDENCIES TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    name VARCHAR(255),
    version VARCHAR(100),
    ecosystem VARCHAR(50),
    is_direct BOOLEAN DEFAULT true,
    license VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dependencies_org_id ON dependencies(organization_id);
CREATE INDEX IF NOT EXISTS idx_dependencies_repo ON dependencies(repository_id);

-- =============================================================================
-- 21. API ENDPOINTS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    endpoint_url VARCHAR NOT NULL,
    http_method VARCHAR,
    direction VARCHAR NOT NULL,
    auth_method VARCHAR,
    file_path TEXT,
    line_number INTEGER,
    code_snippet TEXT,
    framework VARCHAR,
    rule_id VARCHAR,
    confidence VARCHAR,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_endpoints_org_id ON api_endpoints(organization_id);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_repo ON api_endpoints(repository_id);

-- =============================================================================
-- 22. OPENAPI SPECS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS openapi_specs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    spec_content TEXT,
    spec_format VARCHAR DEFAULT 'yaml',
    version VARCHAR DEFAULT '3.0.3',
    generated_at TIMESTAMP DEFAULT NOW(),
    endpoint_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_openapi_specs_org_id ON openapi_specs(organization_id);
CREATE INDEX IF NOT EXISTS idx_openapi_specs_repo ON openapi_specs(repository_id);

-- =============================================================================
-- 23. FILE COMMITS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS file_commits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    file_path TEXT,
    commit_sha VARCHAR(40),
    author_name VARCHAR(255),
    author_email VARCHAR(255),
    committed_at TIMESTAMP,
    additions INTEGER DEFAULT 0,
    deletions INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_file_commits_org_id ON file_commits(organization_id);
CREATE INDEX IF NOT EXISTS idx_file_commits_repo ON file_commits(repository_id);
CREATE INDEX IF NOT EXISTS idx_file_commits_file ON file_commits(file_path);

-- =============================================================================
-- 24. COMMENTS
-- =============================================================================

COMMENT ON TABLE organization_audit_log IS 'Audit trail for all organization changes';
COMMENT ON TABLE organization_schema_versions IS 'History of schema migrations per organization';
COMMENT ON TABLE mobile_apps IS 'Metadata about mobile applications (Android/iOS) found in repositories';
COMMENT ON TABLE mobile_security_findings IS 'Mobile-specific security findings from MobSF scanner';
COMMENT ON TABLE go_security_findings IS 'Go-specific security findings from gosec/GolangCI-Lint';
COMMENT ON TABLE scanner_configs IS 'Per-organization scanner configuration and custom rules';

-- =============================================================================
-- Verification
-- =============================================================================
-- =============================================================================
-- Fix: Ensure api_id is populated for all organizations
-- =============================================================================
CREATE SEQUENCE IF NOT EXISTS organizations_api_id_seq;
UPDATE organizations SET api_id = nextval('organizations_api_id_seq') WHERE api_id IS NULL;

SELECT 'Migration 006 completed: All tables and columns ensured' as status;

SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
  AND table_name IN ('organizations', 'organization_audit_log', 'organization_schema_versions', 
                     'organization_context', 'mobile_apps', 'mobile_security_findings', 
                     'go_security_findings', 'scanner_configs')
ORDER BY table_name;

-- =============================================================================
-- Migration 005: Mobile Security (MobSF) and Go Security (gosec) Scanner Support
-- =============================================================================
-- Adds tables and columns to support:
--   - MobSF (Mobile Security Framework) for Android/iOS scanning
--   - gosec/GolangCI-Lint for Go security scanning
-- =============================================================================

BEGIN;

-- =============================================================================
-- 1. MOBILE APP METADATA TABLE
-- =============================================================================
-- Stores metadata about mobile apps found in repositories

CREATE TABLE IF NOT EXISTS mobile_apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    
    -- App identification
    app_name VARCHAR(255),
    package_name VARCHAR(255),  -- e.g., com.example.app
    bundle_id VARCHAR(255),     -- iOS bundle identifier
    platform VARCHAR(20) NOT NULL,  -- android, ios
    
    -- Version info
    version_name VARCHAR(50),
    version_code INTEGER,
    min_sdk_version INTEGER,    -- Android minSdkVersion
    target_sdk_version INTEGER, -- Android targetSdkVersion
    
    -- App metadata
    app_type VARCHAR(50),       -- apk, aab, ipa, source
    file_path TEXT,             -- Path to APK/IPA if scanned
    file_hash VARCHAR(64),      -- SHA256 of the app file
    file_size_bytes BIGINT,
    
    -- Signing info
    is_signed BOOLEAN,
    signature_algorithm VARCHAR(100),
    certificate_issuer TEXT,
    certificate_subject TEXT,
    certificate_expires_at TIMESTAMP,
    
    -- Permissions (Android)
    permissions JSONB,          -- Array of requested permissions
    dangerous_permissions JSONB, -- Subset of dangerous permissions
    
    -- Capabilities (iOS)
    entitlements JSONB,
    
    -- Security flags
    is_debuggable BOOLEAN DEFAULT false,
    allows_backup BOOLEAN DEFAULT true,
    has_exported_components BOOLEAN DEFAULT false,
    uses_cleartext_traffic BOOLEAN DEFAULT false,
    
    -- Scan metadata
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
-- 2. MOBILE SECURITY FINDINGS TABLE
-- =============================================================================
-- Extends findings with mobile-specific details from MobSF

CREATE TABLE IF NOT EXISTS mobile_security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    mobile_app_id UUID REFERENCES mobile_apps(id) ON DELETE CASCADE,
    
    -- MobSF-specific fields
    mobsf_rule_id VARCHAR(100),
    mobsf_category VARCHAR(100),  -- e.g., code, manifest, binary, network
    
    -- Analysis type
    analysis_type VARCHAR(20),    -- static, dynamic, malware
    
    -- Component info (Android)
    component_type VARCHAR(50),   -- activity, service, receiver, provider
    component_name VARCHAR(255),
    is_exported BOOLEAN,
    
    -- Binary analysis
    binary_analysis_type VARCHAR(50),  -- symbol, string, library
    library_name VARCHAR(255),
    
    -- Network security
    domain VARCHAR(255),
    ip_address VARCHAR(45),
    is_hardcoded_url BOOLEAN,
    uses_http BOOLEAN,
    
    -- Crypto issues
    crypto_algorithm VARCHAR(100),
    is_weak_crypto BOOLEAN,
    key_size INTEGER,
    
    -- API security
    api_endpoint TEXT,
    api_key_exposed BOOLEAN,
    
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mobile_findings_org ON mobile_security_findings(organization_id);
CREATE INDEX IF NOT EXISTS idx_mobile_findings_finding ON mobile_security_findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_mobile_findings_app ON mobile_security_findings(mobile_app_id);
CREATE INDEX IF NOT EXISTS idx_mobile_findings_category ON mobile_security_findings(mobsf_category);

-- =============================================================================
-- 3. GO SECURITY FINDINGS TABLE
-- =============================================================================
-- Extends findings with Go-specific details from gosec/GolangCI-Lint

CREATE TABLE IF NOT EXISTS go_security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    
    -- gosec-specific fields
    gosec_rule_id VARCHAR(20),    -- e.g., G101, G201, G401
    gosec_rule_name VARCHAR(100), -- e.g., "Hardcoded credentials"
    gosec_cwe_id VARCHAR(20),     -- CWE mapping
    
    -- GolangCI-Lint fields
    linter_name VARCHAR(50),      -- gosec, staticcheck, etc.
    linter_severity VARCHAR(20),
    
    -- Code context
    function_name VARCHAR(255),
    package_name VARCHAR(255),
    go_version VARCHAR(20),
    
    -- Issue details
    issue_confidence VARCHAR(20), -- high, medium, low
    issue_what TEXT,              -- What the issue is
    issue_why TEXT,               -- Why it's a problem
    
    -- Specific vulnerability types
    is_sql_injection BOOLEAN DEFAULT false,
    is_command_injection BOOLEAN DEFAULT false,
    is_path_traversal BOOLEAN DEFAULT false,
    is_hardcoded_credential BOOLEAN DEFAULT false,
    is_weak_crypto BOOLEAN DEFAULT false,
    is_insecure_random BOOLEAN DEFAULT false,
    is_ssrf BOOLEAN DEFAULT false,
    is_unsafe_reflection BOOLEAN DEFAULT false,
    
    -- Taint analysis
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
-- 4. ADD SCANNER-SPECIFIC COLUMNS TO FINDINGS
-- =============================================================================

-- Add columns to track which specialized scanner produced the finding
ALTER TABLE findings ADD COLUMN IF NOT EXISTS mobile_app_id UUID REFERENCES mobile_apps(id);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_mobile_finding BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_go_finding BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS gosec_rule_id VARCHAR(20);

CREATE INDEX IF NOT EXISTS idx_findings_mobile_app ON findings(mobile_app_id);
CREATE INDEX IF NOT EXISTS idx_findings_is_mobile ON findings(is_mobile_finding) WHERE is_mobile_finding = true;
CREATE INDEX IF NOT EXISTS idx_findings_is_go ON findings(is_go_finding) WHERE is_go_finding = true;

-- =============================================================================
-- 5. ADD REPOSITORY LANGUAGE DETECTION FLAGS
-- =============================================================================

ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_go_code BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_android_code BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_ios_code BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_mobile_app BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS go_module_path VARCHAR(255);  -- e.g., github.com/org/repo

CREATE INDEX IF NOT EXISTS idx_repos_has_go ON repositories(has_go_code) WHERE has_go_code = true;
CREATE INDEX IF NOT EXISTS idx_repos_has_mobile ON repositories(has_mobile_app) WHERE has_mobile_app = true;

-- =============================================================================
-- 6. SCANNER CONFIGURATION TABLE
-- =============================================================================
-- Stores per-organization scanner configurations

CREATE TABLE IF NOT EXISTS scanner_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    scanner_name VARCHAR(50) NOT NULL,  -- mobsf, gosec, golangci-lint, etc.
    is_enabled BOOLEAN DEFAULT true,
    
    -- Configuration
    config JSONB,                       -- Scanner-specific config
    custom_rules JSONB,                 -- Custom rules/patterns
    excluded_rules JSONB,               -- Rules to skip
    severity_threshold VARCHAR(20),     -- Minimum severity to report
    
    -- Execution settings
    timeout_seconds INTEGER DEFAULT 600,
    max_file_size_mb INTEGER DEFAULT 100,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    UNIQUE(organization_id, scanner_name)
);

CREATE INDEX IF NOT EXISTS idx_scanner_configs_org ON scanner_configs(organization_id);

-- =============================================================================
-- 7. COMMENTS
-- =============================================================================

COMMENT ON TABLE mobile_apps IS 'Metadata about mobile applications (Android/iOS) found in repositories';
COMMENT ON TABLE mobile_security_findings IS 'Mobile-specific security findings from MobSF scanner';
COMMENT ON TABLE go_security_findings IS 'Go-specific security findings from gosec/GolangCI-Lint';
COMMENT ON TABLE scanner_configs IS 'Per-organization scanner configuration and custom rules';

COMMENT ON COLUMN mobile_apps.platform IS 'Mobile platform: android or ios';
COMMENT ON COLUMN mobile_apps.dangerous_permissions IS 'Android dangerous permissions that require runtime approval';
COMMENT ON COLUMN go_security_findings.gosec_rule_id IS 'gosec rule identifier (e.g., G101 for hardcoded credentials)';
COMMENT ON COLUMN go_security_findings.linter_name IS 'Which linter found the issue (gosec, staticcheck, etc.)';

COMMIT;

-- =============================================================================
-- Verification
-- =============================================================================
SELECT 'Migration 005 completed: Mobile and Go scanner support added' as status;

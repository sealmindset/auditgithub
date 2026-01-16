-- Migration: 003_credential_url_test_results
-- Description: Create table for AI Credential-URL Testing Agent results
-- Date: 2025-12-13
-- Multi-tenant: Scoped to organization via organization_id

-- =============================================================================
-- Table: credential_url_test_results
-- Stores comprehensive results from the AI Credential-URL Testing Agent
-- Multi-tenant: Each organization has its own set of test results
-- =============================================================================

CREATE TABLE IF NOT EXISTS credential_url_test_results (
    -- Primary identifiers
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    
    -- Multi-tenant: Organization scope
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    
    -- Target Information
    target_url TEXT NOT NULL,
    credential_type VARCHAR(100),
    credential_value TEXT,
    credential_environment VARCHAR(50),
    confidence_score INTEGER,
    
    -- Authentication Results
    auth_status VARCHAR(20) DEFAULT 'not_tested' CHECK (auth_status IN ('yes', 'failed', 'not_tested')),
    auth_status_code INTEGER,
    auth_response_time_ms INTEGER,
    auth_error_message TEXT,
    auth_headers_used JSONB DEFAULT '[]',
    
    -- Path Discovery Results
    discovered_paths JSONB DEFAULT '[]',
    discovered_paths_count INTEGER DEFAULT 0,
    hidden_paths_found INTEGER DEFAULT 0,
    
    -- Data Sampling
    sample_data_retrieved JSONB DEFAULT '[]',
    data_sensitivity_indicators JSONB DEFAULT '[]',
    
    -- OSINT Results
    osint_findings JSONB DEFAULT '[]',
    github_repos_found INTEGER DEFAULT 0,
    documentation_links_found INTEGER DEFAULT 0,
    
    -- AI Analysis
    ai_overview TEXT,
    ai_risk_assessment TEXT,
    ai_recommendations JSONB DEFAULT '[]',
    threat_level VARCHAR(20) CHECK (threat_level IN ('critical', 'high', 'medium', 'low', 'info', NULL)),
    
    -- Test Configuration
    test_mode VARCHAR(20) DEFAULT 'cautious' CHECK (test_mode IN ('none', 'cautious', 'insane')),
    
    -- Metadata
    tested_at TIMESTAMP WITH TIME ZONE,
    test_duration_seconds INTEGER,
    llm_provider VARCHAR(50),
    llm_model VARCHAR(100),
    raw_llm_responses JSONB DEFAULT '[]',
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_cred_url_results_org ON credential_url_test_results(organization_id);
CREATE INDEX IF NOT EXISTS idx_cred_url_results_repo ON credential_url_test_results(repository_id);
CREATE INDEX IF NOT EXISTS idx_cred_url_results_org_repo ON credential_url_test_results(organization_id, repository_id);
CREATE INDEX IF NOT EXISTS idx_cred_url_results_target ON credential_url_test_results(target_url);
CREATE INDEX IF NOT EXISTS idx_cred_url_results_auth ON credential_url_test_results(auth_status);
CREATE INDEX IF NOT EXISTS idx_cred_url_results_threat ON credential_url_test_results(threat_level);
CREATE INDEX IF NOT EXISTS idx_cred_url_results_tested ON credential_url_test_results(tested_at);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_credential_url_test_results_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_credential_url_test_results_updated_at ON credential_url_test_results;
CREATE TRIGGER trigger_credential_url_test_results_updated_at
    BEFORE UPDATE ON credential_url_test_results
    FOR EACH ROW
    EXECUTE FUNCTION update_credential_url_test_results_updated_at();

-- =============================================================================
-- Table: credential_url_test_status
-- Tracks auto-test initialization status per project (to avoid re-testing on every page load)
-- Multi-tenant: Scoped to organization
-- =============================================================================

CREATE TABLE IF NOT EXISTS credential_url_test_status (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    
    -- Multi-tenant scope
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    
    -- Status tracking
    initial_test_completed BOOLEAN DEFAULT false,
    initial_test_at TIMESTAMP WITH TIME ZONE,
    total_correlations_tested INTEGER DEFAULT 0,
    total_correlations_found INTEGER DEFAULT 0,
    last_test_at TIMESTAMP WITH TIME ZONE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Unique constraint per org+repo
    CONSTRAINT unique_test_status_per_repo UNIQUE (organization_id, repository_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_cred_url_test_status_org ON credential_url_test_status(organization_id);
CREATE INDEX IF NOT EXISTS idx_cred_url_test_status_repo ON credential_url_test_status(repository_id);
CREATE INDEX IF NOT EXISTS idx_cred_url_test_status_org_repo ON credential_url_test_status(organization_id, repository_id);

-- Trigger for updated_at
CREATE OR REPLACE FUNCTION update_credential_url_test_status_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_credential_url_test_status_updated_at ON credential_url_test_status;
CREATE TRIGGER trigger_credential_url_test_status_updated_at
    BEFORE UPDATE ON credential_url_test_status
    FOR EACH ROW
    EXECUTE FUNCTION update_credential_url_test_status_updated_at();

-- Comments for documentation
COMMENT ON TABLE credential_url_test_results IS 'Stores results from AI Credential-URL Testing Agent including auth status, discovered paths, OSINT findings, and AI analysis. Multi-tenant scoped to organization.';
COMMENT ON COLUMN credential_url_test_results.organization_id IS 'Organization this test result belongs to (multi-tenant scope)';
COMMENT ON COLUMN credential_url_test_results.auth_status IS 'Authentication result: yes (authenticated), failed (auth failed), not_tested (not yet tested)';
COMMENT ON COLUMN credential_url_test_results.test_mode IS 'Testing aggressiveness: none (no limits), cautious (evasion techniques), insane (all safeties off)';
COMMENT ON COLUMN credential_url_test_results.threat_level IS 'AI-assessed threat level based on findings';
COMMENT ON COLUMN credential_url_test_results.discovered_paths IS 'JSON array of {method, path, status_code, sample_data, success}';
COMMENT ON COLUMN credential_url_test_results.osint_findings IS 'JSON array of {url, type, description, relevance}';

COMMENT ON TABLE credential_url_test_status IS 'Tracks auto-test initialization status per project to avoid re-testing on every page load. Multi-tenant scoped to organization.';
COMMENT ON COLUMN credential_url_test_status.initial_test_completed IS 'Whether the initial auto-test has been completed for this project';

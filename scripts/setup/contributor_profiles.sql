-- Migration: Add Contributor Profiles for unified identity management
-- This creates tables for managing contributor identities and their aliases

-- =============================================================================
-- CONTRIBUTOR PROFILES - Unified Identity
-- =============================================================================

CREATE TABLE IF NOT EXISTS contributor_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Canonical identity (preferred display)
    display_name VARCHAR NOT NULL,
    primary_email VARCHAR UNIQUE,
    primary_github_username VARCHAR,
    
    -- Entra ID / Azure AD integration
    entra_id_object_id VARCHAR UNIQUE,  -- Azure AD Object ID (GUID)
    entra_id_upn VARCHAR,               -- User Principal Name
    entra_id_employee_id VARCHAR,       -- Employee ID from HR
    entra_id_job_title VARCHAR,
    entra_id_department VARCHAR,
    entra_id_manager_upn VARCHAR,       -- Manager's UPN for escalation
    
    -- Employment status
    employment_status VARCHAR DEFAULT 'unknown',  -- active, inactive, terminated, contractor, unknown
    employment_verified_at TIMESTAMP,
    employment_start_date TIMESTAMP,
    employment_end_date TIMESTAMP,
    
    -- Aggregated stats
    total_repos INTEGER DEFAULT 0,
    total_commits INTEGER DEFAULT 0,
    last_activity_at TIMESTAMP,
    first_activity_at TIMESTAMP,
    
    -- Risk assessment
    risk_score INTEGER DEFAULT 0,
    is_stale BOOLEAN DEFAULT FALSE,
    has_elevated_access BOOLEAN DEFAULT FALSE,
    files_with_findings INTEGER DEFAULT 0,
    critical_files_count INTEGER DEFAULT 0,
    
    -- AI analysis
    ai_identity_confidence NUMERIC(3, 2),
    ai_summary TEXT,
    
    -- Verification metadata
    is_verified BOOLEAN DEFAULT FALSE,
    verified_by UUID REFERENCES users(id),
    verified_at TIMESTAMP,
    notes TEXT,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Index for common queries
CREATE INDEX IF NOT EXISTS idx_contributor_profiles_primary_email ON contributor_profiles(primary_email);
CREATE INDEX IF NOT EXISTS idx_contributor_profiles_entra_id ON contributor_profiles(entra_id_object_id);
CREATE INDEX IF NOT EXISTS idx_contributor_profiles_employment_status ON contributor_profiles(employment_status);
CREATE INDEX IF NOT EXISTS idx_contributor_profiles_is_stale ON contributor_profiles(is_stale);

-- =============================================================================
-- CONTRIBUTOR ALIASES - All identities linked to a profile
-- =============================================================================

CREATE TABLE IF NOT EXISTS contributor_aliases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES contributor_profiles(id) ON DELETE CASCADE,
    
    -- Identity information
    alias_type VARCHAR NOT NULL,      -- 'email', 'github_username', 'name'
    alias_value VARCHAR NOT NULL,     -- The actual value
    is_primary BOOLEAN DEFAULT FALSE, -- Is this the preferred alias of its type?
    
    -- Source tracking
    source VARCHAR,                   -- 'git_log', 'github_api', 'entra_id', 'manual'
    first_seen_at TIMESTAMP,
    last_seen_at TIMESTAMP,
    
    -- Match metadata
    match_confidence NUMERIC(3, 2),
    match_reason VARCHAR,
    
    created_at TIMESTAMP DEFAULT NOW(),
    
    UNIQUE(alias_type, alias_value)
);

CREATE INDEX IF NOT EXISTS idx_contributor_aliases_profile_id ON contributor_aliases(profile_id);
CREATE INDEX IF NOT EXISTS idx_contributor_aliases_alias_value ON contributor_aliases(alias_value);
CREATE INDEX IF NOT EXISTS idx_contributor_aliases_alias_type_value ON contributor_aliases(alias_type, alias_value);

-- =============================================================================
-- LINK EXISTING CONTRIBUTORS TO PROFILES
-- =============================================================================

-- Add profile_id to contributors table
ALTER TABLE contributors 
ADD COLUMN IF NOT EXISTS profile_id UUID REFERENCES contributor_profiles(id);

CREATE INDEX IF NOT EXISTS idx_contributors_profile_id ON contributors(profile_id);

-- =============================================================================
-- HELPER VIEW: Contributor Profile Summary
-- =============================================================================

CREATE OR REPLACE VIEW contributor_profile_summary AS
SELECT 
    cp.id,
    cp.display_name,
    cp.primary_email,
    cp.primary_github_username,
    cp.employment_status,
    cp.entra_id_upn,
    cp.entra_id_department,
    cp.total_repos,
    cp.total_commits,
    cp.last_activity_at,
    cp.is_stale,
    cp.risk_score,
    (
        SELECT COUNT(*) 
        FROM contributor_aliases ca 
        WHERE ca.profile_id = cp.id
    ) as alias_count,
    (
        SELECT json_agg(json_build_object(
            'type', ca.alias_type,
            'value', ca.alias_value,
            'is_primary', ca.is_primary
        ))
        FROM contributor_aliases ca 
        WHERE ca.profile_id = cp.id
    ) as aliases
FROM contributor_profiles cp;

COMMENT ON TABLE contributor_profiles IS 'Unified contributor identity that aggregates all aliases (emails, usernames). Designed to integrate with Entra ID for employment status verification.';
COMMENT ON TABLE contributor_aliases IS 'An alias (email, username, name variation) linked to a ContributorProfile. Allows tracking all the different identities a single person has used.';

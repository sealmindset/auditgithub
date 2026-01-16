-- Database Migration Script
-- Syncs database schema with models.py
-- Run with: docker-compose exec db psql -U auditgh -d auditgh_kb -f /migrations/migrate.sql

BEGIN;

-- ============================================================================
-- Fix remediations table schema
-- ============================================================================
-- The current table has: vuln_id, vuln_type, context_hash, code_diff
-- The model expects: finding_id, diff, confidence

-- Add missing columns if they don't exist
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS finding_id UUID REFERENCES findings(id);
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS diff TEXT;
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS confidence NUMERIC(3, 2);

-- Migrate data from old columns to new if old columns exist
DO $$
BEGIN
    -- Copy code_diff to diff if code_diff exists
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'remediations' AND column_name = 'code_diff') THEN
        UPDATE remediations SET diff = code_diff WHERE diff IS NULL AND code_diff IS NOT NULL;
    END IF;
END $$;

-- ============================================================================
-- Ensure contributors table has profile_id column
-- ============================================================================
ALTER TABLE contributors ADD COLUMN IF NOT EXISTS profile_id UUID REFERENCES contributor_profiles(id);

-- ============================================================================
-- Ensure all new tables exist (SQLAlchemy should have created these)
-- ============================================================================

-- api_endpoints table
CREATE TABLE IF NOT EXISTS api_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id),
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

-- openapi_specs table
CREATE TABLE IF NOT EXISTS openapi_specs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) UNIQUE,
    spec_content TEXT,
    spec_format VARCHAR DEFAULT 'yaml',
    version VARCHAR DEFAULT '3.0.3',
    generated_at TIMESTAMP DEFAULT NOW(),
    endpoint_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- ============================================================================
-- Create indexes for better query performance
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_api_endpoints_repo_id ON api_endpoints(repository_id);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_direction ON api_endpoints(direction);
CREATE INDEX IF NOT EXISTS idx_remediations_finding_id ON remediations(finding_id);

COMMIT;

-- Output results
SELECT 'Migration completed successfully!' AS status;
SELECT table_name, column_name 
FROM information_schema.columns 
WHERE table_name IN ('remediations', 'api_endpoints', 'openapi_specs')
ORDER BY table_name, ordinal_position;

-- Migration: 016_commit_analyses.sql
-- Purpose: Cache for commit analysis results to avoid repeated GitHub API calls

CREATE TABLE IF NOT EXISTS commit_analyses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Analysis results stored as JSONB
    analysis_data JSONB NOT NULL,

    -- Cache metadata
    commit_count INTEGER NOT NULL DEFAULT 0,
    last_commit_sha VARCHAR(40),
    is_dormant BOOLEAN DEFAULT FALSE,

    -- Timestamps
    analyzed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- One analysis per repository
    CONSTRAINT uq_commit_analyses_repository UNIQUE (repository_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS ix_commit_analyses_repository_id ON commit_analyses(repository_id);
CREATE INDEX IF NOT EXISTS ix_commit_analyses_expires_at ON commit_analyses(expires_at);
CREATE INDEX IF NOT EXISTS ix_commit_analyses_organization_id ON commit_analyses(organization_id);

-- Auto-update trigger for updated_at
CREATE OR REPLACE FUNCTION update_commit_analyses_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_commit_analyses_updated_at ON commit_analyses;
CREATE TRIGGER trg_commit_analyses_updated_at
    BEFORE UPDATE ON commit_analyses
    FOR EACH ROW
    EXECUTE FUNCTION update_commit_analyses_updated_at();

-- Comments
COMMENT ON TABLE commit_analyses IS 'Cached commit analysis results for AI scheduling decisions';
COMMENT ON COLUMN commit_analyses.analysis_data IS 'JSONB containing CommitAnalysisResult: patterns, file_types, contributors';
COMMENT ON COLUMN commit_analyses.expires_at IS 'Cache expiration - re-analyze after this time';
COMMENT ON COLUMN commit_analyses.is_dormant IS 'True if no commits in 90+ days';

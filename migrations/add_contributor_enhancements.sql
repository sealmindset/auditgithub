-- Enhance contributors table for file severity tracking and AI analysis
-- This migration adds fields for detailed contributor analysis with security context

-- Add new columns to contributors table
ALTER TABLE contributors
ADD COLUMN IF NOT EXISTS github_username VARCHAR(255),
ADD COLUMN IF NOT EXISTS commit_percentage NUMERIC(5, 2),
ADD COLUMN IF NOT EXISTS files_contributed JSONB DEFAULT '[]'::jsonb,
ADD COLUMN IF NOT EXISTS folders_contributed JSONB DEFAULT '[]'::jsonb,
ADD COLUMN IF NOT EXISTS ai_summary TEXT;

-- Set defaults for existing records
UPDATE contributors
SET files_contributed = '[]'::jsonb
WHERE files_contributed IS NULL;

UPDATE contributors
SET folders_contributed = '[]'::jsonb
WHERE folders_contributed IS NULL;

-- Add comments for documentation
COMMENT ON COLUMN contributors.github_username IS 'GitHub username extracted from email or API';
COMMENT ON COLUMN contributors.commit_percentage IS 'Percentage of total repository commits';
COMMENT ON COLUMN contributors.files_contributed IS 'JSON array: [{"path": "file.py", "severity": "high", "findings_count": 2}, ...]';
COMMENT ON COLUMN contributors.folders_contributed IS 'JSON array of top-level folders modified';
COMMENT ON COLUMN contributors.ai_summary IS 'AI-generated analysis of contributor security impact';

-- Index for efficient queries on risk and repository
CREATE INDEX IF NOT EXISTS idx_contributors_repo_risk ON contributors(repository_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_contributors_repo_commits ON contributors(repository_id, commits DESC);

-- GIN index for JSONB columns (enables fast containment queries)
CREATE INDEX IF NOT EXISTS idx_contributors_files_gin ON contributors USING GIN (files_contributed);

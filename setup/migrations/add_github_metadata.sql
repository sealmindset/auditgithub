-- Migration: Add GitHub API metadata fields to repositories table
-- Date: 2024-12-07
-- Description: Adds fields from GitHub API that aren't available in local clone

-- Add GitHub metadata columns to repositories
ALTER TABLE repositories
ADD COLUMN IF NOT EXISTS pushed_at TIMESTAMP,
ADD COLUMN IF NOT EXISTS github_created_at TIMESTAMP,
ADD COLUMN IF NOT EXISTS github_updated_at TIMESTAMP,
ADD COLUMN IF NOT EXISTS stargazers_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS watchers_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS forks_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS open_issues_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS size_kb INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS is_fork BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS is_private BOOLEAN DEFAULT TRUE,
ADD COLUMN IF NOT EXISTS visibility VARCHAR(20),
ADD COLUMN IF NOT EXISTS topics JSONB,
ADD COLUMN IF NOT EXISTS license_name VARCHAR(100),
ADD COLUMN IF NOT EXISTS has_wiki BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS has_pages BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS has_discussions BOOLEAN DEFAULT FALSE;

-- Create file_commits table for tracking file-level commit data
CREATE TABLE IF NOT EXISTS file_commits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    
    -- Commit information from GitHub API
    last_commit_sha VARCHAR(40),
    last_commit_date TIMESTAMP,
    last_commit_author VARCHAR(255),
    last_commit_message TEXT,
    
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    CONSTRAINT uq_file_commits_repo_path UNIQUE (repository_id, file_path)
);

-- Create indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_file_commits_repo ON file_commits(repository_id);
CREATE INDEX IF NOT EXISTS idx_file_commits_path ON file_commits(file_path);
CREATE INDEX IF NOT EXISTS idx_file_commits_date ON file_commits(last_commit_date);
CREATE INDEX IF NOT EXISTS idx_repositories_pushed_at ON repositories(pushed_at);
CREATE INDEX IF NOT EXISTS idx_repositories_archived ON repositories(is_archived);

-- Add comment explaining the fields
COMMENT ON COLUMN repositories.pushed_at IS 'Last push to any branch (from GitHub API) - most accurate "last commit" indicator';
COMMENT ON COLUMN repositories.github_created_at IS 'When the repository was created on GitHub';
COMMENT ON COLUMN repositories.github_updated_at IS 'Last metadata update on GitHub (not code changes)';
COMMENT ON COLUMN repositories.visibility IS 'Repository visibility: public, private, or internal';
COMMENT ON COLUMN repositories.topics IS 'JSON array of topic tags from GitHub';
COMMENT ON TABLE file_commits IS 'Tracks last commit information for specific files, fetched from GitHub API';

-- Add failure tracking columns for self-annealing
-- This allows the system to automatically skip problematic repos after repeated failures

ALTER TABLE repositories
ADD COLUMN IF NOT EXISTS failure_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS last_failure_at TIMESTAMP,
ADD COLUMN IF NOT EXISTS last_failure_reason VARCHAR(255);

-- Set existing repos to 0 failures
UPDATE repositories
SET failure_count = 0
WHERE failure_count IS NULL;

-- Add index for efficient queries
CREATE INDEX IF NOT EXISTS idx_repositories_failure_count ON repositories(failure_count);

COMMENT ON COLUMN repositories.failure_count IS 'Consecutive failures (timeouts/errors). Reset to 0 on success.';
COMMENT ON COLUMN repositories.last_failure_at IS 'Timestamp of most recent failure';
COMMENT ON COLUMN repositories.last_failure_reason IS 'Reason for last failure (timeout, error, etc)';

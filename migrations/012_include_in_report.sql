-- Migration 012: Add include_in_report column to findings
-- This allows Security Analysts to manually include findings in the Critical Insights section of reports

-- Add include_in_report column (default false - unchecked)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS include_in_report BOOLEAN DEFAULT FALSE;

-- Add index for efficient filtering
CREATE INDEX IF NOT EXISTS idx_findings_include_in_report ON findings(include_in_report) WHERE include_in_report = TRUE;

-- Comment for documentation
COMMENT ON COLUMN findings.include_in_report IS 'When true, finding is manually included in Critical Insights section of Security Report';

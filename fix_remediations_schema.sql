-- Migration to fix remediations table schema
-- Backup the old data first if needed
-- CREATE TABLE remediations_backup AS SELECT * FROM remediations;

BEGIN;

-- Drop old constraints that reference old columns
ALTER TABLE remediations DROP CONSTRAINT IF EXISTS remediations_vuln_id_context_hash_key;
DROP INDEX IF EXISTS idx_remediations_lookup;

-- Drop old columns
ALTER TABLE remediations DROP COLUMN IF EXISTS vuln_id;
ALTER TABLE remediations DROP COLUMN IF EXISTS vuln_type;
ALTER TABLE remediations DROP COLUMN IF EXISTS context_hash;

-- Rename code_diff to diff
ALTER TABLE remediations RENAME COLUMN code_diff TO diff;

-- Add new columns
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS finding_id UUID;
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS confidence NUMERIC(3,2);

-- Add foreign key constraint
ALTER TABLE remediations
  ADD CONSTRAINT remediations_finding_id_fkey
  FOREIGN KEY (finding_id)
  REFERENCES findings(id)
  ON DELETE CASCADE;

-- Create index on finding_id for performance
CREATE INDEX IF NOT EXISTS idx_remediations_finding_id ON remediations(finding_id);

COMMIT;

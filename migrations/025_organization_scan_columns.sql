-- =============================================================================
-- 025: Restore the organizations columns the multi-org code has always read
-- =============================================================================
--
-- The problem
-- -----------
-- migrations/002_organizations.sql creates `organizations` with 30 columns.
-- The live table has 10. Whatever created it here did not run 002, and 006
-- (which re-adds the same columns with ADD COLUMN IF NOT EXISTS) never ran
-- either. There is no migration-tracking table in this database, so nothing
-- recorded the omission and nothing detected it.
--
-- execution/ai_org_agent.py has always read and written the missing columns.
-- The damage was therefore silent and specific:
--
--   * `scan_repos.py --list-orgs` fails outright:
--         column "schema_version" does not exist
--     list_organizations() selects 17 columns; only 10 are there.
--
--   * The organization scan button returns 500 and never launches a scanner.
--     mark_scan_started() writes scan_status and scan_progress, so the first
--     write of every organization scan fails.
--
--   * Schema-drift sync reports a warning on every agent startup, for the same
--     reason, which trained everyone to read that warning as normal noise.
--
-- get_organization() is the exception: it degrades to NULL for the absent
-- fields rather than raising, which is why single-org operations kept working
-- and hid how much else did not.
--
-- What this does
-- --------------
-- Adds the columns, nothing else. Additive and idempotent: ADD COLUMN IF NOT
-- EXISTS touches no existing row's data, and re-running is a no-op. Column
-- names, types and defaults are copied from 002 so this database converges on
-- the declared schema rather than on a third variant.
--
-- Deliberately NOT included, though 002 declares them:
--
--   * database_name NOT NULL UNIQUE -- existing rows would have to be
--     backfilled first, and the constraint is not what anything reads.
--   * unique_default_org EXCLUDE -- an exclusion constraint on a table that
--     may already hold more than one is_default row would fail to add. Check
--     the data before adopting it.
--
-- Both are constraint changes rather than additions, so they are the parts
-- that could reject existing rows. They are left for a separate, deliberate
-- migration.
--
-- Verification after applying:
--
--   docker exec auditgh_api python scripts/scanning/scan_repos.py --list-orgs
--   docker exec auditgh_api python -m pytest tests/test_organization_schema.py
-- =============================================================================

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS database_schema      VARCHAR(255) DEFAULT 'public',

    -- Schema synchronization
    ADD COLUMN IF NOT EXISTS schema_version       VARCHAR(128),
    ADD COLUMN IF NOT EXISTS schema_version_name  VARCHAR(100) DEFAULT 'v1.0.0',
    ADD COLUMN IF NOT EXISTS last_schema_sync     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS schema_sync_status   VARCHAR(50)  DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS schema_sync_error    TEXT,

    -- Scan tracking. scan_status and scan_progress are what the organization
    -- scan endpoint writes on every launch; total_scans is incremented on
    -- completion, so it must default to 0 rather than NULL or the increment
    -- yields NULL.
    ADD COLUMN IF NOT EXISTS last_scan_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS scan_status          VARCHAR(50)  DEFAULT 'idle',
    ADD COLUMN IF NOT EXISTS scan_progress        INTEGER      DEFAULT 0,
    ADD COLUMN IF NOT EXISTS current_scan_id      UUID,
    ADD COLUMN IF NOT EXISTS total_scans          INTEGER      DEFAULT 0,
    ADD COLUMN IF NOT EXISTS total_repos          INTEGER      DEFAULT 0,
    ADD COLUMN IF NOT EXISTS total_findings       INTEGER      DEFAULT 0,

    -- Metadata
    ADD COLUMN IF NOT EXISTS description          TEXT,
    ADD COLUMN IF NOT EXISTS settings             JSONB        DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS created_by           UUID;

-- ADD COLUMN ... DEFAULT backfills existing rows in PostgreSQL 11+, so the
-- counters and statuses above are already correct for rows that predate this
-- migration. These two are for rows written by code paths that set the column
-- explicitly to NULL, and for any pre-11 server.
UPDATE organizations SET scan_status   = 'idle' WHERE scan_status   IS NULL;
UPDATE organizations SET scan_progress = 0      WHERE scan_progress IS NULL;
UPDATE organizations SET total_scans   = 0      WHERE total_scans   IS NULL;

-- Indexes from 002 that were never created here.
CREATE INDEX IF NOT EXISTS idx_organizations_name       ON organizations(name);
CREATE INDEX IF NOT EXISTS idx_organizations_github_org ON organizations(github_org);
CREATE INDEX IF NOT EXISTS idx_organizations_active     ON organizations(is_active);
CREATE INDEX IF NOT EXISTS idx_organizations_default    ON organizations(is_default)
    WHERE is_default = true;

COMMENT ON COLUMN organizations.schema_version IS
    'SHA-256 hash of current schema DDL for drift detection';
COMMENT ON COLUMN organizations.scan_status IS
    'idle, scanning, queued, error or cancelled -- written by the organization scan endpoint';

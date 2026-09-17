-- Migration 023: AuditBoard filings carry the new group key
--
-- Filing moved from grouping on (scanner_name, file_path) to grouping on the
-- defect's identity (scanner_name, rule_id) and the project it lives in. See
-- src/api/services/finding_groups.py for why: the old key merged 11,517
-- findings across 100+ unrelated projects and 1,287 different CVEs into one
-- group, while splitting a single CVE across every project it touched.
--
-- Nothing is backfilled and nothing is dropped. Rows filed before this change
-- have scope = 'global' and are still matched on (scanner_name, file_path);
-- rule_id and repository_id stay NULL on them. Four such issues exist
-- (I#1716 - I#1719, plus I#1720 at 'specific'), they cannot be deleted in
-- AuditBoard, and rewriting their key would make them stop matching their own
-- findings — which is exactly the duplicate-filing failure this key change is
-- meant to prevent.

ALTER TABLE auditboard_issues
    ADD COLUMN IF NOT EXISTS rule_id           VARCHAR(255),
    ADD COLUMN IF NOT EXISTS repository_id     UUID,
    ADD COLUMN IF NOT EXISTS location_count    INTEGER,
    ADD COLUMN IF NOT EXISTS locations_omitted INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS project_count     INTEGER;

-- The lookup behind "has this defect already been filed for this project?",
-- which runs once per findings table render.
CREATE INDEX IF NOT EXISTS ix_auditboard_issues_group_key
    ON auditboard_issues(scanner_name, rule_id, repository_id);

-- Org-tier lookup: same defect, any project.
CREATE INDEX IF NOT EXISTS ix_auditboard_issues_identity
    ON auditboard_issues(scanner_name, rule_id);

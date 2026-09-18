-- Migration 024: issues filed from a hand-picked selection of findings
--
-- Every scope before this one is a rule. 'project' and 'org' ask whether a
-- finding shares a defect identity with the issue, so the issue needs no
-- membership list and a finding scanned tomorrow falls under it automatically.
--
-- A selection is not a rule. Someone ticked rows in the findings table and only
-- those rows are covered. With nothing written down, "is this finding already
-- filed?" has no answer for them: the AuditBoard column would stay empty
-- forever and the same findings would be filed again. Hence a membership table.
--
-- finding_id carries no foreign key, matching auditboard_issues.finding_id. The
-- GRC issue outlives whatever this application later deletes, and a filing
-- history that disappears with its evidence is not an audit trail. The cascade
-- is on the issue row only.

CREATE TABLE IF NOT EXISTS auditboard_issue_findings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auditboard_issue_id UUID NOT NULL
                        REFERENCES auditboard_issues(id) ON DELETE CASCADE,
    finding_id          UUID NOT NULL,
    created_at          TIMESTAMP DEFAULT now(),

    -- A finding appears at most once per issue. Without this a double submit
    -- inflates the coverage count of a record whose description cannot be
    -- edited afterwards.
    CONSTRAINT uq_auditboard_issue_finding UNIQUE (auditboard_issue_id, finding_id)
);

-- Index names match what SQLAlchemy's index=True generates, deliberately.
-- create_all() at src/api/main.py:243 creates missing tables, so on any
-- database that has started the app once this table already exists with
-- SQLAlchemy's own names. Using different names here would leave IF NOT EXISTS
-- satisfied by nothing and build a second, identical index on each column.

-- "Which findings does this issue cover?" - the delete dry run and the issue
-- detail view.
CREATE INDEX IF NOT EXISTS ix_auditboard_issue_findings_auditboard_issue_id
    ON auditboard_issue_findings(auditboard_issue_id);

-- "Is this finding already filed?" - runs once per row of the findings table,
-- so it is the one that has to be fast.
CREATE INDEX IF NOT EXISTS ix_auditboard_issue_findings_finding_id
    ON auditboard_issue_findings(finding_id);

-- Migration 022: Rule equivalence — cross-scanner "same defect" decisions
--
-- Supports the filing principle in src/api/services/finding_groups.py: findings
-- group by (scanner_name, rule_id), which files two GRC issues when two
-- scanners report the same defect. This table records the claim that two rules
-- are one defect, as a proposal an AI pass makes and a person then approves or
-- rejects.
--
-- Only rows with review_decision = 'approved' AND verdict = 'equivalent' change
-- how anything is filed. A pending proposal is deliberately inert: AuditBoard
-- issues cannot be deleted and their descriptions cannot be edited after
-- create, so a wrong merge permanently claims an issue covers a finding it does
-- not describe. Filing a visible duplicate is the cheaper error.
--
-- The pair is stored in canonical order (scanner_a, rule_a) <= (scanner_b,
-- rule_b) so the same two rules cannot be recorded twice in opposite order and
-- carry contradictory verdicts. The unique constraint enforces one verdict per
-- pair per organization; the application is responsible for the ordering.
--
-- DATA CLASSIFICATION: rule identifiers and model rationale only. evidence
-- holds rule metadata and normalized file paths — never code_snippet, because
-- a snippet from a secret-scanner rule is the secret itself.

CREATE TABLE IF NOT EXISTS rule_equivalences (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID,

    -- Not foreign keys: a rule is a value scanners emit, not a row anywhere.
    scanner_a        VARCHAR(100) NOT NULL,
    rule_a           VARCHAR(255) NOT NULL,
    scanner_b        VARCHAR(100) NOT NULL,
    rule_b           VARCHAR(255) NOT NULL,

    -- 'equivalent' or 'distinct'.
    verdict          VARCHAR(20)  NOT NULL,
    confidence       NUMERIC(3,2),
    -- Which model decided, and what it was shown. Without these a verdict is
    -- an assertion nobody can re-examine when the model is replaced.
    model            VARCHAR(255),
    rationale        TEXT,
    evidence         JSONB,
    proposed_at      TIMESTAMP DEFAULT NOW(),

    -- NULL review_decision means unreviewed, which means no effect on grouping.
    review_decision  VARCHAR(20),
    reviewed_by      VARCHAR(255),
    reviewed_at      TIMESTAMP,
    review_note      TEXT,

    created_at       TIMESTAMP DEFAULT NOW(),
    updated_at       TIMESTAMP DEFAULT NOW()
);

-- One verdict per pair per organization. organization_id is nullable and NULLs
-- are distinct in a UNIQUE constraint, so a tenant-wide row (NULL org) can
-- coexist with per-org rows for the same pair; load_equivalence_map() reads
-- both, and union-find makes that idempotent rather than contradictory.
CREATE UNIQUE INDEX IF NOT EXISTS uq_rule_equivalence_pair
    ON rule_equivalences(organization_id, scanner_a, rule_a, scanner_b, rule_b);

-- The only read path that matters at filing time: approved merges.
CREATE INDEX IF NOT EXISTS ix_rule_equivalence_approved
    ON rule_equivalences(review_decision, verdict);

-- The review queue: oldest unreviewed proposal first.
CREATE INDEX IF NOT EXISTS ix_rule_equivalence_pending
    ON rule_equivalences(proposed_at)
    WHERE review_decision IS NULL;

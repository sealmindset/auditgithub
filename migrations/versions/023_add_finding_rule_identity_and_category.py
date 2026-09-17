"""Add rule identity and remediation category to findings

Revision ID: 023
Revises: 022
Create Date: 2026-09-14

Implements:
- rule_id / rule_id_is_stable on findings, so a finding can be keyed to a
  knowledge-base entry. Four of the scanners in this estate emit their rule
  identity only inside the title string and it was discarded at ingest;
  src/services/remediation_classifier.py recovers it, and rule_id_is_stable
  records whether the recovered value is an identifier or prose that an
  upstream release may reword.
- ghsa_id, because grype reports GitHub advisories, not CVEs. Every one of the
  769,825 findings currently in this estate has a NULL cve_id, so a key
  precedence that starts at cve_id resolves nothing.
- remediation_category with its source, confidence and rationale. The source
  column is what keeps a rule-matched count and a model-inferred count from
  being presented as one number.
- excluded_from_actionable / exclusion_reason, so a finding can be kept and
  counted while being left out of the work list. Two scanner rules account for
  71.1% of this estate and neither reports a credential; deleting them would
  destroy the evidence for that claim, and leaving them in would bury the
  report. Exclusion is the third option, and it is reversible.

Deliberately not migrated:
- No existing row is backfilled here. Recovering rule_id from titles is a data
  change over 769,825 rows and belongs in a script an operator runs and can
  inspect the output of, not in a schema migration that runs on deploy. See
  scripts/backfill_rule_identity.py.
- cve_id, package_name and package_version are left alone. They are empty
  because the ingest path does not write them; that is an ingest defect, and
  filling them from titles here would hide it.
- No CHECK constraint on remediation_category. The valid set lives in
  src/api/constants/remediation.py, and a database enum would mean a migration
  every time the taxonomy gains a value.

Index creation takes a brief ACCESS EXCLUSIVE lock on findings. At this row
count that is seconds, not minutes, but it is a lock.
"""
from alembic import op
import sqlalchemy as sa

# Revision identifiers
revision = '023'
down_revision = '022'
branch_labels = None
depends_on = None


def upgrade():
    """Add the rule identity and category columns to findings."""

    # Rule identity
    op.add_column('findings', sa.Column('rule_id', sa.String(512), nullable=True))
    op.add_column('findings', sa.Column('rule_id_is_stable', sa.Boolean, nullable=True))
    op.add_column('findings', sa.Column('ghsa_id', sa.String(32), nullable=True))

    # Remediation category. NULL means "not yet classified", which is distinct
    # from every enum value including false_positive.
    op.add_column('findings', sa.Column('remediation_category', sa.String(64), nullable=True))
    op.add_column('findings', sa.Column('category_source', sa.String(16),
                                        nullable=False, server_default='none'))
    op.add_column('findings', sa.Column('category_confidence', sa.Float, nullable=True))
    op.add_column('findings', sa.Column('category_rationale', sa.Text, nullable=True))
    op.add_column('findings', sa.Column('category_assigned_at', sa.DateTime, nullable=True))

    # Kept, counted, and left out of the work list. Not the same as deleted, and
    # not the same as false_positive: excluding a filename-only match says the
    # scanner never opened the file, where 'false positive' would assert it is clean.
    op.add_column('findings', sa.Column('excluded_from_actionable', sa.Boolean,
                                        nullable=False, server_default=sa.text('false')))
    op.add_column('findings', sa.Column('exclusion_reason', sa.Text, nullable=True))

    # (scanner_name, rule_id) is the knowledge-base key for everything that has
    # no advisory identifier, which in this estate is most of the corpus.
    op.create_index('idx_findings_scanner_rule', 'findings', ['scanner_name', 'rule_id'])
    op.create_index('idx_findings_ghsa', 'findings', ['ghsa_id'])

    # The report groups by category within a repository, and counts by source.
    op.create_index('idx_findings_repo_category', 'findings',
                    ['repository_id', 'remediation_category'])
    op.create_index('idx_findings_category_source', 'findings', ['category_source'])
    # Every actionable-report query filters on this, over 769,825 rows.
    op.create_index('idx_findings_excluded', 'findings', ['excluded_from_actionable'])


def downgrade():
    """Drop the rule identity and category columns.

    Destructive: any classification already assigned is lost, including human
    overrides, which exist nowhere else. Re-running the classifier restores the
    rule-derived and model-derived values but not the human ones.
    """
    op.drop_index('idx_findings_excluded', table_name='findings')
    op.drop_index('idx_findings_category_source', table_name='findings')
    op.drop_index('idx_findings_repo_category', table_name='findings')
    op.drop_index('idx_findings_ghsa', table_name='findings')
    op.drop_index('idx_findings_scanner_rule', table_name='findings')

    op.drop_column('findings', 'exclusion_reason')
    op.drop_column('findings', 'excluded_from_actionable')
    op.drop_column('findings', 'category_assigned_at')
    op.drop_column('findings', 'category_rationale')
    op.drop_column('findings', 'category_confidence')
    op.drop_column('findings', 'category_source')
    op.drop_column('findings', 'remediation_category')
    op.drop_column('findings', 'ghsa_id')
    op.drop_column('findings', 'rule_id_is_stable')
    op.drop_column('findings', 'rule_id')

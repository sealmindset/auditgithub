"""Add remediation_actions and the action-to-finding join

Revision ID: 024
Revises: 023
Create Date: 2026-09-14

Implements:
- remediation_actions: one row per piece of work, not per finding. Upgrading
  lodash once closes forty findings; forty effort estimates would overstate the
  work by a factor of forty. The action is what gets estimated, assigned, and
  filed into AuditBoard.
- remediation_action_findings: the many-to-many that makes "one remediation
  covers these forty findings" a queryable fact rather than a claim in prose.
- Measured effort drivers stored alongside the estimated band, so a report can
  print the arithmetic behind a band instead of asserting it.
- auditboard_issue_id for idempotency. A second push updates the existing issue
  instead of creating a duplicate.

Scope is per-organization, matching the decision recorded in the specification:
actions group across the repositories of one organization, so a single lodash
upgrade spanning nine repositories is one action with nine repositories in its
drivers. It does not group across organizations, which have separate databases.

Deliberately not implemented:
- No effort_hours column, in any unit. The band is an estimate and the data that
  would justify converting it to hours — how long past remediations actually
  took — is not collected by this system. A column would invite someone to fill
  it in from intuition and then sum it into a budget.
- No auditboard_status. This release pushes one way only; reading status back
  would make AuditBoard a second source of truth for whether work is done, and
  nothing reconciles the two.
- No rows are created. Grouping runs as a service call over classified
  findings, after 023's backfill, not on deploy.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision = '024'
down_revision = '023'
branch_labels = None
depends_on = None


def upgrade():
    """Create remediation_actions and its join table."""

    op.execute("CREATE SEQUENCE IF NOT EXISTS remediation_actions_api_id_seq")

    op.create_table(
        'remediation_actions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column('api_id', sa.Integer,
                  sa.Sequence('remediation_actions_api_id_seq'), unique=True),

        sa.Column('organization_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),

        # Deterministic identity, e.g. "upgrade:npm:lodash:4.17.21",
        # "rotate:aws_access_key:github", "configure:CKV_AWS_18".
        # Re-running the grouper produces the same key, which is what makes the
        # AuditBoard push idempotent across runs.
        sa.Column('action_key', sa.String(512), nullable=False),

        sa.Column('category', sa.String(64), nullable=False),
        sa.Column('title', sa.String(512), nullable=False),
        sa.Column('remediation_text', sa.Text),

        # Estimated. Named so in the column comment and everywhere it renders.
        sa.Column('effort_band', sa.String(4)),
        sa.Column('effort_score', sa.Integer),
        sa.Column('effort_reasons', postgresql.JSONB, server_default='[]'),
        # Drivers that could not be measured. A band with a non-empty list here
        # rests partly on absent data and says so in the report.
        sa.Column('effort_unknowns', postgresql.JSONB, server_default='[]'),

        # Measured drivers, denormalised so a report does not recount 770k rows
        # per action. Refreshed by the grouper, never hand-edited.
        sa.Column('findings_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('files_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('repos_count', sa.Integer, nullable=False, server_default='0'),
        sa.Column('severity_counts', postgresql.JSONB, server_default='{}'),

        sa.Column('primary_role', sa.String(32)),
        sa.Column('supporting_roles', postgresql.JSONB, server_default='[]'),

        # Populated for dependency actions; NULL elsewhere.
        sa.Column('package_ecosystem', sa.String(32)),
        sa.Column('package_name', sa.String(255)),
        sa.Column('current_version', sa.String(64)),
        sa.Column('fixed_version', sa.String(64)),

        sa.Column('status', sa.String(32), nullable=False, server_default='open'),
        sa.Column('owner_user_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),

        # AuditBoard linkage. NULL means never pushed — distinct from pushed and
        # since deleted at the far end, which this schema cannot detect.
        sa.Column('auditboard_issue_id', sa.String(64), nullable=True),
        sa.Column('auditboard_instance', sa.String(255), nullable=True),
        sa.Column('auditboard_pushed_at', sa.DateTime, nullable=True),
        sa.Column('auditboard_push_status', sa.String(32), server_default='not_pushed'),
        sa.Column('auditboard_push_detail', sa.Text),

        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now(),
                  onupdate=sa.func.now()),

        sa.UniqueConstraint('organization_id', 'action_key', name='uq_remediation_action_key'),
    )

    op.create_index('idx_remediation_actions_org', 'remediation_actions', ['organization_id'])
    op.create_index('idx_remediation_actions_category', 'remediation_actions', ['category'])
    op.create_index('idx_remediation_actions_status', 'remediation_actions', ['status'])
    op.create_index('idx_remediation_actions_auditboard', 'remediation_actions',
                    ['auditboard_issue_id'])

    op.create_table(
        'remediation_action_findings',
        sa.Column('action_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('remediation_actions.id', ondelete='CASCADE'),
                  primary_key=True),
        sa.Column('finding_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('findings.id', ondelete='CASCADE'),
                  primary_key=True),
        # Which repository this finding came from. Denormalised because
        # repos_count is reported per action and the alternative is a join back
        # to findings for every count.
        sa.Column('repository_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('repositories.id', ondelete='CASCADE'), nullable=True),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )

    op.create_index('idx_action_findings_finding', 'remediation_action_findings', ['finding_id'])
    op.create_index('idx_action_findings_repo', 'remediation_action_findings', ['repository_id'])


def downgrade():
    """Drop remediation_actions and its join table.

    Destructive: owner assignments, status changes and auditboard_issue_id are
    lost. Losing auditboard_issue_id means the next push cannot recognise issues
    it already created, so a re-push after a downgrade duplicates every issue in
    AuditBoard. Export the table before downgrading if anything has been pushed.
    """
    op.drop_index('idx_action_findings_repo', table_name='remediation_action_findings')
    op.drop_index('idx_action_findings_finding', table_name='remediation_action_findings')
    op.drop_table('remediation_action_findings')

    op.drop_index('idx_remediation_actions_auditboard', table_name='remediation_actions')
    op.drop_index('idx_remediation_actions_status', table_name='remediation_actions')
    op.drop_index('idx_remediation_actions_category', table_name='remediation_actions')
    op.drop_index('idx_remediation_actions_org', table_name='remediation_actions')
    op.drop_table('remediation_actions')
    op.execute("DROP SEQUENCE IF EXISTS remediation_actions_api_id_seq")

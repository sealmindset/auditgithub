"""Add the finding knowledge base, its version history and the per-org overlay

Revision ID: 025
Revises: 024
Create Date: 2026-09-14

Implements:
- `finding_knowledge_base`, one entry per unique finding signature. Measured
  against the live corpus: 222,844 actionable findings resolve to 2,639 distinct
  keys, and the ten largest cover half of them. The table is sized in hundreds,
  not in hundreds of thousands, which is what makes authoring it feasible.
- `finding_kb_version`, a full snapshot per approved edit, mirroring
  `PromptVersion`. A report issued in March must be re-renderable in September
  against the knowledge base as it stood in March; without a snapshot, re-running
  an old report silently produces different text under the same figures.
- `finding_kb_org_overlay`, so an organization's local standards ("we use the
  internal mirror, not npmjs") live beside the generic entry instead of being
  merged into it. The global entry stays reusable across organizations.

Design notes worth stating, because each is a decision someone could reasonably
have made the other way:

- `status` gates rendering, not storage. Drafts exist, are visible in the UI, and
  never reach a report; a report generated while an entry is draft prints
  'knowledge base entry pending review' rather than draft prose that no one
  approved.
- `source` separates `import` (fetched from an upstream advisory and citable)
  from `ai` (generated) and `human`. This is the same discipline as
  `category_source` on findings: a fetched fact and a generated paragraph must
  never be countable as one number.
- `ai_confidence` is NULL for imported and human entries rather than 1.0. A
  confidence of 1.0 asserts a model was certain; NULL states no model was asked.
- `is_withdrawn` exists because advisories are retracted. An engineer sent to
  remediate a withdrawn advisory has been sent to do nothing, and nothing else
  in this schema would reveal that.
- `mapping_source` on `ttp` defaults to 'none' and in this estate stays there
  for scanner-rule entries: `findings.cwe_id` holds only the literal string
  'HorusecEngine' or empty across all 769,825 rows, so the CWE -> CAPEC -> ATT&CK
  chain has no local input. Advisory entries get a CWE from the advisory itself.

Deliberately not migrated:
- No entries are created. Populating the knowledge base is a fetch for advisory
  keys and an authoring task for rule keys; both belong in a script whose output
  an operator can inspect, not in a migration that runs on deploy.
- No foreign key from `findings.kb_id`. The join is by `kb_key`, derived at read
  time by `src/services/kb_key.py`. A stored FK would need backfilling on every
  new KB entry and would go stale the moment a key precedence changes; deriving
  it costs an indexed lookup and cannot drift.
- No CHECK constraints on the enum-valued columns. The vocabulary lives in
  `src/api/constants/kb.py`; a database enum means a migration per vocabulary
  change, and this vocabulary is expected to grow.

NOTE: this migration will not reach the `security_portal` database on its own.
That database has no `alembic_version` table and is built by
`Base.metadata.create_all`, which creates missing tables but never adds columns.
These are new tables, so `create_all` does apply them on API start -- but see
§9.0 of docs/specs/REPORT_GENERATOR_WIZARD_SPEC.md before assuming the same of
any migration that only adds columns.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

# Revision identifiers
revision = '025'
down_revision = '024'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'finding_knowledge_base',
        sa.Column('id', UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text('gen_random_uuid()')),
        sa.Column('api_id', sa.Integer, sa.Sequence('finding_kb_api_id_seq'), unique=True),

        # Composite key, first match wins: ghsa -> cve -> rule -> cwe.
        sa.Column('kb_key', sa.String(512), nullable=False, unique=True),
        sa.Column('key_type', sa.String(16), nullable=False),

        sa.Column('cve_id', sa.String(32)),
        sa.Column('cwe_id', sa.String(32)),
        sa.Column('ghsa_id', sa.String(32)),
        sa.Column('rule_id', sa.String(512)),
        sa.Column('scanner_name', sa.String(64)),
        # False when the key rests on prose an upstream release may reword, so a
        # silently orphaned entry can be found rather than waited for.
        sa.Column('key_is_stable', sa.Boolean, nullable=False, server_default=sa.text('true')),

        sa.Column('title', sa.Text, nullable=False),
        sa.Column('summary', sa.Text),
        sa.Column('reference_ids', JSONB, server_default=sa.text("'[]'::jsonb")),

        sa.Column('target_asset_type', sa.String(32)),
        sa.Column('target_asset_detail', sa.Text),

        sa.Column('blast_radius', JSONB),
        sa.Column('ttp', JSONB),
        sa.Column('exploitability', JSONB),
        sa.Column('mitigation_options', JSONB, server_default=sa.text("'[]'::jsonb")),

        # From the upstream advisory, kept apart from findings.severity: one is
        # the publisher's rating of the vulnerability, the other a scanner's
        # rating of an occurrence, and they disagree often enough to matter.
        sa.Column('upstream_severity', sa.String(16)),
        sa.Column('is_withdrawn', sa.Boolean, nullable=False, server_default=sa.text('false')),
        sa.Column('affected_packages', JSONB, server_default=sa.text("'[]'::jsonb")),

        sa.Column('status', sa.String(16), nullable=False, server_default='draft'),
        sa.Column('version', sa.Integer, nullable=False, server_default='1'),
        sa.Column('source', sa.String(16), nullable=False, server_default='ai'),
        sa.Column('ai_confidence', sa.Numeric(3, 2)),
        # Where an imported entry came from, so a reader can check it without
        # asking anyone.
        sa.Column('source_url', sa.Text),
        sa.Column('source_fetched_at', sa.DateTime),

        sa.Column('approved_by', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL')),
        sa.Column('approved_at', sa.DateTime),
        sa.Column('created_by', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL')),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
    )

    op.create_index('idx_kb_key_type_status', 'finding_knowledge_base', ['key_type', 'status'])
    op.create_index('idx_kb_cve', 'finding_knowledge_base', ['cve_id'])
    op.create_index('idx_kb_cwe', 'finding_knowledge_base', ['cwe_id'])
    op.create_index('idx_kb_scanner_rule', 'finding_knowledge_base', ['scanner_name', 'rule_id'])
    # Report rendering filters on this for every row it draws.
    op.create_index('idx_kb_status', 'finding_knowledge_base', ['status'])

    op.create_table(
        'finding_kb_versions',
        sa.Column('id', UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text('gen_random_uuid()')),
        sa.Column('kb_id', UUID(as_uuid=True),
                  sa.ForeignKey('finding_knowledge_base.id', ondelete='CASCADE'), nullable=False),
        sa.Column('version', sa.Integer, nullable=False),
        # Full snapshot, not a diff. A diff chain is only replayable while every
        # link survives; a snapshot re-renders an old report on its own.
        sa.Column('snapshot', JSONB, nullable=False),
        sa.Column('change_note', sa.Text),
        sa.Column('changed_by', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL')),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.UniqueConstraint('kb_id', 'version', name='uq_kb_version'),
    )

    op.create_table(
        'finding_kb_org_overlays',
        sa.Column('id', UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text('gen_random_uuid()')),
        sa.Column('kb_id', UUID(as_uuid=True),
                  sa.ForeignKey('finding_knowledge_base.id', ondelete='CASCADE'), nullable=False),
        sa.Column('organization_id', UUID(as_uuid=True),
                  sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        # Replaces the global list when 'replace', appended when 'append'. Made
        # explicit because "the org has mitigation options too" and "the global
        # advice is wrong here" are different statements.
        sa.Column('mitigation_mode', sa.String(16), nullable=False, server_default='append'),
        sa.Column('mitigation_options', JSONB, server_default=sa.text("'[]'::jsonb")),
        sa.Column('notes', sa.Text),
        sa.Column('created_by', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='SET NULL')),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
        sa.UniqueConstraint('kb_id', 'organization_id', name='uq_kb_org_overlay'),
    )
    op.create_index('idx_kb_overlay_org', 'finding_kb_org_overlays', ['organization_id'])


def downgrade():
    """Drop the knowledge base.

    Destructive in a way the other downgrades in this series are not: authored
    blast-radius and mitigation text exists nowhere else, and neither does the
    version history that lets an old report be re-rendered. Imported advisory
    fields can be re-fetched; authored prose cannot be re-derived from anything.
    """
    op.drop_index('idx_kb_overlay_org', table_name='finding_kb_org_overlays')
    op.drop_table('finding_kb_org_overlays')
    op.drop_table('finding_kb_versions')

    op.drop_index('idx_kb_status', table_name='finding_knowledge_base')
    op.drop_index('idx_kb_scanner_rule', table_name='finding_knowledge_base')
    op.drop_index('idx_kb_cwe', table_name='finding_knowledge_base')
    op.drop_index('idx_kb_cve', table_name='finding_knowledge_base')
    op.drop_index('idx_kb_key_type_status', table_name='finding_knowledge_base')
    op.drop_table('finding_knowledge_base')

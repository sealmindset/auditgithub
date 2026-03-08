"""Add prompt management system tables

Revision ID: 020
Revises: 019
Create Date: 2026-03-08

Implements:
- prompts table for centralized AI prompt registry
- prompt_versions table for immutable version history
- prompt_usages table for runtime usage tracking
- prompt_tags table for flexible tagging
- prompt_test_cases table for regression testing
- prompt_audit_log table for append-only audit trail
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision = '020'
down_revision = '019'
branch_labels = None
depends_on = None


def upgrade():
    """Add prompt management tables."""

    # =========================================================================
    # Create sequences
    # =========================================================================
    op.execute("CREATE SEQUENCE IF NOT EXISTS prompts_api_id_seq")

    # =========================================================================
    # prompts — Central registry of all managed AI prompts
    # =========================================================================
    op.create_table(
        'prompts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column('api_id', sa.Integer, sa.Sequence('prompts_api_id_seq'), unique=True),
        sa.Column('slug', sa.String(128), unique=True, nullable=False, index=True),
        sa.Column('name', sa.String(256), nullable=False),
        sa.Column('description', sa.Text),

        # Classification
        sa.Column('category', sa.String(64), nullable=False, index=True),
        sa.Column('subcategory', sa.String(64)),

        # Binding
        sa.Column('agent_id', sa.String(128), index=True),

        # Provider & Model targeting
        sa.Column('provider', sa.String(64)),
        sa.Column('model', sa.String(128)),

        # State
        sa.Column('current_version', sa.Integer, nullable=False, server_default='1'),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true', index=True),
        sa.Column('is_locked', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('locked_by', sa.String(255)),
        sa.Column('locked_reason', sa.Text),

        # Migration tracking
        sa.Column('source_file', sa.String(512)),
        sa.Column('source_line', sa.Integer),

        # Audit
        sa.Column('created_by', sa.String(255)),
        sa.Column('updated_by', sa.String(255)),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
    )

    # =========================================================================
    # prompt_versions — Immutable version history (append-only)
    # =========================================================================
    op.create_table(
        'prompt_versions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column('prompt_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('prompts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('version', sa.Integer, nullable=False),

        # Content
        sa.Column('content', sa.Text, nullable=False),
        sa.Column('system_message', sa.Text),

        # LLM parameters
        sa.Column('parameters', postgresql.JSONB, server_default='{}'),

        # Model override (version-level)
        sa.Column('model', sa.String(128)),

        # Schema definitions
        sa.Column('input_schema', postgresql.JSONB),
        sa.Column('output_schema', postgresql.JSONB),

        # Change tracking
        sa.Column('change_summary', sa.Text),

        # Audit
        sa.Column('created_by', sa.String(255)),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),

        sa.UniqueConstraint('prompt_id', 'version', name='uq_prompt_version'),
    )
    op.create_index('idx_prompt_versions_lookup', 'prompt_versions', ['prompt_id', 'version'])

    # =========================================================================
    # prompt_usages — Runtime usage tracking and metrics
    # =========================================================================
    op.create_table(
        'prompt_usages',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column('prompt_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('prompts.id', ondelete='CASCADE'), nullable=False),

        # Where it's used
        sa.Column('usage_type', sa.String(64), nullable=False),
        sa.Column('location', sa.String(512), nullable=False),
        sa.Column('description', sa.Text),
        sa.Column('is_primary', sa.Boolean, server_default='false'),

        # Runtime metrics
        sa.Column('last_called_at', sa.DateTime),
        sa.Column('call_count', sa.BigInteger, server_default='0'),
        sa.Column('avg_latency_ms', sa.Integer),
        sa.Column('avg_tokens_in', sa.Integer),
        sa.Column('avg_tokens_out', sa.Integer),
        sa.Column('total_tokens', sa.BigInteger, server_default='0'),
        sa.Column('error_count', sa.BigInteger, server_default='0'),

        # Model tracking
        sa.Column('last_model_used', sa.String(128)),
        sa.Column('last_provider_used', sa.String(64)),

        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('idx_prompt_usages_prompt', 'prompt_usages', ['prompt_id'])
    op.create_index('idx_prompt_usages_type', 'prompt_usages', ['usage_type'])

    # =========================================================================
    # prompt_tags — Flexible tagging
    # =========================================================================
    op.create_table(
        'prompt_tags',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column('prompt_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('prompts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('tag', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),

        sa.UniqueConstraint('prompt_id', 'tag', name='uq_prompt_tag'),
    )
    op.create_index('idx_prompt_tags_tag', 'prompt_tags', ['tag'])

    # =========================================================================
    # prompt_test_cases — Saved test inputs for regression testing
    # =========================================================================
    op.create_table(
        'prompt_test_cases',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column('prompt_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('prompts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('name', sa.String(256), nullable=False),
        sa.Column('input_data', postgresql.JSONB, nullable=False),
        sa.Column('expected_output', sa.Text),
        sa.Column('notes', sa.Text),
        sa.Column('created_by', sa.String(255)),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )

    # =========================================================================
    # prompt_audit_log — Immutable, append-only audit trail
    # =========================================================================
    op.create_table(
        'prompt_audit_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column('action', sa.String(64), nullable=False),
        sa.Column('prompt_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('prompt_slug', sa.String(128), nullable=False),
        sa.Column('version', sa.Integer),

        sa.Column('user_id', sa.String(255)),
        sa.Column('user_email', sa.String(256)),

        sa.Column('old_value', postgresql.JSONB),
        sa.Column('new_value', postgresql.JSONB),

        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.Text),

        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
    )
    op.create_index('idx_prompt_audit_prompt', 'prompt_audit_log', ['prompt_id'])
    op.create_index('idx_prompt_audit_user', 'prompt_audit_log', ['user_id'])
    op.create_index('idx_prompt_audit_action', 'prompt_audit_log', ['action'])
    op.create_index('idx_prompt_audit_created', 'prompt_audit_log', ['created_at'])


def downgrade():
    """Remove prompt management tables."""
    op.drop_table('prompt_audit_log')
    op.drop_table('prompt_test_cases')
    op.drop_table('prompt_tags')
    op.drop_table('prompt_usages')
    op.drop_table('prompt_versions')
    op.drop_table('prompts')
    op.execute("DROP SEQUENCE IF EXISTS prompts_api_id_seq")

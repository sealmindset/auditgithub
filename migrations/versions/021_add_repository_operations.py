"""Add repository operations context tables

Revision ID: 021
Revises: 020
Create Date: 2026-03-08

Implements:
- repository_operations table for deployment, hosting, compliance, and infrastructure metadata
- repository_ops_discoveries table for AI discovery run history
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision = '021'
down_revision = '020'
branch_labels = None
depends_on = None


def upgrade():
    """Add repository operations context tables."""

    # =========================================================================
    # Create sequences
    # =========================================================================
    op.execute("CREATE SEQUENCE IF NOT EXISTS repository_operations_api_id_seq")
    op.execute("CREATE SEQUENCE IF NOT EXISTS repository_ops_discoveries_api_id_seq")

    # =========================================================================
    # repository_operations — 1:1 operations context per repository
    # =========================================================================
    op.create_table(
        'repository_operations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column('api_id', sa.Integer, sa.Sequence('repository_operations_api_id_seq'), unique=True),
        sa.Column('repository_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('repositories.id', ondelete='CASCADE'), nullable=False, unique=True),

        # Deployment Status
        sa.Column('deployment_status', sa.String(32), server_default='unknown'),
        sa.Column('deployment_status_notes', sa.Text),

        # Environment URLs (JSONB array of {name, url, is_primary})
        sa.Column('environment_urls', postgresql.JSONB, server_default='[]'),

        # Hosting & Platform
        sa.Column('hosting_platform', sa.String(64)),
        sa.Column('hosting_detail', sa.Text),
        sa.Column('deployment_method', sa.String(64)),
        sa.Column('deployment_method_detail', sa.Text),

        # Team & Ownership
        sa.Column('team_owner', sa.String(256)),
        sa.Column('team_contact_email', sa.String(256)),
        sa.Column('team_slack_channel', sa.String(256)),

        # Business Criticality
        sa.Column('business_criticality', sa.String(32), server_default='medium'),
        sa.Column('business_criticality_notes', sa.Text),

        # Compliance & Governance
        sa.Column('compliance_frameworks', postgresql.JSONB, server_default='[]'),
        sa.Column('data_classification', sa.String(32)),
        sa.Column('regulatory_notes', sa.Text),
        sa.Column('last_compliance_audit_at', sa.DateTime(timezone=True)),

        # Infrastructure
        sa.Column('cicd_platform', sa.String(64)),
        sa.Column('cicd_pipeline_url', sa.Text),
        sa.Column('container_registry', sa.String(128)),
        sa.Column('iac_type', sa.String(64)),
        sa.Column('iac_path', sa.Text),
        sa.Column('monitoring_url', sa.Text),
        sa.Column('alerting_url', sa.Text),
        sa.Column('logging_url', sa.Text),

        # AI Discovery
        sa.Column('last_discovery_at', sa.DateTime(timezone=True)),
        sa.Column('last_discovery_status', sa.String(32)),
        sa.Column('discovery_confidence', sa.Numeric(3, 2)),

        # Metadata
        sa.Column('custom_metadata', postgresql.JSONB, server_default='{}'),
        sa.Column('notes', sa.Text),

        sa.Column('created_by', sa.String(256)),
        sa.Column('updated_by', sa.String(256)),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('idx_repo_ops_repository', 'repository_operations', ['repository_id'])
    op.create_index('idx_repo_ops_status', 'repository_operations', ['deployment_status'])
    op.create_index('idx_repo_ops_platform', 'repository_operations', ['hosting_platform'])
    op.create_index('idx_repo_ops_criticality', 'repository_operations', ['business_criticality'])

    # =========================================================================
    # repository_ops_discoveries — AI discovery run history
    # =========================================================================
    op.create_table(
        'repository_ops_discoveries',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column('api_id', sa.Integer, sa.Sequence('repository_ops_discoveries_api_id_seq'), unique=True),
        sa.Column('repository_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('repositories.id', ondelete='CASCADE'), nullable=False),

        sa.Column('status', sa.String(32), nullable=False, server_default='pending'),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),

        # AI results
        sa.Column('suggestions', postgresql.JSONB, server_default='[]'),
        sa.Column('evidence_files', postgresql.JSONB, server_default='[]'),
        sa.Column('raw_ai_response', sa.Text),

        # Metadata
        sa.Column('triggered_by', sa.String(256)),
        sa.Column('error_message', sa.Text),
        sa.Column('tokens_used', sa.Integer),

        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index('idx_repo_ops_disc_repository', 'repository_ops_discoveries', ['repository_id'])
    op.create_index('idx_repo_ops_disc_status', 'repository_ops_discoveries', ['status'])


def downgrade():
    """Remove repository operations context tables."""
    op.drop_table('repository_ops_discoveries')
    op.drop_table('repository_operations')
    op.execute("DROP SEQUENCE IF EXISTS repository_ops_discoveries_api_id_seq")
    op.execute("DROP SEQUENCE IF EXISTS repository_operations_api_id_seq")

"""Add API key management tables

Revision ID: 019
Revises: 018
Create Date: 2026-02-26

Implements:
- api_keys table for API key storage and scoping
- api_key_audit_log table for key lifecycle events
- is_service_account column on users table
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# Revision identifiers
revision = '019'
down_revision = '018'
branch_labels = None
depends_on = None


def upgrade():
    """Add API key management tables and fields."""

    # =========================================================================
    # Create sequences
    # =========================================================================
    op.execute("CREATE SEQUENCE IF NOT EXISTS api_keys_api_id_seq")
    op.execute("CREATE SEQUENCE IF NOT EXISTS api_key_audit_log_api_id_seq")

    # =========================================================================
    # api_keys table
    # =========================================================================
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column('api_id', sa.Integer, sa.Sequence('api_keys_api_id_seq'), unique=True),

        # Ownership
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),

        # Key identity
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('key_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('key_prefix', sa.String(12), nullable=False),

        # Tool scoping (hierarchical)
        sa.Column('allowed_tool_categories', postgresql.JSONB, nullable=True),
        sa.Column('allowed_tools', postgresql.JSONB, nullable=True),

        # Repository scoping
        sa.Column('allowed_repository_ids', postgresql.JSONB, nullable=True),

        # RBAC override
        sa.Column('permission_overrides', postgresql.JSONB, nullable=True),

        # Rate limiting
        sa.Column('rate_limit_per_hour', sa.Integer, nullable=False, server_default='1000'),

        # Lifecycle
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_ip', sa.String(45), nullable=True),

        # Timestamps
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),

        # Foreign keys
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),

        # Constraints
        sa.UniqueConstraint('user_id', 'organization_id', 'name', name='uq_api_keys_user_name'),
    )

    # Indexes for api_keys
    op.create_index('idx_api_keys_key_hash', 'api_keys', ['key_hash'])
    op.create_index('idx_api_keys_user_id', 'api_keys', ['user_id'])
    op.create_index('idx_api_keys_org_id', 'api_keys', ['organization_id'])
    op.create_index('idx_api_keys_active', 'api_keys', ['is_active'], postgresql_where=sa.text('is_active = true'))
    op.create_index('idx_api_keys_expires', 'api_keys', ['expires_at'], postgresql_where=sa.text('expires_at IS NOT NULL'))

    # =========================================================================
    # api_key_audit_log table
    # =========================================================================
    op.create_table(
        'api_key_audit_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column('api_id', sa.Integer, sa.Sequence('api_key_audit_log_api_id_seq'), unique=True),

        sa.Column('api_key_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('actor_user_id', postgresql.UUID(as_uuid=True), nullable=True),

        sa.Column('event_type', sa.String(50), nullable=False),
        sa.Column('event_detail', postgresql.JSONB, server_default='{}'),

        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),

        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),

        sa.ForeignKeyConstraint(['api_key_id'], ['api_keys.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ondelete='SET NULL'),
    )

    # Indexes for api_key_audit_log
    op.create_index('idx_api_key_audit_key', 'api_key_audit_log', ['api_key_id'])
    op.create_index('idx_api_key_audit_type', 'api_key_audit_log', ['event_type'])
    op.create_index('idx_api_key_audit_created', 'api_key_audit_log', ['created_at'])

    # =========================================================================
    # Add is_service_account to users table
    # =========================================================================
    op.add_column('users', sa.Column('is_service_account', sa.Boolean, nullable=False, server_default='false'))


def downgrade():
    """Remove API key management tables and fields."""

    # Drop column from users
    op.drop_column('users', 'is_service_account')

    # Drop tables
    op.drop_table('api_key_audit_log')
    op.drop_table('api_keys')

    # Drop sequences
    op.execute("DROP SEQUENCE IF EXISTS api_key_audit_log_api_id_seq")
    op.execute("DROP SEQUENCE IF EXISTS api_keys_api_id_seq")

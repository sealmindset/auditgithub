"""Add device flow tables

Revision ID: 017
Revises: 016
Create Date: 2025-02-04

Implements OAuth 2.0 Device Authorization Grant Flow (RFC 8628)
for CLI/device authentication with browser-based OIDC login.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# Revision identifiers
revision = '017'
down_revision = '016'
branch_labels = None
depends_on = None


def upgrade():
    """Create device flow tables."""

    # =========================================================================
    # DeviceFlowRequest - Temporary device authorization requests
    # =========================================================================
    op.create_table(
        'device_flow_requests',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('api_id', sa.Integer, sa.Sequence('device_flow_requests_api_id_seq'), unique=True),
        sa.Column('device_code', sa.String(128), nullable=False, unique=True),
        sa.Column('user_code', sa.String(9), nullable=False, unique=True),
        sa.Column('client_id', sa.String(255), nullable=False),
        sa.Column('client_name', sa.String(255), nullable=False),
        sa.Column('scopes', postgresql.JSONB, server_default='[]'),
        sa.Column('status', sa.String(20), server_default='pending'),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_sub', sa.String(255), nullable=True),
        sa.Column('user_email', sa.String(255), nullable=True),
        sa.Column('user_name', sa.String(255), nullable=True),
        sa.Column('provider', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_poll_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('poll_count', sa.Integer, server_default='0'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    )

    # Create indexes for device_flow_requests
    op.create_index('ix_device_flow_device_code', 'device_flow_requests', ['device_code'])
    op.create_index('ix_device_flow_user_code', 'device_flow_requests', ['user_code'])
    op.create_index('ix_device_flow_status', 'device_flow_requests', ['status'])
    op.create_index('ix_device_flow_expires_at', 'device_flow_requests', ['expires_at'])

    # =========================================================================
    # DeviceAuthorization - Persistent device authorization records
    # =========================================================================
    op.create_table(
        'device_authorizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('api_id', sa.Integer, sa.Sequence('device_authorizations_api_id_seq'), unique=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_sub', sa.String(255), nullable=False),
        sa.Column('user_email', sa.String(255), nullable=False),
        sa.Column('user_name', sa.String(255), nullable=False),
        sa.Column('provider', sa.String(50), nullable=False),
        sa.Column('device_name', sa.String(255), nullable=False),
        sa.Column('client_id', sa.String(255), nullable=False),
        sa.Column('client_name', sa.String(255), nullable=False),
        sa.Column('current_refresh_token_jti', sa.String(255), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('is_active', sa.Boolean, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_used_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_by', sa.String(255), nullable=True),
        sa.Column('revoked_reason', sa.Text, nullable=True),
        sa.Column('token_refresh_count', sa.Integer, server_default='0'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
    )

    # Create indexes for device_authorizations
    op.create_index('ix_device_auth_user_sub', 'device_authorizations', ['user_sub'])
    op.create_index('ix_device_auth_org_id', 'device_authorizations', ['organization_id'])
    op.create_index('ix_device_auth_active', 'device_authorizations', ['is_active'])


def downgrade():
    """Drop device flow tables."""

    # Drop indexes first
    op.drop_index('ix_device_auth_active', 'device_authorizations')
    op.drop_index('ix_device_auth_org_id', 'device_authorizations')
    op.drop_index('ix_device_auth_user_sub', 'device_authorizations')

    op.drop_index('ix_device_flow_expires_at', 'device_flow_requests')
    op.drop_index('ix_device_flow_status', 'device_flow_requests')
    op.drop_index('ix_device_flow_user_code', 'device_flow_requests')
    op.drop_index('ix_device_flow_device_code', 'device_flow_requests')

    # Drop tables
    op.drop_table('device_authorizations')
    op.drop_table('device_flow_requests')

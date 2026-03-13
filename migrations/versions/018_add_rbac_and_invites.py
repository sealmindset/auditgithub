"""Add RBAC and invitation system

Revision ID: 018
Revises: 017
Create Date: 2025-02-04

Implements:
- RBAC fields on users table
- UserInvitation table for email-based onboarding
- UserRepositoryAccess table for granular permissions
- AuthAuditLog table for security logging
- Bootstrap Super Admin accounts
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid
import bcrypt
import os

# Revision identifiers
revision = '018'
down_revision = '017'
branch_labels = None
depends_on = None


def upgrade():
    """Add RBAC system tables and fields."""

    # =========================================================================
    # Modify users table - add RBAC fields
    # =========================================================================

    # Add new columns to users table
    op.add_column('users', sa.Column('access_type', sa.String(), server_default='both'))
    op.add_column('users', sa.Column('local_password_hash', sa.String(), nullable=True))
    op.add_column('users', sa.Column('entra_id_object_id', sa.String(), nullable=True))
    op.add_column('users', sa.Column('entra_id_upn', sa.String(), nullable=True))
    op.add_column('users', sa.Column('auth_provider', sa.String(), server_default='entra'))
    op.add_column('users', sa.Column('is_invited', sa.Boolean(), server_default='false'))
    op.add_column('users', sa.Column('first_login_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('users', sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now()))

    # Update role column to have default and NOT NULL
    op.alter_column('users', 'role', server_default='user', nullable=False)

    # Create unique index on entra_id_object_id
    op.create_index('ix_users_entra_id_object_id', 'users', ['entra_id_object_id'], unique=True)

    # =========================================================================
    # user_invitations table
    # =========================================================================
    op.create_table(
        'user_invitations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('api_id', sa.Integer, sa.Sequence('user_invitations_api_id_seq'), unique=True),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('invite_token', sa.String(64), nullable=False, unique=True),
        sa.Column('invited_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('invited_role', sa.String(), nullable=False, server_default='user'),
        sa.Column('invited_access_type', sa.String(), nullable=False, server_default='ui_only'),
        sa.Column('status', sa.String(), server_default='pending'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('accepted_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['invited_by'], ['users.id']),
    )

    # Indexes for user_invitations
    op.create_index('ix_user_invitations_email', 'user_invitations', ['email'])
    op.create_index('ix_user_invitations_token', 'user_invitations', ['invite_token'], unique=True)
    op.create_index('ix_user_invitations_status', 'user_invitations', ['status'])

    # =========================================================================
    # user_repository_access table
    # =========================================================================
    op.create_table(
        'user_repository_access',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('api_id', sa.Integer, sa.Sequence('user_repository_access_api_id_seq'), unique=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('repository_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('assigned_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['assigned_by'], ['users.id']),
    )

    # Indexes for user_repository_access
    op.create_index('ix_user_repo_access_user_id', 'user_repository_access', ['user_id'])
    op.create_index('ix_user_repo_access_repo_id', 'user_repository_access', ['repository_id'])
    op.create_index('ix_user_repo_access_org_id', 'user_repository_access', ['organization_id'])

    # Unique constraint
    op.create_constraint('uq_user_repo_access', 'user_repository_access', ['user_id', 'repository_id'], type_='unique')

    # =========================================================================
    # auth_audit_log table
    # =========================================================================
    op.create_table(
        'auth_audit_log',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('api_id', sa.Integer, sa.Sequence('auth_audit_log_api_id_seq'), unique=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('event_type', sa.String(), nullable=False),
        sa.Column('auth_method', sa.String(), nullable=True),
        sa.Column('success', sa.Boolean(), server_default='true'),
        sa.Column('failure_reason', sa.String(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('is_break_glass', sa.Boolean(), server_default='false'),
        sa.Column('extra_data', postgresql.JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
    )

    # Indexes for auth_audit_log
    op.create_index('ix_auth_audit_log_email', 'auth_audit_log', ['email'])
    op.create_index('ix_auth_audit_log_user_id', 'auth_audit_log', ['user_id'])
    op.create_index('ix_auth_audit_log_event_type', 'auth_audit_log', ['event_type'])
    op.create_index('ix_auth_audit_log_created_at', 'auth_audit_log', ['created_at'])

    # =========================================================================
    # Bootstrap Super Admin accounts
    # =========================================================================

    # Get password from environment or use default
    break_glass_password = os.getenv('BREAK_GLASS_PASSWORD', 'ChangeMe123!')
    password_hash = bcrypt.hashpw(break_glass_password.encode(), bcrypt.gensalt()).decode()

    # Create admin@example.com with break glass password
    op.execute(f"""
        INSERT INTO users (
            id, username, email, full_name, role, access_type,
            local_password_hash, auth_provider, is_active, created_at
        )
        SELECT
            gen_random_uuid(),
            'break-glass-admin',
            'admin@example.com',
            'Break Glass Admin',
            'super_admin',
            'both',
            '{password_hash}',
            'local',
            true,
            NOW()
        WHERE NOT EXISTS (
            SELECT 1 FROM users WHERE email = 'admin@example.com'
        );
    """)

    # Create admin@company.example (Entra ID)
    op.execute("""
        INSERT INTO users (
            id, username, email, full_name, role, access_type,
            auth_provider, is_active, created_at
        )
        SELECT
            gen_random_uuid(),
            'entra-admin',
            'admin@company.example',
            'Entra Admin',
            'super_admin',
            'both',
            'entra',
            true,
            NOW()
        WHERE NOT EXISTS (
            SELECT 1 FROM users WHERE email = 'admin@company.example'
        );
    """)


def downgrade():
    """Remove RBAC system tables and fields."""

    # Drop tables
    op.drop_table('auth_audit_log')
    op.drop_table('user_repository_access')
    op.drop_table('user_invitations')

    # Drop indexes from users table
    op.drop_index('ix_users_entra_id_object_id', 'users')

    # Remove columns from users table
    op.drop_column('users', 'updated_at')
    op.drop_column('users', 'first_login_at')
    op.drop_column('users', 'is_invited')
    op.drop_column('users', 'auth_provider')
    op.drop_column('users', 'entra_id_upn')
    op.drop_column('users', 'entra_id_object_id')
    op.drop_column('users', 'local_password_hash')
    op.drop_column('users', 'access_type')

    # Revert role column changes
    op.alter_column('users', 'role', server_default=None, nullable=True)

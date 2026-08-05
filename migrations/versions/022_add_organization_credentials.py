"""Add organization_credentials table

Revision ID: 022
Revises: 021
Create Date: 2026-08-05

Implements:
- organization_credentials table so AuditGithub owns its GitHub and Microsoft Graph
  credentials instead of reading them from the operator's process environment
- Recorded privilege level and known access gaps per credential, so a hunt can state
  which surfaces it was not permitted to see rather than reporting a silent zero
- Partial unique index for tenant-wide credentials (organization_id IS NULL), which
  the table-level UNIQUE constraint cannot cover because Postgres treats NULLs as
  distinct

Secret values are Fernet ciphertext written by src/api/secrets_store.py. This
migration creates no secrets and does not migrate any existing environment values —
that is a deliberate operator action, performed through the credentials API.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# Revision identifiers
revision = '022'
down_revision = '021'
branch_labels = None
depends_on = None


def upgrade():
    """Create the organization_credentials table."""

    op.execute("CREATE SEQUENCE IF NOT EXISTS organization_credentials_api_id_seq")

    op.create_table(
        'organization_credentials',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column('api_id', sa.Integer,
                  sa.Sequence('organization_credentials_api_id_seq'), unique=True),

        # NULL = tenant-wide (the Graph application credential), not per-org
        sa.Column('organization_id', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=True),

        sa.Column('credential_type', sa.String(64), nullable=False),
        sa.Column('name', sa.String(128), nullable=False, server_default='default'),
        sa.Column('description', sa.Text),

        # Fernet ciphertext, prefixed "enc:v1:"
        sa.Column('encrypted_value', sa.Text),
        sa.Column('is_encrypted', sa.Boolean, nullable=False, server_default=sa.text('true')),
        sa.Column('key_fingerprint', sa.String(32)),

        # Non-secret identifiers, kept plaintext so the UI need not decrypt to
        # display which application is configured
        sa.Column('client_id', sa.String(128)),
        sa.Column('tenant_id_value', sa.String(128)),

        # Recorded privilege, not inferred privilege
        sa.Column('privilege_level', sa.String(64), server_default='unknown'),
        sa.Column('scopes', postgresql.JSONB, server_default='[]'),
        sa.Column('known_gaps', postgresql.JSONB, server_default='[]'),

        # Length and suffix only — never the value
        sa.Column('value_length', sa.Integer),
        sa.Column('value_suffix', sa.String(8)),

        sa.Column('expires_at', sa.DateTime, nullable=True),
        sa.Column('last_verified_at', sa.DateTime, nullable=True),
        sa.Column('last_verification_status', sa.String(32), server_default='unverified'),
        sa.Column('last_verification_detail', sa.Text),

        sa.Column('is_active', sa.Boolean, server_default=sa.text('true')),

        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True),
                  sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),

        sa.UniqueConstraint('organization_id', 'credential_type', 'name',
                            name='uq_org_credential'),
    )

    op.create_index('idx_org_credentials_org', 'organization_credentials', ['organization_id'])
    op.create_index('idx_org_credentials_type', 'organization_credentials', ['credential_type'])

    # Postgres treats NULL as distinct in a UNIQUE constraint, so uq_org_credential
    # would permit unlimited duplicate tenant-wide rows. A partial index closes that.
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_global_credential
        ON organization_credentials (credential_type, name)
        WHERE organization_id IS NULL
    """)


def downgrade():
    """Drop the organization_credentials table.

    Destructive: stored credentials are Fernet ciphertext and are not recoverable
    from anywhere else. Re-entering them after a downgrade means re-issuing or
    re-collecting every token.
    """
    op.execute("DROP INDEX IF EXISTS uq_global_credential")
    op.drop_index('idx_org_credentials_type', table_name='organization_credentials')
    op.drop_index('idx_org_credentials_org', table_name='organization_credentials')
    op.drop_table('organization_credentials')
    op.execute("DROP SEQUENCE IF EXISTS organization_credentials_api_id_seq")

-- Migration 018: Add OIDC/RBAC columns to users table
-- These columns are required by the SQLAlchemy User model for OIDC authentication,
-- break glass login, and RBAC access control.
--
-- Backup: backups/backup_before_users_access_type.dump
-- Restore: pg_restore -U postgres -d security_portal backups/backup_before_users_access_type.dump

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS access_type VARCHAR NOT NULL DEFAULT 'both',
  ADD COLUMN IF NOT EXISTS local_password_hash VARCHAR,
  ADD COLUMN IF NOT EXISTS oidc_subject VARCHAR,
  ADD COLUMN IF NOT EXISTS oidc_issuer VARCHAR,
  ADD COLUMN IF NOT EXISTS entra_id_object_id VARCHAR,
  ADD COLUMN IF NOT EXISTS entra_id_upn VARCHAR,
  ADD COLUMN IF NOT EXISTS auth_provider VARCHAR DEFAULT 'entra',
  ADD COLUMN IF NOT EXISTS is_invited BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS first_login_at TIMESTAMP,
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT now(),
  ADD COLUMN IF NOT EXISTS is_service_account BOOLEAN DEFAULT false;

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_oidc_subject
  ON users (oidc_subject) WHERE oidc_subject IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS ix_users_entra_id_object_id
  ON users (entra_id_object_id) WHERE entra_id_object_id IS NOT NULL;

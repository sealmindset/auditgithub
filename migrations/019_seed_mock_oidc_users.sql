-- Migration 019: Seed mock-oidc user accounts for development
-- These accounts match the users defined in the mock-oidc service.
-- OIDC subject (sub) values match exactly so login works without invitations.

INSERT INTO users (username, email, full_name, role, access_type, auth_provider, oidc_subject, oidc_issuer, is_active, is_invited, created_at, updated_at)
VALUES
  ('break-glass-admin', 'admin@example.com', 'Break Glass Admin (Super Admin)', 'super_admin', 'both', 'mock-oidc', 'mock-super-admin', 'http://host.docker.internal:3007', true, false, now(), now()),
  ('entra-admin', 'admin@company.example', 'Entra Admin', 'admin', 'both', 'mock-oidc', 'mock-admin', 'http://host.docker.internal:3007', true, false, now(), now()),
  ('superadmin-zapper', 'superadmin@zapper.local', 'Super Admin', 'super_admin', 'both', 'mock-oidc', 'mock-superadmin-zapper', 'http://host.docker.internal:3007', true, false, now(), now()),
  ('admin-zapper', 'admin@zapper.local', 'Mock Admin', 'admin', 'both', 'mock-oidc', 'mock-admin-zapper', 'http://host.docker.internal:3007', true, false, now(), now()),
  ('manager-auditgithub', 'manager@auditgithub.local', 'Mock Manager', 'manager', 'both', 'mock-oidc', 'mock-manager', 'http://host.docker.internal:3007', true, false, now(), now()),
  ('analyst-auditgithub', 'analyst@auditgithub.local', 'Mock Analyst', 'analyst', 'both', 'mock-oidc', 'mock-analyst', 'http://host.docker.internal:3007', true, false, now(), now()),
  ('analyst-zapper', 'analyst@zapper.local', 'Mock Analyst (Zapper)', 'analyst', 'both', 'mock-oidc', 'mock-analyst-zapper', 'http://host.docker.internal:3007', true, false, now(), now()),
  ('user-auditgithub', 'user@auditgithub.local', 'Mock User', 'user', 'both', 'mock-oidc', 'mock-user', 'http://host.docker.internal:3007', true, false, now(), now()),
  ('user-zapper', 'user@zapper.local', 'Mock User (Zapper)', 'user', 'both', 'mock-oidc', 'mock-user-zapper', 'http://host.docker.internal:3007', true, false, now(), now())
ON CONFLICT (email) DO NOTHING;

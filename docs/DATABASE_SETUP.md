# Database Setup Guide

Complete guide for initializing the AuditGH database from scratch.

---

## Quick Start (TL;DR)

```bash
# 1. Start database
docker-compose up -d db && sleep 5

# 2. Apply schema and all migrations
docker-compose exec -T db psql -U postgres -d auditgh_kb < setup/schema.sql
for f in migrations/*.sql; do docker-compose exec -T db psql -U postgres -d auditgh_kb < "$f"; done

# 3. Start API and UI
docker-compose up -d api web-ui

# 4. Run your first scan
docker-compose run --rm --entrypoint bash auditgh -c 'python3 scan_repos.py --target YOUR_ORG'
```

---

## Configuration Reference

| Setting | Value | Source |
|---------|-------|--------|
| Database Name | `auditgh_kb` | `.env`, `docker-compose.yml` |
| Database User | `postgres` | `.env`, `docker-compose.yml` |
| Database Password | `postgres` | `.env`, `docker-compose.yml` |
| Database Host | `db` (container) / `localhost` (host) | `docker-compose.yml` |
| Database Port | `5432` | `docker-compose.yml` |

---

## Prerequisites

1. **Docker and Docker Compose** installed
2. **`.env` file** configured (copy from `.env.example` if needed)
3. **GitHub credentials** set in `.env`:
   ```bash
   GITHUB_TOKEN=ghp_your_token_here
   GITHUB_ORG=your-github-org
   ```

---

## Step 1: Start Fresh Database

Reset and start the database container:

```bash
# Remove existing data (if any) and start fresh
docker-compose down && docker volume rm auditgithub_postgres-data 2>/dev/null
docker-compose up -d db && sleep 5
```

Verify the database was created:

```bash
docker-compose exec -T db psql -U postgres -d postgres -c "SELECT datname FROM pg_database WHERE datname NOT IN ('template0','template1','postgres');"
```

**Expected output:**
```
  datname   
------------
 auditgh_kb
(1 row)
```

---

## Step 2: Apply Base Schema

Load the core schema:

```bash
docker-compose exec -T db psql -U postgres -d auditgh_kb < setup/schema.sql
```

---

## Step 3: Apply All Migrations

Apply all migrations in one command:

```bash
for f in migrations/*.sql; do 
  echo "Applying $f..."
  docker-compose exec -T db psql -U postgres -d auditgh_kb < "$f"
done
```

Or apply individually in order:

```bash
for f in migrations/001_sync_schema.sql \
         migrations/002_organizations.sql \
         migrations/003_credential_url_test_results.sql \
         migrations/004_fix_multi_tenant_repositories.sql \
         migrations/005_mobile_go_scanners.sql \
         migrations/006_ensure_all_tables.sql; do
  echo "Applying $f..."
  docker-compose exec -T db psql -U postgres -d auditgh_kb < "$f"
done
```

### Migration Summary

| Migration | Purpose |
|-----------|---------|
| `001_sync_schema.sql` | Sync remediations, api_endpoints, openapi_specs |
| `002_organizations.sql` | Multi-organization support tables |
| `003_credential_url_test_results.sql` | AI Credential-URL testing |
| `004_fix_multi_tenant_repositories.sql` | Add organization_id to all tables |
| `005_mobile_go_scanners.sql` | MobSF and gosec scanner support |
| `006_ensure_all_tables.sql` | **Catch-all** - ensures all tables exist (safe to re-run) |

> **Note:** Migration 006 is comprehensive and can fix most schema issues. If you encounter missing table errors, run it again.

---

## Step 4: Organizations (Auto-Created)

**Organizations are NOT pre-populated in migrations.** They are created dynamically when:

1. **From Environment Variables**: When the API starts, it reads `GITHUB_TOKEN`/`GITHUB_ORG` and `ORG_{NAME}_TOKEN`/`ORG_{NAME}_GITHUB` patterns from `.env` and auto-registers organizations.

2. **Via CLI**: Run `python3 scan_repos.py --create-org NAME --github-org ORG --token TOKEN`

### To Start with No Organizations

If you want a completely empty organization list:
1. Comment out or remove `GITHUB_TOKEN` and `GITHUB_ORG` from `.env`
2. Remove any `ORG_*_TOKEN` and `ORG_*_GITHUB` entries from `.env`
3. Restart the API: `docker-compose restart api`

### To Add Organizations

Add credentials to `.env`:
```bash
# Primary organization
GITHUB_TOKEN=ghp_your_token_here
GITHUB_ORG=your-github-org

# Additional organization (optional)
ORG_ACME_TOKEN=ghp_acme_token_here
ORG_ACME_GITHUB=acme-corp
```

Then restart the API to auto-register them.

---

## Step 5: Create Additional Tables (Optional)

> **Note:** Migration 006 now creates all required tables. This section is only needed if you're running an older setup.

The API models require additional tables not in the base schema:

```bash
docker-compose exec -T db psql -U postgres -d auditgh_kb << 'EOF'
-- Contributors table
CREATE TABLE IF NOT EXISTS contributors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    repository_id UUID REFERENCES repositories(id),
    organization_id UUID REFERENCES organizations(id),
    username VARCHAR(255),
    email VARCHAR(255),
    name VARCHAR(255),
    avatar_url TEXT,
    contributions INTEGER DEFAULT 0,
    first_commit_at TIMESTAMP,
    last_commit_at TIMESTAMP,
    is_external BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_contributors_repo ON contributors(repository_id);
CREATE INDEX IF NOT EXISTS idx_contributors_org ON contributors(organization_id);

-- Language stats table
CREATE TABLE IF NOT EXISTS language_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    repository_id UUID REFERENCES repositories(id),
    organization_id UUID REFERENCES organizations(id),
    language VARCHAR(100),
    bytes BIGINT,
    percentage DECIMAL(5,2),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_language_stats_repo ON language_stats(repository_id);

-- Dependencies table
CREATE TABLE IF NOT EXISTS dependencies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    repository_id UUID REFERENCES repositories(id),
    organization_id UUID REFERENCES organizations(id),
    name VARCHAR(255),
    version VARCHAR(100),
    package_manager VARCHAR(50),
    is_dev BOOLEAN DEFAULT false,
    license VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dependencies_repo ON dependencies(repository_id);

-- API endpoints table
CREATE TABLE IF NOT EXISTS api_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    repository_id UUID REFERENCES repositories(id),
    organization_id UUID REFERENCES organizations(id),
    method VARCHAR(10),
    path TEXT,
    handler VARCHAR(255),
    file_path TEXT,
    line_number INTEGER,
    auth_required BOOLEAN,
    parameters JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_endpoints_repo ON api_endpoints(repository_id);

-- OpenAPI specs table
CREATE TABLE IF NOT EXISTS openapi_specs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    repository_id UUID REFERENCES repositories(id),
    organization_id UUID REFERENCES organizations(id),
    spec_content JSONB,
    version VARCHAR(50),
    title VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_openapi_specs_repo ON openapi_specs(repository_id);

-- File commits table
CREATE TABLE IF NOT EXISTS file_commits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE,
    repository_id UUID REFERENCES repositories(id),
    organization_id UUID REFERENCES organizations(id),
    file_path TEXT,
    commit_sha VARCHAR(40),
    author VARCHAR(255),
    committed_at TIMESTAMP,
    message TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_file_commits_repo ON file_commits(repository_id);
EOF
```

---

## Step 4: Sync Organization Schemas

The `--sync-schemas` command creates per-organization databases and applies the schema:

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --sync-schemas'
```

**Expected output:**
```
[AIOrganizationAgent] Syncing all organization schemas...
[AIOrganizationAgent] Syncing schema for: example-org
[AIOrganizationAgent] Applying master schema to: auditgh_kb
[AIOrganizationAgent] Schema applied via psycopg2 to: auditgh_kb
[AIOrganizationAgent] Syncing schema for: example-orglabs
[AIOrganizationAgent] Applying master schema to: auditgh_example_orglabs
[AIOrganizationAgent] Schema applied via psycopg2 to: auditgh_example_orglabs
[AIOrganizationAgent] Schema sync complete: 2 synced, 0 already synced, 0 errors

Results: 2 synced, 0 already synced, 0 errors
```

---

## Step 5: Verify Setup

List registered organizations to confirm everything is working:

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --list-orgs'
```

**Expected output:**
```
📋 Registered Organizations:
------------------------------------------------------------
  example-org (default)
    GitHub: example-org | DB: auditgh_kb
    Status: ✓ active | Schema: synced

  example-orglabs
    GitHub: example-orglabs | DB: auditgh_example_orglabs
    Status: ✓ active | Schema: synced

🔑 Organizations with credentials: example-org, example-orglabs
```

---

## Quick Setup (All-in-One)

For a fresh database, run all steps in sequence:

```bash
#!/bin/bash
# Fresh database setup script

# 1. Start database
docker-compose up -d db
sleep 5  # Wait for DB to be ready

# 2. Apply base schema
docker-compose exec -T db psql -U postgres -d auditgh_kb < setup/schema.sql

# 3. Apply migrations (in order)
for f in migrations/001_sync_schema.sql \
         migrations/002_organizations.sql \
         migrations/003_credential_url_test_results.sql \
         migrations/004_fix_multi_tenant_repositories.sql \
         migrations/005_mobile_go_scanners.sql \
         migrations/006_ensure_all_tables.sql; do
  echo "Applying $f..."
  docker-compose exec -T db psql -U postgres -d auditgh_kb < "$f"
done

# 4. Sync organization schemas
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --sync-schemas'

# 5. Verify
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --list-orgs'
```

---

## Database Architecture

After setup, you'll have:

| Database | Purpose |
|----------|---------|
| `auditgh_kb` | Master database with organizations table |
| `auditgh_kb` | example-org organization data |
| `auditgh_example_orglabs` | example-orglabs organization data |

Each organization database contains:
- `repositories` - Scanned repositories
- `scan_runs` - Scan execution history
- `findings` - Security findings
- `remediations` - AI-generated fixes
- And more...

---

## Troubleshooting

### "relation does not exist" errors during migration

These are normal during migration if tables don't exist yet. The `--sync-schemas` command handles dynamic table creation.

### "column schema_version does not exist" or similar organization errors

The `organizations` table may be missing columns required by the AI Organization Agent. This happens when migration `002_organizations.sql` wasn't fully applied.

**Fix:** Add all missing organization columns:

```bash
docker-compose exec -T db psql -U postgres -d auditgh_kb << 'EOF'
-- Add missing columns to organizations table
ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS database_schema VARCHAR(100) DEFAULT 'public',
ADD COLUMN IF NOT EXISTS schema_version VARCHAR(128),
ADD COLUMN IF NOT EXISTS schema_version_name VARCHAR(100) DEFAULT 'v1.0.0',
ADD COLUMN IF NOT EXISTS last_schema_sync TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS schema_sync_status VARCHAR(50) DEFAULT 'synced',
ADD COLUMN IF NOT EXISTS schema_sync_error TEXT,
ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS scan_status VARCHAR(50) DEFAULT 'idle',
ADD COLUMN IF NOT EXISTS scan_progress INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS current_scan_id UUID,
ADD COLUMN IF NOT EXISTS total_scans INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_repos INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_findings INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS description TEXT,
ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS created_by UUID;

SELECT 'Organizations table columns synchronized' as status;
EOF
```

### API crashes with "column X does not exist"

The SQLAlchemy models may have columns that don't exist in the database. This happens when models are updated but migrations aren't created.

**Fix:** Add missing columns to match the models:

```bash
docker-compose exec -T db psql -U postgres -d auditgh_kb << 'EOF'
-- Add missing columns to repositories
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'private';
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS is_private BOOLEAN DEFAULT true;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS is_fork BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS is_archived BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS pushed_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS github_created_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS github_updated_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS stargazers_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS forks_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS open_issues_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS watchers_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS size_kb INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS topics JSONB;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS license_name VARCHAR(100);
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS failure_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS last_failure_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS last_failure_reason VARCHAR;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS architecture_report TEXT;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS architecture_diagram TEXT;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS architecture_preprocessed TEXT;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_wiki BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_pages BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS has_discussions BOOLEAN DEFAULT false;

-- Add missing columns to findings
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_verified_by_scanner BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_validated_active BOOLEAN;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validation_message VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validated_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS investigation_status VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS investigation_started_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS investigation_resolved_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_score INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_factors JSONB;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS snooze_reason VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_started_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS remediation_completed_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_triage_recommendation VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_triage_confidence NUMERIC(3,2);
ALTER TABLE findings ADD COLUMN IF NOT EXISTS ai_triage_reasoning TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS duplicate_group_id UUID;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_primary_in_group BOOLEAN DEFAULT true;

-- Add missing columns to remediations
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS finding_id UUID REFERENCES findings(id);
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS diff TEXT;
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS confidence NUMERIC(3,2);

SELECT 'Schema columns synchronized' as status;
EOF
```

Then restart the API:
```bash
docker-compose restart api
```

### API crashes with "Foreign key could not find table 'organizations'"

The `Organization` model must be defined in `src/api/models.py`. If missing, the API won't start.

### Database connection refused

```bash
# Check if DB container is running
docker-compose ps db

# Check DB logs
docker-compose logs db
```

### Reset everything and start fresh

```bash
# Stop and remove containers + volumes
docker-compose down -v

# Start fresh
docker-compose up -d db
# Then follow steps 2-5 above
```

---

## Next Steps

After database setup:

1. **Run a dry-run scan:**
   ```bash
   docker-compose run --rm --entrypoint bash auditgh -c \
     'python3 scan_repos.py --target example-org --dry-run'
   ```

2. **Run actual scan:**
   ```bash
   docker-compose run --rm --entrypoint bash auditgh -c \
     'python3 scan_repos.py --target example-org'
   ```

3. **Access the Web UI:**
   - http://localhost:3000

---

[← Back to README](../README.md) | [Troubleshooting →](TROUBLESHOOTING.md)

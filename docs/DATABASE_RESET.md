# Database Reset & Backup Guide

This guide covers resetting organization data, managing backups, and restoring from backups.

## Overview

The reset process:
1. **Verifies** the organization exists
2. **Creates** a timestamped backup automatically
3. **Deletes** all organization data (respecting FK constraints)
4. **Resets** organization statistics
5. **Cleans up** expired backups (>30 days)

**⚠️ Important:** A backup is ALWAYS created before deletion and retained for 30 days.

---

## Reset Organization Data

### Using Docker Compose (Recommended)

```bash
# Reset with confirmation prompt
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --target sleepnumberlabs'

# Reset without confirmation (for automation)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --target sleepnumberlabs --force'
```

### Using scan_repos.py Flags

```bash
# Reset via scan_repos.py
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --reset-org --target sleepnumberlabs --reset-force'
```

### Running Locally (Without Docker)

```bash
# Direct script execution
python scripts/reset_organization_data.py --target sleepnumberlabs --force

# Via scan_repos.py
python scan_repos.py --reset-org --target sleepnumberlabs --reset-force
```

### Example Output

```
============================================================
Organization Reset: sleepnumberlabs
============================================================
Organization ID: 902d2572-4042-420f-9add-9e60f8683ac9
GitHub Org: sleepnumberlabs

Current Data:
  - repositories: 45 records
  - scan_runs: 89 records
  - findings: 12,543 records
  - dependencies: 234 records

Total records to delete: 12,911
============================================================

⚠️  WARNING: This will permanently delete all data for this organization!
A backup will be created and retained for 30 days.

Type 'sleepnumberlabs' to confirm reset: sleepnumberlabs

2024-01-15 10:30:00 - INFO - Creating backup for organization 'sleepnumberlabs'...
2024-01-15 10:30:05 - INFO - ✓ Backup created successfully
  - SQL file: backups/organizations/sleepnumberlabs_20240115_103000.sql
  - Metadata: backups/organizations/sleepnumberlabs_20240115_103000.json

2024-01-15 10:30:06 - INFO - Deleting data for organization 'sleepnumberlabs'...
  ✓ Deleted 0 rows from credential_url_test_status
  ✓ Deleted 0 rows from credential_url_test_results
  ✓ Deleted 0 rows from file_commits
  ✓ Deleted 0 rows from openapi_specs
  ✓ Deleted 0 rows from api_endpoints
  ✓ Deleted 234 rows from dependencies
  ✓ Deleted 0 rows from language_stats
  ✓ Deleted 0 rows from contributors
  ✓ Deleted 12543 rows from findings
  ✓ Deleted 89 rows from scan_runs
  ✓ Deleted 45 rows from repositories
  ✓ Reset organization stats

============================================================
✓ Organization 'sleepnumberlabs' has been reset successfully!
  Backup saved to: backups/organizations/sleepnumberlabs_20240115_103000.sql
  Backup will be retained for 30 days
============================================================
```

---

## Backup Management

### List All Backups

```bash
# Docker
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --list-backups'

# Or via scan_repos.py
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --list-backups'
```

### List Backups for Specific Organization

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --list-backups --target sleepnumberlabs'
```

### Example Backup List

```
================================================================================
Organization Backups (Retention: 30 days)
================================================================================

sleepnumberlabs
  Created: 2024-01-15T10:30:00
  Age: 2 days | Status: ✓ Active | File: ✓
  Stats: {'repositories': 45, 'findings': 12543, 'scan_runs': 89}
  File: backups/organizations/sleepnumberlabs_20240115_103000.sql

sleepnumberlabs
  Created: 2024-01-10T08:15:00
  Age: 7 days | Status: ✓ Active | File: ✓
  Stats: {'repositories': 42, 'findings': 11200, 'scan_runs': 85}
  File: backups/organizations/sleepnumberlabs_20240110_081500.sql

sealmindset
  Created: 2023-12-01T14:00:00
  Age: 47 days | Status: ⚠️ EXPIRED | File: ✓
  Stats: {'repositories': 60, 'findings': 22954, 'scan_runs': 119}
  File: backups/organizations/sealmindset_20231201_140000.sql

================================================================================
```

---

## Cleanup Old Backups

Backups older than 30 days are automatically cleaned up during reset. You can also run cleanup manually:

### Preview Cleanup (Dry Run)

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --cleanup-old-backups --dry-run'
```

### Execute Cleanup

```bash
# Via standalone script
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --cleanup-old-backups'

# Via scan_repos.py
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --cleanup-backups'
```

---

## Restore from Backup

### Restore Command

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --restore sleepnumberlabs \
    --backup-file backups/organizations/sleepnumberlabs_20240115_103000.sql'
```

### Manual Restore via psql

```bash
# Copy backup into container
docker cp backups/organizations/sleepnumberlabs_20240115_103000.sql \
  $(docker-compose ps -q db):/tmp/restore.sql

# Execute restore
docker-compose exec db psql -U postgres -d auditgh_kb -f /tmp/restore.sql
```

---

## Backup Details

### File Locations

| File Type | Location | Description |
|-----------|----------|-------------|
| SQL Backup | `backups/organizations/{org}_{timestamp}.sql` | Data export |
| Metadata | `backups/organizations/{org}_{timestamp}.json` | Stats and retention info |

### Backup Contents

The SQL backup contains CSV exports of all organization data:

```sql
-- Organization Data Backup
-- Organization: sleepnumberlabs
-- Organization ID: 902d2572-4042-420f-9add-9e60f8683ac9
-- Created: 2024-01-15T10:30:00
-- Retention: 30 days
-- Delete after: 2024-02-14T10:30:00

-- Table: repositories
-- Rows: 45
\COPY repositories FROM STDIN WITH CSV HEADER;
id,api_id,organization_id,name,full_name,url,...
902d...,1,902d...,api-service,sleepnumberlabs/api-service,...
\.

-- Table: findings
-- Rows: 12543
\COPY findings FROM STDIN WITH CSV HEADER;
...
```

### Metadata File

```json
{
  "organization_name": "sleepnumberlabs",
  "organization_id": "902d2572-4042-420f-9add-9e60f8683ac9",
  "created_at": "2024-01-15T10:30:00",
  "retention_days": 30,
  "delete_after": "2024-02-14T10:30:00",
  "stats": {
    "repositories": 45,
    "scan_runs": 89,
    "findings": 12543,
    "contributors": 0,
    "language_stats": 0,
    "dependencies": 234,
    "api_endpoints": 0,
    "openapi_specs": 0,
    "file_commits": 0
  },
  "backup_file": "backups/organizations/sleepnumberlabs_20240115_103000.sql"
}
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKUP_DIR` | `backups/organizations` | Backup storage directory |
| `BACKUP_RETENTION_DAYS` | `30` | Days to retain backups |
| `POSTGRES_DB` | `auditgh_kb` | Database name |
| `POSTGRES_USER` | `auditgh` | Database user |
| `POSTGRES_HOST` | `localhost` | Database host |
| `POSTGRES_PORT` | `5432` | Database port |

### Customize Retention

```bash
# Set custom retention (e.g., 90 days)
export BACKUP_RETENTION_DAYS=90

docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --target myorg --force'
```

---

## Common Workflows

### Reset + Fresh Scan

```bash
# Step 1: Reset the organization
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --target sleepnumberlabs --force'

# Step 2: Run fresh scan
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --target sleepnumberlabs'
```

### Weekly Cleanup Cron

```bash
# Add to crontab
0 2 * * 0 cd /path/to/auditgithub && docker-compose run --rm --entrypoint bash auditgh -c 'python scripts/reset_organization_data.py --cleanup-old-backups'
```

### Pre-Migration Backup

```bash
# Before applying schema changes
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --target sealmindset'
# (Don't confirm - just creates backup without deleting)
# Or use pg_dump directly:
docker-compose exec db pg_dump -U postgres auditgh_kb > backups/pre_migration_$(date +%Y%m%d).sql
```

---

## Troubleshooting

### "Organization not found"

```bash
# List available organizations
docker-compose run --rm --entrypoint bash auditgh -c 'python3 scan_repos.py --list-orgs'
```

### "Database connection failed"

Check database environment variables:
```bash
# Verify database is running
docker-compose ps db

# Test connection
docker-compose exec db psql -U postgres -d auditgh_kb -c "SELECT 1;"
```

### "Backup file not found"

```bash
# List actual backup files
ls -la backups/organizations/

# Check if backup directory exists
mkdir -p backups/organizations
```

### "Permission denied"

```bash
# Fix backup directory permissions
chmod 755 backups/organizations
```

### "column schema_version does not exist" or similar organization errors

The `organizations` table may be missing columns required by the AI Organization Agent.

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
EOF
```

### API crashes after restore with "column X does not exist"

After restoring from backup, the database schema may be out of sync with the current SQLAlchemy models. This happens when models have been updated since the backup was created.

**Fix:** Sync the schema columns:

```bash
docker-compose exec -T db psql -U postgres -d auditgh_kb << 'EOF'
-- Sync repositories columns
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS visibility VARCHAR(20) DEFAULT 'private';
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS is_disabled BOOLEAN DEFAULT false;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS is_private BOOLEAN DEFAULT true;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS pushed_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS github_created_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS github_updated_at TIMESTAMP;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS stargazers_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS forks_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS open_issues_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS failure_count INTEGER DEFAULT 0;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS architecture_report TEXT;
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS architecture_diagram TEXT;

-- Sync findings columns
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_verified_by_scanner BOOLEAN DEFAULT false;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS is_validated_active BOOLEAN;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS validated_at TIMESTAMP;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS investigation_status VARCHAR;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_score INTEGER;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS risk_factors JSONB;

-- Sync remediations columns
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS finding_id UUID REFERENCES findings(id);
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS diff TEXT;
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS confidence NUMERIC(3,2);
EOF

# Restart API to pick up changes
docker-compose restart api
```

> **Tip:** See [DATABASE_SETUP.md](DATABASE_SETUP.md#api-crashes-with-column-x-does-not-exist) for the complete list of columns.

---

## CLI Reference

### reset_organization_data.py

| Flag | Description |
|------|-------------|
| `--target, -t ORG` | Target organization name |
| `--force, -f` | Skip confirmation prompt |
| `--list-backups, -l` | List all backups |
| `--restore, -r ORG` | Restore organization from backup |
| `--backup-file, -b PATH` | Backup file for restore |
| `--cleanup-old-backups, -c` | Remove expired backups |
| `--dry-run` | Preview without changes |

### scan_repos.py Flags

| Flag | Description |
|------|-------------|
| `--reset-org` | Reset organization (use with --target) |
| `--reset-force` | Skip confirmation |
| `--list-backups` | List backups |
| `--cleanup-backups` | Remove expired backups |

---

[← Back to README](../README.md) | [AI Agents →](AI_AGENTS.md)

# AuditGH Restore Guide

Complete guide for restoring AuditGH data from backups, including organization-level restores, full database restores, and disaster recovery procedures.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Restore Types](#restore-types)
4. [Organization Restore](#organization-restore)
5. [Full Database Restore](#full-database-restore)
6. [Disaster Recovery](#disaster-recovery)
7. [Migration Scenarios](#migration-scenarios)
8. [Post-Restore Verification](#post-restore-verification)
9. [Troubleshooting](#troubleshooting)

---

## Overview

AuditGH supports multiple restore scenarios:

| Restore Type | Source | Use Case |
|--------------|--------|----------|
| **Organization Restore** | JSON backup | Restore single org, clone org, migrate between instances |
| **Full Database Restore** | SQL backup | Disaster recovery, complete system restore |
| **Selective Restore** | JSON backup | Restore specific data (findings, test results, etc.) |

### Restore Decision Tree

```
Need to restore data?
│
├─ Single organization? ──────────► Organization Restore (JSON)
│   ├─ Same org name? ────────────► Restore (update existing)
│   └─ Different org name? ───────► Restore as new org
│
├─ Multiple organizations? ───────► Loop through org restores
│
└─ Complete system restore? ──────► Full Database Restore (SQL)
```

---

## Prerequisites

### Before You Begin

1. **Verify backup file exists and is valid**
2. **Ensure sufficient disk space**
3. **Stop any running scans or tests**
4. **Notify users of potential downtime**

### Required Services

```bash
# Start required services
docker-compose up -d db

# Wait for database to be ready
sleep 10

# Verify database is running
docker-compose exec db pg_isready -U postgres
```

### Backup File Requirements

**For Organization Restore (JSON):**
- Valid JSON file created by `backup_organization.py`
- File must be accessible from the container (in project directory)

**For Full Database Restore (SQL):**
- Valid SQL dump created by `pg_dump`
- Uncompressed or gzip-compressed

### Pre-Restore Checklist

- [ ] Backup file verified and accessible
- [ ] Current data backed up (if preserving)
- [ ] Database service running
- [ ] Sufficient disk space available
- [ ] Users notified of maintenance window

---

## Restore Types

### Organization Restore Options

| Option | Description | Command Flag |
|--------|-------------|--------------|
| **Update Existing** | Restore to same org, update existing data | (default) |
| **Create New** | Create new org with different name | `--as-new NAME` |
| **Dry Run** | Preview without making changes | `--dry-run` |
| **Force** | Skip confirmation prompts | `--force` |

### Full Database Restore Options

| Option | Description |
|--------|-------------|
| **Complete Replace** | Drop and recreate database |
| **Merge** | Add to existing data (may cause conflicts) |
| **Schema Only** | Restore structure without data |
| **Data Only** | Restore data into existing schema |

---

## Organization Restore

### Preview Restore (Dry Run)

Always preview before restoring:

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backups/myorg_backup.json --dry-run'
```

**Example output:**
```
Loading backup: backups/example-orglabs_backup_20251214.json

Backup Summary:
--------------------------------------------------
  Organization: example-orglabs
  Backup Date:  2024-12-14T22:26:51.123456
  Version:      1.0

  Contents:
    Repositories:      1
    Findings:          121
    Credentials:       0
    API Endpoints:     0
    URL Correlations:  0
    Test Results:      139
    Scan Runs:         1
    Contributors:      0

[DRY RUN] Would perform the following operations:
  ~ Using existing organization: example-orglabs

  Restoring repositories...
    Restored 1 repositories
  Restoring findings...
    Restored 121 findings
  Restoring credential-URL test results...
    Restored 139 test results
  Restoring scan runs...
    Restored 1 scan runs

[DRY RUN] No changes were made.
```

### Restore to Existing Organization

Restores data to the same organization, updating existing records:

```bash
# Interactive (with confirmation)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backups/myorg_backup.json'

# Non-interactive (skip confirmation)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backups/myorg_backup.json --force'
```

**What happens:**
1. Existing repositories are deleted and recreated
2. Findings are upserted (insert or update)
3. Test results are upserted
4. All IDs are preserved

### Restore as New Organization

Creates a new organization with all data from the backup:

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backups/myorg_backup.json --as-new neworgname'
```

**What happens:**
1. New organization created with specified name
2. All entities get new UUIDs
3. Relationships are preserved with new IDs
4. Original backup remains unchanged

**Use cases:**
- Clone an organization for testing
- Migrate org to new name
- Create sandbox from production data

### Restore Specific Backup File

```bash
# List available backups
ls -la backups/*.json

# Restore specific backup
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backups/example-org_backup_20251214_222658.json'
```

### Restore from Remote Location

```bash
# Download backup first
curl -o backups/remote_backup.json https://backup-server/myorg_backup.json

# Or use wget
wget -O backups/remote_backup.json https://backup-server/myorg_backup.json

# Then restore
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backups/remote_backup.json'
```

---

## Full Database Restore

### Complete Database Restore

**⚠️ WARNING: This will DELETE all existing data!**

```bash
# Step 1: Stop all services except database
docker-compose stop api web-ui auditgh

# Step 2: Drop and recreate database
docker-compose exec -T db psql -U postgres -c "DROP DATABASE IF EXISTS auditgh_kb;"
docker-compose exec -T db psql -U postgres -c "CREATE DATABASE auditgh_kb;"

# Step 3: Restore from backup
docker-compose exec -T db psql -U postgres -d auditgh_kb < backups/auditgh_kb_backup.sql

# Step 4: Restart all services
docker-compose up -d
```

### Restore Compressed Backup

```bash
# For gzip compressed backups
gunzip -c backups/auditgh_kb_backup.sql.gz | docker-compose exec -T db psql -U postgres -d auditgh_kb

# Or using zcat
zcat backups/auditgh_kb_backup.sql.gz | docker-compose exec -T db psql -U postgres -d auditgh_kb
```

### Restore Custom Format Backup

```bash
# Custom format allows parallel restore
docker-compose exec -T db pg_restore -U postgres -d auditgh_kb -j 4 < backups/auditgh_kb_backup.dump
```

### Restore to Different Database

```bash
# Create new database
docker-compose exec -T db psql -U postgres -c "CREATE DATABASE auditgh_kb_restored;"

# Restore to new database
docker-compose exec -T db psql -U postgres -d auditgh_kb_restored < backups/auditgh_kb_backup.sql

# Update .env to point to new database (optional)
# POSTGRES_DB=auditgh_kb_restored
```

### Schema-Only Restore

Restore database structure without data:

```bash
docker-compose exec -T db psql -U postgres -d auditgh_kb < backups/schema_only.sql
```

### Data-Only Restore

Restore data into existing schema:

```bash
# Ensure schema exists first
docker-compose exec -T db psql -U postgres -d auditgh_kb < setup/schema.sql

# Then restore data
docker-compose exec -T db psql -U postgres -d auditgh_kb < backups/data_only.sql
```

---

## Disaster Recovery

### Complete System Recovery

Follow these steps for full disaster recovery:

```bash
#!/bin/bash
# scripts/disaster_recovery.sh

BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: ./disaster_recovery.sh <backup_file.sql>"
    exit 1
fi

echo "=== AuditGH Disaster Recovery ==="
echo "Backup file: $BACKUP_FILE"
echo ""

# Step 1: Verify backup file
if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup file not found!"
    exit 1
fi

echo "Step 1: Stopping services..."
docker-compose down

echo "Step 2: Starting database only..."
docker-compose up -d db
sleep 10

echo "Step 3: Dropping existing database..."
docker-compose exec -T db psql -U postgres -c "DROP DATABASE IF EXISTS auditgh_kb;"

echo "Step 4: Creating fresh database..."
docker-compose exec -T db psql -U postgres -c "CREATE DATABASE auditgh_kb;"

echo "Step 5: Restoring from backup..."
if [[ "$BACKUP_FILE" == *.gz ]]; then
    gunzip -c "$BACKUP_FILE" | docker-compose exec -T db psql -U postgres -d auditgh_kb
else
    docker-compose exec -T db psql -U postgres -d auditgh_kb < "$BACKUP_FILE"
fi

echo "Step 6: Applying any pending migrations..."
for f in migrations/*.sql; do
    echo "  Applying: $f"
    docker-compose exec -T db psql -U postgres -d auditgh_kb < "$f" 2>/dev/null || true
done

echo "Step 7: Starting all services..."
docker-compose up -d

echo "Step 8: Waiting for services to be ready..."
sleep 15

echo "Step 9: Verifying services..."
docker-compose ps

echo ""
echo "=== Disaster Recovery Complete ==="
echo "Please verify the application at http://localhost:3000"
```

### Recovery from Organization Backups Only

If you only have organization JSON backups:

```bash
#!/bin/bash
# Recover from organization backups

echo "=== Recovery from Organization Backups ==="

# Step 1: Fresh database setup
docker-compose down
docker-compose up -d db
sleep 10

# Step 2: Apply schema
docker-compose exec -T db psql -U postgres -d auditgh_kb < setup/schema.sql

# Step 3: Apply migrations
for f in migrations/*.sql; do
    docker-compose exec -T db psql -U postgres -d auditgh_kb < "$f" 2>/dev/null || true
done

# Step 4: Restore each organization
for backup in backups/*_backup_*.json; do
    echo "Restoring: $backup"
    docker-compose run --rm --entrypoint bash auditgh -c \
      "python scripts/restore_organization.py --file $backup --force"
done

# Step 5: Start all services
docker-compose up -d

echo "=== Recovery Complete ==="
```

---

## Migration Scenarios

### Migrate Organization to New Instance

**On source instance:**
```bash
# Create backup
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/backup_organization.py --org myorg --output backups/'

# Copy backup to new instance
scp backups/myorg_backup_*.json user@new-server:/path/to/auditgithub/backups/
```

**On target instance:**
```bash
# Restore as new org (or same name)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backups/myorg_backup_*.json --force'
```

### Clone Organization for Testing

```bash
# Backup production org
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/backup_organization.py --org production-org --output backups/'

# Restore as test org
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backups/production-org_backup_*.json --as-new test-org'
```

### Merge Organizations

To merge data from multiple organizations:

```bash
# Backup source org
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/backup_organization.py --org source-org --output backups/'

# Restore into target org (creates new records)
# Note: This requires manual ID conflict resolution
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backups/source-org_backup.json --as-new merged-org'
```

---

## Post-Restore Verification

### Verify Organization Data

```bash
# Check organization exists
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/backup_organization.py --list'

# Verify counts match backup
docker-compose exec -T db psql -U postgres -d auditgh_kb -c "
SELECT 
    o.name as org_name,
    COUNT(DISTINCT r.id) as repos,
    COUNT(DISTINCT f.id) as findings
FROM organizations o
LEFT JOIN repositories r ON r.organization_id = o.id
LEFT JOIN findings f ON f.repository_id = r.id
GROUP BY o.name;
"
```

### Verify Database Integrity

```bash
# Check for orphaned records
docker-compose exec -T db psql -U postgres -d auditgh_kb -c "
-- Findings without repositories
SELECT COUNT(*) as orphaned_findings 
FROM findings f 
LEFT JOIN repositories r ON f.repository_id = r.id 
WHERE r.id IS NULL;

-- Repositories without organizations
SELECT COUNT(*) as orphaned_repos 
FROM repositories r 
LEFT JOIN organizations o ON r.organization_id = o.id 
WHERE o.id IS NULL;
"
```

### Verify Application Access

```bash
# Check API health
curl -s http://localhost:8000/health | jq .

# Check organization list via API
curl -s http://localhost:8000/organizations/ | jq .

# Open UI and verify
open http://localhost:3000
```

### Verify Test Results

```bash
# Check credential-URL test results restored
docker-compose exec -T db psql -U postgres -d auditgh_kb -c "
SELECT 
    target_url,
    auth_status,
    tested_at
FROM credential_url_test_results
ORDER BY tested_at DESC
LIMIT 5;
"
```

---

## Troubleshooting

### Common Restore Errors

#### "Organization not found"

The backup references an organization that doesn't exist:

```bash
# Create the organization first, or use --as-new
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backup.json --as-new neworg'
```

#### "Duplicate key violation"

Data already exists with the same ID:

```bash
# Option 1: Use --force to update existing
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backup.json --force'

# Option 2: Restore as new org
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backup.json --as-new neworg'

# Option 3: Clear existing data first
docker-compose exec -T db psql -U postgres -d auditgh_kb -c \
  "DELETE FROM findings WHERE repository_id IN (SELECT id FROM repositories WHERE organization_id = 'ORG_ID');"
```

#### "Foreign key constraint"

Dependencies must be restored in order:

```bash
# Restore order: organizations → repositories → findings/endpoints/etc.
# The restore script handles this automatically
```

#### "Invalid JSON"

Backup file is corrupted:

```bash
# Validate JSON
python3 -c "import json; json.load(open('backup.json'))"

# If invalid, try to recover
python3 -c "
import json
with open('backup.json', 'r') as f:
    content = f.read()
    # Try to find valid JSON portion
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        print(f'Error at position {e.pos}: {e.msg}')
"
```

#### "Connection refused"

Database not running:

```bash
# Start database
docker-compose up -d db
sleep 10

# Verify connection
docker-compose exec db pg_isready -U postgres
```

#### "Permission denied"

File permissions issue:

```bash
# Fix backup file permissions
chmod 644 backups/*.json
chmod 644 backups/*.sql

# Fix directory permissions
chmod 755 backups/
```

### Restore Logs

Enable detailed logging:

```bash
# Capture all output
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backup.json --force' 2>&1 | tee restore.log

# Review log
cat restore.log
```

### Rollback Failed Restore

If restore fails partway through:

```bash
# Option 1: Restore from pre-restore backup
docker-compose exec -T db psql -U postgres -d auditgh_kb < backups/pre_restore_backup.sql

# Option 2: Delete partially restored data
docker-compose exec -T db psql -U postgres -d auditgh_kb -c "
DELETE FROM findings WHERE repository_id IN (
    SELECT id FROM repositories WHERE organization_id = 'PARTIAL_ORG_ID'
);
DELETE FROM repositories WHERE organization_id = 'PARTIAL_ORG_ID';
DELETE FROM organizations WHERE id = 'PARTIAL_ORG_ID';
"
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Preview restore | `... 'python scripts/restore_organization.py --file backup.json --dry-run'` |
| Restore org | `... 'python scripts/restore_organization.py --file backup.json --force'` |
| Restore as new | `... 'python scripts/restore_organization.py --file backup.json --as-new neworg'` |
| Full DB restore | `docker-compose exec -T db psql -U postgres -d auditgh_kb < backup.sql` |
| Verify restore | `... 'python scripts/backup_organization.py --list'` |

---

## Related Documentation

- [Backup Guide](BACKUP.md) - How to create backups
- [Database Setup](DATABASE_SETUP.md) - Initial database configuration
- [Database Reset](DATABASE_RESET.md) - Reset and rebuild database
- [Cheatsheet](CHEATSHEET.md) - Quick command reference

---

*Last updated: December 2024*

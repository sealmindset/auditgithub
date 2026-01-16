# AuditGH Backup Guide

Complete guide for backing up AuditGH data, including organization-level backups, full database backups, and backup strategies.

---

## Table of Contents

1. [Overview](#overview)
2. [Backup Types](#backup-types)
3. [Prerequisites](#prerequisites)
4. [Organization Backup](#organization-backup)
5. [Full Database Backup](#full-database-backup)
6. [Backup Strategies](#backup-strategies)
7. [Backup Verification](#backup-verification)
8. [Automation](#automation)
9. [Troubleshooting](#troubleshooting)

---

## Overview

AuditGH supports two backup approaches:

| Backup Type | Format | Scope | Use Case |
|-------------|--------|-------|----------|
| **Organization Backup** | JSON | Single org or all orgs | Migrate orgs, clone data, selective restore |
| **Full Database Backup** | SQL | Entire database | Disaster recovery, full system restore |

### What Gets Backed Up

**Organization Backup includes:**
- Organization metadata
- Repositories (all fields)
- Findings (security vulnerabilities)
- Credentials (if table exists)
- API Endpoints
- Credential-URL Correlations
- Credential-URL Test Results (including raw HTTP request/response)
- Scan Runs
- Contributors

**Full Database Backup includes:**
- All of the above
- System tables
- User sessions
- Configuration data

---

## Prerequisites

### Required Services

Ensure the following services are running:

```bash
# Check service status
docker-compose ps

# Expected output:
# NAME             STATUS
# auditgh_db       Up (healthy)
# auditgh_api      Up
# auditgh_ui       Up
```

If services are not running:

```bash
docker-compose up -d
```

### Required Permissions

- **Docker access**: User must be able to run `docker-compose` commands
- **File system access**: Write access to the `backups/` directory
- **Database access**: PostgreSQL user with SELECT permissions (default: `postgres`)

### Disk Space Requirements

Estimate backup size based on your data:

| Data Volume | Estimated Backup Size |
|-------------|----------------------|
| 1 org, 10 repos, 1K findings | ~1-5 MB |
| 1 org, 50 repos, 10K findings | ~20-50 MB |
| 1 org, 100 repos, 50K findings | ~100-200 MB |
| Multiple orgs | Sum of individual orgs |

Check available disk space:

```bash
df -h .
```

---

## Organization Backup

Organization backups create portable JSON files that can be restored to the same or different AuditGH instance.

### List Available Organizations

Before backing up, see what organizations exist:

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/backup_organization.py --list'
```

**Example output:**
```
Available Organizations:
--------------------------------------------------------------------------------
  sealmindset          sealmindset               Repos: 62    Findings: 29004
  sleepnumberlabs      sleepnumberlabs           Repos: 1     Findings: 121
```

### Backup Single Organization

```bash
# Basic backup
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/backup_organization.py --org ORGNAME --output backups/'

# Example
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/backup_organization.py --org sealmindset --output backups/'
```

**Output:**
```
Backing up organization: sealmindset
  Backing up organization: sealmindset (991a1366-1f57-4ac6-971c-7beb0e12371d)
    - Backing up repositories...
      Found 62 repositories
    - Backing up findings...
      Found 29004 findings
    - Backing up API endpoints...
      Found 18424 API endpoints
    - Backing up test results...
      Found 1 test results
    - Backing up scan runs...
      Found 64 scan runs
    - Backing up contributors...
      Found 38 contributors
  Saved: backups/sealmindset_backup_20251214_222658.json (75594.6 KB)

Backup complete: backups/sealmindset_backup_20251214_222658.json
```

### Backup All Organizations

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/backup_organization.py --all --output backups/'
```

This creates separate backup files for each organization.

### Backup File Naming

Backup files are named automatically:
```
{org_name}_backup_{YYYYMMDD}_{HHMMSS}.json
```

Example: `sealmindset_backup_20251214_222658.json`

### Backup File Structure

```json
{
  "metadata": {
    "backup_version": "1.0",
    "backup_date": "2024-12-14T22:26:58.123456",
    "organization_id": "991a1366-1f57-4ac6-971c-7beb0e12371d",
    "organization_name": "sealmindset",
    "summary": {
      "repositories": 62,
      "findings": 29004,
      "credentials": 0,
      "api_endpoints": 18424,
      "credential_url_correlations": 0,
      "credential_url_test_results": 1,
      "scan_runs": 64,
      "contributors": 38
    }
  },
  "organization": { ... },
  "repositories": [ ... ],
  "findings": [ ... ],
  "api_endpoints": [ ... ],
  "credential_url_test_results": [ ... ],
  "scan_runs": [ ... ],
  "contributors": [ ... ]
}
```

### Custom Output Directory

```bash
# Create dated backup directory
mkdir -p backups/$(date +%Y-%m-%d)

docker-compose run --rm --entrypoint bash auditgh -c \
  "python scripts/backup_organization.py --all --output backups/$(date +%Y-%m-%d)/"
```

---

## Full Database Backup

For complete disaster recovery, use PostgreSQL's native backup tools.

### Quick Database Backup

```bash
# Backup entire database to SQL file
docker-compose exec -T db pg_dump -U postgres auditgh_kb > backups/auditgh_kb_backup_$(date +%Y%m%d_%H%M%S).sql
```

### Compressed Backup

```bash
# Compressed backup (recommended for large databases)
docker-compose exec -T db pg_dump -U postgres auditgh_kb | gzip > backups/auditgh_kb_backup_$(date +%Y%m%d_%H%M%S).sql.gz
```

### Custom Format Backup (Parallel Restore)

```bash
# Custom format allows parallel restore
docker-compose exec -T db pg_dump -U postgres -Fc auditgh_kb > backups/auditgh_kb_backup_$(date +%Y%m%d_%H%M%S).dump
```

### Schema-Only Backup

```bash
# Backup schema without data
docker-compose exec -T db pg_dump -U postgres --schema-only auditgh_kb > backups/schema_only_$(date +%Y%m%d).sql
```

### Data-Only Backup

```bash
# Backup data without schema (for migrations)
docker-compose exec -T db pg_dump -U postgres --data-only auditgh_kb > backups/data_only_$(date +%Y%m%d).sql
```

---

## Backup Strategies

### Daily Backup Strategy

Create a backup script for daily execution:

```bash
#!/bin/bash
# scripts/daily_backup.sh

BACKUP_DIR="backups/daily"
DATE=$(date +%Y%m%d)
RETENTION_DAYS=7

# Create backup directory
mkdir -p $BACKUP_DIR

# Organization backups
docker-compose run --rm --entrypoint bash auditgh -c \
  "python scripts/backup_organization.py --all --output $BACKUP_DIR/"

# Full database backup
docker-compose exec -T db pg_dump -U postgres auditgh_kb | gzip > $BACKUP_DIR/full_backup_$DATE.sql.gz

# Clean up old backups
find $BACKUP_DIR -name "*.json" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete

echo "Daily backup complete: $BACKUP_DIR"
```

### Pre-Migration Backup

Before any schema changes or major updates:

```bash
#!/bin/bash
# scripts/pre_migration_backup.sh

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="backups/migrations/$TIMESTAMP"

mkdir -p $BACKUP_DIR

echo "Creating pre-migration backup..."

# Full database backup
docker-compose exec -T db pg_dump -U postgres auditgh_kb > $BACKUP_DIR/full_backup.sql

# Organization backups
docker-compose run --rm --entrypoint bash auditgh -c \
  "python scripts/backup_organization.py --all --output $BACKUP_DIR/"

# Schema snapshot
docker-compose exec -T db pg_dump -U postgres --schema-only auditgh_kb > $BACKUP_DIR/schema.sql

echo "Pre-migration backup saved to: $BACKUP_DIR"
echo "Proceed with migration when ready."
```

### Offsite Backup

Copy backups to remote storage:

```bash
# Sync to S3
aws s3 sync backups/ s3://your-bucket/auditgh-backups/

# Sync to remote server
rsync -avz backups/ user@backup-server:/backups/auditgh/

# Copy to network drive
cp -r backups/ /mnt/backup-drive/auditgh/
```

---

## Backup Verification

### Verify Backup File Integrity

```bash
# Check JSON validity
python3 -c "import json; json.load(open('backups/sealmindset_backup_20251214.json'))" && echo "Valid JSON"

# Check file size
ls -lh backups/*.json

# View backup summary
python3 -c "
import json
with open('backups/sealmindset_backup_20251214.json') as f:
    data = json.load(f)
    print('Organization:', data['metadata']['organization_name'])
    print('Backup Date:', data['metadata']['backup_date'])
    print('Summary:', json.dumps(data['metadata']['summary'], indent=2))
"
```

### Verify SQL Backup

```bash
# Check SQL file is valid
head -20 backups/auditgh_kb_backup.sql

# Check compressed file
zcat backups/auditgh_kb_backup.sql.gz | head -20

# Count tables in backup
grep -c "CREATE TABLE" backups/auditgh_kb_backup.sql
```

### Test Restore (Dry Run)

```bash
# Preview what would be restored
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/restore_organization.py --file backups/myorg_backup.json --dry-run'
```

---

## Automation

### Cron Job Setup

Add to crontab for automated daily backups:

```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * cd /path/to/auditgithub && ./scripts/daily_backup.sh >> logs/backup.log 2>&1
```

### GitHub Actions Backup

```yaml
# .github/workflows/backup.yml
name: Daily Backup

on:
  schedule:
    - cron: '0 2 * * *'  # 2 AM UTC daily
  workflow_dispatch:  # Manual trigger

jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Start services
        run: docker-compose up -d db
        
      - name: Wait for database
        run: sleep 10
        
      - name: Create backup
        run: |
          docker-compose exec -T db pg_dump -U postgres auditgh_kb > backup.sql
          
      - name: Upload backup
        uses: actions/upload-artifact@v4
        with:
          name: database-backup-${{ github.run_number }}
          path: backup.sql
          retention-days: 30
```

---

## Troubleshooting

### Common Issues

#### "Container not running"

```bash
# Start the database container
docker-compose up -d db
sleep 5

# Retry backup
```

#### "Permission denied"

```bash
# Create backups directory with proper permissions
mkdir -p backups
chmod 755 backups
```

#### "Disk space full"

```bash
# Check disk usage
df -h

# Clean old backups
find backups/ -name "*.json" -mtime +30 -delete
find backups/ -name "*.sql*" -mtime +30 -delete

# Clean Docker
docker system prune -f
```

#### "Table does not exist"

This is normal - some tables may not exist in your installation. The backup script handles this gracefully and skips missing tables.

#### "Connection refused"

```bash
# Check if database is running
docker-compose ps db

# Check database logs
docker-compose logs db

# Restart database
docker-compose restart db
```

### Backup Logs

Enable verbose logging:

```bash
# Redirect output to log file
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/backup_organization.py --all --output backups/' 2>&1 | tee backups/backup.log
```

---

## Quick Reference

| Task | Command |
|------|---------|
| List orgs | `... 'python scripts/backup_organization.py --list'` |
| Backup one org | `... 'python scripts/backup_organization.py --org NAME --output backups/'` |
| Backup all orgs | `... 'python scripts/backup_organization.py --all --output backups/'` |
| Full DB backup | `docker-compose exec -T db pg_dump -U postgres auditgh_kb > backup.sql` |
| Compressed backup | `docker-compose exec -T db pg_dump -U postgres auditgh_kb \| gzip > backup.sql.gz` |
| Verify JSON | `python3 -c "import json; json.load(open('backup.json'))"` |

---

## Next Steps

- [Restore Guide](RESTORE.md) - How to restore from backups
- [Database Setup](DATABASE_SETUP.md) - Initial database configuration
- [Database Reset](DATABASE_RESET.md) - Reset and rebuild database

---

*Last updated: December 2024*

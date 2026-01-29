# Scripts Directory

Organized collection of utility scripts for the AuditGH Security Portal.

## Directory Structure

```
scripts/
├── setup/           Setup and configuration scripts
├── orgs/            Organization management scripts
├── scanning/        Security scanning scripts
├── architecture/    Architecture generation scripts
├── maintenance/     Data processing and maintenance scripts
└── batch/           Batch processing scripts
```

## Setup Scripts (`setup/`)

Installation, configuration, and database management.

### Database Setup
- **`run-migrations.sh`** - Run database migrations
- **`fix-both-dbs.sh`** - Fix schema in both databases (security_portal and auditgh_kb)
- **`fix-org-schema.sh`** - Fix organizations table schema
- **`fix_repo_structure.sh`** - Fix repository table structure

### Environment Setup
- **`install_dependencies.sh`** - Install system dependencies
- **`setup_docker.sh`** - Setup Docker environment
- **`setup_mac.sh`** - Setup development environment on macOS

**Usage:**
```bash
# Initial setup
./scripts/setup/setup_docker.sh

# Run migrations
./scripts/setup/run-migrations.sh

# Fix database schemas
./scripts/setup/fix-both-dbs.sh
```

## Organization Management (`orgs/`)

Tools for managing GitHub organizations.

- **`org.sh`** - Command-line organization management tool
- **`org_manager.py`** - Python backend for organization operations
- **`manage-orgs.sh`** - Interactive menu for organization management
- **`add-org.sh`** - Legacy: Add organization (use org.sh instead)
- **`add_sleepnumber_org.py`** - Legacy: Add Sleep Number org (use org.sh instead)

**Usage:**
```bash
# List organizations
./scripts/orgs/org.sh list

# Create organization
./scripts/orgs/org.sh create myorg github-org-name token

# Import repositories
./scripts/orgs/org.sh import myorg

# Interactive menu
./scripts/orgs/manage-orgs.sh
```

See [Organization Management Guide](../docs/ORG_MANAGEMENT_GUIDE.md) for detailed documentation.

## Scanning Scripts (`scanning/`)

Security scanning and vulnerability detection.

- **`scan_repos.py`** - Main repository scanning script
- **`scan_pattern.sh`** - Scan repositories matching a pattern
- **`rescan_pattern.sh`** - Rescan repositories matching a pattern
- **`rescan_plsql_repos.py`** - Rescan PL/SQL repositories
- **`orchestrate_scans.py`** - Orchestrate parallel scans
- **`discover_repos.sh`** - Discover repositories in GitHub organization

**Usage:**
```bash
# Scan single repository
docker-compose run --rm scanner --target myorg/myrepo

# Scan pattern
./scripts/scanning/scan_pattern.sh "webapp-*"

# Rescan all
./scripts/scanning/rescan_pattern.sh "*"

# Orchestrate parallel scans
python scripts/scanning/orchestrate_scans.py --org sleepnumber --max-workers 4
```

## Architecture Generation (`architecture/`)

AI-powered architecture documentation generation.

- **`gen-arch.sh`** - Generate architecture for single repository
- **`gen-arch-batch.sh`** - Generate architecture for multiple repositories
- **`gen-arch-batch-docker.sh`** - Batch generation in Docker
- **`generate_architecture_cli.py`** - Python CLI for architecture generation

**Usage:**
```bash
# Generate for single repo
./scripts/architecture/gen-arch.sh sleepnumber webapp-frontend

# Batch generate with pattern
./scripts/architecture/gen-arch-batch-docker.sh "sleepnumber" "webapp-*" --skip-if-exists

# Using Python CLI
python scripts/architecture/generate_architecture_cli.py --org sleepnumber --repo myrepo
```

See [Architecture Generation Guide](../docs/gen-arch.md) for detailed documentation.

## Maintenance Scripts (`maintenance/`)

Data processing, backfills, and system maintenance.

### Data Backfills
- **`backfill_pushed_at.py`** - Backfill pushed_at timestamps from GitHub
- **`backfill_pushed_at_priority.py`** - Priority backfill for active repos
- **`update_pushed_at_from_findings.py`** - Update timestamps from findings

### Data Cleanup
- **`cleanup_ghost_repos.py`** - Remove orphaned repository records
- **`fix_archived_repo_dates.py`** - Fix dates for archived repositories

### Data Ingestion
- **`ingest_reports.py`** - Ingest vulnerability scan reports
- **`ingest_scans.py`** - Ingest scan results
- **`update_repos_from_intel.py`** - Update repositories from intelligence data

### Validation
- **`validate_scan_metadata.py`** - Validate scan metadata integrity

**Usage:**
```bash
# Backfill pushed_at dates
python scripts/maintenance/backfill_pushed_at.py --org sleepnumber

# Cleanup ghost repos
python scripts/maintenance/cleanup_ghost_repos.py

# Ingest scan results
python scripts/maintenance/ingest_scans.py --scan-dir /path/to/scans

# Validate metadata
python scripts/maintenance/validate_scan_metadata.py
```

## Batch Processing (`batch/`)

Batch operations and bulk processing.

- **`batch_process.py`** - Main batch processing script for multiple repositories

**Usage:**
```bash
# Process multiple repos
python scripts/batch/batch_process.py sleepnumber "webapp-*" --skip-if-exists --delay=60

# Via Docker
docker-compose exec api python scripts/batch/batch_process.py sleepnumber "*"
```

See [Batch Processing Guide](../docs/BATCH_PROCESSING_GUIDE.md) for detailed documentation.

## Common Workflows

### Initial Setup

```bash
# 1. Setup environment
./scripts/setup/setup_docker.sh

# 2. Run migrations
./scripts/setup/run-migrations.sh

# 3. Fix schemas if needed
./scripts/setup/fix-both-dbs.sh

# 4. Create organization
./scripts/orgs/org.sh create myorg github-org token

# 5. Import repositories
./scripts/orgs/org.sh import myorg
```

### Daily Operations

```bash
# Scan new repositories
./scripts/scanning/scan_pattern.sh "new-*"

# Generate architecture for new repos
./scripts/architecture/gen-arch-batch-docker.sh "myorg" "new-*" --skip-if-exists

# Update repository metadata
python scripts/maintenance/update_repos_from_intel.py
```

### Maintenance Tasks

```bash
# Weekly: Backfill timestamps
python scripts/maintenance/backfill_pushed_at_priority.py

# Monthly: Cleanup ghost repos
python scripts/maintenance/cleanup_ghost_repos.py

# As needed: Validate scan metadata
python scripts/maintenance/validate_scan_metadata.py
```

## Best Practices

1. **Always use Docker for scanning**: Scanner requires many dependencies
   ```bash
   docker-compose run --rm scanner ...
   ```

2. **Use batch processing for multiple repos**: More efficient than individual scans
   ```bash
   python scripts/batch/batch_process.py org "pattern"
   ```

3. **Skip existing architecture**: Use `--skip-if-exists` flag
   ```bash
   ./scripts/architecture/gen-arch-batch-docker.sh org "*" --skip-if-exists
   ```

4. **Add delays between operations**: Prevents API rate limiting
   ```bash
   python scripts/batch/batch_process.py org "*" --delay=60
   ```

5. **Use patterns for selective operations**: More efficient than processing all
   ```bash
   ./scripts/scanning/scan_pattern.sh "webapp-*"
   ```

## Migrating from Old Paths

If you have scripts or documentation referencing old paths:

| Old Path | New Path |
|----------|----------|
| `./add-org.sh` | `./scripts/orgs/add-org.sh` |
| `./gen-arch-batch-docker.sh` | `./scripts/architecture/gen-arch-batch-docker.sh` |
| `./scan_repos.py` | `./scripts/scanning/scan_repos.py` |
| `./batch_process.py` | `./scripts/batch/batch_process.py` |
| `./fix-both-dbs.sh` | `./scripts/setup/fix-both-dbs.sh` |

## Contributing

When adding new scripts:

1. Place in appropriate category folder
2. Update this README with description and usage
3. Add execute permissions: `chmod +x script.sh`
4. Include usage documentation in script header
5. Follow naming conventions:
   - Shell scripts: `kebab-case.sh`
   - Python scripts: `snake_case.py`

## See Also

- [Organization Management Guide](../docs/ORG_MANAGEMENT_GUIDE.md)
- [Batch Processing Guide](../docs/BATCH_PROCESSING_GUIDE.md)
- [Architecture Generation Guide](../docs/gen-arch.md)
- [Quickstart Guide](../docs/QUICKSTART.md)

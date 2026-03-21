# Scan Validation System

## Overview

The scan validation system ensures that all repository metadata (commit dates, languages, descriptions, branches) is automatically updated and kept in sync with the latest scan data. This system runs automatically after every scan completes.

## Architecture

### 1. Core Components

#### `ingest_reports.py`
Contains the metadata extraction and update logic:

- **`get_repo_metadata_from_intel(org_name, repo_name)`**
  - Extracts metadata from `_intel.json` and `_cloc.json` files
  - Returns: `pushed_at`, `language`, `description`, `default_branch`

- **`update_repository_metadata(session, repo_id, org_name, repo_name)`**
  - Updates repository metadata in the database
  - Only updates fields that have new values (doesn't overwrite existing data with NULL)
  - Returns True if successful, False otherwise

#### `validate_scan_metadata.py`
Standalone validation script that can be run manually or as part of orchestration:

```bash
# Validate all repositories
python validate_scan_metadata.py

# Validate specific organization
python validate_scan_metadata.py --org example-org

# Validate specific repository
python validate_scan_metadata.py --org example-orglabs --repo my-api
```

### 2. Integration Points

The metadata validation is automatically triggered at these points:

#### A. During Report Ingestion (`ingest_reports.py`)
After ingesting all scan data for a repository:

```python
# Ingest OpenAPI specifications
...

# VALIDATION: Update repository metadata from latest scan files
update_repository_metadata(session, repo_id, org_name, repo_name)
```

#### B. During Scan Ingestion (`ingest_scans.py`)
After ingesting findings from scan runs:

```python
db.commit()

# VALIDATION: Update repository metadata from latest scan files
try:
    from ingest_reports import update_repository_metadata
    update_repository_metadata(db, str(repo.id), github_org, repo_name)
except Exception as e:
    logger.warning(f"Could not update repository metadata: {e}")
```

#### C. During Scan Orchestration (`orchestrate_scans.py`)
After all scans and ingestion complete:

```python
# Run ingestion
subprocess.run(ingest_cmd, check=True)

# Run metadata validation to ensure repository info is complete
validate_cmd = [sys.executable, "validate_scan_metadata.py", "--org", self.org]
if repo:
    validate_cmd.extend(["--repo", repo])
subprocess.run(validate_cmd, check=True)
```

### 3. Data Flow

```
┌─────────────────┐
│  scan_repos.py  │  (Scans repos, creates _intel.json and _cloc.json)
└────────┬────────┘
         │
         v
┌─────────────────┐
│ orchestrate_    │  (Orchestrates all scanners)
│ scans.py        │
└────────┬────────┘
         │
         v
┌─────────────────┐
│ ingest_scans.py │  (Ingests findings) ──> update_repository_metadata()
│ OR              │                          ├─> Reads _intel.json
│ ingest_reports  │                          ├─> Reads _cloc.json
│ .py             │                          └─> Updates DB
└────────┬────────┘
         │
         v
┌─────────────────┐
│ validate_scan_  │  (Final validation pass)
│ metadata.py     │  ──> Ensures all metadata is complete
└─────────────────┘
```

## Metadata Sources

### `_intel.json` Files

Located at: `vulnerability_reports/{org}/{repo}/{repo}_intel.json`

Provides:
- **pushed_at**: Latest commit date from contributors
- **description**: Repository description from GitHub
- **default_branch**: Default branch name (main/master)

Example structure:
```json
{
  "contributors": {
    "total_commits": 28,
    "total_contributors": 3,
    "top_contributors": [
      {
        "name": "Chris Savoie",
        "email": "chris@example.com",
        "commits": 25,
        "last_commit_at": "2020-03-16T14:25:43Z"
      }
    ]
  },
  "repository": {
    "description": "Oracle APEX application and ORDS Rest API",
    "default_branch": "master"
  }
}
```

### `_cloc.json` Files

Located at: `vulnerability_reports/{org}/{repo}/{repo}_cloc.json`

Provides:
- **language**: Primary programming language (by line count)

Example structure:
```json
{
  "SQL": {
    "nFiles": 15,
    "blank": 120,
    "comment": 80,
    "code": 2500
  },
  "JavaScript": {
    "nFiles": 5,
    "blank": 50,
    "comment": 30,
    "code": 800
  },
  "SUM": {
    "nFiles": 20,
    "blank": 170,
    "comment": 110,
    "code": 3300
  }
}
```

## Database Updates

The validation system updates the `repositories` table:

```sql
UPDATE repositories
SET pushed_at = :pushed_at,        -- Latest commit date
    language = :language,           -- Primary language
    description = :description,     -- Repository description
    default_branch = :default_branch, -- Default branch
    updated_at = NOW()
WHERE id = :repo_id
```

**Important**: The system uses `COALESCE` logic to only update NULL or missing fields, preserving existing data.

## Manual Validation

You can manually validate repository metadata at any time:

### Docker Environment
```bash
# Validate all organizations
docker exec auditgh_api python /app/validate_scan_metadata.py

# Validate specific organization
docker exec auditgh_api python /app/validate_scan_metadata.py --org example-org

# Validate specific repository
docker exec auditgh_api python /app/validate_scan_metadata.py --org example-orglabs --repo my-api

# Enable verbose logging
docker exec auditgh_api python /app/validate_scan_metadata.py --org example-org -v
```

### Local Environment
```bash
# Validate all
python validate_scan_metadata.py

# Validate organization
python validate_scan_metadata.py --org example-org

# Validate specific repo
python validate_scan_metadata.py --org example-org --repo EBS-E-7000-Store-Inventory-REST-API
```

## Monitoring and Logs

The validation system provides comprehensive logging:

```
2026-01-20 16:00:00,000 - INFO - ================================================================================
2026-01-20 16:00:00,000 - INFO - Repository Metadata Validation After Scan
2026-01-20 16:00:00,000 - INFO - ================================================================================
2026-01-20 16:00:00,000 - INFO - Target: example-org
2026-01-20 16:00:00,000 - INFO - Total Repositories: 1872
2026-01-20 16:00:00,000 - INFO - ================================================================================
2026-01-20 16:00:00,010 - INFO - Updated metadata for example-org/my-api: pushed_at, language
2026-01-20 16:00:00,020 - INFO - Updated metadata for example-org/my-service: pushed_at, language, description
...
2026-01-20 16:00:10,000 - INFO - ================================================================================
2026-01-20 16:00:10,000 - INFO - Validation Complete!
2026-01-20 16:00:10,000 - INFO - ================================================================================
2026-01-20 16:00:10,000 - INFO - Total Repositories: 1872
2026-01-20 16:00:10,000 - INFO - Updated: 828
2026-01-20 16:00:10,000 - INFO - No metadata found: 1044
2026-01-20 16:00:10,000 - INFO - Errors: 0
2026-01-20 16:00:10,000 - INFO - ================================================================================
```

## Troubleshooting

### Missing Metadata

If repositories are missing metadata after validation:

1. **Check if scan files exist**:
   ```bash
   ls vulnerability_reports/example-org/my-repo/my-repo_intel.json
   ls vulnerability_reports/example-org/my-repo/my-repo_cloc.json
   ```

2. **Verify file contents**:
   ```bash
   cat vulnerability_reports/example-org/my-repo/my-repo_intel.json | jq .
   ```

3. **Check repository has been scanned**:
   ```bash
   docker exec auditgh_db psql -U postgres -d security_portal -c \
     "SELECT name, last_scanned_at, pushed_at, language FROM repositories WHERE name = 'my-repo';"
   ```

4. **Run validation manually with verbose logging**:
   ```bash
   docker exec auditgh_api python /app/validate_scan_metadata.py \
     --org example-org --repo my-repo -v
   ```

### Incomplete intel.json

Some repositories may have incomplete `_intel.json` files if:
- The repository has no commits
- GitHub API access is limited
- The scan was interrupted

Check the scan logs for errors during the scan process.

## Benefits

1. **Automatic Synchronization**: Metadata is always up-to-date without manual intervention
2. **Consistent Data**: All repositories have complete metadata for scheduling and display
3. **Validation at Every Step**: Multiple checkpoints ensure data integrity
4. **Manual Override**: Can be run manually if needed for specific repositories
5. **Comprehensive Logging**: Easy to track what was updated and why

## Configuration

No configuration is required. The system automatically:
- Detects report file locations
- Handles both flat and org-based directory structures
- Works with both example-org and example-orglabs organizations
- Preserves existing data when updating

## Integration with Scheduling

The scheduling system relies on accurate `pushed_at` dates to determine scan frequency. The validation system ensures these dates are always available and current, enabling:

- AI-powered scheduling based on repository activity
- Accurate "last commit" displays in the UI
- Proper repository prioritization for scanning
- Historical tracking of repository activity

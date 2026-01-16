# Self-Annealing System

## Overview

The scanner now includes a self-annealing system that automatically learns from failures and adapts to problematic repositories.

### Self-Annealing Agent

**Script**: `scripts/self_annealing_agent.py`

**Features**:
- DOE-based approach: Systematic detection, diagnosis, repair, reporting
- Auto-repairs: Contributors, Languages, SBOM, Finding Types
- Data Quality Score: Calculates overall integrity percentage
- JSON Reports: Saved to `logs/annealing_report_*.json`

**Manual Usage**:

```bash
# Dry run (detect only)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/self_annealing_agent.py --dry-run'

# Full run (detect + repair)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/self_annealing_agent.py'
```

### Built-in Scheduler

The application includes a configurable cron scheduler that can automatically run the self-annealing agent.

**Configuration** (`.env`):

```bash
# Enable the scheduler
SCHEDULER_ENABLED=true

# Data Integrity Agent - runs daily at 3 AM by default
ANNEALING_CRON=0 3 * * *
ANNEALING_ENABLED=true
ANNEALING_DRY_RUN=false

# Automated scanning - disabled by default
SCAN_CRON=0 */6 * * *
SCAN_ENABLED=false

# Automated backups - weekly on Sunday at 2 AM
BACKUP_CRON=0 2 * * 0
BACKUP_ENABLED=false
```

**API Endpoints**:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scheduler/status` | GET | Get scheduler status and all jobs |
| `/scheduler/jobs` | GET | List all configured jobs |
| `/scheduler/jobs/{name}` | GET | Get specific job status |
| `/scheduler/jobs/{name}/trigger` | POST | Manually trigger a job |
| `/scheduler/next-runs` | GET | Get next scheduled run times |
| `/scheduler/start` | POST | Start the scheduler |
| `/scheduler/stop` | POST | Stop the scheduler |

**Manual Trigger via API**:

```bash
# Trigger self-annealing manually
curl -X POST http://localhost:8000/scheduler/jobs/annealing/trigger

# Check scheduler status
curl http://localhost:8000/scheduler/status
```

## How It Works

### 1. Failure Tracking
When a repository scan fails (timeout or error), the system:
- Increments `failure_count` in the database
- Records `last_failure_at` timestamp
- Saves `last_failure_reason` (e.g., "timeout after 5.2m", "error: ConnectionError")

### 2. Automatic Skip Logic
Before scanning a repository, the system checks:

```
┌─────────────────────────────────────────────┐
│ 1. Has repo failed ≥3 times?               │
│    └─> YES: Skip if failed within 7 days   │
│    └─> NO: Continue checks                 │
├─────────────────────────────────────────────┤
│ 2. Was repo scanned within 48 hours?       │
│    └─> YES: Skip (if --skipscan flag)      │
│    └─> NO: Continue checks                 │
├─────────────────────────────────────────────┤
│ 3. Is repo inactive (>180 days)?           │
│    └─> YES: Skip                            │
│    └─> NO: Continue to scan                │
└─────────────────────────────────────────────┘
```

### 3. Self-Healing
- **On Success**: Failure count resets to 0
- **On Failure**: Failure count increments
- **Periodic Retry**: After 7 days, even problematic repos are retried

## Configuration

Default thresholds (configurable):
- **Failure threshold**: 3 consecutive failures → auto-skip
- **Retry period**: 7 days before attempting again
- **Timeout**: 5 minutes per repo (with progress monitoring)
- **Idle threshold**: 3 minutes of no progress → timeout

## Example Scenarios

### Scenario 1: Problematic Repo
```
Scan 1: ❌ Timeout (5m) → failure_count = 1
Scan 2: ❌ Timeout (5m) → failure_count = 2
Scan 3: ❌ Timeout (5m) → failure_count = 3
Scan 4: ⏭️ SKIPPED (3 failures, last 2 days ago)
...
Scan 10 (8 days later): 🔄 RETRY → ✅ Success → failure_count = 0
```

### Scenario 2: Transient Issue
```
Scan 1: ❌ Error (network issue) → failure_count = 1
Scan 2: ✅ Success → failure_count = 0 (reset)
```

### Scenario 3: Permanently Problematic
```
Scan 1: ❌ Timeout → failure_count = 1
Scan 2: ❌ Timeout → failure_count = 2
Scan 3: ❌ Timeout → failure_count = 3
Every scan: ⏭️ SKIPPED (until 7 days pass)
Retry after 7 days: ❌ Timeout → failure_count = 4
Every scan: ⏭️ SKIPPED (until 7 days pass again)
```

## Database Schema

```sql
ALTER TABLE repositories
ADD COLUMN failure_count INTEGER DEFAULT 0,
ADD COLUMN last_failure_at TIMESTAMP,
ADD COLUMN last_failure_reason VARCHAR(255);
```

## Migration

Run the migration to add tracking columns:

```bash
docker-compose exec db psql -U postgres -d auditgh -f /app/migrations/add_failure_tracking.sql
```

## Logs

Watch for self-annealing logs during scans:

```
INFO:root:⏭️ Skipping repo-name: Repository has failed 3 times (last: timeout after 5.2m, 2.1d ago). Will retry after 7 days.
INFO:root:📊 Recorded failure for repo-name: timeout after 5.2m (count: 3)
INFO:root:✅ Reset failure count for repo-name (was: 2)
```

## Benefits

1. **Automatic**: No manual intervention needed for problematic repos
2. **Self-healing**: Automatically retries to detect if issues resolved
3. **Efficient**: Saves time by skipping known problematic repos
4. **Configurable**: Thresholds can be adjusted per environment
5. **Observable**: Clear logging shows what's happening

## Manual Override

To force scan a problematic repo:

```bash
docker-compose run --rm auditgh --repo "repo-name" --overridescan
```

The `--overridescan` flag bypasses ALL skip logic including failure tracking.

---

## Data Integrity Agent

In addition to scan failure tracking, the system includes a **Self-Annealing Data Integrity Agent** that detects and repairs data quality issues.

### Purpose

The Data Integrity Agent implements DOE (Design of Experiments) principles to:
1. **DETECT** data integrity issues across all repositories
2. **DIAGNOSE** root causes of missing or inconsistent data
3. **REPAIR** issues automatically when possible
4. **REPORT** on data quality metrics and trends
5. **PREVENT** future issues through continuous monitoring

### Issue Types Detected

| Issue Type | Description | Auto-Repair |
|------------|-------------|-------------|
| `missing_contributors` | Contributors in intel file but not in DB | ✅ Yes |
| `missing_languages` | Languages in intel file but not in DB | ✅ Yes |
| `missing_sbom` | SBOM in syft file but not in DB | ✅ Yes |
| `missing_findings` | Findings in scanner files but not in DB | ⚠️ Manual |
| `incorrect_finding_type` | Horusec typed as 'vulnerability' not 'sast' | ✅ Yes |
| `stale_data` | Data older than scan files | ⚠️ Manual |
| `orphaned_records` | Records without parent repository | ⚠️ Manual |

### Usage

```bash
# Detect issues only (dry run)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/self_annealing_agent.py --dry-run'

# Detect and auto-repair issues
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/self_annealing_agent.py'

# Verbose output
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/self_annealing_agent.py --verbose'
```

### Example Output

```
============================================================
SELF-ANNEALING DATA INTEGRITY AGENT
============================================================

[Phase 1] DETECTION - Scanning for data integrity issues...

Issue Summary:
  missing_contributors: 25 repositories affected
  missing_languages: 30 repositories affected
  missing_sbom: 15 repositories affected

[Phase 2] DIAGNOSIS - Analyzing 70 issues...

[Phase 3] REPAIR - Fixing auto-repairable issues...
  ✓ Repaired: repo-name - missing_contributors
  ✓ Repaired: repo-name - missing_languages
  ✓ Repaired: repo-name - missing_sbom

============================================================
SELF-ANNEALING REPORT
============================================================
Timestamp: 2024-12-15 01:43:12
Repositories Scanned: 273
Issues Detected: 115
Issues Repaired: 59
Issues Failed: 56
Data Quality Score: 94.9%

Recommendations:
  • Run contributor ingestion for affected repositories
  • Run language stats ingestion for affected repositories
  • Run SBOM ingestion for affected repositories

Report saved to: logs/annealing_report_20241215_014315.json
```

### Data Quality Score

The agent calculates a **Data Quality Score** based on:

```
Score = (total_checks - issues + repaired) / total_checks × 100
```

Where:
- `total_checks` = repositories × 4 data dimensions
- `issues` = detected issues
- `repaired` = successfully repaired issues

### Scheduled Execution

For continuous monitoring, add to cron:

```bash
# Run daily at 3 AM
0 3 * * * cd /path/to/auditgithub && docker-compose run --rm --entrypoint bash auditgh -c 'python scripts/self_annealing_agent.py' >> logs/annealing.log 2>&1
```

### Integration with CI/CD

Add to your CI/CD pipeline to ensure data quality:

```yaml
# .github/workflows/data-quality.yml
name: Data Quality Check

on:
  schedule:
    - cron: '0 3 * * *'  # Daily at 3 AM
  workflow_dispatch:

jobs:
  data-quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Data Integrity Agent
        run: |
          docker-compose run --rm --entrypoint bash auditgh -c \
            'python scripts/self_annealing_agent.py'
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: data-quality-report
          path: logs/annealing_report_*.json
```

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Self-Annealing Data Agent                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │  DETECTION  │───▶│  DIAGNOSIS  │───▶│   REPAIR    │     │
│  │             │    │             │    │             │     │
│  │ • Scan DB   │    │ • Analyze   │    │ • Auto-fix  │     │
│  │ • Scan files│    │ • Categorize│    │ • Log manual│     │
│  │ • Compare   │    │ • Prioritize│    │ • Commit    │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│         │                                     │             │
│         ▼                                     ▼             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    REPORT                            │   │
│  │  • Quality Score  • Recommendations  • JSON Export   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

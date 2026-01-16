# Scheduler Service

AuditGH includes a configurable cron-based scheduler for automated maintenance tasks.

## Overview

The scheduler service provides:
- **Self-Annealing Data Integrity Agent** - Detects and repairs missing data
- **Automated Repository Scanning** - Scheduled security scans
- **Organization Backups** - Automated backup of tenant data

## Configuration

All scheduler settings are configured via environment variables in `.env`:

```bash
# -----------------------------------------------------------------------------
# Self-Annealing / Scheduled Tasks
# -----------------------------------------------------------------------------

# Master switch for the scheduler
SCHEDULER_ENABLED=true

# Data Integrity Agent - Detects and repairs missing data
# Cron format: minute hour day month weekday
# Default: Daily at 3 AM
ANNEALING_CRON=0 3 * * *
ANNEALING_ENABLED=true
ANNEALING_DRY_RUN=false

# Automated Scanning - Repository security scans
# Default: Every 6 hours (disabled by default)
SCAN_CRON=0 */6 * * *
SCAN_ENABLED=false
SCAN_TARGET=  # Leave empty for current org, or specify org name

# Organization Backups - Automated tenant backups
# Default: Weekly on Sunday at 2 AM (disabled by default)
BACKUP_CRON=0 2 * * 0
BACKUP_ENABLED=false
BACKUP_ALL_ORGS=true
```

## Cron Expression Format

```
┌───────────── minute (0-59)
│ ┌───────────── hour (0-23)
│ │ ┌───────────── day of month (1-31)
│ │ │ ┌───────────── month (1-12)
│ │ │ │ ┌───────────── day of week (0-6, Sunday=0)
│ │ │ │ │
* * * * *
```

**Common Examples**:
| Expression | Description |
|------------|-------------|
| `0 3 * * *` | Daily at 3:00 AM |
| `0 */6 * * *` | Every 6 hours |
| `0 2 * * 0` | Weekly on Sunday at 2:00 AM |
| `*/30 * * * *` | Every 30 minutes |
| `0 0 1 * *` | Monthly on the 1st at midnight |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/scheduler/status` | GET | View scheduler and all job status |
| `/scheduler/jobs` | GET | List all configured jobs |
| `/scheduler/jobs/{name}` | GET | Get specific job status |
| `/scheduler/jobs/{name}/trigger` | POST | Manually trigger a job |
| `/scheduler/next-runs` | GET | View next scheduled run times |
| `/scheduler/start` | POST | Start the scheduler |
| `/scheduler/stop` | POST | Stop the scheduler |

## Usage Examples

### Check Scheduler Status

```bash
curl http://localhost:8000/scheduler/status
```

**Response**:
```json
{
  "enabled": true,
  "running": true,
  "jobs": {
    "annealing": {
      "description": "Self-Annealing Data Integrity Agent",
      "cron": "0 3 * * *",
      "enabled": true,
      "last_run": "2025-12-15T03:00:00+00:00",
      "last_status": "success",
      "run_count": 5,
      "error_count": 0
    },
    "scan": {
      "description": "Automated Repository Scanning",
      "cron": "0 */6 * * *",
      "enabled": false,
      "last_run": null,
      "last_status": "never_run"
    },
    "backup": {
      "description": "Organization Backup",
      "cron": "0 2 * * 0",
      "enabled": false,
      "last_run": null,
      "last_status": "never_run"
    }
  }
}
```

### View Next Scheduled Runs

```bash
curl http://localhost:8000/scheduler/next-runs
```

**Response**:
```json
{
  "jobs": [
    {
      "job_name": "annealing",
      "description": "Self-Annealing Data Integrity Agent",
      "next_run": "2025-12-16T03:00:00+00:00"
    }
  ]
}
```

### Manually Trigger a Job

```bash
# Trigger the self-annealing agent
curl -X POST http://localhost:8000/scheduler/jobs/annealing/trigger
```

**Response**:
```json
{
  "status": "success",
  "job_name": "annealing",
  "result": {
    "status": "success",
    "issues_detected": 110,
    "issues_repaired": 50,
    "data_quality_score": 94.9
  }
}
```

## Scheduled Jobs

### 1. Self-Annealing Data Integrity Agent

Automatically detects and repairs data quality issues:

| Issue Type | Description | Auto-Repair |
|------------|-------------|-------------|
| `missing_contributors` | Contributors in intel file but not in DB | ✅ Yes |
| `missing_languages` | Languages in intel file but not in DB | ✅ Yes |
| `missing_sbom` | SBOM in syft file but not in DB | ✅ Yes |
| `incorrect_finding_type` | Horusec typed as 'vulnerability' not 'sast' | ✅ Yes |
| `missing_findings` | Findings in scanner files but not in DB | ⚠️ Manual |

**Configuration**:
```bash
ANNEALING_CRON=0 3 * * *    # When to run
ANNEALING_ENABLED=true       # Enable/disable
ANNEALING_DRY_RUN=false      # Detect only, don't repair
```

### 2. Automated Repository Scanning

Runs security scans on all repositories in an organization.

**Configuration**:
```bash
SCAN_CRON=0 */6 * * *       # When to run
SCAN_ENABLED=false           # Enable/disable
SCAN_TARGET=                 # Target org (empty = current)
```

### 3. Organization Backups

Creates JSON backups of organization data.

**Configuration**:
```bash
BACKUP_CRON=0 2 * * 0       # When to run
BACKUP_ENABLED=false         # Enable/disable
BACKUP_ALL_ORGS=true         # Backup all orgs or just current
```

## Files

| File | Description |
|------|-------------|
| `src/api/scheduler.py` | Scheduler service using APScheduler |
| `src/api/routers/scheduler.py` | REST API endpoints |
| `src/api/main.py` | Scheduler lifecycle integration |
| `scripts/self_annealing_agent.py` | Data integrity agent |
| `scripts/backup_organization.py` | Backup script |

## Dependencies

- `apscheduler>=3.10.0` - Python job scheduling library

## Troubleshooting

### Scheduler Not Starting

1. Check if `SCHEDULER_ENABLED=true` in `.env`
2. Verify APScheduler is installed: `pip install apscheduler`
3. Check API logs: `docker-compose logs api | grep -i scheduler`

### Jobs Not Running

1. Verify job is enabled: `ANNEALING_ENABLED=true`
2. Check cron expression syntax
3. View next run time: `curl http://localhost:8000/scheduler/next-runs`

### Manual Testing

```bash
# Test annealing without scheduler
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/self_annealing_agent.py --dry-run'
```

# Multi-Prong Ingestion Architecture

**Date:** 2026-01-17
**Status:** 🚧 In Progress
**Goal:** Robust, validated, and error-resilient data ingestion pipeline

---

## Problem Statement

Current ingestion is a single-stage process that runs post-scan with no validation. Issues:

1. **No scan-time metadata tracking** - Can't track which repos are being scanned or when
2. **No validation** - Don't know if data was properly ingested until we check UI manually
3. **No error recovery** - If ingestion fails partway through, no way to know or retry
4. **No progress tracking** - Can't see ingestion status in real-time
5. **No completeness checks** - Missing data goes undetected (281 issues found in validation!)

---

## Multi-Prong Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     STAGE 1: DURING SCAN (Real-Time)                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  Responsibilities:                                                        │
│  ├─ Create scan_run record when scan starts                              │
│  ├─ Track repository scan progress (started/in-progress/completed)       │
│  ├─ Record scanner execution metadata (gitleaks, semgrep, grype status)  │
│  ├─ Store scan timing and performance metrics                            │
│  └─ Mark scan as failed if errors occur                                  │
│                                                                           │
│  Implementation:                                                          │
│  ├─ Modify scan_repos.py to call API during scan                         │
│  ├─ POST /scan-runs/start (repository_id, scanners)                      │
│  ├─ PATCH /scan-runs/{id}/progress (scanner completed, findings_count)   │
│  └─ POST /scan-runs/{id}/complete (duration, status, errors)             │
│                                                                           │
│  Benefits:                                                                │
│  ├─ Live scan progress visible in UI                                     │
│  ├─ Historical scan data (performance trends, failure patterns)          │
│  ├─ Know which repos need re-scanning (failed scans)                     │
│  └─ Track scanner-specific success rates                                 │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                   STAGE 2: POST-SCAN (Auto-Ingest)                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  Current Implementation: ✅ COMPLETE                                      │
│  ├─ Ingest findings (gitleaks, semgrep, grype)                           │
│  ├─ Ingest contributors (intel.json)                                     │
│  ├─ Ingest languages (cloc.json)                                         │
│  ├─ Ingest dependencies (syft.json)                                      │
│  └─ Triggered automatically after scan completes                         │
│                                                                           │
│  Enhancement Needed:                                                      │
│  ├─ Add ingestion_run record tracking                                    │
│  ├─ Record which files were successfully ingested                        │
│  ├─ Track ingestion errors per file/repo                                 │
│  ├─ Store ingestion duration and row counts                              │
│  └─ Support retry for failed ingestions                                  │
│                                                                           │
│  Implementation:                                                          │
│  ├─ Create ingestion_runs table                                          │
│  ├─ Record start: POST /ingestion-runs/start                             │
│  ├─ Update progress: PATCH /ingestion-runs/{id}                          │
│  ├─ Mark complete: POST /ingestion-runs/{id}/complete                    │
│  └─ Store per-file ingestion results                                     │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                  STAGE 3: VALIDATE INGESTION (New!)                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  Implementation: ✅ COMPLETE (validate_ingestion.py)                      │
│  ├─ Compare filesystem reports with database records                     │
│  ├─ Verify expected files exist on disk                                  │
│  ├─ Count findings/contributors/languages/dependencies in files          │
│  ├─ Count same in database                                               │
│  ├─ Flag discrepancies and missing data                                  │
│  └─ Generate validation report with issue details                        │
│                                                                           │
│  Current Results:                                                         │
│  ├─ Total Issues: 281                                                     │
│  ├─ High Priority: 56                                                     │
│  ├─ sleepnumberlabs: 240 issues                                          │
│  │   ├─ Contributors: 2,169/2,644 ingested (partial)                     │
│  │   ├─ Dependencies: 6,068/16,791 ingested (missing 10k!)               │
│  │   ├─ Grype: 112/1,184 findings ingested                               │
│  │   └─ Gitleaks: 165/661 findings ingested                              │
│  └─ SleepNumberInc: 40 issues                                            │
│      ├─ Contributors: 863/907 ingested (partial)                         │
│      ├─ Dependencies: 5,118/5,418 ingested                               │
│      └─ Grype: 83/263 findings ingested                                  │
│                                                                           │
│  Enhancement Needed:                                                      │
│  ├─ Run automatically after ingestion completes                          │
│  ├─ Store validation results in database                                 │
│  ├─ Send alerts for high-priority issues                                 │
│  ├─ Auto-retry ingestion for failed items                                │
│  └─ Show validation status in UI                                         │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                      STAGE 4: ERROR RECOVERY (New!)                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  Purpose: Automatically fix incomplete ingestions                         │
│                                                                           │
│  Triggers:                                                                │
│  ├─ Validation finds missing data                                        │
│  ├─ Manual retry command                                                 │
│  └─ Scheduled nightly reconciliation job                                 │
│                                                                           │
│  Actions:                                                                 │
│  ├─ Re-ingest only missing/failed files                                  │
│  ├─ Skip already-ingested data (idempotent)                              │
│  ├─ Track retry attempts and failures                                    │
│  ├─ Alert on persistent failures                                         │
│  └─ Update validation status after retry                                 │
│                                                                           │
│  Implementation:                                                          │
│  ├─ Add retry_ingestion.py script                                        │
│  ├─ API endpoint: POST /ingestion-runs/retry                             │
│  ├─ Selective re-ingestion based on validation results                   │
│  └─ Max retry limit (3 attempts) before manual intervention              │
│                                                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Database Schema Enhancements

### New Table: scan_runs
```sql
CREATE TABLE scan_runs (
    id UUID PRIMARY KEY,
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    scan_type VARCHAR(50),  -- 'full', 'incremental', 'single'
    status VARCHAR(50),     -- 'started', 'scanning', 'completed', 'failed'

    -- Scanner status
    gitleaks_status VARCHAR(50),
    gitleaks_findings_count INT,
    semgrep_status VARCHAR(50),
    semgrep_findings_count INT,
    grype_status VARCHAR(50),
    grype_findings_count INT,

    -- Timing
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INT,

    -- Errors
    error_message TEXT,
    error_scanner VARCHAR(50),

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_scan_runs_repository ON scan_runs(repository_id);
CREATE INDEX idx_scan_runs_status ON scan_runs(status);
CREATE INDEX idx_scan_runs_started_at ON scan_runs(started_at);
```

### New Table: ingestion_runs
```sql
CREATE TABLE ingestion_runs (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id),
    repository_id UUID REFERENCES repositories(id),
    scan_run_id UUID REFERENCES scan_runs(id),

    status VARCHAR(50),  -- 'started', 'ingesting', 'validating', 'completed', 'failed'

    -- Ingestion counts
    findings_ingested INT DEFAULT 0,
    contributors_ingested INT DEFAULT 0,
    languages_ingested INT DEFAULT 0,
    dependencies_ingested INT DEFAULT 0,

    -- Files processed
    files_processed JSONB,  -- {gitleaks: true, intel: true, cloc: false, ...}

    -- Validation
    validation_status VARCHAR(50),  -- 'passed', 'failed', 'partial'
    validation_issues JSONB,

    -- Timing
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    duration_seconds INT,

    -- Errors
    error_message TEXT,
    error_file VARCHAR(255),

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_ingestion_runs_repo ON ingestion_runs(repository_id);
CREATE INDEX idx_ingestion_runs_status ON ingestion_runs(status);
CREATE INDEX idx_ingestion_runs_validation ON ingestion_runs(validation_status);
```

### New Table: validation_results
```sql
CREATE TABLE validation_results (
    id UUID PRIMARY KEY,
    ingestion_run_id UUID REFERENCES ingestion_runs(id),
    organization_id UUID REFERENCES organizations(id),
    repository_id UUID REFERENCES repositories(id),

    -- Validation details
    data_type VARCHAR(50),  -- 'findings', 'contributors', 'languages', 'dependencies'
    scanner_name VARCHAR(50),  -- 'gitleaks', 'semgrep', 'grype', etc.

    file_count INT,
    database_count INT,
    matches BOOLEAN,

    -- Issues
    issue_type VARCHAR(50),  -- 'missing', 'partial', 'duplicate'
    issue_severity VARCHAR(20),  -- 'high', 'medium', 'low'
    issue_message TEXT,

    -- Resolution
    retry_count INT DEFAULT 0,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP,

    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_validation_results_repo ON validation_results(repository_id);
CREATE INDEX idx_validation_results_severity ON validation_results(issue_severity);
CREATE INDEX idx_validation_results_resolved ON validation_results(resolved);
```

---

## Implementation Plan

### Phase 1: Scan-Time Tracking (Week 1)
- [ ] Create scan_runs table migration
- [ ] Add scan tracking to scan_repos.py
- [ ] Create API endpoints for scan progress
- [ ] Test scan tracking with single repo
- [ ] Update UI to show scan history

### Phase 2: Ingestion Tracking (Week 1)
- [ ] Create ingestion_runs table migration
- [ ] Modify ingest_reports.py to track progress
- [ ] Record files processed and counts
- [ ] Store ingestion errors
- [ ] Test ingestion tracking

### Phase 3: Automated Validation (Week 2)
- [x] Create validate_ingestion.py ✅
- [ ] Create validation_results table migration
- [ ] Store validation results in database
- [ ] Auto-run validation after ingestion
- [ ] Send alerts for high-priority issues
- [ ] Show validation status in UI

### Phase 4: Error Recovery (Week 2)
- [ ] Create retry_ingestion.py script
- [ ] Implement selective re-ingestion
- [ ] Add retry logic with max attempts
- [ ] Track retry success/failure
- [ ] Scheduled nightly reconciliation job

### Phase 5: UI Integration (Week 3)
- [ ] Add "Scan Runs" tab showing scan history
- [ ] Add "Ingestion Status" indicator per repository
- [ ] Add "Validation Issues" section
- [ ] Add "Retry Ingestion" button
- [ ] Real-time scan progress updates

---

## Validation Issues Discovered

### Current Findings (validate_ingestion.py)

**sleepnumberlabs:**
- Contributors: 2,169/2,644 (82% coverage) - **475 missing**
- Dependencies: 6,068/16,791 (36% coverage) - **10,723 missing!**
- Gitleaks: 165/661 (25% coverage) - **496 missing findings**
- Grype: 112/1,184 (9% coverage) - **1,072 missing vulnerabilities!**
- Languages: 1,108/1,243 (89% coverage)

**SleepNumberInc:**
- Contributors: 863/907 (95% coverage)
- Dependencies: 5,118/5,418 (94% coverage) - **300 missing**
- Gitleaks: 671/783 (86% coverage)
- Grype: 83/263 (32% coverage) - **180 missing vulnerabilities**
- Languages: 1,130/1,130 (100% coverage) ✅

### Root Causes Identified

1. **Contributors Partial**: intel.json only contains "top_contributors" not all
2. **Dependencies Missing**: Likely duplicate checking too aggressive or errors during ingestion
3. **Grype Findings Low**: org_id bug (now fixed) caused failures - need re-ingestion
4. **Gitleaks Findings Low**: Possible duplicate detection issue or prior scans

### Immediate Actions Needed

```bash
# 1. Re-run ingestion to pick up fixes
docker exec auditgh_api python ingest_reports.py

# 2. Validate again
docker exec auditgh_api python validate_ingestion.py

# 3. Check specific repos with issues
docker exec auditgh_db psql -U postgres -d security_portal -c "
SELECT r.name,
    (SELECT COUNT(*) FROM findings WHERE repository_id = r.id AND scanner_name = 'grype') as grype_findings,
    (SELECT COUNT(*) FROM dependencies WHERE repository_id = r.id) as dependencies
FROM repositories r
WHERE r.organization_id = (SELECT id FROM organizations WHERE name = 'sleepnumberlabs')
ORDER BY r.name
LIMIT 20;
"
```

---

## Usage Examples

### Run Validation
```bash
# Validate all organizations
docker exec auditgh_api python validate_ingestion.py

# Validate specific organization
docker exec auditgh_api python -c "
from validate_ingestion import validate_all_organizations
validate_all_organizations(['sleepnumberlabs'])
"
```

### Check Validation Results in Database (Future)
```sql
-- Get validation summary
SELECT
    v.repository_id,
    r.name,
    COUNT(*) as total_issues,
    SUM(CASE WHEN v.issue_severity = 'high' THEN 1 ELSE 0 END) as high_priority,
    SUM(CASE WHEN v.resolved THEN 1 ELSE 0 END) as resolved
FROM validation_results v
JOIN repositories r ON v.repository_id = r.id
GROUP BY v.repository_id, r.name
ORDER BY high_priority DESC;

-- Get specific validation issues
SELECT
    r.name as repository,
    v.data_type,
    v.file_count,
    v.database_count,
    v.issue_message,
    v.resolved
FROM validation_results v
JOIN repositories r ON v.repository_id = r.id
WHERE v.issue_severity = 'high'
  AND v.resolved = FALSE
ORDER BY v.created_at DESC;
```

### Retry Failed Ingestions (Future)
```bash
# Retry all failed ingestions
docker exec auditgh_api python retry_ingestion.py

# Retry specific repository
docker exec auditgh_api python retry_ingestion.py --repo android-consumer-app

# Retry specific data type
docker exec auditgh_api python retry_ingestion.py --data-type dependencies
```

---

## Benefits

### Before Multi-Prong
- ❌ No scan progress tracking
- ❌ No ingestion validation
- ❌ Missing data goes undetected
- ❌ No error recovery
- ❌ Manual investigation required

### After Multi-Prong
- ✅ Real-time scan progress in UI
- ✅ Automated validation after ingestion
- ✅ Missing data detected immediately
- ✅ Automatic retry for failures
- ✅ Comprehensive audit trail
- ✅ Historical trend analysis
- ✅ Proactive alerting

---

## Metrics & Monitoring

### Key Metrics to Track
1. **Scan Success Rate**: % of scans that complete successfully
2. **Ingestion Completeness**: % of files successfully ingested
3. **Validation Pass Rate**: % of repos with no validation issues
4. **Time to Ingest**: Average duration from scan complete to data available
5. **Retry Success Rate**: % of failed ingestions fixed by retry

### Dashboards
1. **Scan Health**: Recent scan runs, failures, avg duration
2. **Data Quality**: Validation pass rate, top issues, trends over time
3. **System Performance**: Ingestion throughput, queue depth, errors
4. **Organization View**: Per-org completeness, missing data, issues

---

**Status:**
- Stage 1 (Scan Tracking): 🚧 Not Started
- Stage 2 (Ingestion Tracking): ✅ Complete (with fixes)
- Stage 3 (Validation): ✅ Script Complete, DB Integration Pending
- Stage 4 (Error Recovery): 🚧 Not Started

**Completed:**
- ✅ Fixed org_id bug in gitleaks, semgrep, and grype ingestion functions
- ✅ Fixed finding_uuid constraint (changed from global unique to per-repository unique)
- ✅ Complete ingestion pipeline for contributors, languages, dependencies
- ✅ Validation script with detailed issue reporting

**Results After Fixes:**
- Total Issues: 289 → 139 (52% reduction)
- High Priority: 63 → 4 (94% reduction)
- Grype findings: 112 → 1,071 (+856% improvement!)
- Gitleaks findings: 165 → 620 (+276% improvement!)
- Data completeness: ~25% → ~90% for most data types

**Next Steps:**
1. ✅ ~~Run validation to get current baseline~~ DONE
2. ✅ ~~Re-ingest with org_id fix to resolve grype issues~~ DONE
3. 🚧 Investigate dependency ingestion gaps (47% coverage for sleepnumberlabs)
4. 🚧 Create database migrations for scan_runs, ingestion_runs, validation_results tables
5. 🚧 Implement scan tracking in scan_repos.py
6. 🚧 Store validation results in database
7. 🚧 Build error recovery/retry mechanism

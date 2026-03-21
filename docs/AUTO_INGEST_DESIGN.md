# Auto-Ingest Design: Coupling Scan and Data Ingestion

**Date:** 2026-01-16
**Issue:** Scanned data is not automatically ingested into the database, requiring manual intervention
**Goal:** Seamlessly integrate scanning and ingestion so data is immediately available in the Web UI

---

## Problem Statement

Currently, the workflow requires two separate steps:

```bash
# Step 1: Scan repositories
docker-compose run --rm scanner --target myorg

# Step 2: Manually ingest results (EASY TO FORGET!)
docker exec auditgh_api python ingest_reports.py
```

**Issues:**
1. Users forget to run ingestion
2. Data doesn't appear in UI immediately after scanning
3. Two-step process is error-prone
4. No indication that ingestion is needed

**Recent Example:**
- example-org: 1,878 repos scanned
- Database showed only 1 repo (old data)
- All 1,877 new repos were in JSON files but not ingested

---

## Solution Options

### Option 1: Post-Scan Hook (Recommended) ⭐

**Description:** Scanner automatically calls ingestion after completing all scans

**Pros:**
- ✅ Single command workflow
- ✅ Immediate data availability
- ✅ No user intervention needed
- ✅ Works in all environments (Docker, local, CI/CD)
- ✅ Clear success/failure feedback

**Cons:**
- ⚠️ Adds time to scanner execution
- ⚠️ Requires database connection from scanner
- ⚠️ Scanner failure also fails ingestion

**Implementation:**

Add to `scan_repos.py` after scan summary (line ~5850):

```python
# After scan summary is printed
logging.info("=" * 80)
logging.info("Scan Summary")
logging.info("=" * 80)
logging.info(f"Total repositories: {scan_results['total']}")
logging.info(f"Successful: {scan_results['success']}")
logging.info("=" * 80)

# AUTO-INGEST: Automatically load scan results into database
if not args.dry_run and scan_results['success'] > 0:
    logging.info("=" * 80)
    logging.info("Auto-Ingesting Scan Results")
    logging.info("=" * 80)

    try:
        # Import ingestion functions
        import sys
        sys.path.insert(0, '/app')
        from ingest_reports import ingest_organization

        # Get organization name
        org_name = args.target or args.org or config.ORG_NAME

        # Run ingestion
        logging.info(f"Ingesting data for organization: {org_name}")
        ingest_organization(org_name, config.REPORT_DIR)
        logging.info("✅ Data ingestion completed successfully")

    except Exception as e:
        logging.error(f"❌ Auto-ingestion failed: {e}")
        logging.error("Run manually: docker exec auditgh_api python ingest_reports.py")

    logging.info("=" * 80)
```

**Add flag to disable:**
```python
parser.add_argument("--no-auto-ingest", action="store_true",
                    help="Disable automatic data ingestion after scan")
```

---

### Option 2: Docker Compose Post-Scan Service

**Description:** Docker Compose runs ingestion service after scanner completes

**docker-compose.yml:**
```yaml
services:
  scanner:
    # existing scanner config

  ingest:
    build:
      context: .
      dockerfile: Dockerfile.api
    command: python ingest_reports.py
    volumes:
      - ./vulnerability_reports:/app/vulnerability_reports
    depends_on:
      - db
      - scanner
    environment:
      - DATABASE_URL=${DATABASE_URL}
    profiles:
      - scan
```

**Usage:**
```bash
# Both scanner and ingestion run automatically
docker-compose --profile scan up scanner ingest
```

**Pros:**
- ✅ Separation of concerns
- ✅ Scanner doesn't need DB access
- ✅ Can retry ingestion independently

**Cons:**
- ❌ Requires Docker Compose
- ❌ Doesn't work for local CLI usage
- ❌ More complex orchestration

---

### Option 3: Background Ingestion Worker

**Description:** API watches for new scan reports and auto-ingests

**Implementation:**
- FastAPI background task monitors `/vulnerability_reports/`
- Detects new/modified JSON files
- Automatically ingests on file change
- Uses file system watcher (watchdog)

**Pros:**
- ✅ Truly automatic (no manual trigger)
- ✅ Works for any scan source
- ✅ Parallel ingestion while scanning

**Cons:**
- ❌ Complex implementation
- ❌ Resource intensive (file watching)
- ❌ Race conditions possible
- ❌ Harder to debug failures

---

### Option 4: API Endpoint for Scan + Ingest

**Description:** Create unified API endpoint that orchestrates both

**New endpoint:** `POST /scan-and-ingest`

```python
@router.post("/scan-and-ingest")
async def scan_and_ingest(
    organization: str,
    rescan_days: int = None,
    background_tasks: BackgroundTasks
):
    # 1. Trigger scanner via subprocess
    # 2. Wait for completion
    # 3. Run ingestion
    # 4. Return combined results
```

**Pros:**
- ✅ Single API call
- ✅ Unified error handling
- ✅ Progress tracking

**Cons:**
- ❌ Long-running API request (timeout issues)
- ❌ Scanner must run in API container
- ❌ Resource contention

---

## Recommended Implementation: Option 1 (Enhanced)

### Phase 1: Basic Auto-Ingest

Add automatic ingestion to `scan_repos.py` with opt-out flag:

```python
# After line ~5850 (after scan summary)
def auto_ingest_results(org_name: str, report_dir: str, dry_run: bool = False):
    """
    Automatically ingest scan results into database.

    Args:
        org_name: Organization name
        report_dir: Directory containing scan reports
        dry_run: If True, skip ingestion
    """
    if dry_run:
        logging.info("Skipping auto-ingest (dry-run mode)")
        return

    try:
        logging.info("=" * 80)
        logging.info("AUTO-INGEST: Loading results into database")
        logging.info("=" * 80)

        # Import ingestion module
        import sys
        sys.path.insert(0, '/app')
        from ingest_reports import ingest_all_organizations

        # Run ingestion
        logging.info(f"Ingesting reports from: {report_dir}")
        results = ingest_all_organizations(report_dir)

        # Report results
        for org, stats in results.items():
            logging.info(f"  {org}: {stats['repos']} repos, {stats['findings']} findings")

        logging.info("✅ Auto-ingest completed successfully")
        logging.info("=" * 80)
        return True

    except ImportError as e:
        logging.warning(f"⚠️  Auto-ingest unavailable: {e}")
        logging.warning("   Run manually: docker exec auditgh_api python ingest_reports.py")
        return False

    except Exception as e:
        logging.error(f"❌ Auto-ingest failed: {e}")
        logging.error("   Run manually: docker exec auditgh_api python ingest_reports.py")
        return False

# Call after scan completes
if not args.no_auto_ingest:
    auto_ingest_results(
        org_name=args.target or args.org or config.ORG_NAME,
        report_dir=config.REPORT_DIR,
        dry_run=args.dry_run
    )
```

### Phase 2: Smart Ingestion

Only ingest files modified since last scan:

```python
def auto_ingest_results_incremental(org_name: str, report_dir: str, since_timestamp: float):
    """Ingest only new/modified reports since timestamp."""
    new_reports = []

    org_dir = os.path.join(report_dir, org_name)
    for repo_dir in os.listdir(org_dir):
        report_path = os.path.join(org_dir, repo_dir)
        if os.path.getmtime(report_path) > since_timestamp:
            new_reports.append(report_path)

    # Ingest only new reports
    ingest_specific_reports(new_reports)
```

### Phase 3: Progress Feedback

Show real-time ingestion progress:

```python
def auto_ingest_with_progress(org_name: str, report_dir: str):
    """Ingest with progress bar."""
    from tqdm import tqdm

    reports = find_all_reports(org_name, report_dir)

    with tqdm(total=len(reports), desc="Ingesting") as pbar:
        for report in reports:
            ingest_single_report(report)
            pbar.update(1)
```

---

## Migration Plan

### Step 1: Update Scanner (Week 1)
- Add `auto_ingest_results()` function to scan_repos.py
- Add `--no-auto-ingest` flag
- Default: auto-ingest enabled
- Test with single repo

### Step 2: Update Ingestion Script (Week 1)
- Make `ingest_reports.py` importable as module
- Add function: `ingest_all_organizations()`
- Return structured results dict
- Add incremental mode support

### Step 3: Update Documentation (Week 1)
- Update README.md
- Update CHEATSHEET.md
- Add AUTO_INGEST.md guide
- Update troubleshooting docs

### Step 4: Rollout (Week 2)
- Deploy to dev environment
- Test with both organizations
- Monitor for issues
- Gather feedback

### Step 5: Enhancements (Week 3+)
- Add incremental ingestion
- Add progress feedback
- Add Slack/email notifications
- Add retry logic

---

## Usage Examples

### Before (Current):
```bash
# Two separate commands
docker-compose run --rm scanner --target myorg
docker exec auditgh_api python ingest_reports.py  # EASY TO FORGET!
```

### After (Auto-Ingest):
```bash
# Single command - everything handled
docker-compose run --rm scanner --target myorg

# Output:
# ================================================================================
# Scan Summary
# ================================================================================
# Total repositories: 1871
# Successful: 1871
# ================================================================================
# AUTO-INGEST: Loading results into database
# ================================================================================
# Ingesting reports from: /app/vulnerability_reports
#   example-org: 1871 repos, 754 findings
# ✅ Auto-ingest completed successfully
# ================================================================================
```

### Disable Auto-Ingest (if needed):
```bash
docker-compose run --rm scanner --target myorg --no-auto-ingest
```

---

## Backward Compatibility

- Default behavior changes to auto-ingest
- `--no-auto-ingest` flag for old behavior
- Manual ingestion still works: `docker exec auditgh_api python ingest_reports.py`
- Existing workflows unaffected (just faster)

---

## Error Handling

1. **Database unavailable:** Log warning, continue (manual ingest later)
2. **Ingestion fails:** Log error with manual command, don't fail scan
3. **Partial ingestion:** Track progress, resume from last successful
4. **Permission errors:** Log clear message with fix instructions

---

## Success Criteria

- ✅ Single command workflow
- ✅ Data appears in UI immediately after scan
- ✅ Zero manual intervention needed
- ✅ Clear feedback on success/failure
- ✅ Opt-out available if needed
- ✅ Works in all environments (Docker, local, CI/CD)

---

## Implementation Checklist

- [ ] Add auto_ingest_results() to scan_repos.py
- [ ] Add --no-auto-ingest flag
- [ ] Make ingest_reports.py importable
- [ ] Add structured return values
- [ ] Update CHEATSHEET.md
- [ ] Update README.md
- [ ] Add error handling
- [ ] Add progress feedback
- [ ] Test with both orgs
- [ ] Document rollback procedure

---

## Rollback Plan

If auto-ingest causes issues:

```bash
# Temporary: Use --no-auto-ingest flag
docker-compose run --rm scanner --target myorg --no-auto-ingest

# Permanent: Revert scan_repos.py
git checkout HEAD~1 scan_repos.py
docker-compose build scanner
```

---

**Recommendation:** Implement Option 1 (Post-Scan Hook) with incremental ingestion and progress feedback. This provides the best balance of simplicity, reliability, and user experience.

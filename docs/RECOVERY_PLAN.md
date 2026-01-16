# Recovery Plan: Schema Drift and Feature Restoration

## Executive Summary

The multi-tenant framework implementation caused schema drift and data ingestion issues that affected the UI/UX presentation of findings. This plan outlines the steps to restore proper functionality while preserving the multi-tenant capability.

---

## Root Cause Analysis

### Issue 1: Findings Display Incorrect
- **Symptom**: On `/findings/{id}`, the description shows evidence/results instead of what the finding is about
- **Cause**: `ingest_horusec()` and other ingest functions are putting scanner output in wrong fields
  - `title` contains: vulnerability name + description (concatenated)
  - `description` contains: evidence/code snippet
- **Expected**:
  - `title`: Short vulnerability name (e.g., "Password found in hardcoded URL")
  - `description`: What the vulnerability is and why it matters
  - `code_snippet` or `evidence`: The actual code/data found

### Issue 2: Repositories Page Shows "No Results"
- **Symptom**: `/repositories` shows "No results found" despite 62 repos in DB
- **Cause**: DataTable localStorage filter persistence has stale filters
- **Fix**: Clear browser localStorage for `table-filters-repositories`

### Issue 3: Multi-Tenant Selector Confusion
- **Symptom**: `auditbamgh` appeared as a tenant name
- **Cause**: Confusion between repo names and organization names
- **Status**: RESOLVED - `auditbamgh` is a repo in `sealmindset` org, not a tenant

### Issue 4: Credential-URL Testing Not Implemented
- **Symptom**: Original feature request for AI-powered credential testing incomplete
- **Cause**: Focus shifted to multi-tenant framework before completing credential testing
- **Status**: Table `credential_url_test_results` exists but no testing logic implemented

---

## Recovery Plan

### Phase 1: Fix Data Ingestion (Priority: HIGH)
**Goal**: Ensure findings are ingested with correct field mapping

1. **Audit ingest functions** in `ingest_scans.py`:
   - `ingest_horusec()` - Fix title/description/evidence mapping
   - `ingest_whispers()` - Verify field mapping
   - `ingest_bearer()` - Verify field mapping
   - `ingest_trivy()` - Verify field mapping
   - All other ingest functions

2. **Add `evidence` or `code_snippet` field** if not properly used:
   - Scanner output/code should go in `code_snippet`
   - Human-readable explanation should go in `description`

3. **Re-ingest test data** after fixes to verify

### Phase 2: Fix UI Display (Priority: HIGH)
**Goal**: Ensure findings page displays data correctly

1. **Review `/findings/[id]/page.tsx`**:
   - Ensure `description` displays vulnerability explanation
   - Ensure `code_snippet` displays evidence
   - Add separate "Evidence" section if needed

2. **Clear stale localStorage filters**:
   - Add "Reset Filters" button to DataTable
   - Or document manual clear process

### Phase 3: Complete Credential-URL Testing (Priority: MEDIUM)
**Goal**: Implement AI-powered credential testing feature

1. **Review existing schema** (`credential_url_test_results` table)
2. **Implement credential testing logic**:
   - Extract credentials from findings (secrets scanners)
   - Map credentials to discovered API endpoints
   - AI-powered test generation
   - Safe execution with rate limiting
   - Result storage and reporting

3. **Add UI for credential testing**:
   - View test results
   - Trigger manual tests
   - Configure test policies

### Phase 4: Stabilize Multi-Tenant Framework (Priority: MEDIUM)
**Goal**: Ensure multi-tenant works correctly without breaking existing features

1. **Verify organization filtering** in all API endpoints
2. **Test organization switching** in UI
3. **Ensure scan data is properly scoped** to organizations
4. **Document multi-tenant usage** clearly

---

## Execution Order

```
Week 1: Phase 1 + Phase 2 (Fix data ingestion and UI)
Week 2: Phase 4 (Stabilize multi-tenant)
Week 3+: Phase 3 (Credential testing feature)
```

---

## Immediate Actions

### Action 1: Fix Horusec Ingestion
The `ingest_horusec()` function needs to properly parse Horusec output:
- Horusec `details` → `title` (short name)
- Horusec `description` → `description` (what it is)
- Horusec `code` → `code_snippet` (evidence)

### Action 2: Clear Browser Cache
Users should clear localStorage:
1. Open DevTools (F12)
2. Application → Local Storage
3. Delete keys starting with `table-filters-`

### Action 3: Re-run Ingestion
After fixing ingest functions:
```bash
# Clear existing findings
docker-compose exec -T db psql -U postgres -d auditgh_kb -c "DELETE FROM findings;"

# Re-ingest from existing reports
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 ingest_scans.py --repo-name auditbamgh --repo-dir /app/vulnerability_reports/auditbamgh'
```

---

## Files to Modify

| File | Change |
|------|--------|
| `ingest_scans.py` | Fix field mapping in all ingest functions |
| `src/web-ui/app/findings/[id]/page.tsx` | Add Evidence section, fix Description display |
| `src/web-ui/components/data-table.tsx` | Add "Reset Filters" button |
| `src/api/routers/findings.py` | Ensure `code_snippet` is returned in API |

---

## Verification Checklist

- [ ] Findings display proper title (short vulnerability name)
- [ ] Findings display proper description (what the vulnerability is)
- [ ] Findings display evidence/code snippet separately
- [ ] Repositories page shows all 62 repos
- [ ] Organization selector works correctly
- [ ] Scans are scoped to correct organization
- [ ] Credential-URL testing table is populated (Phase 3)

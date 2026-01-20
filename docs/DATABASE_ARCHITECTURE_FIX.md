# Database Architecture Fix - January 2026

## Problem

The system had **two conflicting database architectures**:

### Old Architecture (Causing Errors)
- Per-organization databases: `org_sleepnumberinc`, `org_sleepnumberlabs`, etc.
- API router trying to connect to these separate databases
- **Error**: `database "org_sleepnumberinc" does not exist`

### New Architecture (Correct)
- Single shared database: `security_portal`
- Data filtered by `organization_id` column
- All ingestion scripts already using this approach

## Root Cause

The API router ([src/api/routers/organizations.py](../src/api/routers/organizations.py)) had two endpoints that were still using the old architecture:

1. `GET /organizations/{org_name}/repositories` - Line 619-671
2. `GET /organizations/{org_name}/findings` - Line 674-737

These endpoints were:
- Reading `org.database_name` from the Organization model
- Creating new database connections: `postgresql://.../{org.database_name}`
- Attempting to query non-existent org-specific databases

## Solution Applied

### 1. Fixed Repository Endpoint

**Before:**
```python
# Connect to org-specific database
org_db_url = db_url.rsplit('/', 1)[0] + '/' + org.database_name
engine = create_engine(org_db_url)
org_db = OrgSession()
repos = org_db.query(models.Repository).all()
```

**After:**
```python
# Query shared database with organization_id filtering
repos = db.query(models.Repository).filter(
    models.Repository.organization_id == org.id
).all()
```

### 2. Fixed Findings Endpoint

**Before:**
```python
# Connect to org-specific database
org_db_url = db_url.rsplit('/', 1)[0] + '/' + org.database_name
engine = create_engine(org_db_url)
org_db = OrgSession()
findings = org_db.query(models.Finding).all()
```

**After:**
```python
# Query shared database with JOIN and organization filtering
findings = db.query(models.Finding).join(
    models.Repository,
    models.Finding.repository_id == models.Repository.id
).filter(
    models.Repository.organization_id == org.id
).all()
```

## Benefits

✅ **No More Database Errors**: System uses only the `security_portal` database that exists
✅ **Consistent Architecture**: All components (ingestion, API, UI) use the same database approach
✅ **Simpler Deployment**: No need to create/manage separate databases per organization
✅ **Better Performance**: Single connection pool instead of multiple database connections
✅ **Easier Maintenance**: One schema to migrate, one database to backup

## Files Modified

- [src/api/routers/organizations.py](../src/api/routers/organizations.py)
  - Line 619-671: `get_organization_repositories()` endpoint
  - Line 674-737: `get_organization_findings()` endpoint

## Testing

After applying the fix:

```bash
# Restart API to apply changes
docker-compose restart api

# Test repositories endpoint
curl -s 'http://localhost:8000/organizations/SleepNumberInc/repositories?limit=5' | jq
# ✅ Returns repositories without database errors

# Test findings endpoint
curl -s 'http://localhost:8000/organizations/SleepNumberInc/findings?limit=5' | jq
# ✅ Returns findings without database errors
```

## Database Schema

The system uses **organization_id filtering** on a shared database:

```sql
-- Organizations table
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255),
    github_org VARCHAR(255),
    database_name VARCHAR(255)  -- Legacy field, kept for reference only
);

-- Repositories table
CREATE TABLE repositories (
    id UUID PRIMARY KEY,
    organization_id UUID REFERENCES organizations(id),  -- Used for filtering
    name VARCHAR(255)
);

-- Findings table
CREATE TABLE findings (
    id UUID PRIMARY KEY,
    repository_id UUID REFERENCES repositories(id)
);

-- Query pattern: Filter by organization_id
SELECT r.*
FROM repositories r
WHERE r.organization_id = :org_id;

-- Join pattern: Get findings for an organization
SELECT f.*
FROM findings f
JOIN repositories r ON f.repository_id = r.id
WHERE r.organization_id = :org_id;
```

## Legacy Compatibility

The `database_name` field in the Organization model is **kept for backward compatibility** but is no longer used for actual database connections. It's only:

1. Stored in the database
2. Returned in API responses
3. Passed to `set_current_org_database()` for logging/context (but not used for connections)

This ensures existing code that reads this field doesn't break.

## Future Cleanup (Optional)

If desired, you can eventually:

1. **Remove database_name field** from Organization model
2. **Remove set_current_org_database()** function (no longer needed)
3. **Update API responses** to not include database_name

However, these are **optional** - the system works correctly with these legacy fields present.

## Summary

The fix changes the API from attempting to connect to multiple per-org databases to using the single shared `security_portal` database with proper filtering. This aligns the API with the existing ingestion architecture and eliminates all "database does not exist" errors.

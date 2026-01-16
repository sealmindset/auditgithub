# Fix Missing Repository URLs

## Problem

The application throws one of these errors:

**Error 1: URL is NULL**
```
Project repository URL is missing
```

**Error 2: URL is set but repo not accessible**
```
Failed to clone repository: Cloning into '/tmp/auditgh_arch_xxx'...
remote: Repository not found.
fatal: repository 'https://github.com/org/repo/' not found
```

These occur when attempting to generate architecture diagrams or perform other operations that require cloning the repository.

---

## Root Causes

### Cause 1: NULL URL in Database

Repositories created before the URL field was added, or imported without URL data, have NULL values in the `url` column.

**Location of error:** `src/api/routers/ai.py` lines 543-544, 790-791

```python
if not project.url:
    raise HTTPException(status_code=400, detail="Project repository URL is missing")
```

### Cause 2: Invalid or Inaccessible URL

The URL is set in the database but:
- The repository was moved or deleted
- The organization name is incorrect
- The repository is private and `GITHUB_TOKEN` lacks access
- The repository is on a different platform (Azure DevOps, GitLab)

### Cause 3: Authentication Issues

Private repositories require a valid `GITHUB_TOKEN` with appropriate permissions.

---

## Solution Overview

1. **Immediate fix:** Update NULL URLs in the database directly
2. **Preventive fix:** Update `ingest_scans.py` to auto-populate missing URLs
3. **Batch fix:** Run a script to fix all missing URLs at once

---

## Implementation

### Option 1: Direct Database Update (Single Repository)

For a single repository, run:

```bash
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "UPDATE repositories SET url = 'https://github.com/YOUR_ORG/REPO_NAME' WHERE name = 'REPO_NAME';"
```

**Example:**
```bash
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "UPDATE repositories SET url = 'https://github.com/sleepnumberdev/coveo-search' WHERE name = 'coveo-search';"
```

---

### Option 2: Batch Update All Missing URLs

Update all repositories with missing URLs using a single SQL command:

```bash
# Set your GitHub organization
GITHUB_ORG="sleepnumberdev"

docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "UPDATE repositories SET url = 'https://github.com/${GITHUB_ORG}/' || name WHERE url IS NULL;"
```

**Verify the update:**
```bash
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "SELECT name, url FROM repositories WHERE url IS NOT NULL ORDER BY name;"
```

**Check for remaining NULL URLs:**
```bash
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "SELECT name FROM repositories WHERE url IS NULL;"
```

---

### Option 3: Run the Fix Script

Use the existing `fix_repo_urls.py` script:

```bash
# Set the GitHub organization environment variable
export GITHUB_ORG="sleepnumberdev"

# Run the fix script
python fix_repo_urls.py
```

**Script location:** `fix_repo_urls.py` (project root)

**What it does:**
1. Queries all repositories with NULL URLs
2. Constructs URL using pattern: `https://github.com/{GITHUB_ORG}/{repo_name}`
3. Updates each repository record
4. Commits changes to database

---

### Option 4: Preventive Fix in Ingestion

The `ingest_scans.py` file should auto-fix missing URLs when processing repositories.

**Add this logic after fetching existing repos:**

```python
# 1. Get or Create Repository
repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
github_org = os.getenv("GITHUB_ORG", "sealmindset")
repo_url = f"https://github.com/{github_org}/{repo_name}"

if not repo:
    repo = models.Repository(
        name=repo_name,
        description=f"Imported from {repo_dir}",
        default_branch="main",
        url=repo_url
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)
elif not repo.url:
    # Fix missing URL for existing repos
    repo.url = repo_url
    db.commit()
    logger.info(f"Updated missing URL for {repo_name}: {repo_url}")
```

**Locations to update in `ingest_scans.py`:**
- Lines ~550-568 (single repo ingestion)
- Lines ~660-677 (batch ingestion)

---

## Verification

### Check for Missing URLs

```sql
-- Count repos with missing URLs
SELECT COUNT(*) as missing_urls FROM repositories WHERE url IS NULL;

-- List repos with missing URLs
SELECT id, name, created_at FROM repositories WHERE url IS NULL ORDER BY name;
```

### Verify All URLs are Set

```sql
-- Show all repos with their URLs
SELECT name, url FROM repositories ORDER BY name;

-- Confirm no NULL URLs remain
SELECT COUNT(*) as total,
       SUM(CASE WHEN url IS NULL THEN 1 ELSE 0 END) as missing_urls
FROM repositories;
```

---

## URL Pattern

The standard URL pattern for GitHub repositories:

```
https://github.com/{organization}/{repository_name}
```

**Examples:**
| Repository Name | Constructed URL |
|----------------|-----------------|
| `coveo-search` | `https://github.com/sleepnumberdev/coveo-search` |
| `api-gateway` | `https://github.com/sleepnumberdev/api-gateway` |
| `web-frontend` | `https://github.com/sleepnumberdev/web-frontend` |

---

## Handling Special Cases

### Repositories with Hyphen-Prefixed Names

Some repositories may have names starting with `-` (e.g., `-EBS-F-7005-AP-UPD-PYMT-METHOD`). These work normally in URLs:

```bash
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "UPDATE repositories SET url = 'https://github.com/sleepnumberdev/-EBS-F-7005-AP-UPD-PYMT-METHOD' WHERE name = '-EBS-F-7005-AP-UPD-PYMT-METHOD';"
```

### Different GitHub Organizations

If repositories belong to different organizations, update them individually:

```sql
-- Update repos for org1
UPDATE repositories
SET url = 'https://github.com/org1/' || name
WHERE name IN ('repo1', 'repo2') AND url IS NULL;

-- Update repos for org2
UPDATE repositories
SET url = 'https://github.com/org2/' || name
WHERE name IN ('repo3', 'repo4') AND url IS NULL;
```

### Azure DevOps or GitLab Repositories

For non-GitHub repositories, adjust the URL pattern:

```sql
-- Azure DevOps
UPDATE repositories
SET url = 'https://dev.azure.com/YOUR_ORG/YOUR_PROJECT/_git/' || name
WHERE name = 'azure-repo' AND url IS NULL;

-- GitLab
UPDATE repositories
SET url = 'https://gitlab.com/YOUR_ORG/' || name
WHERE name = 'gitlab-repo' AND url IS NULL;
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `UPDATE 0` returned | Repository name doesn't match - check spelling with `SELECT name FROM repositories;` |
| Still getting "URL is missing" | Restart the API: `docker-compose restart api` |
| Wrong organization in URL | Re-run update with correct `GITHUB_ORG` value |
| Can't connect to database | Check Docker is running: `docker-compose ps` |
| "Repository not found" after URL fix | URL is wrong or repo is inaccessible - see below |

---

### Troubleshooting "Repository Not Found" Error

If you get `Failed to clone repository... Repository not found` after setting the URL:

**Step 1: Verify the repository exists and is accessible**

```bash
# Check if you can access the repo via GitHub CLI
gh repo view ORG/REPO_NAME --json url,name,isPrivate

# Example
gh repo view sleepnumberdev/coveo-search --json url,name,isPrivate
```

**Step 2: Search for the correct repository**

```bash
# Search across all accessible repos
gh search repos "REPO_NAME" --json fullName,url

# List repos in a specific org
gh repo list ORG_NAME --limit 200 --json name | grep -i "search-term"
```

**Step 3: Check authentication**

```bash
# Verify GitHub auth status
gh auth status

# Check if token has access to the org
gh org list
```

**Step 4: Verify the URL in the database**

```bash
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "SELECT name, url FROM repositories WHERE name = 'REPO_NAME';"
```

**Step 5: Update with correct URL**

If the org or repo name is different:

```bash
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "UPDATE repositories SET url = 'https://github.com/CORRECT_ORG/CORRECT_NAME' WHERE name = 'REPO_NAME';"
```

---

### Authentication for Private Repositories

Ensure `GITHUB_TOKEN` is set and has access to private repos:

```bash
# Check current token
echo $GITHUB_TOKEN

# Verify token permissions
gh auth status

# Test clone manually
git clone https://github.com/ORG/REPO_NAME /tmp/test-clone
```

If the token lacks access:
1. Generate a new token with `repo` scope at https://github.com/settings/tokens
2. Update `GITHUB_TOKEN` in your environment or `.env` file
3. Restart the API: `docker-compose restart api`

---

## Quick Reference Commands

```bash
# List all repos with missing URLs
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "SELECT name FROM repositories WHERE url IS NULL;"

# Fix all missing URLs (replace YOUR_ORG)
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "UPDATE repositories SET url = 'https://github.com/YOUR_ORG/' || name WHERE url IS NULL;"

# Verify fix
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "SELECT COUNT(*) FROM repositories WHERE url IS NULL;"

# Fix single repo
docker-compose exec db psql -U auditgh -d auditgh_kb -c \
  "UPDATE repositories SET url = 'https://github.com/YOUR_ORG/REPO_NAME' WHERE name = 'REPO_NAME';"
```

---

## Prevention

To prevent this issue in the future:

1. **Always set `GITHUB_ORG`** environment variable before running scans
2. **Use updated `ingest_scans.py`** that auto-fixes missing URLs (fix applied)
3. **Run `fix_repo_urls.py`** periodically as maintenance
4. **Add NOT NULL constraint** (optional, may break existing workflows):
   ```sql
   -- Only run after fixing all NULL URLs
   ALTER TABLE repositories ALTER COLUMN url SET NOT NULL;
   ```

---

## Applied Fix: Auto-Populate Missing URLs

The `ingest_scans.py` file has been updated to automatically fix missing URLs when processing repositories. This fix was applied at two locations:

**Location 1:** Lines ~550-568 (single repo ingestion)
**Location 2:** Lines ~660-677 (batch ingestion)

**The fix:**

```python
# 1. Get or Create Repository
repo = db.query(models.Repository).filter(models.Repository.name == repo_name).first()
github_org = os.getenv("GITHUB_ORG", "sealmindset")
repo_url = f"https://github.com/{github_org}/{repo_name}"

if not repo:
    repo = models.Repository(
        name=repo_name,
        description=f"Imported from {repo_dir}",
        default_branch="main",
        url=repo_url
    )
    db.add(repo)
    db.commit()
    db.refresh(repo)
elif not repo.url:
    # Fix missing URL for existing repos
    repo.url = repo_url
    db.commit()
    logger.info(f"Updated missing URL for {repo_name}: {repo_url}")
```

**What this does:**
1. When a repository is processed during ingestion
2. If the repo exists but has a NULL URL
3. Automatically constructs and sets the URL using `GITHUB_ORG`
4. Logs the update for visibility

**Important:** Set the correct `GITHUB_ORG` environment variable before running scans:

```bash
export GITHUB_ORG="your-github-org"
python scan_repos.py --repo="repo-name" --org your-github-org
```

---

## Summary of Error Resolution Flow

```
Error: "Project repository URL is missing"
    │
    ├─► Check if URL is NULL in database
    │       SELECT url FROM repositories WHERE name = 'repo';
    │
    ├─► If NULL: Update URL
    │       UPDATE repositories SET url = '...' WHERE name = 'repo';
    │
    └─► If still failing: Restart API
            docker-compose restart api

Error: "Repository not found"
    │
    ├─► Verify repo exists: gh repo view ORG/REPO
    │
    ├─► Check authentication: gh auth status
    │
    ├─► Search for correct name: gh search repos "REPO"
    │
    ├─► Update with correct URL if wrong
    │
    └─► Ensure GITHUB_TOKEN has repo access
```

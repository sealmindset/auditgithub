# AuditGH Cheatsheet

Quick reference guide for common AuditGH operations, from startup to advanced scanning.

---

## Table of Contents

1. [First-Time Setup](#first-time-setup)
2. [Starting the Application](#starting-the-application)
3. [Scanning Variations](#scanning-variations)
4. [Organization Management](#organization-management)
5. [Data Ingestion](#data-ingestion)
6. [Service Management](#service-management)
7. [Troubleshooting Quick Fixes](#troubleshooting-quick-fixes)

---

## First-Time Setup

### 1. Prerequisites
```bash
# Verify Docker is installed
docker --version  # Should be 20.10+
docker-compose --version

# Verify Git is installed
git --version
```

### 2. Clone and Configure
```bash
# Clone repository
git clone https://github.com/sealmindset/auditgithub.git
cd auditgithub

# Copy environment template
cp .env.sample .env

# Edit .env with your settings
nano .env  # or vim, code, etc.
```

### 3. Required Environment Variables
```bash
# Minimum configuration in .env:

# GitHub Tokens
GITHUB_TOKEN=ghp_your_default_token_here
GITHUB_ORG=your_default_org_name

# For multiple organizations (optional)
ORG_SLEEPNUMBERLABS_TOKEN=ghp_token_for_org1
ORG_SLEEPNUMBERLABS_GITHUB=sleepnumberlabs
ORG_SLEEPNUMBERINC_TOKEN=ghp_token_for_org2
ORG_SLEEPNUMBERINC_GITHUB=SleepNumberInc

# Database (defaults are fine for dev)
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=security_portal
DATABASE_URL=postgres://postgres:postgres@db:5432/security_portal

# AI Provider (optional - for AI-powered analysis)
AI_PROVIDER=anthropic_foundry
ANTHROPIC_MODEL=cogdep-aifoundry-dev-eus2-claude-sonnet-4-5
AZURE_AI_FOUNDRY_ENDPOINT=https://your-endpoint.azure.com/anthropic
AZURE_AI_FOUNDRY_API_KEY=your_api_key_here
```

### 4. Initial Database Setup
```bash
# Start database first
docker-compose up -d db

# Wait for database to be ready (5-10 seconds)
sleep 10

# Initialize database schema
docker-compose up -d api
docker exec auditgh_api python init_db.py

# Verify tables were created
docker exec auditgh_db psql -U postgres -d security_portal -c "\dt"
```

### 5. Create Organizations
```bash
# Create your first organization
docker exec auditgh_api python -c "
from src.api.database import SessionLocal
from src.api import models
import uuid

db = SessionLocal()
org = models.Organization(
    id=str(uuid.uuid4()),
    name='sleepnumberlabs',
    display_name='Sleep Number Labs',
    github_org='sleepnumberlabs',
    database_name='org_sleepnumberlabs',
    is_active=True,
    is_default=True
)
db.add(org)
db.commit()
print(f'Created organization: {org.name}')
"

# Add second organization (optional)
docker exec auditgh_api python -c "
from src.api.database import SessionLocal
from src.api import models
import uuid

db = SessionLocal()
org = models.Organization(
    id=str(uuid.uuid4()),
    name='SleepNumberInc',
    display_name='Sleep Number Inc',
    github_org='SleepNumberInc',
    database_name='org_sleepnumberinc',
    is_active=True,
    is_default=False
)
db.add(org)
db.commit()
print(f'Created organization: {org.name}')
"
```

---

## Starting the Application

### Start All Services
```bash
# Start everything (API, Web UI, Database, Redis, Session Cleanup)
docker-compose up -d

# Verify all services are running
docker-compose ps

# Check logs for any errors
docker-compose logs -f

# Access the application
# Web UI: http://localhost:3000
# API: http://localhost:8000
# API Docs: http://localhost:8000/docs
```

### Start Specific Services
```bash
# Just database and API
docker-compose up -d db api

# Just web UI (requires API to be running)
docker-compose up -d web-ui

# With Redis for caching
docker-compose up -d db redis api web-ui
```

### Health Check
```bash
# Check API health
curl http://localhost:8000/health

# Check database connection
docker exec auditgh_db pg_isready -U postgres

# Check Redis (if running)
docker exec auditgh-redis redis-cli ping
```

---

## Scanning Variations

**🔥 NEW:** All scans now automatically ingest data into the database when complete! No manual `ingest_reports.py` needed.

### Basic Scans

#### 1. Dry Run (Preview Only)
**What it does:** Lists repositories that would be scanned without actually scanning
```bash
docker-compose run --rm scanner --target sleepnumberlabs --dry-run
```

#### 2. Basic Scan (All Repos) ⭐ RECOMMENDED
**What it does:** Scans all repositories + automatically loads results into database
**Data immediately available in Web UI!**
```bash
docker-compose run --rm scanner --target sleepnumberlabs

# Output shows auto-ingest:
# ================================================================================
# Scan Summary
# ================================================================================
# Total repositories: 484
# Successful: 484
# ================================================================================
# AUTO-INGEST: Loading scan results into database
# ================================================================================
# Ingesting reports from: /app/vulnerability_reports
#   ✅ sleepnumberlabs: 484 repos, 277 findings
# ✅ Auto-ingest completed successfully
# ================================================================================
```

#### 3. Single Repository Scan
**What it does:** Scans only one specific repository
```bash
docker-compose run --rm scanner --target sleepnumberlabs --repo repository-name
```

### Incremental Scans

#### 4. Rescan Stale Repos (Recommended for Daily Use)
**What it does:** Only scans repos that haven't been scanned in X days + new repos
```bash
# Rescan repos older than 14 days
docker-compose run --rm scanner --target sleepnumberlabs --rescan-days 14

# Rescan repos older than 7 days
docker-compose run --rm scanner --target sleepnumberlabs --rescan-days 7
```

#### 5. Override Previous Scans (Force Rescan)
**What it does:** Rescans everything regardless of when it was last scanned
```bash
docker-compose run --rm scanner --target sleepnumberlabs --overridescan
```

### AI-Powered Scans

#### 6. Scan with AI Analysis
**What it does:** Runs scans + AI-powered analysis for deeper insights
**Requirements:** AI_PROVIDER configured in .env
```bash
docker-compose run --rm scanner --target sleepnumberlabs --ai-agent
```

#### 7. AI Analysis with Auto-Remediation
**What it does:** AI analyzes findings and suggests fixes
```bash
docker-compose run --rm scanner --target sleepnumberlabs --ai-agent --ai-auto-remediate
```

#### 8. Disable AI (Override Default)
**What it does:** Explicitly disables AI even if configured
```bash
docker-compose run --rm scanner --target sleepnumberlabs --no-ai-agent
```

### Advanced Scans

#### 9. High-Performance Scan
**What it does:** Uses more workers for faster scanning (requires more RAM)
```bash
docker-compose run --rm scanner --target sleepnumberlabs --max-workers 8
```

#### 10. Include Forks and Archived Repos
**What it does:** Scans repos normally excluded (forks and archived)
```bash
docker-compose run --rm scanner --target sleepnumberlabs --include-forks --include-archived
```

#### 11. Custom Timeout Settings
**What it does:** Adjusts timeouts for slow networks or large repos
```bash
# Longer timeouts for large repositories
docker-compose run --rm scanner \
  --target sleepnumberlabs \
  --repo-timeout 10 \
  --scanner-timeout 20
```

#### 12. Debug Mode
**What it does:** Verbose logging for troubleshooting
```bash
docker-compose run --rm scanner --target sleepnumberlabs --loglevel DEBUG
```

#### 13. Disable Auto-Ingest (Manual Control)
**What it does:** Scans without automatically ingesting data (old behavior)
**Use when:** Testing, troubleshooting, or need to review reports first
```bash
# Scan without auto-ingest
docker-compose run --rm scanner --target sleepnumberlabs --no-auto-ingest

# Then manually ingest when ready
docker exec auditgh_api python ingest_reports.py
```

### Comprehensive Scans

#### 14. Full Production Scan (Recommended Monthly)
**What it does:** Complete scan with AI, all repos, overriding previous results + auto-ingest
```bash
docker-compose run --rm scanner \
  --target sleepnumberlabs \
  --overridescan \
  --ai-agent \
  --include-forks \
  --include-archived \
  --max-workers 4
```

#### 15. Quick Daily Scan (Recommended)
**What it does:** Fast incremental scan of changed/new repos + auto-ingest
```bash
docker-compose run --rm scanner \
  --target sleepnumberlabs \
  --rescan-days 1 \
  --max-workers 4
```

#### 16. Weekly Comprehensive Scan
**What it does:** Thorough weekly scan with AI analysis + auto-ingest
```bash
docker-compose run --rm scanner \
  --target sleepnumberlabs \
  --rescan-days 7 \
  --ai-agent \
  --max-workers 4
```

### Multi-Organization Scans

#### 17. Scan Multiple Organizations
**What it does:** Runs scans sequentially for multiple organizations + auto-ingest each
```bash
# Scan first organization (auto-ingests)
docker-compose run --rm scanner --target sleepnumberlabs

# Scan second organization (auto-ingests)
docker-compose run --rm scanner --target SleepNumberInc

# Or use a loop for multiple orgs (each auto-ingests)
for org in sleepnumberlabs SleepNumberInc; do
  docker-compose run --rm scanner --target $org
done

# Data for all orgs immediately available in Web UI!
```

### Scan Variations Summary Table

| Use Case | Command | When to Use | Auto-Ingest |
|----------|---------|-------------|-------------|
| Preview | `--dry-run` | Before first scan or testing | No |
| First scan | `--target org` | Initial setup | ✅ Yes |
| Daily | `--rescan-days 1` | Continuous monitoring | ✅ Yes |
| Weekly | `--rescan-days 7 --ai-agent` | Regular comprehensive review | ✅ Yes |
| Monthly | `--overridescan --ai-agent` | Full audit | ✅ Yes |
| Single repo | `--repo name` | Investigating specific issue | ✅ Yes |
| Debug | `--loglevel DEBUG` | Troubleshooting problems | ✅ Yes |
| Fast scan | `--max-workers 8` | When you need results quickly | ✅ Yes |
| Manual ingest | `--no-auto-ingest` | Need to review reports first | No |

**Note:** All scans (except dry-run) now automatically ingest data! No need to run `ingest_reports.py` manually.

---

## Organization Management

### List Organizations
```bash
# List all configured organizations
docker-compose run --rm scanner --list-orgs

# Or query database directly
docker exec auditgh_api python -c "
from src.api.database import SessionLocal
from src.api import models

db = SessionLocal()
orgs = db.query(models.Organization).all()
for org in orgs:
    print(f'{org.name}: {org.github_org} (default: {org.is_default})')
"
```

### Switch Default Organization
```bash
# Set a different default organization
docker exec auditgh_api python -c "
from src.api.database import SessionLocal
from src.api import models

db = SessionLocal()
# Unset current default
db.query(models.Organization).update({'is_default': False})
# Set new default
org = db.query(models.Organization).filter_by(name='SleepNumberInc').first()
org.is_default = True
db.commit()
print(f'Set {org.name} as default')
"
```

### Check Organization Stats
```bash
# View repository and finding counts
curl http://localhost:8000/organizations/ | jq

# Or via API
curl http://localhost:8000/organizations/sleepnumberlabs | jq
```

---

## Data Ingestion

**🔥 NEW:** Auto-ingest is now automatic! Data is loaded immediately after scanning.

### Automatic Ingestion (Default)
```bash
# Just scan - data is automatically ingested!
docker-compose run --rm scanner --target sleepnumberlabs

# Output shows auto-ingest:
# ================================================================================
# AUTO-INGEST: Loading scan results into database
# ================================================================================
#   ✅ sleepnumberlabs: 484 repos, 277 findings
# ✅ Auto-ingest completed successfully
# ================================================================================

# Data immediately available at http://localhost:3000
```

### Manual Ingestion (Only if using --no-auto-ingest)
```bash
# If you disabled auto-ingest, run manually:
docker exec auditgh_api python ingest_reports.py
```

### Verify Ingestion
```bash
# Check repository count
docker exec auditgh_db psql -U postgres -d security_portal -c \
  "SELECT COUNT(*) FROM repositories;"

# Check findings count
docker exec auditgh_db psql -U postgres -d security_portal -c \
  "SELECT scanner_name, COUNT(*) FROM findings GROUP BY scanner_name;"

# Check per organization
docker exec auditgh_db psql -U postgres -d security_portal -c \
  "SELECT o.name, COUNT(r.id) as repos, COUNT(f.id) as findings
   FROM organizations o
   LEFT JOIN repositories r ON o.id = r.organization_id
   LEFT JOIN findings f ON r.id = f.repository_id
   GROUP BY o.name;"
```

---

## Service Management

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f api
docker-compose logs -f web-ui
docker-compose logs -f db

# Last 100 lines
docker-compose logs --tail=100 api

# Scanner logs (while running)
docker-compose run --rm scanner --target sleepnumberlabs 2>&1 | tee scan.log
```

### Restart Services
```bash
# Restart all services
docker-compose restart

# Restart specific service
docker-compose restart api
docker-compose restart web-ui

# Rebuild and restart after code changes
docker-compose build api
docker-compose up -d api
```

### Clean Restart
```bash
# Stop everything
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker-compose down -v

# Rebuild from scratch
docker-compose build --no-cache
docker-compose up -d
```

### Resource Monitoring
```bash
# Check container resource usage
docker stats

# Check disk usage
docker system df

# Clean up unused resources
docker system prune -a
```

---

## Troubleshooting Quick Fixes

### Database Connection Errors
```bash
# Check if database is running
docker-compose ps db

# Restart database
docker-compose restart db

# Check database logs
docker-compose logs db

# Test connection
docker exec auditgh_db pg_isready -U postgres
```

### API Not Responding
```bash
# Check API logs
docker-compose logs -f api

# Restart API
docker-compose restart api

# Reinitialize database
docker exec auditgh_api python init_db.py

# Check health endpoint
curl http://localhost:8000/health
```

### Web UI Not Loading
```bash
# Check if Web UI container is running
docker-compose ps web-ui

# Check logs for errors
docker-compose logs web-ui

# Restart Web UI
docker-compose restart web-ui

# Rebuild if needed
docker-compose build web-ui
docker-compose up -d web-ui
```

### Scanner Failures
```bash
# Check scanner logs
docker-compose logs scanner

# Verify GitHub token is valid
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Run with debug logging
docker-compose run --rm scanner --target sleepnumberlabs --loglevel DEBUG

# Check for timeout issues
docker-compose run --rm scanner \
  --target sleepnumberlabs \
  --repo-timeout 10 \
  --scanner-timeout 20
```

### CORS Errors (Zero Day Analysis or API calls)
```bash
# Restart API to reload middleware
docker-compose restart api

# Check browser console for specific error
# Common fix: Clear browser cache and localStorage
# In browser console: localStorage.clear()
```

### Organization Selection Not Persisting
```bash
# Clear browser localStorage
# In browser console:
localStorage.clear()
location.reload()

# Check if OrganizationSelector.tsx has localStorage implementation
# Should see localStorage.setItem('selectedOrganization', orgName)
```

### Out of Memory Errors
```bash
# Reduce max workers
docker-compose run --rm scanner --target sleepnumberlabs --max-workers 2

# Check Docker memory allocation
docker stats

# Increase Docker memory limit in Docker Desktop settings
# Recommended: 8GB for full scans
```

### Port Already in Use
```bash
# Check what's using port 8000
lsof -i :8000

# Change port in docker-compose.yml
# api:
#   ports:
#     - "8001:8000"  # Changed from 8000:8000

# Or stop conflicting service
sudo kill -9 $(lsof -ti:8000)
```

---

## Quick Command Reference

### Most Common Commands
```bash
# Start application
docker-compose up -d

# Daily scan (incremental)
docker-compose run --rm scanner --target sleepnumberlabs --rescan-days 1

# Ingest reports
docker exec auditgh_api python ingest_reports.py

# View API logs
docker-compose logs -f api

# Access Web UI
open http://localhost:3000

# Stop application
docker-compose down
```

### Emergency Fixes
```bash
# Nuclear option: full restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
docker exec auditgh_api python init_db.py

# Database reset (WARNING: loses data)
docker-compose down -v
docker-compose up -d db
sleep 10
docker-compose up -d api
docker exec auditgh_api python init_db.py
```

---

## Next Steps

- **Learn More:** Read [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)
- **Configure AI:** See [docs/AI_AGENTS.md](docs/AI_AGENTS.md)
- **Multi-Tenant:** Review [docs/MULTI_TENANT.md](docs/MULTI_TENANT.md)
- **Troubleshooting:** Check [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

## PostgreSQL

To stop PostgreSQL installed via Homebrew:

```bash
brew services stop postgresql
```

Or if you have a specific version:

```bash
brew services stop postgresql@14
brew services stop postgresql@15
brew services stop postgresql@16
```

To check what's running:

```bash
brew services list | grep postgres
```

To stop it without using brew services (one-time stop):

```bash
pg_ctl -D /usr/local/var/postgres stop
```

# or for Apple Silicon:
```bash
pg_ctl -D /opt/homebrew/var/postgres stop
```

### Rebuild
To rebuild Docker from scratch for this project:

# Stop and remove everything (containers, volumes, networks)
```bash
docker compose down -v
```

# Remove any dangling images/cache
```bash
docker system prune -f
```

# Rebuild and start fresh
```bash
docker compose up --build -d
```

### If you want a complete clean slate (removes ALL Docker data, not just this project):


# Nuclear option - removes everything
```bash
docker compose down -v
docker system prune -a --volumes -f
docker compose up --build -d
```

For this specific project, you likely want:

# Stop containers and remove volumes (wipes database)
```bash
docker compose down -v
```

# Rebuild images and start
```bash
docker compose up --build -d
```

# Watch logs to see startup
```bash
docker compose logs -f
```

This will:

- Stop all containers
- Delete all volumes (database data)
- Rebuild images from scratch
- Start fresh with empty database
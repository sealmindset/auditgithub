# AuditGH Cheatsheet

Quick reference for common operations. Print this out or keep it handy.

---

## � Configuration Reference

| Setting | Value | Notes |
|---------|-------|-------|
| Database | `auditgh_kb` | PostgreSQL database name |
| DB User | `postgres` | Default PostgreSQL user |
| DB Password | `postgres` | Default (change in production) |
| API Port | `8000` | FastAPI backend |
| UI Port | `3000` | Next.js frontend |
| DB Port | `5432` | PostgreSQL |

---

## 🚀 Starting the Application

### Fresh Start (New Installation)

```bash
# 1. Start database
docker-compose up -d db && sleep 5

# 2. Apply schema and migrations
docker-compose exec -T db psql -U postgres -d auditgh_kb < setup/schema.sql
for f in migrations/*.sql; do docker-compose exec -T db psql -U postgres -d auditgh_kb < "$f"; done

# 3. Start API and UI
docker-compose up -d api web-ui
```

### Quick Start (Database Already Set Up)

```bash
# Start all services
docker-compose up -d

# Verify all services are running
docker-compose ps
```

**Expected output:**
```
NAME              STATUS          PORTS
auditgh_db        Up (healthy)    0.0.0.0:5432->5432/tcp
auditgh_api       Up (healthy)    0.0.0.0:8000->8000/tcp
auditgh_ui        Up              0.0.0.0:3000->3000/tcp
```

> **Note:** The scanner (`auditgh_scanner`) runs on-demand and won't appear unless actively scanning.

### Access Points

| Service | URL | Purpose |
|---------|-----|---------|
| Web UI | http://localhost:3000 | Dashboard |
| API | http://localhost:8000 | REST API |
| API Docs | http://localhost:8000/docs | Swagger UI |
| Database | localhost:5432 | PostgreSQL |

---

## 🔍 Running Scans

> **Architecture Note:** The scanner runs in a dedicated container (`auditgh_scanner`) separate from the API, with resource limits of 8GB RAM and 4 CPUs for heavy security scanning operations.

### First-Time Scan (New Organization)

```bash
# 1. List available organizations
docker-compose run --rm scanner --list-orgs

# 2. Dry run to preview what will be scanned
docker-compose run --rm scanner --target myorg --dry-run

# 3. Run actual scan
docker-compose run --rm scanner --target myorg
```

### Incremental Scan (New + Recently Updated Repos)

This is the **recommended approach** for regular scanning - picks up new repos and rescans repos that have been updated:

```bash
# Scan new repos + rescan repos updated in last 14 days
docker-compose run --rm scanner --target myorg --rescan-days 14

# Scan new repos + rescan repos updated in last 7 days
docker-compose run --rm scanner --target myorg --rescan-days 7

# Scan new repos + rescan repos updated in last 30 days
docker-compose run --rm scanner --target myorg --rescan-days 30
```

> **How it works:** `--rescan-days N` will:
> 1. Scan any **new repositories** not yet in the database
> 2. Rescan existing repos whose **last scan was more than N days ago**
> 3. Skip repos recently scanned (within N days)

### Force Rescan (All Repos)

```bash
# Rescan everything regardless of last scan date
docker-compose run --rm scanner --target myorg --force-rescan
```

### Complete Reset + Fresh Scan

```bash
# Step 1: Reset organization data (creates backup)
docker-compose run --rm scanner python scripts/reset_organization_data.py --target myorg --force

# Step 2: Run fresh scan from scratch
docker-compose run --rm scanner --target myorg
```

### Scan with AI Analysis

```bash
# Enable AI agent for enhanced analysis
docker-compose run --rm scanner --target myorg --ai-agent

# With specific AI provider
docker-compose run --rm scanner --target myorg --ai-agent --ai-provider claude
```

### Scan Single Repository

```bash
docker-compose run --rm scanner --target myorg --repo specific-repo-name
```

---

## 🔄 Restarting Services

### When to Restart What

| Change Made | Restart Command | Why |
|-------------|-----------------|-----|
| `.env` changes | `docker-compose down && docker-compose up -d` | Env vars loaded at startup |
| UI/UX changes (React) | `docker-compose restart web-ui` | Hot reload may not catch all |
| API changes (Python) | `docker-compose restart api` | Python needs restart |
| Scanner changes | `docker-compose build scanner` | Scanner runs on-demand |
| New npm packages | `docker-compose build web-ui && docker-compose up -d web-ui` | Need to rebuild |
| New pip packages (API) | `docker-compose build api && docker-compose up -d api` | Need to rebuild |
| New pip packages (Scanner) | `docker-compose build scanner` | Scanner runs on-demand |
| Database schema | See "Applying Migrations" below | Migrations required |

### Quick Restart Commands

```bash
# Restart single service
docker-compose restart api
docker-compose restart web-ui

# Scanner runs on-demand, no restart needed
# Just rebuild if code changed: docker-compose build scanner

# Restart all services (keeps data)
docker-compose restart

# Full restart (recreates containers)
docker-compose down && docker-compose up -d
```

### Rebuilding After Code Changes

```bash
# Rebuild specific service
docker-compose build api
docker-compose build web-ui
docker-compose build scanner

# Rebuild and restart
docker-compose up -d --build api

# Rebuild without cache (clean build)
docker-compose build --no-cache api
docker-compose build --no-cache scanner
docker-compose up -d api
```

---

## 📦 Applying Migrations

```bash
# Apply all migrations in order
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/002_organizations.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/003_credential_url_test_results.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/004_fix_multi_tenant_repositories.sql

# Check current schema
docker-compose exec db psql -U postgres -d auditgh_kb -c "\dt"
```

---

## 🛑 Graceful Shutdown & Safe Restart

### Standard Shutdown

```bash
# Stop all services gracefully (keeps data)
docker-compose down
```

### Safe Restart (Prevents Data Corruption)

**IMPORTANT:** Always follow this sequence to prevent database corruption:

```bash
# Option 1: Simple restart (recommended)
docker-compose down && docker-compose up -d

# Option 2: If you need to apply .env changes
docker-compose down
# Edit .env file
docker-compose up -d

# Option 3: After code changes requiring rebuild
docker-compose down
docker-compose build api scanner  # rebuild changed services
docker-compose up -d
```

> **⚠️ Never use `docker-compose kill` unless absolutely necessary** - it doesn't allow services to gracefully close database connections.

### Shutdown with Cleanup

```bash
# Stop and remove containers, networks
docker-compose down

# Stop and remove volumes (DELETES DATA!)
docker-compose down -v

# Stop, remove containers, and remove images
docker-compose down --rmi local
```

### Emergency Stop (Use with Caution)

```bash
# Force stop all containers immediately (may cause data issues)
docker-compose kill

# Then clean up
docker-compose down
```

### Shutdown Sequence (Manual - When Needed)

```bash
# 1. Stop scanner if running (usually not needed - runs on-demand)
# docker-compose stop scanner

# 2. Stop web UI first (no database connections)
docker-compose stop web-ui

# 3. Stop API (closes DB connections gracefully)
docker-compose stop api

# 4. Stop database last (ensures all connections closed)
docker-compose stop db
```

---

## 🔧 Common Operations

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
```

### Database Access

```bash
# Interactive psql shell
docker-compose exec db psql -U postgres -d auditgh_kb

# Run single query
docker-compose exec db psql -U postgres -d auditgh_kb -c "SELECT COUNT(*) FROM findings;"

# Backup database
docker-compose exec db pg_dump -U postgres auditgh_kb > backup_$(date +%Y%m%d).sql
```

### Organization Management

```bash
# List organizations
docker-compose run --rm scanner --list-orgs

# Check schema drift
docker-compose run --rm scanner --check-drift

# Sync schemas
docker-compose run --rm scanner --sync-schemas

# List backups
docker-compose run --rm scanner --list-backups
```

### Health Checks

```bash
# Check service status
docker-compose ps

# Check API health
curl http://localhost:8000/health

# Check database connection
docker-compose exec db pg_isready -U postgres

# Check disk usage
docker system df
```

---

## 🔧 Scanner Selection

Run specific scanners instead of all:

```bash
# Run only specific scanners
docker-compose run --rm scanner --target myorg --scanners semgrep,trivy,gitleaks

# Run new Phase 1 scanners only
docker-compose run --rm scanner --target myorg --scanners horusec,whispers,bearer,terrascan
```

### Available Scanners

| Scanner | Flag | Purpose |
|---------|------|---------|
| `semgrep` | SAST | Static code analysis |
| `trivy` | SCA | Vulnerability scanning |
| `grype` | SCA | Dependency vulnerabilities |
| `gitleaks` | Secrets | Git history secrets |
| `trufflehog` | Secrets | Verified secrets |
| `checkov` | IaC | Terraform/K8s |
| `bandit` | SAST | Python security |
| `horusec` | SAST | Multi-tool aggregation |
| `whispers` | Secrets | Config file secrets |
| `bearer` | Data Flow | PII/PHI detection |
| `terrascan` | IaC | 500+ IaC policies |
| `dockle` | Container | Dockerfile linting |
| `gosec` | Go | Go security analysis |
| `golangci-lint` | Go | Go linter with security |
| `mobsf` | Mobile | Android/iOS security |

---

## 📋 Quick Reference Table

| Task | Command |
|------|---------|
| Start all | `docker-compose up -d` |
| Stop all | `docker-compose down` |
| Safe restart | `docker-compose down && docker-compose up -d` |
| View logs | `docker-compose logs -f` |
| Restart API | `docker-compose restart api` |
| Rebuild all | `docker-compose build --no-cache` |
| List orgs | `docker-compose run --rm scanner --list-orgs` |
| Dry run scan | `docker-compose run --rm scanner --target ORG --dry-run` |
| Run scan | `docker-compose run --rm scanner --target ORG` |
| Scan single repo | `docker-compose run --rm scanner --target ORG --repo REPO_NAME` |
| Incremental scan (14 days) | `docker-compose run --rm scanner --target ORG --rescan-days 14` |
| Force rescan | `docker-compose run --rm scanner --target ORG --force-rescan` |
| Reset org | `docker-compose run --rm scanner python scripts/reset_organization_data.py --target ORG --force` |
| DB shell | `docker-compose exec db psql -U postgres -d auditgh_kb` |
| Backup DB | `docker-compose exec db pg_dump -U postgres auditgh_kb > backup.sql` |

---

## 💾 Organization Backup & Restore

### List Organizations
```bash
docker-compose run --rm scanner python scripts/backup_organization.py --list
```

### Backup Single Organization
```bash
docker-compose run --rm scanner python scripts/backup_organization.py --org myorg --output backups/
```

### Backup All Organizations
```bash
docker-compose run --rm scanner python scripts/backup_organization.py --all --output backups/
```

### Restore Organization (Update Existing)
```bash
docker-compose run --rm scanner python scripts/restore_organization.py --file backups/myorg_backup_20241214.json
```

### Restore as New Organization
```bash
docker-compose run --rm scanner python scripts/restore_organization.py --file backups/myorg_backup_20241214.json --as-new neworg
```

### Preview Restore (Dry Run)
```bash
docker-compose run --rm scanner python scripts/restore_organization.py --file backups/myorg_backup_20241214.json --dry-run
```

**Backup includes:** Repositories, Findings, Credentials, API Endpoints, Credential-URL Correlations, Test Results, Scan Runs, Contributors

---

## ⚠️ Troubleshooting Quick Fixes

| Problem | Quick Fix |
|---------|-----------|
| Service won't start | `docker-compose logs SERVICE` to check errors |
| Port already in use | `lsof -i :PORT` then kill process or change port |
| Database connection failed | `docker-compose restart db` and wait 10s |
| Stale containers | `docker-compose down && docker-compose up -d` |
| Out of disk space | `docker system prune -a` |
| Permission denied | `chmod +x script.sh` or check file ownership |
| Encryption error | Delete `/tmp/auditgithub_secrets.json` and restart |

---

## 🔑 Environment Variables Quick Reference

```bash
# Required
GITHUB_ORG=your-org
GITHUB_TOKEN=ghp_xxx
POSTGRES_PASSWORD=your_password

# Recommended for production
SECRETS_MASTER_KEY=32_char_key_here

# Optional AI
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-xxx
```

---

[← Back to README](../README.md) | [Full Configuration →](CONFIGURATION.md)

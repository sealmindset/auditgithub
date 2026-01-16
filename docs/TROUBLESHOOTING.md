# Troubleshooting Guide

Common issues and solutions for AuditGH.

## Quick Diagnostics

```bash
# Check all services
docker-compose ps

# View logs
docker-compose logs -f

# Test database connection
docker-compose exec db psql -U postgres -d auditgh_kb -c "SELECT 1;"

# Test API
curl http://localhost:8000/health

# List organizations
docker-compose run --rm scanner --list-orgs
```

---

## Database Issues

### "password authentication failed for user"

**Cause:** Incorrect database credentials or `DATABASE_URL` overriding settings.

**Solution:**
```bash
# Check .env file
grep POSTGRES .env

# Ensure these are set correctly:
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=auditgh_kb
POSTGRES_HOST=db

# DATABASE_URL should match:
DATABASE_URL=postgres://postgres:postgres@db:5432/auditgh_kb
```

### "database does not exist"

**Cause:** Database not created or wrong database name.

**Solution:**
```bash
# Create database manually
docker-compose exec db psql -U postgres -c "CREATE DATABASE auditgh_kb;"

# Or restart with fresh volume
docker-compose down -v
docker-compose up -d
```

### "relation does not exist"

**Cause:** Migrations not applied.

**Solution:**
```bash
# Apply schema and all migrations at once
docker-compose exec -T db psql -U postgres -d auditgh_kb < setup/schema.sql
for f in migrations/*.sql; do docker-compose exec -T db psql -U postgres -d auditgh_kb < "$f"; done
```

Or apply individually:
```bash
docker-compose exec -T db psql -U postgres -d auditgh_kb < setup/schema.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/001_sync_schema.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/002_organizations.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/003_credential_url_test_results.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/004_fix_multi_tenant_repositories.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/005_mobile_go_scanners.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/006_ensure_all_tables.sql
```

### "column schema_version does not exist"

**Cause:** `organizations` table missing columns from migration `002_organizations.sql`.

**Solution:**
```bash
docker-compose exec -T db psql -U postgres -d auditgh_kb << 'EOF'
ALTER TABLE organizations 
ADD COLUMN IF NOT EXISTS database_schema VARCHAR(100) DEFAULT 'public',
ADD COLUMN IF NOT EXISTS schema_version VARCHAR(128),
ADD COLUMN IF NOT EXISTS schema_version_name VARCHAR(100) DEFAULT 'v1.0.0',
ADD COLUMN IF NOT EXISTS last_schema_sync TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS schema_sync_status VARCHAR(50) DEFAULT 'synced',
ADD COLUMN IF NOT EXISTS schema_sync_error TEXT,
ADD COLUMN IF NOT EXISTS last_scan_at TIMESTAMPTZ,
ADD COLUMN IF NOT EXISTS scan_status VARCHAR(50) DEFAULT 'idle',
ADD COLUMN IF NOT EXISTS scan_progress INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS current_scan_id UUID,
ADD COLUMN IF NOT EXISTS total_scans INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_repos INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS total_findings INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS description TEXT,
ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS created_by UUID;
EOF
```

### "value too long for type character varying"

**Cause:** Column size too small for data.

**Solution:**
```bash
# Example: Fix schema_version column
docker-compose exec -T db psql -U postgres -d auditgh_kb -c \
  "ALTER TABLE organizations ALTER COLUMN schema_version TYPE VARCHAR(128);"
```

---

## Authentication Issues

### "Bad credentials" from GitHub

**Cause:** Invalid or expired PAT.

**Solution:**
1. Verify token hasn't expired
2. Check token has required scopes (`repo`, `read:org`)
3. Test token directly:
```bash
curl -H "Authorization: token YOUR_TOKEN" https://api.github.com/user
```

### "Organization not found"

**Cause:** Organization not registered or credentials not configured.

**Solution:**
```bash
# List available organizations
docker-compose run --rm scanner --list-orgs

# Check credentials status
curl http://localhost:8000/organizations/myorg/credentials/status

# Re-add credentials via .env and restart
echo "ORG_MYORG_TOKEN=ghp_xxx" >> .env
echo "ORG_MYORG_GITHUB=my-github-org" >> .env
docker-compose restart
```

### "cryptography.fernet.InvalidToken"

**Cause:** Encryption key mismatch between containers.

**Solution:**
```bash
# Set consistent key in .env
SECRETS_MASTER_KEY=your_32_character_key_here

# Clear old secrets
docker-compose exec api rm -f /tmp/auditgithub_secrets.json

# Restart
docker-compose down && docker-compose up -d
```

---

## Container Issues

### Container won't start

**Diagnosis:**
```bash
# Check logs
docker-compose logs api
docker-compose logs db
docker-compose logs scanner  # Note: scanner only runs on-demand

# Check for port conflicts
lsof -i :8000
lsof -i :5432
lsof -i :3000
```

**Common fixes:**
```bash
# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Remove orphan containers
docker-compose down --remove-orphans
```

### Out of disk space

**Solution:**
```bash
# Clean up Docker
docker system prune -a

# Remove old images
docker image prune -a

# Check disk usage
docker system df
```

### Container keeps restarting

**Diagnosis:**
```bash
# Check exit code
docker-compose ps

# View recent logs
docker-compose logs --tail=100 api
```

**Common causes:**
- Missing environment variables
- Database not ready
- Invalid configuration

> **Note:** The scanner container (`auditgh_scanner`) runs on-demand and exits after completion. It won't appear in `docker-compose ps` unless actively running.

---

## Scan Issues

### Scan hangs or times out

**Cause:** Repository too large or scanner stuck.

**Solution:**
```bash
# Increase timeout
docker-compose run --rm scanner --target myorg --repo-timeout 60

# Skip problematic repo
docker-compose run --rm scanner --target myorg --exclude-repos problematic-repo

# Reduce parallelism
docker-compose run --rm scanner --target myorg --max-workers 2
```

### "Scanner not found"

**Cause:** Scanner binary not installed in container.

**Solution:**
```bash
# Rebuild scanner container with all scanners
docker-compose build --no-cache scanner

# Or run an interactive shell for debugging
docker-compose run --rm --entrypoint bash scanner
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

### No findings generated

**Diagnosis:**
```bash
# Check scan completed with verbose output
docker-compose run --rm scanner --target myorg -v

# Check database for findings
docker-compose exec db psql -U postgres -d auditgh_kb -c \
  "SELECT COUNT(*) FROM findings;"

# Check report directory
ls -la vulnerability_reports/
```

---

## AI Issues

### "AI provider not configured"

**Solution:**
```bash
# Check .env
grep AI_ .env
grep ANTHROPIC .env
grep OPENAI .env

# Ensure one provider is configured:
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...

# Or:
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
```

### "Rate limit exceeded"

**Solution:**
```bash
# Use cautious mode
--ai-mode cautious

# Reduce parallel workers
--max-workers 2

# Add delays between requests
export AI_REQUEST_DELAY=2
```

### Ollama connection refused

**Solution:**
```bash
# Start Ollama server
ollama serve

# Pull required model
ollama pull llama3

# Verify connection
curl http://localhost:11434/api/tags

# Check .env
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3
```

### AI hallucinations / incorrect findings

**Mitigation:**
1. Switch to Claude (lower hallucination rate)
2. Review AI confidence scores
3. Cross-reference with raw scanner output
4. Use `--ai-mode cautious`

---

## Web UI Issues

### UI not loading

**Diagnosis:**
```bash
# Check web-ui container
docker-compose logs web-ui

# Verify port
curl http://localhost:3000

# Check API connection
curl http://localhost:8000/health
```

**Solution:**
```bash
# Rebuild UI
docker-compose build --no-cache web-ui
docker-compose up -d web-ui
```

### API errors in browser console

**Common causes:**
- CORS not configured
- API not running
- Wrong API URL

**Solution:**
```bash
# Check API is running
curl http://localhost:8000/

# Verify CORS headers
curl -I http://localhost:8000/organizations/
```

### Data not showing for organization

**Cause:** Wrong organization selected or data not scoped correctly.

**Solution:**
```bash
# Select correct organization
curl -X POST http://localhost:8000/organizations/myorg/select

# Verify data exists
docker-compose exec db psql -U postgres -d auditgh_kb -c \
  "SELECT name, organization_id FROM repositories LIMIT 5;"
```

---

## Multi-Tenant Issues

### Data appearing in wrong organization

**Cause:** Migration 004 not applied.

**Solution:**
```bash
# Apply multi-tenant fix
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/004_fix_multi_tenant_repositories.sql

# Verify data is scoped
docker-compose exec db psql -U postgres -d auditgh_kb -c \
  "SELECT o.name, COUNT(r.id) FROM organizations o LEFT JOIN repositories r ON r.organization_id = o.id GROUP BY o.name;"
```

### Schema drift detected

**Solution:**
```bash
# Check drift details
docker-compose run --rm scanner --check-drift

# Sync schemas
docker-compose run --rm scanner --sync-schemas
```

---

## Performance Issues

### Slow scans

**Optimization:**
```bash
# Increase workers (if CPU allows)
--max-workers 8

# Use fast profile
--profile fast

# Exclude large repos
--exclude-repos large-monorepo

# Skip unchanged repos
--rescan-days 7
```

### High memory usage

**Solution:**
```bash
# Reduce workers
docker-compose run --rm scanner --target myorg --max-workers 2

# The scanner container is configured with resource limits:
# - Scanner: 8GB RAM limit, 4 CPUs
# - API: 4GB RAM limit, 2 CPUs

# For Docker Desktop: Settings → Resources → Memory
# Ensure at least 10GB allocated for optimal performance
```

> **Note:** The scanner and API run in separate containers with dedicated resource limits, preventing heavy scans from impacting API responsiveness.

### Database slow queries

**Diagnosis:**
```bash
# Check slow queries
docker-compose exec db psql -U postgres -d auditgh_kb -c \
  "SELECT query, calls, mean_time FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"
```

**Solution:**
```bash
# Add missing indexes
docker-compose exec -T db psql -U postgres -d auditgh_kb -c \
  "CREATE INDEX IF NOT EXISTS idx_findings_org ON findings(organization_id);"

# Vacuum database
docker-compose exec db psql -U postgres -d auditgh_kb -c "VACUUM ANALYZE;"
```

---

## Reset Everything (Nuclear Option)

When all else fails:

```bash
# Stop everything
docker-compose down -v

# Remove all containers and images
docker system prune -a

# Rebuild from scratch
docker-compose build --no-cache
docker-compose up -d

# Re-apply all migrations
docker-compose exec -T db psql -U postgres -d auditgh_kb < setup/schema.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/002_organizations.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/003_credential_url_test_results.sql
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/004_fix_multi_tenant_repositories.sql

# Verify
docker-compose run --rm scanner --list-orgs
```

---

## Getting Help

### Collect Diagnostics

```bash
# Create diagnostic bundle
mkdir -p diagnostics
docker-compose ps > diagnostics/services.txt
docker-compose logs > diagnostics/logs.txt
docker-compose exec db psql -U postgres -d auditgh_kb -c "\dt" > diagnostics/tables.txt
env | grep -E "(POSTGRES|GITHUB|AI_)" > diagnostics/env.txt
```

### Log Locations

| Log | Location |
|-----|----------|
| API logs | `docker-compose logs api` |
| Scanner logs | `docker-compose logs scanner` (only during active scans) |
| Database logs | `docker-compose logs db` |
| Web UI logs | `docker-compose logs web-ui` |
| Scan reports | `vulnerability_reports/` |

---

[← Back to README](../README.md)

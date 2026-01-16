# Configuration Reference

Complete reference for all AuditGH configuration options.

## Environment Variables

### GitHub Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GITHUB_ORG` | Yes | - | Default GitHub organization to scan |
| `GITHUB_TOKEN` | Yes | - | GitHub Personal Access Token |
| `GITHUB_API` | No | `https://api.github.com` | GitHub API base URL (for GHE) |

### Database Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_HOST` | No | `db` | PostgreSQL host |
| `POSTGRES_PORT` | No | `5432` | PostgreSQL port |
| `POSTGRES_USER` | No | `auditgh` | PostgreSQL username |
| `POSTGRES_PASSWORD` | Yes | - | PostgreSQL password |
| `POSTGRES_DB` | No | `auditgh_kb` | PostgreSQL database name |
| `DATABASE_URL` | No | - | Full connection string (overrides above) |

### Security Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRETS_MASTER_KEY` | Prod | Auto-generated | 32-char encryption key for secrets |
| `JWT_SECRET` | No | Auto-generated | JWT signing key |

### AI Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ENABLE_AI` | No | `false` | Enable AI features |
| `AI_PROVIDER` | No | `openai` | AI provider: `openai`, `claude`, `ollama` |
| `OPENAI_API_KEY` | If OpenAI | - | OpenAI API key |
| `OPENAI_MODEL` | No | `gpt-4o` | OpenAI model name |
| `ANTHROPIC_API_KEY` | If Claude | - | Anthropic API key |
| `OLLAMA_HOST` | If Ollama | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | No | `llama3` | Ollama model name |

### Scan Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SKIP_SCAN` | No | `false` | Skip automatic scan on container start |
| `REPORT_DIR` | No | `vulnerability_reports` | Output directory for reports |
| `CLONE_DIR` | No | `/tmp/repos` | Directory for cloned repositories |
| `MAX_WORKERS` | No | `4` | Parallel scan workers |
| `REPO_TIMEOUT` | No | `30` | Per-repository timeout (minutes) |

### Backup Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BACKUP_DIR` | No | `backups/organizations` | Backup storage directory |
| `BACKUP_RETENTION_DAYS` | No | `30` | Days to retain backups |

### Multi-Tenant Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MULTI_TENANT_ENABLED` | No | `false` | Enable multi-organization support |
| `DEFAULT_TENANT_SLUG` | No | `default` | **Deprecated** - Legacy fallback tenant |

> **Note:** `MULTI_TENANT_ENABLED` is a **runtime variable** - no rebuild required. Just change the value and restart containers.

### Multi-Organization Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ORG_{NAME}_TOKEN` | No | - | PAT for organization {NAME} |
| `ORG_{NAME}_GITHUB` | No | - | GitHub org name for {NAME} |

**Example for multiple organizations:**
```bash
# Default organization (used by GITHUB_TOKEN)
GITHUB_ORG=sealmindset
GITHUB_TOKEN=ghp_xxx

# Additional organizations
ORG_SLEEPNUMBERLABS_TOKEN=ghp_yyy
ORG_SLEEPNUMBERLABS_GITHUB=sleepnumberlabs

ORG_ACMECORP_TOKEN=ghp_zzz
ORG_ACMECORP_GITHUB=acme-corp
```

---

## Sample .env File

```bash
# =============================================================================
# AuditGH Configuration
# =============================================================================

# -----------------------------------------------------------------------------
# GitHub Configuration
# -----------------------------------------------------------------------------
GITHUB_ORG=sealmindset
GITHUB_TOKEN=ghp_your_token_here

# For GitHub Enterprise:
# GITHUB_API=https://github.mycompany.com/api/v3

# -----------------------------------------------------------------------------
# Database Configuration
# -----------------------------------------------------------------------------
POSTGRES_HOST=db
POSTGRES_PORT=5432
POSTGRES_USER=auditgh
POSTGRES_PASSWORD=postgres
POSTGRES_DB=auditgh_kb

# -----------------------------------------------------------------------------
# Security Configuration
# -----------------------------------------------------------------------------
# Generate with: LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32; echo
SECRETS_MASTER_KEY=your_32_character_secret_key_here

# -----------------------------------------------------------------------------
# AI Configuration (Optional)
# -----------------------------------------------------------------------------
ENABLE_AI=true
AI_PROVIDER=claude

# Anthropic Claude
ANTHROPIC_API_KEY=sk-ant-api03-...

# OpenAI (alternative)
# AI_PROVIDER=openai
# OPENAI_API_KEY=sk-...
# OPENAI_MODEL=gpt-4o

# Ollama (local)
# AI_PROVIDER=ollama
# OLLAMA_HOST=http://localhost:11434
# OLLAMA_MODEL=llama3

# -----------------------------------------------------------------------------
# Scan Configuration
# -----------------------------------------------------------------------------
SKIP_SCAN=false
REPORT_DIR=vulnerability_reports
MAX_WORKERS=4
REPO_TIMEOUT=30

# -----------------------------------------------------------------------------
# Multi-Organization Configuration
# -----------------------------------------------------------------------------
# Add additional organizations:
# ORG_ACME_TOKEN=ghp_acme_token_here
# ORG_ACME_GITHUB=acme-corp

# ORG_CLIENTX_TOKEN=ghp_clientx_token_here
# ORG_CLIENTX_GITHUB=clientx-org

# -----------------------------------------------------------------------------
# Backup Configuration
# -----------------------------------------------------------------------------
BACKUP_DIR=backups/organizations
BACKUP_RETENTION_DAYS=30
```

---

## Docker Compose Configuration

### Architecture Overview

The Docker Compose setup uses **separate containers** for different workloads:

| Service | Container | Purpose | Resources |
|---------|-----------|---------|-----------|
| `scanner` | `auditgh_scanner` | Security scanning (on-demand) | 8GB RAM, 4 CPUs |
| `api` | `auditgh_api` | REST API backend | 4GB RAM, 2 CPUs |
| `web-ui` | `auditgh_ui` | Next.js dashboard | - |
| `db` | `auditgh_db` | PostgreSQL database | - |

This separation ensures heavy scanning operations don't impact API responsiveness.

### docker-compose.yml

```yaml
services:
  # Scanner - runs on-demand for security scans
  scanner:
    build:
      context: .
      dockerfile: Dockerfile.scanner
    container_name: auditgh_scanner
    env_file:
      - .env
    environment:
      - POSTGRES_HOST=db
      - POSTGRES_PORT=${POSTGRES_PORT:-5432}
      - POSTGRES_USER=${POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-postgres}
      - POSTGRES_DB=${POSTGRES_DB:-auditgh_kb}
      - SECRETS_MASTER_KEY=${SECRETS_MASTER_KEY}
    volumes:
      - .:/app
      - ./vulnerability_reports:/app/vulnerability_reports
      - dependency-cache:/root/.cache/dependency-check
      - semgrep-cache:/root/.cache/semgrep
      - trivy-cache:/root/.cache/trivy
      - grype-cache:/root/.cache/grype
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '1'
          memory: 2G
    command: >
      --org ${GITHUB_ORG} --api-base ${GITHUB_API:-https://api.github.com}
      --report-dir /app/vulnerability_reports --max-workers 4 --loglevel INFO
    depends_on:
      db:
        condition: service_started
    profiles:
      - scan

  # API - lightweight FastAPI backend
  api:
    build:
      context: .
      dockerfile: Dockerfile.api
    container_name: auditgh_api
    ports:
      - "8000:8000"
    env_file:
      - .env
    environment:
      - POSTGRES_HOST=db
      - POSTGRES_PORT=${POSTGRES_PORT:-5432}
      - POSTGRES_USER=${POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-postgres}
      - POSTGRES_DB=${POSTGRES_DB:-auditgh_kb}
      - SECRETS_MASTER_KEY=${SECRETS_MASTER_KEY}
      - AI_PROVIDER=${AI_PROVIDER:-openai}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '0.5'
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    depends_on:
      db:
        condition: service_started
    restart: unless-stopped

  # Web UI - Next.js frontend
  web-ui:
    build:
      context: .
      dockerfile: Dockerfile.ui
    container_name: auditgh_ui
    ports:
      - "3000:3000"
    environment:
      - API_BASE=http://api:8000
    depends_on:
      api:
        condition: service_healthy
    restart: unless-stopped

  # Database - PostgreSQL
  db:
    image: postgres:15-alpine
    container_name: auditgh_db
    environment:
      - POSTGRES_USER=${POSTGRES_USER:-postgres}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-postgres}
      - POSTGRES_DB=${POSTGRES_DB:-auditgh_kb}
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-postgres}"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  postgres-data:
  dependency-cache:
  semgrep-cache:
  trivy-cache:
  grype-cache:
```

### Running Scans

```bash
# Run a scan (starts scanner container on-demand)
docker-compose run --rm scanner --target myorg

# Dry run
docker-compose run --rm scanner --target myorg --dry-run

# List organizations
docker-compose run --rm scanner --list-orgs
```

---

## CLI Arguments

### scan_repos.py

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--org` | string | env | GitHub organization |
| `--repo` | string | - | Specific repository |
| `--target` | string | - | Target registered organization |
| `--dry-run` | flag | false | Preview without scanning |
| `--force-rescan` | flag | false | Rescan all repos |
| `--rescan-days` | int | - | Rescan repos older than N days |
| `--include-forks` | flag | false | Include forked repos |
| `--include-archived` | flag | false | Include archived repos |
| `--max-workers` | int | 4 | Parallel workers |
| `--repo-timeout` | int | 30 | Per-repo timeout (minutes) |
| `--ai-agent` | flag | false | Enable AI analysis |
| `--ai-provider` | string | env | AI provider |
| `--ai-auto-remediate` | flag | false | Generate remediation |
| `-v, --verbose` | flag | false | Verbose output |

### Organization Management

| Argument | Type | Description |
|----------|------|-------------|
| `--list-orgs` | flag | List all organizations |
| `--create-org` | string | Create new organization |
| `--github-org` | string | GitHub org (for --create-org) |
| `--sync-schemas` | flag | Sync all schemas |
| `--check-drift` | flag | Check schema drift |
| `--reset-org` | flag | Reset organization data |
| `--reset-force` | flag | Skip confirmation |
| `--list-backups` | flag | List backups |
| `--cleanup-backups` | flag | Remove old backups |

---

## API Configuration

### CORS Settings

```python
# src/api/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### Rate Limiting

```python
# Configure in src/api/main.py
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.get("/api/scan")
@limiter.limit("10/minute")
async def scan_endpoint():
    ...
```

---

## Scanner Configuration

### Profiles

| Profile | Scanners | Time | Use Case |
|---------|----------|------|----------|
| `fast` | Gitleaks, OSS | ~5 min | Quick check |
| `balanced` | + Semgrep, Trivy | ~15 min | Regular scans |
| `deep` | + CodeQL, all | ~45 min | Full audit |

### Individual Scanner Options

```bash
# Gitleaks
GITLEAKS_CONFIG=/path/to/custom.toml

# Semgrep
SEMGREP_RULES=p/security-audit
SEMGREP_TIMEOUT=300

# Trivy
TRIVY_SEVERITY=CRITICAL,HIGH
TRIVY_IGNORE_UNFIXED=true

# Grype
GRYPE_DB_AUTO_UPDATE=true
```

---

## Logging Configuration

### Log Levels

| Level | Description |
|-------|-------------|
| `DEBUG` | Detailed debugging |
| `INFO` | General information |
| `WARNING` | Warnings |
| `ERROR` | Errors only |

### Configuration

```bash
# Environment
LOG_LEVEL=INFO
LOG_FORMAT=json  # or 'text'

# Python
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

---

## Security Best Practices

### Production Checklist

- [ ] Set unique `SECRETS_MASTER_KEY`
- [ ] Use strong `POSTGRES_PASSWORD`
- [ ] Configure CORS for specific origins
- [ ] Enable HTTPS (via reverse proxy)
- [ ] Rotate GitHub PATs every 90 days
- [ ] Use separate PATs per organization
- [ ] Enable database SSL
- [ ] Set up backup retention
- [ ] Configure rate limiting

### Secrets Management

```bash
# Generate secure key
LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32; echo

# Never commit .env to git
echo ".env" >> .gitignore

# Use Docker secrets in production
docker secret create secrets_master_key ./key.txt
```

---

[← Back to README](../README.md) | [Troubleshooting →](TROUBLESHOOTING.md)

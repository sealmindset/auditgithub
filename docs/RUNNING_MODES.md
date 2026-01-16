# Running Modes

AuditGH can be run in multiple ways depending on your needs. This guide explains each mode and when to use it.

## Overview

| Mode | Best For | Pros | Cons |
|------|----------|------|------|
| **Docker Compose** | Production, CI/CD | Isolated, reproducible, includes all services | Requires Docker |
| **Local CLI** | Development, debugging | Fast iteration, direct access | Manual dependency management |
| **Hybrid** | Advanced users | Best of both worlds | More complex setup |

---

## Docker Compose Mode (Recommended)

### Architecture Overview

The Docker Compose setup uses **separate containers** for different workloads:

| Container | Purpose | Resources | Lifecycle |
|-----------|---------|-----------|-----------|
| `auditgh_scanner` | Security scanning | 8GB RAM, 4 CPUs | On-demand |
| `auditgh_api` | REST API backend | 4GB RAM, 2 CPUs | Always running |
| `auditgh_ui` | Web dashboard | - | Always running |
| `auditgh_db` | PostgreSQL database | - | Always running |

This separation ensures that heavy scanning operations don't impact API responsiveness.

### What You Get
- ✅ All services in isolated containers
- ✅ PostgreSQL database included
- ✅ Web UI and API automatically available
- ✅ Consistent environment across machines
- ✅ Easy multi-organization support
- ✅ Automatic service discovery
- ✅ Resource isolation between scanner and API

### What You Don't Get
- ❌ Direct filesystem access to scan results
- ❌ Ability to modify code without rebuilding
- ❌ Native debugger attachment

### Starting the Stack

```bash
# Start all services in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

### Running Scans

The scanner runs in a dedicated container with its own resource limits:

```bash
# Basic scan (default organization)
docker-compose run --rm scanner

# Scan specific organization
docker-compose run --rm scanner --target myorg

# Dry run (preview only)
docker-compose run --rm scanner --target myorg --dry-run

# With AI agent enabled
docker-compose run --rm scanner --target myorg --ai-agent
```

### Running Management Commands

```bash
# List organizations
docker-compose run --rm scanner --list-orgs

# Reset organization data
docker-compose run --rm scanner python scripts/reset_organization_data.py --target myorg --force

# Check schema drift
docker-compose run --rm scanner --check-drift
```

### Accessing Services

| Service | URL | Description |
|---------|-----|-------------|
| Web UI | http://localhost:3000 | React dashboard |
| API | http://localhost:8000 | FastAPI backend |
| API Docs | http://localhost:8000/docs | Swagger UI |
| Database | localhost:5432 | PostgreSQL (user: auditgh) |

---

## Local CLI Mode

### What You Get
- ✅ Fast iteration during development
- ✅ Direct access to scan results
- ✅ Easy debugging with IDE
- ✅ No Docker overhead
- ✅ Modify code without rebuilding

### What You Don't Get
- ❌ Must manage Python dependencies manually
- ❌ Must run PostgreSQL separately
- ❌ Web UI requires separate `npm run dev`
- ❌ Environment differences between machines

### Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export GITHUB_ORG=your-org
export GITHUB_TOKEN=ghp_xxx
export POSTGRES_HOST=localhost
export POSTGRES_DB=auditgh_kb
export POSTGRES_USER=auditgh
export POSTGRES_PASSWORD=postgres
```

### Running Scans

```bash
# Basic scan
python scan_repos.py

# With target organization
python scan_repos.py --target myorg

# Dry run
python scan_repos.py --dry-run

# Verbose output
python scan_repos.py -v
```

### Running Individual Scanners

```bash
# Run specific scanner
python execution/scan_gitleaks.py --org myorg --token $GITHUB_TOKEN
python execution/scan_oss.py --org myorg --token $GITHUB_TOKEN
python execution/scan_semgrep.py --org myorg --token $GITHUB_TOKEN

# Run orchestrator with profile
python execution/orchestrate_scans.py \
  --org myorg \
  --token $GITHUB_TOKEN \
  --profile balanced
```

### Running API Locally

```bash
# Start FastAPI server
cd src/api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Running Web UI Locally

```bash
# Start React dev server
cd src/web-ui
npm install
npm run dev
```

---

## Hybrid Mode

Run database in Docker, everything else locally. Best for development.

### Setup

```bash
# Start only database
docker-compose up -d db

# Run scans locally
source venv/bin/activate
export POSTGRES_HOST=localhost
python scan_repos.py --target myorg

# Run API locally
uvicorn src.api.main:app --reload
```

### When to Use
- Developing new features
- Debugging database issues
- Testing schema changes
- Performance profiling

---

## CI/CD Mode

For automated pipelines (GitHub Actions, Jenkins, etc.)

### GitHub Actions Example

```yaml
name: Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Start services
        run: docker-compose up -d db api

      - name: Run scan
        env:
          GITHUB_TOKEN: ${{ secrets.SCAN_TOKEN }}
        run: |
          docker-compose run --rm scanner --target ${{ github.repository_owner }}

      - name: Export results
        run: |
          docker-compose exec -T db pg_dump -U postgres auditgh_kb > scan_results.sql

      - uses: actions/upload-artifact@v4
        with:
          name: scan-results
          path: scan_results.sql
```

---

## Command Reference

### Docker Compose Commands

| Command | Description |
|---------|-------------|
| `docker-compose up -d` | Start all services |
| `docker-compose down` | Stop all services |
| `docker-compose down -v` | Stop and remove volumes |
| `docker-compose logs -f` | Follow logs |
| `docker-compose ps` | List running services |
| `docker-compose build --no-cache` | Rebuild containers |
| `docker-compose exec db psql -U postgres -d auditgh_kb` | Database shell |

### Scan Commands

| Command | Description |
|---------|-------------|
| `--target ORG` | Scan specific organization |
| `--dry-run` | Preview without scanning |
| `--force-rescan` | Rescan all repos |
| `--rescan-days N` | Rescan repos older than N days |
| `--repo-timeout N` | Per-repo timeout (minutes) |
| `--max-workers N` | Parallel workers |
| `--ai-agent` | Enable AI analysis |
| `-v, --verbose` | Verbose output |

### Management Commands

| Command | Description |
|---------|-------------|
| `--list-orgs` | List organizations |
| `--create-org NAME` | Create organization |
| `--reset-org` | Reset organization data |
| `--list-backups` | List backups |
| `--sync-schemas` | Sync database schemas |
| `--check-drift` | Check schema drift |

---

## Performance Comparison

| Metric | Docker | Local | Hybrid |
|--------|--------|-------|--------|
| Startup time | ~30s | ~5s | ~15s |
| Scan speed | Baseline | +10-20% | +10-20% |
| Memory usage | Higher | Lower | Medium |
| Disk usage | Higher | Lower | Medium |
| Reproducibility | Excellent | Variable | Good |

---

[← Back to README](../README.md) | [Multi-Tenant Setup →](MULTI_TENANT.md)

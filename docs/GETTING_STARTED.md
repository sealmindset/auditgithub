# Getting Started with AuditGH

This guide walks you through installing and running your first scan with AuditGH.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Docker** | Desktop with Compose v2 | Recommended for easiest setup |
| **Python** | 3.11+ | Only if running locally without Docker |
| **GitHub Token** | PAT (classic) | Requires `repo` and `read:org` scopes |
| **PostgreSQL** | 14+ | Included in Docker Compose |

## Quick Start (5 Minutes)

### 1. Clone the Repository

```bash
git clone https://github.com/sealmindset/auditgithub.git
cd auditgithub
```

### 2. Configure Environment

```bash
# Copy sample environment file
cp .env.sample .env

# Edit with your settings
nano .env  # or use your preferred editor
```

**Minimum required variables:**
```bash
# GitHub Configuration
GITHUB_ORG=your-org-name
GITHUB_TOKEN=ghp_your_token_here

# Database (defaults work for Docker)
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=auditgh_kb
```

### 3. Start Database and Apply Migrations

```bash
# Start database
docker-compose up -d db && sleep 5

# Apply schema and all migrations
docker-compose exec -T db psql -U postgres -d auditgh_kb < setup/schema.sql
for f in migrations/*.sql; do docker-compose exec -T db psql -U postgres -d auditgh_kb < "$f"; done
```

### 4. Start API and Web UI

```bash
# Start remaining services
docker-compose up -d api web-ui

# Verify services are running
docker-compose ps
```

You should see:
- `db` - PostgreSQL database (port 5432)
- `api` - FastAPI backend (port 8000)
- `web-ui` - Next.js frontend (port 3000)

### 5. Run Your First Scan

```bash
# Dry run to preview what will be scanned
docker-compose run --rm scanner --target YOUR_ORG --dry-run

# Run actual scan
docker-compose run --rm scanner --target YOUR_ORG
```

> **Note:** The scanner runs in a dedicated container separate from the API, with its own resource limits (up to 8GB RAM) for heavy security scanning operations.

### 6. View Results

- **Web UI**: http://localhost:3000
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

---

## macOS Setup Script

For macOS users, we provide an automated setup script:

```bash
chmod +x setup_mac.sh
./setup_mac.sh
```

This script will:
1. Check for Docker installation
2. Create `.env` file with prompts
3. Generate encryption keys
4. Start the Docker stack
5. Initialize the database

---

## Verify Installation

```bash
# List organizations (should show your default org)
docker-compose run --rm scanner --list-orgs

# Test API
curl http://localhost:8000/organizations/

# Check database connection
docker-compose exec db psql -U postgres -d auditgh_kb -c "SELECT name FROM organizations;"
```

---

## Next Steps

- **[Running Modes](RUNNING_MODES.md)** - Docker vs CLI, when to use each
- **[Multi-Tenant Setup](MULTI_TENANT.md)** - Add multiple GitHub organizations
- **[AI Agents](AI_AGENTS.md)** - Configure AI-powered analysis
- **[Configuration Reference](CONFIGURATION.md)** - All environment variables

---

## Common First-Time Issues

### "Permission denied" on setup script
```bash
chmod +x setup_mac.sh
```

### Docker not running
```bash
# Start Docker Desktop, then:
docker-compose up -d
```

### GitHub token invalid
Ensure your PAT has these scopes:
- `repo` (Full control of private repositories)
- `read:org` (Read org membership)

### Database connection failed
```bash
# Check if db container is running
docker-compose ps db

# View logs
docker-compose logs db
```

---

[← Back to README](../README.md)

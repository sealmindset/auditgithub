# AuditGH Quick Start Card

**5-Minute Setup Guide** - Get scanning in minutes

---

## 1. Initial Setup (First Time Only)

```bash
# Clone and configure
git clone https://github.com/sealmindset/auditgithub.git
cd auditgithub
cp .env.sample .env

# Edit .env - Add your GitHub token
nano .env  # Set GITHUB_TOKEN=ghp_your_token_here

# Start services
docker-compose up -d

# Initialize database
docker exec auditgh_api python init_db.py
```

**Access Web UI:** http://localhost:3000

---

## 2. Your First Scan

```bash
# Preview what will be scanned (dry run)
docker-compose run --rm scanner --target myorg --dry-run

# Run actual scan
docker-compose run --rm scanner --target myorg

# Load results into database
docker exec auditgh_api python ingest_reports.py
```

**View Results:** http://localhost:3000 → Select organization from dropdown

---

## 3. Daily Use

```bash
# Quick incremental scan (only new/changed repos)
docker-compose run --rm scanner --target myorg --rescan-days 1
docker exec auditgh_api python ingest_reports.py
```

---

## 4. Common Commands

```bash
# Service management
docker-compose up -d              # Start all services
docker-compose logs -f api        # View API logs
docker-compose restart api        # Restart API
docker-compose down               # Stop everything

# Scanning variations
--dry-run                        # Preview without scanning
--target myorg                   # Specify organization
--rescan-days 7                  # Incremental (weekly)
--overridescan                   # Force rescan everything
--ai-agent                       # Enable AI analysis
--repo specific-repo             # Scan single repository
--loglevel DEBUG                 # Verbose output
```

---

## 5. Troubleshooting

```bash
# Service not working?
docker-compose restart api

# No data in UI?
docker exec auditgh_api python ingest_reports.py

# Database issues?
docker exec auditgh_api python init_db.py

# Check logs
docker-compose logs -f api

# Nuclear option (fresh restart)
docker-compose down
docker-compose up -d
docker exec auditgh_api python init_db.py
```

---

## 6. Multi-Organization Setup

```bash
# Add organization credentials to .env
ORG_MYORG_TOKEN=ghp_token_here
ORG_MYORG_GITHUB=my-github-org

# Create organization in database
docker exec auditgh_api python -c "
from src.api.database import SessionLocal
from src.api import models
import uuid

db = SessionLocal()
org = models.Organization(
    id=str(uuid.uuid4()),
    name='myorg',
    display_name='My Organization',
    github_org='my-github-org',
    database_name='org_myorg',
    is_active=True,
    is_default=False
)
db.add(org)
db.commit()
print('Created organization: myorg')
"

# Scan the organization
docker-compose run --rm scanner --target myorg
docker exec auditgh_api python ingest_reports.py
```

---

## 7. Recommended Scan Schedule

| Frequency | Command | Purpose |
|-----------|---------|---------|
| **Daily** | `--target myorg --rescan-days 1` | New/changed repos |
| **Weekly** | `--target myorg --rescan-days 7 --ai-agent` | Comprehensive with AI |
| **Monthly** | `--target myorg --overridescan --ai-agent` | Full audit |

---

## 8. Complete Workflow Example

```bash
# Morning routine - scan new changes
docker-compose run --rm scanner --target myorg --rescan-days 1
docker exec auditgh_api python ingest_reports.py

# View results
open http://localhost:3000

# Check specific repository
docker-compose run --rm scanner --target myorg --repo critical-app

# Re-ingest
docker exec auditgh_api python ingest_reports.py
```

---

## Need More Help?

- **Complete Guide:** [CHEATSHEET.md](CHEATSHEET.md) - All commands with explanations
- **Full Documentation:** [docs/](docs/) - Detailed guides
- **Issues:** [GitHub Issues](https://github.com/sealmindset/auditgithub/issues)

---

## Key Files

- `.env` - Configuration (GitHub tokens, AI keys)
- `docker-compose.yml` - Service definitions
- `scan_repos.py` - Scanner entry point
- `ingest_reports.py` - Load scan results to database
- `vulnerability_reports/` - Scan output directory

---

## Ports

- **3000** - Web UI
- **8000** - API
- **5432** - PostgreSQL
- **6379** - Redis

---

**That's it!** You're now scanning. See [CHEATSHEET.md](CHEATSHEET.md) for advanced usage.

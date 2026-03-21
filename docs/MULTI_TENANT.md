# Multi-Tenant Organization Management

AuditGH supports scanning multiple GitHub organizations from a single installation. Each organization's data is securely isolated with its own credentials.

## Enabling Multi-Tenant Mode

Multi-tenant support is controlled by an environment variable:

```bash
# In .env file
MULTI_TENANT_ENABLED=true
```

> **Note:** This is a **runtime variable** - no rebuild required. Just change the value and restart:
> ```bash
> docker-compose down
> docker-compose up -d api web-ui
> ```

| Setting | Behavior |
|---------|----------|
| `MULTI_TENANT_ENABLED=false` | Single organization mode (default org only) |
| `MULTI_TENANT_ENABLED=true` | Multiple organizations with isolated data |

---

## Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      AuditGH Instance                        │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  example-org │  │    acme      │  │   clientx    │      │
│  │   (default)  │  │              │  │              │      │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤      │
│  │ PAT: ghp_... │  │ PAT: ghp_... │  │ PAT: ghp_... │      │
│  │ Repos: 60    │  │ Repos: 120   │  │ Repos: 45    │      │
│  │ Findings: 2k │  │ Findings: 5k │  │ Findings: 1k │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │              PostgreSQL (auditgh_kb)                   │ │
│  │  organization_id scopes all data per tenant            │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Quick Setup

### Method 1: Environment Variables (Recommended)

Add organizations to your `.env` file:

```bash
# Default organization (used when no --target specified)
GITHUB_ORG=example-org
GITHUB_TOKEN=ghp_your_default_token

# Additional organizations - naming convention: ORG_{NAME}_TOKEN and ORG_{NAME}_GITHUB
ORG_ACME_TOKEN=ghp_acme_pat_here
ORG_ACME_GITHUB=acme-corp

ORG_CLIENTX_TOKEN=ghp_clientx_pat_here
ORG_CLIENTX_GITHUB=clientx-org

ORG_EXAMPLE_ORG_LABS_TOKEN=ghp_example-org_pat_here
ORG_EXAMPLE_ORG_LABS_GITHUB=example-orglabs
```

**That's it!** On startup, the system automatically:
1. Loads all `ORG_*` credentials from `.env`
2. Registers new organizations in the database
3. Stores PATs securely in the encrypted secrets manager

### Method 2: CLI Creation

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --create-org mycompany --github-org my-github-org --token ghp_xxx'
```

### Method 3: API Creation

```bash
curl -X POST http://localhost:8000/organizations/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mycompany",
    "github_org": "my-github-org",
    "github_token": "ghp_xxx"
  }'
```

---

## Scanning Organizations

### Scan Default Organization

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py'
```

### Scan Specific Organization

```bash
# Scan acme (uses ORG_ACME_TOKEN automatically)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --target acme'

# Scan clientx
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --target clientx'
```

### Dry Run (Preview)

```bash
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --target acme --dry-run'
```

---

## Managing Organizations

### List All Organizations

```bash
# CLI
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --list-orgs'

# API
curl http://localhost:8000/organizations/
```

**Example output:**
```
📋 Registered Organizations:
------------------------------------------------------------
  example-org (default)
    GitHub: example-org | DB: auditgh_kb
    Status: ✓ active | Schema: synced
    Last scan: 2024-01-15 10:30:00

  acme
    GitHub: acme-corp | DB: auditgh_kb
    Status: ✓ active | Schema: synced
    Last scan: 2024-01-14 22:00:00

🔑 Organizations with credentials: example-org, acme
```

### Update/Rotate PAT

**Via `.env` file:**
1. Update the token in `.env`
2. Restart: `docker-compose restart`

**Via API (no restart needed):**
```bash
curl -X PUT http://localhost:8000/organizations/acme/credentials \
  -H "Content-Type: application/json" \
  -d '{"github_token": "ghp_new_token_here"}'
```

### Check Credential Status

```bash
curl http://localhost:8000/organizations/acme/credentials/status
```

### Select Organization Context

For the Web UI to show the correct organization's data:

```bash
curl -X POST http://localhost:8000/organizations/acme/select
```

---

## Data Isolation

### How It Works

All data is scoped by `organization_id`:

```sql
-- Each table has organization_id column
SELECT * FROM repositories WHERE organization_id = 'uuid-of-acme';
SELECT * FROM findings WHERE organization_id = 'uuid-of-acme';
SELECT * FROM scan_runs WHERE organization_id = 'uuid-of-acme';
```

### Tables with Organization Scoping

| Table | Description |
|-------|-------------|
| `repositories` | GitHub repositories |
| `scan_runs` | Scan execution records |
| `findings` | Security findings |
| `contributors` | Repository contributors |
| `language_stats` | Language breakdown |
| `dependencies` | Package dependencies |
| `api_endpoints` | Discovered API endpoints |
| `openapi_specs` | OpenAPI specifications |
| `file_commits` | File commit history |
| `credential_url_test_results` | Credential testing results |

### Unique Constraints

Repository names are unique **per organization**, not globally:

```sql
-- Both can exist simultaneously
INSERT INTO repositories (name, organization_id) VALUES ('api-service', 'acme-uuid');
INSERT INTO repositories (name, organization_id) VALUES ('api-service', 'clientx-uuid');
```

---

## Schema Management

### Check Schema Drift

Detect if organization schemas are out of sync:

```bash
# CLI
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --check-drift'

# API
curl http://localhost:8000/organizations/schema/drift
```

### Sync Schemas

Bring all organizations to the latest schema:

```bash
# CLI - sync all
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --sync-schemas'

# API - sync specific org
curl -X POST http://localhost:8000/organizations/acme/sync-schema
```

---

## Reset Organization Data

See [Database Reset Guide](DATABASE_RESET.md) for complete details.

### Quick Reset

```bash
# Reset with backup (prompts for confirmation)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --target acme'

# Reset without confirmation (automation)
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --target acme --force'
```

### Reset + Fresh Scan

```bash
# Step 1: Reset
docker-compose run --rm --entrypoint bash auditgh -c \
  'python scripts/reset_organization_data.py --target acme --force'

# Step 2: Fresh scan
docker-compose run --rm --entrypoint bash auditgh -c \
  'python3 scan_repos.py --target acme'
```

---

## Security Considerations

### Credential Storage

- PATs are encrypted using Fernet (AES-128-CBC)
- Encryption key: `SECRETS_MASTER_KEY` environment variable
- Secrets file: `/tmp/auditgithub_secrets.json` (in container)

### Generate Secure Master Key

```bash
# Generate 32-character key
LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32; echo
```

### Best Practices

1. **Use separate PATs** for each organization
2. **Rotate PATs regularly** (every 90 days recommended)
3. **Use minimum required scopes**: `repo`, `read:org`
4. **Set `SECRETS_MASTER_KEY`** in production (don't use auto-generated)
5. **Backup encryption key** securely - losing it means re-adding all credentials

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/organizations/` | List all organizations |
| GET | `/organizations/current` | Get current organization |
| GET | `/organizations/{name}` | Get organization details |
| POST | `/organizations/` | Create new organization |
| POST | `/organizations/{name}/select` | Select organization context |
| PUT | `/organizations/{name}/credentials` | Update PAT |
| GET | `/organizations/{name}/credentials/status` | Check credentials |
| POST | `/organizations/{name}/sync-schema` | Sync schema |
| GET | `/organizations/schema/drift` | Check drift |
| GET | `/organizations/configured` | List orgs with credentials |

---

## Troubleshooting

### "Organization not found"

```bash
# List available organizations
docker-compose run --rm --entrypoint bash auditgh -c 'python3 scan_repos.py --list-orgs'

# Check if credentials are configured
curl http://localhost:8000/organizations/myorg/credentials/status
```

### "Invalid token" or "Bad credentials"

1. Verify PAT hasn't expired
2. Check PAT has required scopes (`repo`, `read:org`)
3. Verify organization name matches GitHub exactly

### "Encryption error"

```bash
# Clear secrets and restart
docker-compose exec api rm -f /tmp/auditgithub_secrets.json
docker-compose restart api

# Re-add credentials via API or restart to reload from .env
```

### Data appearing in wrong organization

This was fixed in migration `004_fix_multi_tenant_repositories.sql`. If you see this:

```bash
# Apply the fix migration
docker-compose exec -T db psql -U postgres -d auditgh_kb < migrations/004_fix_multi_tenant_repositories.sql
```

---

[← Back to README](../README.md) | [Database Reset →](DATABASE_RESET.md)

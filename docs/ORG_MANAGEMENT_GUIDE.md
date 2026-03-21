# Organization Management Guide

Complete guide for managing GitHub organizations in the AuditGH security portal system.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [API Endpoints](#api-endpoints)
4. [Command-Line Tools](#command-line-tools)
5. [Interactive Menu](#interactive-menu)
6. [Python Backend](#python-backend)
7. [Common Workflows](#common-workflows)
8. [Troubleshooting](#troubleshooting)

## Overview

The AuditGH system supports multiple GitHub organizations, each with isolated repositories, findings, and security scan data. You can manage organizations through:

- **REST API** - Full CRUD operations via HTTP endpoints
- **CLI Tool** (`org.sh`) - Command-line interface for scripting
- **Interactive Menu** (`manage-orgs.sh`) - User-friendly guided interface
- **Python Backend** (`org_manager.py`) - Direct Python API

## Quick Start

### Adding a New Organization

**Using Interactive Menu** (Recommended for beginners):
```bash
./manage-orgs.sh
# Select option 3: Create new organization
# Follow the prompts
```

**Using Command-Line**:
```bash
./org.sh create example-org example-org ghp_xxxxxxxxxxxx --display-name "Example Organization"
./org.sh import example-org
```

**Using API**:
```bash
curl -X POST http://localhost:8000/api/organizations/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example-org",
    "github_org": "example-org",
    "github_token": "ghp_xxxxxxxxxxxx",
    "display_name": "Example Organization",
    "set_as_default": false
  }'
```

### Listing Organizations

```bash
# CLI
./org.sh list

# Interactive
./manage-orgs.sh  # Select option 1

# API
curl http://localhost:8000/api/organizations/

# Python
python org_manager.py list
```

## API Endpoints

All endpoints are under the `/api/organizations` prefix.

### List Organizations
```http
GET /api/organizations/
Query Parameters:
  - include_inactive: boolean (default: false)

Response: Array of OrganizationResponse
```

Example:
```bash
curl "http://localhost:8000/api/organizations/?include_inactive=false"
```

### Get Organization Details
```http
GET /api/organizations/{org_name}

Response: OrganizationResponse
```

Example:
```bash
curl http://localhost:8000/api/organizations/example-org
```

### Create Organization
```http
POST /api/organizations/
Body: CreateOrganizationRequest
{
  "name": "string",              // Required: lowercase, alphanumeric
  "github_org": "string",        // Required: GitHub org name
  "github_token": "string",      // Required: GitHub PAT
  "display_name": "string",      // Optional: human-readable name
  "create_database": true,       // Optional: create separate database
  "set_as_default": false        // Optional: set as default org
}

Response: OrganizationResponse
```

Example:
```bash
curl -X POST http://localhost:8000/api/organizations/ \
  -H "Content-Type: application/json" \
  -d '{
    "name": "myorg",
    "github_org": "my-github-org",
    "github_token": "ghp_xxxxxxxxxxxx",
    "display_name": "My Organization"
  }'
```

### Update Organization
```http
PATCH /api/organizations/{org_name}
Body: UpdateOrganizationRequest
{
  "display_name": "string",      // Optional
  "is_active": boolean,          // Optional
  "is_default": boolean          // Optional
}

Response: OrganizationResponse
```

Example:
```bash
curl -X PATCH http://localhost:8000/api/organizations/myorg \
  -H "Content-Type: application/json" \
  -d '{"display_name": "Updated Name"}'
```

### Delete Organization
```http
DELETE /api/organizations/{org_name}
Query Parameters:
  - drop_database: boolean (default: false)

Response: {"success": true, "message": "..."}
```

Example:
```bash
curl -X DELETE "http://localhost:8000/api/organizations/myorg?drop_database=false"
```

### Import Repositories
```http
POST /api/organizations/{org_name}/import
Query Parameters:
  - confirm: boolean (default: false)

Response: {
  "success": boolean,
  "message": "string",
  "total": number,
  "created": number,
  "updated": number,
  "failed": number
}
```

Example:
```bash
curl -X POST "http://localhost:8000/api/organizations/example-org/import?confirm=true"
```

### Sync Repositories
```http
POST /api/organizations/{org_name}/sync-repos

Response: {
  "success": boolean,
  "message": "string",
  "total": number,
  "synced": number,
  "failed": number
}
```

Example:
```bash
curl -X POST http://localhost:8000/api/organizations/example-org/sync-repos
```

### Update Credentials
```http
PUT /api/organizations/{org_name}/credentials
Body: UpdateCredentialsRequest
{
  "github_token": "string",      // Required
  "github_org": "string"         // Optional
}

Response: {"success": true, "message": "..."}
```

Example:
```bash
curl -X PUT http://localhost:8000/api/organizations/example-org/credentials \
  -H "Content-Type: application/json" \
  -d '{"github_token": "ghp_new_token_here"}'
```

### Get Organization Repositories
```http
GET /api/organizations/{org_name}/repositories
Query Parameters:
  - skip: number (default: 0)
  - limit: number (default: 100, max: 1000)

Response: Array of Repository objects
```

### Get Organization Findings
```http
GET /api/organizations/{org_name}/findings
Query Parameters:
  - skip: number (default: 0)
  - limit: number (default: 100, max: 1000)
  - severity: string (optional: critical, high, medium, low)
  - repository_id: string (optional)

Response: Array of Finding objects
```

## Command-Line Tools

### org.sh - CLI Tool

The `org.sh` script provides command-line access to all organization management features.

#### Usage

```bash
./org.sh <command> [arguments]
```

#### Commands

**List Organizations**:
```bash
./org.sh list                          # List active organizations
./org.sh list --include-inactive       # Include inactive organizations
./org.sh list --json                   # Output as JSON
```

**Show Organization**:
```bash
./org.sh show example-org
./org.sh show example-org --json
```

**Create Organization**:
```bash
./org.sh create <name> <github-org> <token> [options]

# Examples:
./org.sh create myorg my-github-org ghp_token123
./org.sh create myorg my-github-org ghp_token123 --display-name "My Organization"
./org.sh create myorg my-github-org ghp_token123 --set-default
```

**Update Organization**:
```bash
./org.sh update <name> [options]

# Examples:
./org.sh update myorg --display-name "New Name"
./org.sh update myorg --active true
./org.sh update myorg --set-default
```

**Delete Organization**:
```bash
./org.sh delete <name> [--force]

# Examples:
./org.sh delete oldorg                 # Prompts for confirmation
./org.sh delete oldorg --force         # Skips confirmation
```

**Import Repositories**:
```bash
./org.sh import <name> [--token TOKEN]

# Examples:
./org.sh import example-org                    # Uses GITHUB_TOKEN env var
./org.sh import example-org --token ghp_xxx    # Uses specified token
```

**Set Default Organization**:
```bash
./org.sh set-default <name>

# Example:
./org.sh set-default example-org
```

#### Options

- `--include-inactive` - Include inactive organizations in list
- `--json` - Output as JSON
- `--display-name NAME` - Set display name
- `--set-default` - Set as default organization
- `--active true|false` - Set active status
- `--force` - Skip confirmation prompts
- `--token TOKEN` - GitHub token

## Interactive Menu

### manage-orgs.sh - Interactive Interface

The `manage-orgs.sh` script provides a user-friendly interactive menu for all organization management operations.

#### Usage

```bash
./manage-orgs.sh
```

#### Menu Options

1. **List all organizations** - View all registered organizations with counts
2. **Show organization details** - View detailed information about an organization
3. **Create new organization** - Guided organization creation with prompts
4. **Update organization** - Update organization properties
5. **Delete organization** - Delete organization with confirmation
6. **Import repositories from GitHub** - Import all repos from GitHub
7. **Set default organization** - Set the default organization
8. **Exit** - Exit the menu

#### Features

- Color-coded output for better readability
- Input validation
- Confirmation prompts for destructive operations
- Secure token input (hidden from terminal)
- Option to import repositories immediately after creation
- Clear error messages and success feedback

## Python Backend

### org_manager.py - Python API

The `org_manager.py` module provides direct Python access to organization management.

#### Usage as CLI

```bash
python org_manager.py <command> [arguments]
```

#### Usage as Python Module

```python
from org_manager import OrgManager

# Create manager instance
with OrgManager() as manager:
    # List organizations
    orgs = manager.list_organizations(json_output=True)

    # Get organization details
    org = manager.get_organization("example-org", json_output=True)

    # Create organization
    new_org = manager.create_organization(
        name="myorg",
        github_org="my-github-org",
        github_token="ghp_xxxxxxxxxxxx",
        display_name="My Organization",
        set_as_default=False
    )

    # Update organization
    updated_org = manager.update_organization(
        org_name="myorg",
        display_name="Updated Name",
        is_active=True
    )

    # Delete organization
    success = manager.delete_organization("oldorg", force=True)

    # Import repositories
    result = manager.import_repositories("myorg", github_token="ghp_xxx")
```

#### Methods

**OrgManager.list_organizations(include_inactive=False, json_output=False)**
- Returns list of organization dictionaries
- Prints formatted table if json_output=False

**OrgManager.get_organization(org_name, json_output=False)**
- Returns organization dictionary or None
- Prints formatted details if json_output=False

**OrgManager.create_organization(name, github_org, github_token, display_name=None, set_as_default=False)**
- Creates new organization
- Returns organization dictionary

**OrgManager.update_organization(org_name, display_name=None, is_active=None, set_as_default=None)**
- Updates organization properties
- Returns updated organization dictionary

**OrgManager.delete_organization(org_name, force=False)**
- Deletes organization
- Returns True if successful

**OrgManager.import_repositories(org_name, github_token=None)**
- Imports all repositories from GitHub
- Returns import result dictionary with counts

## Common Workflows

### Workflow 1: Adding a New Organization

1. Create the organization:
   ```bash
   ./org.sh create example-org example-org ghp_xxxxxxxxxxxx --display-name "Example Organization"
   ```

2. Import repositories:
   ```bash
   ./org.sh import example-org
   ```

3. Verify import:
   ```bash
   ./org.sh show example-org
   ```

4. Run security scan:
   ```bash
   docker-compose run --rm scanner --target example-org
   ```

### Workflow 2: Switching Default Organization

```bash
# List organizations to see current default
./org.sh list

# Set new default
./org.sh set-default example-org

# Verify change
./org.sh list
```

### Workflow 3: Rotating GitHub Token

```bash
# Update credentials via API
curl -X PUT http://localhost:8000/api/organizations/example-org/credentials \
  -H "Content-Type: application/json" \
  -d '{"github_token": "ghp_new_token_here"}'

# Or restart Docker containers with updated .env
docker-compose down
# Edit .env with new token
docker-compose up -d
```

### Workflow 4: Bulk Organization Management

```bash
# Create script to add multiple organizations
#!/bin/bash

ORGS=(
  "org1:github-org-1:ghp_token1"
  "org2:github-org-2:ghp_token2"
  "org3:github-org-3:ghp_token3"
)

for ORG_LINE in "${ORGS[@]}"; do
  IFS=':' read -r NAME GITHUB_ORG TOKEN <<< "$ORG_LINE"
  ./org.sh create "$NAME" "$GITHUB_ORG" "$TOKEN"
  ./org.sh import "$NAME" --token "$TOKEN"
done
```

### Workflow 5: Monitoring Organization Status

```bash
# Get JSON output for processing
./org.sh list --json > orgs.json

# Parse with jq
cat orgs.json | jq '.[] | select(.total_repos > 0) | {name, total_repos, total_findings}'

# Check specific organization
./org.sh show example-org --json | jq '{name, total_repos, total_findings}'
```

## Troubleshooting

### Issue: "Organization already exists"

**Problem**: Trying to create an organization with a name that already exists.

**Solution**:
```bash
# Check existing organizations
./org.sh list

# Use a different name or update the existing organization
./org.sh update existingorg --display-name "New Display Name"
```

### Issue: "Invalid GitHub token"

**Problem**: The GitHub token is expired, revoked, or has insufficient permissions.

**Solution**:
1. Generate a new token at https://github.com/settings/tokens
2. Required scopes: `repo`, `read:org`, `read:user`
3. Update credentials:
   ```bash
   curl -X PUT http://localhost:8000/api/organizations/myorg/credentials \
     -H "Content-Type: application/json" \
     -d '{"github_token": "ghp_new_token"}'
   ```

### Issue: "GitHub organization not found"

**Problem**: The GitHub organization name is incorrect or not accessible.

**Solution**:
1. Verify organization name on GitHub
2. Ensure token has access to the organization
3. Update organization:
   ```bash
   ./org.sh update myorg --github-org correct-org-name
   ```

### Issue: "Failed to get database session"

**Problem**: Database connection issues or Docker containers not running.

**Solution**:
```bash
# Check Docker containers
docker-compose ps

# Restart if needed
docker-compose down
docker-compose up -d

# Check database connection
docker-compose exec db psql -U postgres -d security_portal -c "SELECT 1;"
```

### Issue: "Column does not exist" errors

**Problem**: Database schema is missing columns from migrations.

**Solution**:
```bash
# Run schema fix script
./fix-both-dbs.sh

# Or apply migrations manually
docker-compose exec db psql -U postgres -d security_portal -f /docker-entrypoint-initdb.d/002_organizations.sql
```

### Issue: "Duplicate key value" errors

**Problem**: PostgreSQL sequence is out of sync.

**Solution**:
```bash
# Fix sequence in Docker
docker-compose exec db psql -U postgres -d security_portal << 'EOF'
SELECT setval('organizations_api_id_seq', (SELECT MAX(api_id) FROM organizations));
EOF
```

### Issue: Repository import fails for some repos

**Problem**: Some repositories may be private, archived, or have API issues.

**Solution**:
- Check the import summary for failed count
- Review logs for specific errors
- Retry with:
  ```bash
  ./org.sh import myorg
  ```
- For persistent failures, check GitHub API status

### Issue: Cannot access API endpoints

**Problem**: API server not running or authentication issues.

**Solution**:
```bash
# Check API health
curl http://localhost:8000/health

# Check API logs
docker-compose logs api

# Restart API
docker-compose restart api
```

## Best Practices

1. **Use descriptive organization names**: Choose clear, lowercase names without special characters

2. **Set display names**: Always provide a human-readable display name for better UX

3. **Secure token storage**: Never commit GitHub tokens to version control. Use environment variables or secrets manager.

4. **Import repositories after creation**: Always import repositories immediately after creating an organization

5. **Regular syncs**: Periodically sync repository metadata to stay up-to-date:
   ```bash
   curl -X POST http://localhost:8000/api/organizations/myorg/sync-repos
   ```

6. **Monitor failed imports**: Check import results and investigate failed repositories

7. **Backup before deletion**: Export organization data before deleting:
   ```bash
   ./org.sh show myorg --json > myorg-backup.json
   ```

8. **Use interactive menu for one-off tasks**: Use `manage-orgs.sh` for manual operations

9. **Use CLI for automation**: Use `org.sh` in scripts and CI/CD pipelines

10. **Use API for integrations**: Use REST API for web applications and external integrations

## Additional Resources

- **API Documentation**: http://localhost:8000/docs (when API is running)
- **GitHub Token Setup**: https://github.com/settings/tokens
- **Database Schema**: See `migrations/002_organizations.sql`
- **Backup Scripts**: See `add-org.sh.backup` and `add_example-org_org.py.backup`

## Support

For issues or questions:
1. Check this guide's troubleshooting section
2. Review API logs: `docker-compose logs api`
3. Review scanner logs: `docker-compose logs scanner`
4. Check GitHub token permissions
5. Verify database connectivity

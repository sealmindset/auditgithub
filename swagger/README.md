# AuditGH API Swagger Documentation

Comprehensive OpenAPI 3.0 specification for the AuditGH Security Portal API.

## Overview

This directory contains the complete API documentation organized by functional areas using the OpenAPI 3.0 specification format. The documentation is split into modular components for maintainability and reusability.

## Directory Structure

```
swagger/
├── openapi.yaml              # Main OpenAPI specification file
├── components/
│   ├── schemas.yaml          # Reusable data schemas
│   ├── responses.yaml        # Common response definitions
│   └── parameters.yaml       # Reusable parameters
└── paths/
    ├── organizations/        # Organization management endpoints
    ├── repositories/         # Repository management endpoints
    ├── findings/             # Security findings endpoints
    ├── scans/                # Security scan endpoints
    ├── github/               # GitHub integration endpoints
    ├── auth/                 # Authentication endpoints
    ├── tenants/              # Multi-tenant management
    ├── secrets/              # Secret detection endpoints
    ├── attack-surface/       # Attack surface analysis
    ├── attack-paths/         # Attack path visualization
    ├── analytics/            # Analytics and metrics
    ├── sla/                  # SLA tracking
    ├── contributors/         # Contributor profiles
    ├── ai/                   # AI-powered analysis
    ├── jira/                 # Jira integration
    ├── cribl/                # Cribl Stream integration
    ├── settings/             # System settings
    ├── scheduler/            # Job scheduling
    └── feedback/             # User feedback

```

## Viewing the Documentation

### Using Swagger UI (Online)

1. Visit [Swagger Editor](https://editor.swagger.io/)
2. Upload the `openapi.yaml` file
3. Browse the interactive documentation

### Using Swagger UI (Local)

```bash
# Install Swagger UI
npm install -g swagger-ui-watcher

# Serve documentation
swagger-ui-watcher swagger/openapi.yaml
```

### Using Redoc (Alternative)

```bash
# Install Redoc CLI
npm install -g redoc-cli

# Generate HTML documentation
redoc-cli bundle swagger/openapi.yaml -o docs/api.html
```

### Integrating with FastAPI

FastAPI automatically generates OpenAPI documentation. To use this spec:

```python
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

app = FastAPI()

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    # Load your custom OpenAPI spec
    import yaml
    with open("swagger/openapi.yaml") as f:
        openapi_schema = yaml.safe_load(f)

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
```

## API Organization

### Core API (Organizations & Repositories)

**Organizations** - Multi-organization management
- `GET /api/organizations` - List organizations
- `POST /api/organizations` - Create organization
- `GET /api/organizations/{org_name}` - Get organization details
- `PATCH /api/organizations/{org_name}` - Update organization
- `DELETE /api/organizations/{org_name}` - Delete organization
- `POST /api/organizations/{org_name}/import` - Import repositories
- `POST /api/organizations/{org_name}/sync-repos` - Sync repositories
- `GET /api/organizations/{org_name}/repositories` - List org repositories
- `GET /api/organizations/{org_name}/findings` - List org findings
- `PUT /api/organizations/{org_name}/credentials` - Update credentials
- `POST /api/organizations/{org_name}/scan` - Start scan

**Repositories** - Repository management
- `GET /api/repositories` - List all repositories
- `GET /api/repositories/{repo_id}` - Get repository details
- `POST /api/repositories/{repo_id}/scan` - Scan repository
- `GET /api/repositories/{repo_id}/architecture` - Get architecture docs

**Findings** - Security findings management
- `GET /api/findings` - List findings (with filtering)
- `GET /api/findings/{finding_id}` - Get finding details
- `PATCH /api/findings/{finding_id}` - Update finding
- `PATCH /api/findings/{finding_id}/status` - Update status
- `GET /api/findings/statistics` - Get statistics

**Scans** - Security scan orchestration
- `GET /api/scans` - List scans
- `GET /api/scans/{scan_id}` - Get scan details
- `DELETE /api/scans/{scan_id}` - Cancel scan
- `GET /api/scans/{scan_id}/status` - Get scan status

### GitHub Integration

- `GET /api/github/repos/{repo_name}/metadata` - Get GitHub metadata
- `POST /api/github/repos/{repo_name}/sync` - Sync from GitHub
- `POST /api/github/sync-all` - Sync all repositories
- `GET /api/github/sync-status` - Get sync status

### Authentication & Authorization

- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `POST /api/auth/refresh` - Refresh token
- `GET /api/auth/me` - Get current user

### Security Features

- `GET /api/secrets` - List detected secrets
- `GET /api/attack-surface` - Get attack surface analysis
- `GET /api/attack-paths` - List attack paths

### Analytics & Reporting

- `GET /api/analytics/dashboard` - Dashboard metrics
- `GET /api/analytics/trends` - Trend data
- `GET /api/sla/metrics` - SLA metrics
- `GET /api/contributors` - Contributor profiles

### AI-Powered Analysis

- `POST /api/ai/architecture/generate` - Generate architecture documentation

### Integrations

**Jira**
- `GET /api/jira/tickets` - List Jira tickets
- `POST /api/jira/tickets` - Create Jira ticket

**Cribl**
- `POST /api/cribl/forward` - Forward logs to Cribl Stream

### System Management

- `GET /api/settings` - Get settings
- `PATCH /api/settings` - Update settings
- `GET /api/scheduler/jobs` - List scheduled jobs
- `POST /api/scheduler/jobs` - Schedule job
- `POST /api/feedback` - Submit feedback

## Authentication

All API endpoints (except login) require JWT authentication:

```bash
# Login to get token
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Use token in requests
curl http://localhost:8000/api/organizations \
  -H "Authorization: Bearer <your-jwt-token>"
```

## Common Patterns

### Pagination

Most list endpoints support pagination:

```bash
GET /api/findings?skip=0&limit=100
```

Parameters:
- `skip`: Number of records to skip (default: 0)
- `limit`: Number of records to return (default: 100, max: 1000)

### Filtering

List endpoints support various filters:

```bash
# Filter findings by severity
GET /api/findings?severity=high

# Filter by multiple criteria
GET /api/findings?severity=high&status=open&repository_id=<uuid>
```

### Response Format

All responses return JSON:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "sleepnumber",
  "display_name": "Sleep Number",
  "is_active": true,
  "total_repos": 42,
  "total_findings": 156
}
```

### Error Responses

Errors follow standard format:

```json
{
  "detail": "Resource not found"
}
```

HTTP Status Codes:
- `200` - Success
- `400` - Bad Request (validation error)
- `401` - Unauthorized (authentication required)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found
- `500` - Internal Server Error

## Examples

### Create Organization and Import Repositories

```bash
# 1. Create organization
curl -X POST http://localhost:8000/api/organizations/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "sleepnumber",
    "github_org": "sleepnumber",
    "github_token": "ghp_xxxxxxxxxxxx",
    "display_name": "Sleep Number"
  }'

# 2. Import repositories
curl -X POST "http://localhost:8000/api/organizations/sleepnumber/import?confirm=true" \
  -H "Authorization: Bearer <token>"

# 3. Start security scan
curl -X POST "http://localhost:8000/api/organizations/sleepnumber/scan?scan_type=full" \
  -H "Authorization: Bearer <token>"
```

### Query Findings

```bash
# Get all critical findings
curl "http://localhost:8000/api/findings?severity=critical&status=open" \
  -H "Authorization: Bearer <token>"

# Get statistics
curl http://localhost:8000/api/findings/statistics \
  -H "Authorization: Bearer <token>"

# Update finding status
curl -X PATCH http://localhost:8000/api/findings/<finding-id>/status \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"status": "resolved", "resolution_notes": "Fixed in PR #123"}'
```

## Development

### Validating the Spec

```bash
# Using swagger-cli
npm install -g @apidevtools/swagger-cli
swagger-cli validate swagger/openapi.yaml

# Using openapi-generator
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli validate \
  -i /local/swagger/openapi.yaml
```

### Generating Client SDKs

```bash
# Generate Python client
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/swagger/openapi.yaml \
  -g python \
  -o /local/clients/python

# Generate TypeScript client
docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/swagger/openapi.yaml \
  -g typescript-axios \
  -o /local/clients/typescript
```

## Maintenance

### Adding New Endpoints

1. Create path file in appropriate subdirectory: `paths/<category>/<endpoint>.yaml`
2. Add path reference to `openapi.yaml`
3. Update this README with endpoint documentation
4. Validate spec: `swagger-cli validate swagger/openapi.yaml`

### Adding New Schemas

1. Add schema definition to `components/schemas.yaml`
2. Reference in path files using `$ref: '../../components/schemas.yaml#/<SchemaName>'`
3. Validate spec

### Best Practices

- Use consistent naming conventions
- Include comprehensive descriptions
- Provide examples for all schemas
- Document all query parameters
- Specify all possible HTTP status codes
- Keep related endpoints in same subdirectory
- Reference reusable components instead of duplicating

## Resources

- [OpenAPI Specification](https://spec.openapis.org/oas/v3.0.3)
- [Swagger Editor](https://editor.swagger.io/)
- [Swagger UI](https://swagger.io/tools/swagger-ui/)
- [Redoc](https://github.com/Redocly/redoc)
- [OpenAPI Generator](https://openapi-generator.tech/)

## Support

For API questions or issues:
1. Check this documentation
2. View interactive docs at `http://localhost:8000/docs` (when API is running)
3. Review source code in `src/api/routers/`
4. Submit feedback via POST `/api/feedback`

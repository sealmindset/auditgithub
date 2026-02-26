# OpenAPI Specification & Swagger Completeness Plan

**Document Purpose:** Roadmap for achieving a complete, comprehensive OpenAPI specification that developers, DevOps engineers, and security analysts can use to test, learn, and integrate with all AuditGH API services.

**Created:** 2026-02-26
**Status:** Proposed
**Audience:** Solution Architects, Backend Engineers, DevOps, Security Analysts

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current State Assessment](#2-current-state-assessment)
3. [Strategy: Single Source of Truth](#3-strategy-single-source-of-truth)
4. [Phase 1 — Foundation (Critical)](#4-phase-1--foundation-critical)
5. [Phase 2 — Router Enrichment (High)](#5-phase-2--router-enrichment-high)
6. [Phase 3 — Schema & Model Quality (High)](#6-phase-3--schema--model-quality-high)
7. [Phase 4 — Developer Experience (Medium)](#7-phase-4--developer-experience-medium)
8. [Phase 5 — CI/CD & Governance (Medium)](#8-phase-5--cicd--governance-medium)
9. [Router-by-Router Work Matrix](#9-router-by-router-work-matrix)
10. [File Inventory](#10-file-inventory)
11. [Estimated Effort](#11-estimated-effort)
12. [Success Criteria](#12-success-criteria)
13. [Appendix: Undocumented Endpoint Inventory](#appendix-undocumented-endpoint-inventory)

---

## 1. Executive Summary

### The Problem

AuditGH has **315+ API endpoints** across 28 router modules, but the documentation tells two incomplete stories:

| Source | Coverage | Quality | Accessible |
|--------|----------|---------|------------|
| **Hand-written swagger/** | 51 endpoints (16%) | High quality (schemas, examples, descriptions) | Not served — must be opened manually |
| **FastAPI auto-docs /docs** | 315+ endpoints (100%) | Inconsistent (7.5/10 average) | Live at `http://localhost:8000/docs` |

**Neither source gives developers, DevOps, or security analysts a complete, testable, self-service API reference.**

### The Solution

**Enrich the FastAPI auto-generated OpenAPI as the single source of truth**, applying the quality standards from the hand-written spec directly into the Python code. This means:

- Every endpoint gets a docstring, summary, response_model, and error responses
- Every Pydantic field gets a `Field(description=...)`
- Every router gets consistent tags and security annotations
- The hand-written `swagger/` directory becomes the reference archive
- Developers get a complete, live, testable Swagger UI at `/docs`

### Key Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Endpoints with docstrings | ~60% | 100% |
| Endpoints with response_model | ~45% | 100% |
| Endpoints with error responses | ~7% (2/28 routers) | 100% |
| Fields with Field() descriptions | ~8% (36/463) | 100% |
| Routers with tags | 96% (27/28) | 100% |
| Security annotations | 0% | 100% |
| Request/response examples | ~10% | 80%+ |

---

## 2. Current State Assessment

### 2.1 Hand-Written Swagger Specification

**Location:** `swagger/`
**Version:** OpenAPI 3.0.3, `version: 2.0.0` (mismatches FastAPI's `version: 1.0.0`)

**Strengths:**
- Well-organized modular structure (50+ YAML files)
- Comprehensive schemas with descriptions, examples, enums, and format annotations (715 lines in `schemas.yaml`)
- Reusable components: 6 common responses, 13 common parameters, 16+ schemas
- JWT security scheme documented
- Pagination, filtering, and error response patterns documented

**Weaknesses:**
- Documents only 51 of 315+ endpoints (16% coverage)
- Not served by the running application (dead files unless manually opened)
- Not integrated into FastAPI's `/docs` or `/openapi.json`
- Disconnected from code — no automated sync, drift is guaranteed
- Missing entire domains: AI Chat, Device Flow, Users, Invitations, Projects, API Audit, Schedules, Git Sync

### 2.2 FastAPI Auto-Generated Documentation

**Location:** `/docs` (Swagger UI), `/redoc` (ReDoc), `/openapi.json`
**Version:** `version: 1.0.0`

```python
# src/api/main.py:95-99
app = FastAPI(
    title="AuditGitHub Security Platform",
    description="API for managing security scans, findings, and remediation workflows.",
    version="1.0.0"
)
```

**Strengths:**
- Covers ALL 315+ endpoints automatically
- Always in sync with code (cannot drift)
- Live and interactive — developers can test endpoints directly
- Automatic Pydantic model rendering
- Request/response validation is enforced by the framework

**Weaknesses by Router Quality:**

| Quality Tier | Routers | Issues |
|-------------|---------|--------|
| **EXCELLENT** | organizations, auth, users, device_flow | Minor: could add more Field() descriptions |
| **GOOD** | findings, schedules, tenants, cribl, ai_chat | Missing: error responses, some Field() gaps |
| **FAIR** | ai, api_audit, analytics, attack_surface, github_sync, projects, contributor_profiles | Missing: response_model on many endpoints, no Field() |
| **POOR** | feedback, git_sync, jira, settings, repositories, scans | Missing: tags, response_model, docstrings, Field() |

### 2.3 Gap Summary: What Is Missing for Each Audience

**Developers trying to integrate:**
- Cannot see error response shapes for 93% of endpoints
- No request/response examples for 90% of endpoints
- No Field descriptions for 92% of model properties — just type hints
- Cannot distinguish optional vs required fields reliably

**DevOps trying to automate:**
- No SDK generation possible (incomplete response models)
- No contract testing possible (no explicit error responses)
- Rate limit headers documented in CORS middleware but not in OpenAPI
- Authentication requirements per-endpoint not visible

**Security analysts trying to audit:**
- RBAC permissions per endpoint not documented
- No security scheme annotations on individual endpoints
- Cannot see which endpoints require admin vs analyst vs user roles
- Attack surface endpoints poorly documented

---

## 3. Strategy: Single Source of Truth

### Decision: FastAPI Auto-Docs as Primary, Swagger/ as Archive

```
┌──────────────────────────────────────────────────────────────┐
│                     BEFORE (Current)                         │
│                                                              │
│  swagger/openapi.yaml ─── 51 endpoints, high quality         │
│         (NOT SERVED)      but static, drifts                 │
│                                                              │
│  FastAPI /docs ────────── 315+ endpoints, medium quality     │
│         (LIVE)            auto-generated, always current     │
│                                                              │
│  Result: Two incomplete sources, neither fully useful         │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                      AFTER (Target)                          │
│                                                              │
│  FastAPI /docs ────────── 315+ endpoints, HIGH quality       │
│         (LIVE)            enriched from swagger/ quality      │
│                           standards into Python code          │
│                                                              │
│  /openapi.json ────────── Complete, exportable, versionable  │
│         (LIVE)            SDK generation ready                │
│                                                              │
│  swagger/ ─────────────── Archived reference (read-only)     │
│         (ARCHIVE)         kept for schema design patterns     │
│                                                              │
│  Result: One complete, live, testable source of truth         │
└──────────────────────────────────────────────────────────────┘
```

### Why Not Keep the Hand-Written Spec?

| Approach | Pros | Cons |
|----------|------|------|
| **Enrich FastAPI code** (chosen) | Always in sync, one place to update, live testing, framework-enforced | Requires touching 28 router files |
| Keep hand-written spec | Beautiful YAML organization | Must manually sync 315+ endpoints, will drift immediately |
| Merge both into custom_openapi() | Combines quality + coverage | Complex merge logic, two places to update, merge conflicts |

---

## 4. Phase 1 — Foundation (Critical)

**Goal:** Establish the enrichment pattern and fix structural issues.
**Effort:** 1-2 days

### 4.1 Update FastAPI App Metadata

```python
# src/api/main.py — Update app configuration
app = FastAPI(
    title="AuditGH Security Portal API",
    description="""
Comprehensive API for GitHub organization security auditing, vulnerability scanning,
and threat assessment. The AuditGH platform provides multi-organization support with
isolated data, automated security scanning, and AI-powered threat analysis.

## Features
- Multi-organization GitHub repository management
- Automated security scanning (Gitleaks, Semgrep, Grype, Trivy)
- Vulnerability tracking and remediation workflows
- AI-powered architecture analysis and threat assessment
- Attack surface mapping and path analysis
- SLA tracking and compliance reporting

## Authentication
All API endpoints require JWT authentication via Bearer token:
```
Authorization: Bearer <your-jwt-token>
```

Obtain tokens via POST /api/auth/login or OAuth 2.0 Device Flow.

## Rate Limiting
API requests are rate-limited per user. Check response headers:
- `X-RateLimit-Limit`: Maximum requests per window
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Window reset timestamp

## Pagination
List endpoints support `skip` and `limit` query parameters:
- `skip`: Records to skip (default: 0)
- `limit`: Records to return (default: 100, max: 1000)
    """,
    version="2.0.0",
    contact={"name": "AuditGH Support", "email": "support@auditgh.local"},
    license_info={"name": "GPL-3.0", "url": "https://www.gnu.org/licenses/gpl-3.0.html"},
    openapi_tags=[...],  # See 4.2
)
```

### 4.2 Define Global Tags with Descriptions

Add to `main.py` before router registration:

```python
tags_metadata = [
    {"name": "Authentication", "description": "User login, logout, token refresh, and OAuth 2.0 Device Flow"},
    {"name": "Device Flow", "description": "OAuth 2.0 Device Authorization Grant (RFC 8628) for CLI authentication"},
    {"name": "Users", "description": "User management, profile, and service account operations"},
    {"name": "Invitations", "description": "User invitation management with RBAC-scoped access"},
    {"name": "Organizations", "description": "Multi-organization management, credentials, and repository import"},
    {"name": "Repositories", "description": "GitHub repository management, metadata, and scan history"},
    {"name": "Findings", "description": "Security findings: listing, filtering, status updates, and statistics"},
    {"name": "Scans", "description": "Security scan orchestration, status tracking, and results"},
    {"name": "Schedules", "description": "Scan schedule management with cron expressions and recommendations"},
    {"name": "Analytics", "description": "Security metrics, hero dashboards, threat radar, and executive summaries"},
    {"name": "AI Analysis", "description": "AI-powered architecture analysis, remediation, triage, and zero-day assessment"},
    {"name": "AI Chat", "description": "Interactive AI assistant for security analysis conversations"},
    {"name": "API Audit", "description": "API endpoint discovery, OpenAPI analysis, and Swagger documentation"},
    {"name": "Attack Surface", "description": "Attack surface mapping: secrets, abandoned repos, stale contributors"},
    {"name": "Attack Paths", "description": "Attack path visualization and remediation priority"},
    {"name": "Contributor Profiles", "description": "Git contributor activity, risk scoring, and commit analysis"},
    {"name": "Secrets", "description": "Detected secrets management and credential lifecycle"},
    {"name": "SLA", "description": "Service level agreement tracking and compliance metrics"},
    {"name": "GitHub Sync", "description": "GitHub API synchronization for repository metadata and files"},
    {"name": "Git Sync", "description": "Git push operations for README and diagram generation"},
    {"name": "Projects", "description": "Project grouping, tagging, and cross-repository management"},
    {"name": "Tenants", "description": "Multi-tenant organization provisioning and management"},
    {"name": "Settings", "description": "System configuration and key-value settings"},
    {"name": "Scheduler", "description": "Background job scheduling and APScheduler management"},
    {"name": "Cribl Integration", "description": "Cribl Stream log forwarding configuration and testing"},
    {"name": "Jira Integration", "description": "Jira ticket creation and synchronization"},
    {"name": "Feedback", "description": "User feedback submission for features and bugs"},
]

app = FastAPI(
    ...
    openapi_tags=tags_metadata,
)
```

### 4.3 Add Global Security Scheme

```python
# Add to main.py or create src/api/openapi_config.py
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )

    # Add security scheme
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token obtained from POST /api/auth/login or OAuth 2.0 Device Flow"
        }
    }

    # Apply security globally
    openapi_schema["security"] = [{"BearerAuth": []}]

    # Add servers
    openapi_schema["servers"] = [
        {"url": "http://localhost:8000", "description": "Local development"},
        {"url": "https://api.auditgh.local", "description": "Production"},
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
```

### 4.4 Create Common Response Models

Create `src/api/schemas/common.py`:

```python
from pydantic import BaseModel, Field
from typing import Optional, List, Any

class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Error message describing what went wrong",
                        example="Resource not found")

class ValidationErrorDetail(BaseModel):
    loc: List[str] = Field(..., description="Location of the validation error")
    msg: str = Field(..., description="Error message")
    type: str = Field(..., description="Error type")

class ValidationErrorResponse(BaseModel):
    detail: List[ValidationErrorDetail] = Field(..., description="List of validation errors")

class SuccessResponse(BaseModel):
    success: bool = Field(True, description="Whether the operation succeeded")
    message: str = Field(..., description="Human-readable result message",
                         example="Operation completed successfully")

class PaginatedResponse(BaseModel):
    """Base for paginated list responses."""
    total: int = Field(..., description="Total number of records matching the query")
    skip: int = Field(0, description="Number of records skipped")
    limit: int = Field(100, description="Maximum records returned")

# Standard error responses dict for use in responses={} parameter
STANDARD_ERRORS = {
    400: {"model": ErrorResponse, "description": "Bad request — validation error"},
    401: {"model": ErrorResponse, "description": "Unauthorized — authentication required"},
    403: {"model": ErrorResponse, "description": "Forbidden — insufficient permissions"},
    404: {"model": ErrorResponse, "description": "Not found — resource does not exist"},
    429: {"model": ErrorResponse, "description": "Too many requests — rate limit exceeded"},
    500: {"model": ErrorResponse, "description": "Internal server error"},
}

# Convenience subsets
CRUD_ERRORS = {k: v for k, v in STANDARD_ERRORS.items() if k in (400, 401, 403, 404, 500)}
LIST_ERRORS = {k: v for k, v in STANDARD_ERRORS.items() if k in (400, 401, 403, 500)}
CREATE_ERRORS = {k: v for k, v in STANDARD_ERRORS.items() if k in (400, 401, 403, 500)}
```

---

## 5. Phase 2 — Router Enrichment (High)

**Goal:** Every endpoint has a docstring, summary, response_model, and error responses.
**Effort:** 5-8 days (can be parallelized across developers)

### 5.1 Enrichment Pattern

Every endpoint should follow this pattern:

```python
from src.api.schemas.common import CRUD_ERRORS, LIST_ERRORS

@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    summary="Get finding by ID",
    responses=CRUD_ERRORS,
)
async def get_finding(
    finding_id: str = Path(..., description="UUID of the finding to retrieve"),
    db: Session = Depends(get_db),
):
    """
    Retrieve a single security finding by its unique identifier.

    Returns the complete finding record including severity, status,
    file location, scanner information, and remediation guidance.

    **Required permissions:** `findings:read`
    """
    ...
```

**Checklist per endpoint:**
- [ ] `summary=` parameter (short, for Swagger UI sidebar)
- [ ] `response_model=` parameter (Pydantic model)
- [ ] `responses=` parameter (error codes from common dict)
- [ ] Docstring (detailed description, permissions, behavior notes)
- [ ] All `Path()`, `Query()`, `Body()` parameters have `description=`

### 5.2 Priority Order for Router Enrichment

Routers ordered by audience impact (high-traffic + most requested by developers/DevOps/security):

| Priority | Router | Endpoints | Current Quality | Effort |
|----------|--------|-----------|-----------------|--------|
| **P1** | auth.py | 7 | GOOD | Small |
| **P1** | device_flow.py | 9 | GOOD | Small |
| **P1** | organizations.py | 23 | GOOD | Medium |
| **P1** | repositories.py | 3 | POOR | Small |
| **P1** | findings.py | 28 | GOOD | Medium |
| **P1** | scans.py | 3 | POOR | Small |
| **P2** | users.py | 7 | GOOD | Small |
| **P2** | invitations.py | 4 | FAIR | Small |
| **P2** | schedules.py | 17 | GOOD | Medium |
| **P2** | analytics.py | 14 | FAIR | Medium |
| **P2** | ai.py | 36 | FAIR | Large |
| **P2** | ai_chat.py | 6 | FAIR | Small |
| **P3** | api_audit.py | 43 | FAIR | Large |
| **P3** | attack_surface.py | 16 | FAIR | Medium |
| **P3** | attack_paths.py | 7 | FAIR | Small |
| **P3** | secrets.py | 8 | FAIR | Small |
| **P3** | sla.py | 9 | FAIR | Small |
| **P3** | contributor_profiles.py | 22 | FAIR | Medium |
| **P3** | projects.py | 34 | FAIR | Large |
| **P4** | github_sync.py | 15 | FAIR | Medium |
| **P4** | tenants.py | 8 | FAIR | Small |
| **P4** | cribl.py | 8 | FAIR | Small |
| **P4** | scheduler.py | 7 | FAIR | Small |
| **P4** | settings.py | 5 | POOR | Small |
| **P4** | feedback.py | 5 | POOR | Small |
| **P4** | git_sync.py | 5 | POOR | Small |
| **P4** | jira.py | 1 | POOR | Tiny |

### 5.3 Router Enrichment Example: Before and After

**BEFORE** (typical current state):
```python
@router.get("/")
async def list_findings(
    severity: str = None,
    status: str = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
):
    """List findings with optional filters."""
    ...
```

**AFTER** (enriched):
```python
@router.get(
    "/",
    response_model=PaginatedFindingsResponse,
    summary="List security findings",
    responses=LIST_ERRORS,
)
async def list_findings(
    severity: Optional[str] = Query(
        None,
        description="Filter by severity level",
        enum=["critical", "high", "medium", "low", "info"],
        example="high",
    ),
    status: Optional[str] = Query(
        None,
        description="Filter by finding status",
        enum=["open", "in_progress", "resolved", "false_positive", "risk_accepted"],
        example="open",
    ),
    skip: int = Query(0, ge=0, description="Number of records to skip for pagination"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum records to return"),
    db: Session = Depends(get_db),
):
    """
    List security findings across all repositories with filtering and pagination.

    Supports filtering by severity, status, scanner, repository, and date range.
    Results are ordered by severity (critical first) then by creation date (newest first).

    **Required permissions:** `findings:read`

    **Rate limit:** Standard (see response headers)
    """
    ...
```

---

## 6. Phase 3 — Schema & Model Quality (High)

**Goal:** Every Pydantic model field has a `Field()` with description, example, and constraints.
**Effort:** 3-5 days

### 6.1 Fields Requiring Enrichment

**463 fields currently lack `Field()` descriptions across all Pydantic models.**

**Pattern to apply:**

```python
# BEFORE
class FindingResponse(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    scanner_name: Optional[str]
    file_path: Optional[str]
    line_start: Optional[int]

# AFTER
class FindingResponse(BaseModel):
    id: str = Field(..., description="Unique finding identifier (UUID)", example="550e8400-e29b-41d4-a716-446655440000")
    title: str = Field(..., description="Short finding title", example="Hardcoded AWS Access Key")
    description: Optional[str] = Field(None, description="Detailed finding description with context")
    severity: str = Field(..., description="Severity level", enum=["critical", "high", "medium", "low", "info"], example="high")
    status: str = Field("open", description="Current finding status", enum=["open", "in_progress", "resolved", "false_positive", "risk_accepted"])
    scanner_name: Optional[str] = Field(None, description="Scanner that detected this finding", example="gitleaks")
    file_path: Optional[str] = Field(None, description="File path where finding was detected", example="src/config/aws.ts")
    line_start: Optional[int] = Field(None, description="Starting line number in file", example=42)
```

### 6.2 Models Missing Entirely (Need to Create)

These SQLAlchemy models have no corresponding Pydantic response schema:

| SQLAlchemy Model | Used In Router | Fields | Action |
|------------------|----------------|--------|--------|
| ScanSchedule | schedules.py | 20+ | Create ScheduleResponse |
| FileCommit | github_sync.py | 12+ | Create FileCommitResponse |
| Contributor | contributor_profiles.py | 15+ | Create ContributorResponse |
| Dependency | repositories.py | 10+ | Create DependencyResponse |
| APIEndpoint | api_audit.py | 12+ | Create APIEndpointResponse |
| OpenAPISpec | api_audit.py | 8+ | Create OpenAPISpecResponse |

### 6.3 Create Pydantic Schemas File Structure

```
src/api/schemas/
├── __init__.py
├── common.py          # ErrorResponse, PaginatedResponse, STANDARD_ERRORS
├── organizations.py   # Org request/response models (migrate from router)
├── repositories.py    # Repo request/response models
├── findings.py        # Finding request/response models (migrate from router)
├── scans.py           # Scan request/response models
├── auth.py            # Login, token, user response models
├── schedules.py       # Schedule request/response models
├── analytics.py       # Dashboard, trends, hero metrics models
├── ai.py              # AI analysis request/response models
└── security.py        # Attack surface, secrets, SLA models
```

This consolidates inline Pydantic models from routers into a shared schemas package, enabling reuse and consistent documentation.

---

## 7. Phase 4 — Developer Experience (Medium)

**Goal:** Make the API documentation truly self-service for all audiences.
**Effort:** 2-3 days

### 7.1 Add Request/Response Examples

Use Pydantic `model_config` with JSON Schema examples:

```python
class CreateOrganizationRequest(BaseModel):
    model_config = {"json_schema_extra": {
        "examples": [{
            "name": "sleepnumber",
            "github_org": "sleepnumber",
            "github_token": "ghp_xxxxxxxxxxxxxxxxxxxx",
            "display_name": "Sleep Number",
            "create_database": True,
            "set_as_default": False,
        }]
    }}

    name: str = Field(..., description="Internal name (lowercase, alphanumeric)",
                      pattern=r'^[a-z0-9]+$', example="sleepnumber")
    ...
```

### 7.2 Add RBAC Permission Annotations

Document required permissions in endpoint docstrings AND as OpenAPI extension:

```python
@router.delete(
    "/{org_name}",
    summary="Delete organization",
    responses=CRUD_ERRORS,
    openapi_extra={
        "x-required-permissions": ["organizations:delete"],
        "x-required-role": "admin",
    },
)
async def delete_organization(...):
    """
    Permanently delete an organization and all associated data.

    **Required role:** admin
    **Required permissions:** `organizations:delete`

    This operation:
    - Removes the organization record
    - Drops the organization's isolated database
    - Deletes all associated repositories and findings
    - Cannot be undone
    """
```

### 7.3 Add Rate Limit Documentation

Document rate limits as OpenAPI extensions on endpoints that have custom limits:

```python
@router.post(
    "/ai/architecture/generate",
    summary="Generate architecture documentation",
    openapi_extra={
        "x-rate-limit": "10/minute",
        "x-rate-limit-reason": "AI inference is computationally expensive",
    },
)
```

### 7.4 Enhance Swagger UI Configuration

```python
# In main.py or openapi_config.py
app = FastAPI(
    ...
    swagger_ui_parameters={
        "docExpansion": "none",           # Collapse all by default
        "filter": True,                    # Enable search
        "persistAuthorization": True,      # Remember auth token
        "tryItOutEnabled": True,           # Enable Try It Out by default
        "displayRequestDuration": True,    # Show request timing
        "defaultModelsExpandDepth": 2,     # Expand schema models
    },
)
```

---

## 8. Phase 5 — CI/CD & Governance (Medium)

**Goal:** Prevent documentation regression and enable SDK generation.
**Effort:** 1-2 days

### 8.1 OpenAPI Schema Export Script

Create `scripts/export_openapi.py`:

```python
"""Export the complete OpenAPI schema to a file for SDK generation and validation."""
import json
import yaml
from src.api.main import app

def export():
    schema = app.openapi()

    # Export JSON
    with open("openapi.json", "w") as f:
        json.dump(schema, f, indent=2)

    # Export YAML
    with open("openapi.yaml", "w") as f:
        yaml.dump(schema, f, default_flow_style=False, sort_keys=False)

    # Report
    paths = schema.get("paths", {})
    endpoints = sum(len(methods) for methods in paths.values())
    schemas = len(schema.get("components", {}).get("schemas", {}))
    print(f"Exported: {endpoints} endpoints, {schemas} schemas")

if __name__ == "__main__":
    export()
```

### 8.2 CI Validation Step

Add to GitHub Actions workflow:

```yaml
# .github/workflows/openapi-validation.yml
name: OpenAPI Validation
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Export OpenAPI schema
        run: python scripts/export_openapi.py
      - name: Validate schema
        run: |
          npm install -g @apidevtools/swagger-cli
          swagger-cli validate openapi.json
      - name: Check for undocumented endpoints
        run: python scripts/check_openapi_coverage.py
```

### 8.3 Coverage Check Script

Create `scripts/check_openapi_coverage.py`:

```python
"""Ensure all endpoints have required OpenAPI documentation."""
import json
import sys

def check():
    with open("openapi.json") as f:
        schema = json.load(f)

    issues = []
    for path, methods in schema.get("paths", {}).items():
        for method, spec in methods.items():
            if method in ("parameters",):
                continue
            endpoint = f"{method.upper()} {path}"

            if not spec.get("summary"):
                issues.append(f"  MISSING summary: {endpoint}")
            if not spec.get("description"):
                issues.append(f"  MISSING description: {endpoint}")
            if "200" in spec.get("responses", {}) or "201" in spec.get("responses", {}):
                pass  # Has success response
            else:
                issues.append(f"  MISSING success response: {endpoint}")

    if issues:
        print(f"OpenAPI Coverage Issues ({len(issues)}):")
        for issue in issues:
            print(issue)
        sys.exit(1)
    else:
        print("All endpoints fully documented!")

if __name__ == "__main__":
    check()
```

### 8.4 SDK Generation (Optional)

```bash
# Add Makefile targets
generate-sdk-python:
    python scripts/export_openapi.py
    docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
      -i /local/openapi.json -g python -o /local/clients/python \
      --additional-properties=packageName=auditgh_client

generate-sdk-typescript:
    python scripts/export_openapi.py
    docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
      -i /local/openapi.json -g typescript-axios -o /local/clients/typescript
```

---

## 9. Router-by-Router Work Matrix

Each cell indicates what work is needed per router:

| Router | Docstrings | summary= | response_model | responses={} | Field() | Examples | Total Changes |
|--------|:----------:|:---------:|:--------------:|:------------:|:-------:|:--------:|:-------------:|
| **auth.py** | 1 missing | 7 add | 6 add | 7 add | 0 add | 4 add | ~25 |
| **device_flow.py** | 0 missing | 2 add | 6 add | 9 add | 3 add | 4 add | ~24 |
| **organizations.py** | 2 missing | 15 add | 16 add | 23 add | 8 add | 6 add | ~70 |
| **repositories.py** | 0 missing | 3 add | 3 add | 3 add | 5 add | 2 add | ~16 |
| **findings.py** | 0 missing | 12 add | 10 add | 28 add | 14 add | 6 add | ~70 |
| **scans.py** | 1 missing | 3 add | 2 add | 3 add | 4 add | 2 add | ~15 |
| **users.py** | 0 missing | 2 add | 2 add | 7 add | 5 add | 3 add | ~19 |
| **invitations.py** | 0 missing | 1 add | 1 add | 4 add | 4 add | 2 add | ~12 |
| **schedules.py** | 0 missing | 5 add | 3 add | 17 add | 6 add | 4 add | ~35 |
| **analytics.py** | 2 missing | 14 add | 9 add | 14 add | 12 add | 5 add | ~56 |
| **ai.py** | 5 missing | 30 add | 22 add | 36 add | 20 add | 10 add | ~123 |
| **ai_chat.py** | 0 missing | 3 add | 3 add | 6 add | 2 add | 3 add | ~17 |
| **api_audit.py** | 3 missing | 35 add | 36 add | 43 add | 15 add | 10 add | ~142 |
| **attack_surface.py** | 2 missing | 12 add | 9 add | 16 add | 15 add | 5 add | ~59 |
| **attack_paths.py** | 1 missing | 5 add | 5 add | 7 add | 6 add | 3 add | ~27 |
| **secrets.py** | 1 missing | 5 add | 4 add | 8 add | 6 add | 3 add | ~27 |
| **sla.py** | 1 missing | 6 add | 4 add | 9 add | 8 add | 3 add | ~31 |
| **contributor_profiles.py** | 3 missing | 15 add | 11 add | 22 add | 12 add | 5 add | ~68 |
| **projects.py** | 5 missing | 25 add | 30 add | 34 add | 10 add | 8 add | ~112 |
| **github_sync.py** | 2 missing | 10 add | 9 add | 15 add | 8 add | 4 add | ~48 |
| **tenants.py** | 0 missing | 3 add | 2 add | 8 add | 3 add | 3 add | ~19 |
| **cribl.py** | 0 missing | 3 add | 3 add | 8 add | 0 add | 3 add | ~17 |
| **scheduler.py** | 1 missing | 5 add | 5 add | 7 add | 5 add | 3 add | ~26 |
| **settings.py** | 3 missing | 5 add | 5 add | 5 add | 4 add | 2 add | ~24 |
| **feedback.py** | 2 missing | 5 add | 5 add | 5 add | 3 add | 2 add | ~22 |
| **git_sync.py** | 2 missing | 5 add | 5 add | 5 add | 3 add | 2 add | ~22 |
| **jira.py** | 0 missing | 1 add | 1 add | 1 add | 2 add | 1 add | ~6 |
| **TOTALS** | ~36 | ~237 | ~217 | ~315+ | ~183 | ~108 | **~1,096** |

---

## 10. File Inventory

### New Files to Create

| File | Purpose |
|------|---------|
| `src/api/schemas/__init__.py` | Schemas package init |
| `src/api/schemas/common.py` | ErrorResponse, STANDARD_ERRORS, PaginatedResponse |
| `src/api/schemas/organizations.py` | Org request/response models |
| `src/api/schemas/repositories.py` | Repo request/response models |
| `src/api/schemas/findings.py` | Finding request/response models |
| `src/api/schemas/scans.py` | Scan request/response models |
| `src/api/schemas/auth.py` | Auth request/response models |
| `src/api/schemas/schedules.py` | Schedule request/response models |
| `src/api/schemas/analytics.py` | Analytics response models |
| `src/api/schemas/ai.py` | AI request/response models |
| `src/api/schemas/security.py` | Attack surface, secrets, SLA models |
| `src/api/openapi_config.py` | Custom OpenAPI schema configuration |
| `scripts/export_openapi.py` | OpenAPI JSON/YAML exporter |
| `scripts/check_openapi_coverage.py` | CI coverage validation |
| `.github/workflows/openapi-validation.yml` | CI validation workflow |

### Files to Modify

| File | Changes |
|------|---------|
| `src/api/main.py` | App metadata, tags_metadata, custom_openapi(), swagger_ui_parameters |
| `src/api/routers/*.py` (28 files) | Add summary=, responses=, response_model=, Field(), docstrings |
| All inline Pydantic models | Add Field() with description=, example= |

### Files to Archive (No Delete)

| File | Action |
|------|--------|
| `swagger/openapi.yaml` | Add header comment: "ARCHIVED — source of truth is now FastAPI /docs" |
| `swagger/README.md` | Update to point developers to /docs instead |

---

## 11. Estimated Effort

| Phase | Tasks | Effort | Parallelizable |
|-------|-------|--------|----------------|
| **Phase 1: Foundation** | App metadata, tags, security scheme, common schemas | 1-2 days | No (sequential) |
| **Phase 2: Router Enrichment** | 28 routers × (summary + responses + docstrings) | 5-8 days | Yes (per router) |
| **Phase 3: Schema Quality** | 463 fields × Field() + 6 new schema files | 3-5 days | Yes (per schema) |
| **Phase 4: Developer Experience** | Examples, RBAC annotations, rate limits, UI config | 2-3 days | Yes |
| **Phase 5: CI/CD** | Export script, validation workflow, coverage check | 1-2 days | No |
| **TOTAL** | | **12-20 days** | |

### Recommended Team Split

- **1 developer:** Phase 1 (foundation) + Phase 5 (CI/CD)
- **2-3 developers:** Phase 2 (routers) — split by priority tier
- **1 developer:** Phase 3 (schemas) + Phase 4 (DX)

---

## 12. Success Criteria

### Definition of Done

| Criterion | Measurement |
|-----------|-------------|
| **100% endpoint coverage** | Every endpoint visible at `/docs` with summary, description, response_model, error responses |
| **100% field documentation** | Every Pydantic model field has `Field(description=...)` |
| **Zero drift** | Single source of truth — code IS the spec |
| **Self-service testing** | Developer can test any endpoint via Swagger UI "Try It Out" with only a JWT token |
| **SDK generation ready** | `openapi-generator validate` passes with zero errors |
| **CI enforcement** | PR cannot merge if new endpoint lacks documentation |
| **RBAC visibility** | Every endpoint shows required role/permissions in description |

### Acceptance Test

A new developer joining the team should be able to:

1. Navigate to `http://localhost:8000/docs`
2. See all 315+ endpoints organized by tag with descriptions
3. Authenticate using "Try It Out" on POST `/api/auth/login`
4. Understand any endpoint's purpose, parameters, response shape, and errors without reading source code
5. Generate a working Python or TypeScript client using `openapi-generator`

---

## Appendix: Undocumented Endpoint Inventory

### Endpoints in Code but NOT in Hand-Written swagger/

These 264+ endpoints exist in FastAPI routers but have no corresponding path in `swagger/paths/`:

**AI Analysis (36 endpoints):**
- POST /api/ai/remediate, /api/ai/triage, /api/ai/analyze-finding
- POST /api/ai/zero-day, /api/ai/credential-url, /api/ai/api-paths
- POST /api/ai/executive-summary, /api/ai/commit-analysis
- GET /api/ai/architecture/{repo_id}, /api/ai/threat-model/{repo_id}
- POST /api/ai/batch-triage, /api/ai/risk-score
- And 24 more...

**AI Chat (6 endpoints):**
- POST /api/ai-chat/send, GET /api/ai-chat/sessions
- GET /api/ai-chat/sessions/{id}, DELETE /api/ai-chat/sessions/{id}
- GET /api/ai-chat/sessions/{id}/messages, POST /api/ai-chat/clear

**API Audit (43 endpoints):**
- GET /api/api-audit/repos/{id}/endpoints
- GET /api/api-audit/repos/{id}/swagger-files
- GET /api/api-audit/repos/{id}/openapi-specs
- POST /api/api-audit/repos/{id}/discover
- GET /api/api-audit/swagger-ui/{repo_id}
- POST /api/global/api-audit/scan-all
- And 37 more...

**Analytics (14 endpoints):**
- GET /api/analytics/hero-metrics, /api/analytics/threat-radar
- GET /api/analytics/executive-summary, /api/analytics/repo-risk
- GET /api/analytics/ai-insights, /api/analytics/posture
- GET /api/analytics/scan-velocity, /api/analytics/remediation-funnel
- And 6 more...

**Attack Surface (16 endpoints):**
- GET /api/attack-surface/secrets, /api/attack-surface/abandoned-repos
- GET /api/attack-surface/stale-contributors, /api/attack-surface/high-risk
- GET /api/attack-surface/public-exposure, /api/attack-surface/summary
- POST /api/attack-surface/scan, /api/attack-surface/ir/findings
- And 8 more...

**Contributor Profiles (22 endpoints):**
- GET /api/contributors/{id}/activity, /api/contributors/{id}/risk
- GET /api/contributors/{id}/commits, /api/contributors/anomalies
- GET /api/contributors/leaderboard, /api/contributors/trends
- And 16 more...

**Device Flow (9 endpoints):**
- POST /api/auth/device/code, /api/auth/device/token
- GET /api/auth/device/verify, POST /api/auth/device/authorize
- GET /api/auth/device/status/{code}, POST /api/auth/device/revoke
- And 3 more...

**Invitations (4 endpoints):**
- POST /api/invitations, GET /api/invitations
- POST /api/invitations/{id}/accept, DELETE /api/invitations/{id}

**Projects (34 endpoints):**
- CRUD operations, tags, repositories, findings
- Statistics, exports, bulk operations
- And many more...

**Schedules (17 endpoints):**
- CRUD for scan schedules
- GET /api/schedules/recommendations
- POST /api/schedules/{id}/enable, /api/schedules/{id}/disable
- And 11 more...

**Users (7 endpoints):**
- GET /api/users, POST /api/users
- GET /api/users/{id}, PATCH /api/users/{id}
- DELETE /api/users/{id}, GET /api/users/me
- PATCH /api/users/{id}/role

**Other undocumented routers:** git_sync (5), scheduler (7), additional settings, feedback, cribl, sla endpoints not in hand-written spec.

---

*This plan transforms AuditGH's API documentation from 16% hand-written coverage to 100% live, testable, SDK-ready documentation — directly serving developers, DevOps engineers, and security analysts.*

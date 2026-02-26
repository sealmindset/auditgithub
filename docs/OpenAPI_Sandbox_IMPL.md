# OpenAPI Sandbox & Developer Portal — Implementation Plan

**Document Purpose:** Complete implementation plan for building a fully operational sandbox API environment with Swagger UI, Swagger Editor, and Redoc — enabling developers, DevOps engineers, and security analysts to test, learn, and integrate with all AuditGH API services using realistic dummy data and API key authentication, with zero impact to production.

**Created:** 2026-02-26
**Status:** Draft — Awaiting Approval
**Audience:** Backend Engineers, DevOps, Solution Architects
**Dependencies:** [OpenAPI_PLAN.md](OpenAPI_PLAN.md) (spec enrichment), [API_Key_PLAN.md](API_Key_PLAN.md) (key system design)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Architecture Overview](#2-architecture-overview)
3. [Design Decisions](#3-design-decisions)
4. [Phase 1 — Sandbox Infrastructure](#4-phase-1--sandbox-infrastructure)
5. [Phase 2 — Sandbox API Key Authentication](#5-phase-2--sandbox-api-key-authentication)
6. [Phase 3 — Dummy Data Seed Engine](#6-phase-3--dummy-data-seed-engine)
7. [Phase 4 — OpenAPI Spec Enrichment](#7-phase-4--openapi-spec-enrichment)
8. [Phase 5 — Swagger Editor & Redoc Services](#8-phase-5--swagger-editor--redoc-services)
9. [Phase 6 — Developer Portal Landing Page](#9-phase-6--developer-portal-landing-page)
10. [Phase 7 — Auto-Reset & Lifecycle Management](#10-phase-7--auto-reset--lifecycle-management)
11. [Phase 8 — CI/CD & Validation](#11-phase-8--cicd--validation)
12. [Database Schema](#12-database-schema)
13. [File Inventory](#13-file-inventory)
14. [Environment Variables](#14-environment-variables)
15. [Testing Plan](#15-testing-plan)
16. [Security Considerations](#16-security-considerations)
17. [Phased Rollout Timeline](#17-phased-rollout-timeline)

---

## 1. Executive Summary

### The Problem

AuditGH has **315+ API endpoints** across 28 router modules, but there is no safe, self-service environment where developers, DevOps engineers, and security analysts can:

- Explore and test all available API services interactively
- Understand request/response schemas with realistic data
- Integrate their clients without risking production data
- Learn what security scanning capabilities are available
- Validate their automation scripts before pointing at production

### The Solution

Build a **sandbox API environment** running as a sidecar service alongside the production stack, with:

| Component | URL | Purpose |
|-----------|-----|---------|
| **Sandbox API** | `http://localhost:8001/docs` | Fully operational AuditGH API with enriched Swagger UI |
| **Swagger Editor** | `http://localhost:8080` | Edit and test the OpenAPI spec interactively |
| **Redoc** | `http://localhost:8001/redoc` | Beautiful read-only API documentation |
| **Developer Portal** | `http://localhost:8001/` | Landing page linking all three views |

**Key properties:**
- **Full realistic dataset** — 3 orgs, 50+ repos, 500+ findings, scan history, AI results, schedules, contributors, attack paths
- **Read-write with auto-reset** — Full CRUD operations; dummy data resets every 24 hours (or on-demand)
- **Simplified sandbox API keys** — `agh_sandbox_xxx` keys grant full access; no RBAC complexity
- **Zero production risk** — Separate database, separate port, separate container
- **Complete OpenAPI spec** — Every endpoint documented with summaries, response models, error codes, examples

### Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────┐
│                        AuditGH Developer Portal                        │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐ │
│  │  Swagger Editor   │  │   Sandbox API    │  │     Redoc            │ │
│  │  (Docker image)   │  │  (FastAPI clone) │  │  (built-in FastAPI)  │ │
│  │  :8080            │  │  :8001           │  │  :8001/redoc         │ │
│  │                   │  │                  │  │                      │ │
│  │  Edit & test the  │  │  /docs  Swagger  │  │  Read-only beautiful │ │
│  │  OpenAPI spec     │  │  /redoc Redoc    │  │  reference docs      │ │
│  │                   │  │  /     Landing   │  │                      │ │
│  └──────────────────┘  └────────┬─────────┘  └──────────────────────┘ │
│                                  │                                      │
│                     ┌────────────┼────────────┐                        │
│                     │            │            │                        │
│              ┌──────┴──────┐ ┌──┴──────┐ ┌──┴──────────┐             │
│              │ Sandbox DB  │ │ Sandbox │ │ Seed Engine  │             │
│              │ PostgreSQL  │ │ Redis   │ │ (auto-reset) │             │
│              │ auditgh_    │ │ DB 1    │ │ 24hr cycle   │             │
│              │ sandbox     │ │         │ │              │             │
│              └─────────────┘ └─────────┘ └──────────────┘             │
│                                                                        │
│  ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┐ │
│  │                  PRODUCTION (untouched)                          │ │
│  │  API :8000  │  Web UI :3000  │  DB auditgh_kb  │  Redis DB 0   │ │
│  └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘ │
└────────────────────────────────────────────────────────────────────────┘
```

### Authentication Flow

```
Developer                 Sandbox API (:8001)           Sandbox DB
   │                           │                           │
   │  GET /docs                │                           │
   │ ────────────────────────► │                           │
   │  ◄─────────────────────── │  Swagger UI (no auth)    │
   │     Swagger UI loaded     │                           │
   │                           │                           │
   │  Click "Authorize"        │                           │
   │  Enter: agh_sandbox_admin │                           │
   │                           │                           │
   │  GET /api/findings        │                           │
   │  X-API-Key: agh_sandbox_  │                           │
   │    admin                  │                           │
   │ ────────────────────────► │                           │
   │                           │  Validate key hash        │
   │                           │ ─────────────────────────►│
   │                           │  ◄────────────────────────│
   │                           │  Key valid, role=admin    │
   │  ◄─────────────────────── │                           │
   │     200: [findings...]    │                           │
   │                           │                           │
```

---

## 2. Architecture Overview

### 2.1 Service Topology

| Service | Container Name | Port | Image | Purpose |
|---------|---------------|------|-------|---------|
| Sandbox API | `auditgh_sandbox` | 8001 | `Dockerfile.api` (same codebase) | Full AuditGH API with sandbox config |
| Sandbox DB | Shared `auditgh_db` | 5432 | `postgres:15-alpine` | Separate database `auditgh_sandbox` on same PostgreSQL instance |
| Sandbox Redis | Shared `auditgh-redis` | 6379 | `redis:7-alpine` | Separate Redis DB 1 (production uses DB 0) |
| Swagger Editor | `auditgh_swagger_editor` | 8080 | `swaggerapi/swagger-editor` | Interactive OpenAPI spec editor + tester |

### 2.2 Isolation Model

```
PostgreSQL Instance (auditgh_db)
├── auditgh_kb          ← Production database (untouched)
└── auditgh_sandbox     ← Sandbox database (dummy data, auto-resettable)

Redis Instance (auditgh-redis)
├── DB 0                ← Production (sessions, RBAC cache, token blacklist)
└── DB 1                ← Sandbox (sandbox sessions, rate limits)
```

### 2.3 What the Sandbox Shares vs. Isolates

| Component | Shared? | Isolation Method |
|-----------|---------|------------------|
| PostgreSQL server | Shared | Separate database name (`auditgh_sandbox`) |
| Redis server | Shared | Separate database number (DB 1 vs DB 0) |
| Codebase | Shared | Same Docker image, different env vars |
| Docker network | Shared | Same `docker-compose` network |
| Volumes | **Not shared** | Sandbox has no persistent volume |
| Auth/Sessions | **Not shared** | Sandbox uses own API key table |
| GitHub tokens | **Not shared** | Sandbox has no GitHub API access |
| AI providers | **Not shared** | Sandbox returns mock AI responses |

---

## 3. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Deployment model | Sidecar service in existing docker-compose | One `docker-compose up` starts everything; developers don't manage a separate stack |
| Database isolation | Separate database on same PostgreSQL | Zero risk of cross-contamination; shared server saves resources |
| Redis isolation | Separate DB number (DB 1) | Clean key separation; shared server saves resources |
| Authentication | Simplified sandbox API keys (`agh_sandbox_xxx`) | Let people explore without RBAC friction; full key system ships with production |
| Dummy data | Full realistic dataset (3 orgs, 50+ repos, 500+ findings) | Exercises every endpoint; demonstrates real-world usage patterns |
| Write behavior | Read-write with 24hr auto-reset | Users test full CRUD workflows; data always returns to known-good state |
| Manual reset | Available via `POST /api/sandbox/reset` (admin key only) | On-demand recovery if data gets messy during testing |
| Swagger UI | Enhanced FastAPI `/docs` with branding + persistent auth | Zero extra dependencies; lives on the sandbox API itself |
| Swagger Editor | Separate Docker container at `:8080` | Full editing capability; loads exported `openapi.json` from sandbox |
| Redoc | Built-in FastAPI `/redoc` | Zero extra dependencies; beautiful read-only reference |
| AI endpoints | Mock responses (no real LLM calls) | Sandbox doesn't need API keys for OpenAI/Anthropic; returns realistic canned responses |
| GitHub API | Disabled (mock responses) | Sandbox doesn't clone repos or hit GitHub API |
| Scanner | Disabled | No actual scanning; scan endpoints return mock progress/results |
| OpenAPI spec source | FastAPI auto-generated (enriched in code) | Per [OpenAPI_PLAN.md](OpenAPI_PLAN.md) strategy: code IS the spec |

---

## 4. Phase 1 — Sandbox Infrastructure

**Goal:** Sandbox API runs as a sidecar service on port 8001 with its own database.
**Effort:** 2-3 days

### 4.1 Docker Compose Service Definition

Add to `docker-compose.yml`:

```yaml
  # ─────────────────────────────────────────────────
  # Developer Portal: Sandbox API (port 8001)
  # ─────────────────────────────────────────────────
  sandbox:
    container_name: auditgh_sandbox
    build:
      context: .
      dockerfile: Dockerfile.api
    ports:
      - "8001:8000"
    environment:
      # Database: separate sandbox database on shared PostgreSQL
      - POSTGRES_HOST=db
      - POSTGRES_PORT=5432
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=auditgh_sandbox
      # Redis: separate DB 1
      - REDIS_URL=redis://redis:6379/1
      # Sandbox mode flag
      - SANDBOX_MODE=true
      - SANDBOX_AUTO_RESET_HOURS=24
      # Auth: disable OIDC, enable sandbox keys
      - AUTH_REQUIRED=true
      - AUTH_SANDBOX_KEYS=true
      - ENTRA_TENANT_ID=
      - OKTA_DOMAIN=
      # AI: mock mode (no real API calls)
      - AI_PROVIDER=mock
      - OPENAI_API_KEY=
      - ANTHROPIC_API_KEY=
      # GitHub: disabled
      - GITHUB_TOKEN=
      # Scheduler: disabled
      - SCHEDULER_ENABLED=false
      # Secrets
      - SECRETS_MASTER_KEY=${SECRETS_MASTER_KEY}
      - SESSION_SECRET=${SESSION_SECRET:-sandbox-secret-key-change-in-production}
      - JWT_SECRET_KEY=${JWT_SECRET_KEY:-sandbox-jwt-secret}
      # Misc
      - MULTI_TENANT_ENABLED=false
      - CORS_ORIGINS=http://localhost:8080,http://localhost:8001,http://localhost:3000
    volumes:
      - .:/app
    depends_on:
      db:
        condition: service_started
      redis:
        condition: service_started
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: "1"
          memory: 2G
```

### 4.2 Sandbox Mode Detection

Create `src/api/sandbox.py`:

```python
"""Sandbox mode configuration and utilities."""
import os

SANDBOX_MODE = os.environ.get("SANDBOX_MODE", "false").lower() == "true"
SANDBOX_AUTO_RESET_HOURS = int(os.environ.get("SANDBOX_AUTO_RESET_HOURS", "24"))

def is_sandbox() -> bool:
    """Check if running in sandbox mode."""
    return SANDBOX_MODE
```

### 4.3 Database Initialization on Startup

Modify `src/api/main.py` startup event to auto-create the sandbox database and seed data:

```python
@app.on_event("startup")
async def startup_event():
    # ... existing initialization ...

    # Sandbox-specific initialization
    if is_sandbox():
        from src.api.sandbox_seed import initialize_sandbox
        await initialize_sandbox()
        logger.info("Sandbox environment initialized with dummy data")
```

### 4.4 Sandbox Database Creation Script

Create `scripts/init_sandbox_db.py`:

```python
"""Create the auditgh_sandbox database if it doesn't exist."""
import psycopg2
from psycopg2 import sql
import os

def create_sandbox_db():
    host = os.environ.get("POSTGRES_HOST", "db")
    port = os.environ.get("POSTGRES_PORT", "5432")
    user = os.environ.get("POSTGRES_USER", "postgres")
    password = os.environ.get("POSTGRES_PASSWORD", "postgres")

    conn = psycopg2.connect(
        host=host, port=port, user=user, password=password, dbname="postgres"
    )
    conn.autocommit = True
    cursor = conn.cursor()

    # Check if sandbox DB exists
    cursor.execute(
        "SELECT 1 FROM pg_database WHERE datname = %s", ("auditgh_sandbox",)
    )
    if not cursor.fetchone():
        cursor.execute(
            sql.SQL("CREATE DATABASE {}").format(
                sql.Identifier("auditgh_sandbox")
            )
        )
        print("Created database: auditgh_sandbox")
    else:
        print("Database auditgh_sandbox already exists")

    cursor.close()
    conn.close()

if __name__ == "__main__":
    create_sandbox_db()
```

---

## 5. Phase 2 — Sandbox API Key Authentication

**Goal:** Simple API key auth that lets users explore the sandbox without RBAC friction.
**Effort:** 2-3 days

### 5.1 Design

Sandbox keys are **pre-generated** and stored in the sandbox database. No key generation UI is needed for the sandbox — the keys are seeded automatically and documented in the Swagger UI description.

| Key Name | Key Value | Role | Description |
|----------|-----------|------|-------------|
| Admin Key | `agh_sandbox_admin` | super_admin | Full access to all endpoints including reset |
| Analyst Key | `agh_sandbox_analyst` | analyst | Read/write findings, execute scans, read repos |
| Readonly Key | `agh_sandbox_readonly` | user | Read-only access to all data |

### 5.2 Database Table: `sandbox_api_keys`

```sql
CREATE TABLE sandbox_api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    key_hash        VARCHAR(64) NOT NULL UNIQUE,
    key_value       VARCHAR(64) NOT NULL,        -- Stored in plaintext for sandbox
    role            VARCHAR(50) NOT NULL DEFAULT 'analyst',
    description     TEXT,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMP DEFAULT NOW()
);
```

> **Note:** Unlike the production API key system (see [API_Key_PLAN.md](API_Key_PLAN.md)), sandbox keys store the key value in plaintext for display in documentation. This is intentional — sandbox keys have no production access.

### 5.3 Authentication Middleware

Create `src/api/middleware/sandbox_auth.py`:

```python
"""Sandbox API key authentication middleware."""
import hashlib
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

# Endpoints that don't require auth (Swagger UI, health, landing page)
PUBLIC_PATHS = {
    "/", "/docs", "/redoc", "/openapi.json",
    "/health", "/api/sandbox/keys",
    "/favicon.ico",
}

class SandboxAuthMiddleware(BaseHTTPMiddleware):
    """
    Validates sandbox API keys from X-API-Key header.
    Falls through to public paths without auth.
    """

    async def dispatch(self, request: Request, call_next):
        # Allow public paths
        path = request.url.path
        if path in PUBLIC_PATHS or path.startswith("/static"):
            return await call_next(request)

        # Extract API key from header
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            # Also check query param (for Swagger UI Try It Out)
            api_key = request.query_params.get("api_key")

        if not api_key:
            raise HTTPException(
                status_code=401,
                detail="API key required. Pass via X-API-Key header. "
                       "Get sandbox keys at GET /api/sandbox/keys"
            )

        # Validate key against sandbox database
        from src.api.database import SessionLocal
        from src.api import models

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        db = SessionLocal()
        try:
            sandbox_key = db.execute(
                models.text(
                    "SELECT name, role, is_active FROM sandbox_api_keys "
                    "WHERE key_hash = :hash"
                ),
                {"hash": key_hash}
            ).fetchone()
        finally:
            db.close()

        if not sandbox_key or not sandbox_key.is_active:
            raise HTTPException(
                status_code=401,
                detail="Invalid or inactive sandbox API key"
            )

        # Attach key info to request state
        request.state.sandbox_key_name = sandbox_key.name
        request.state.sandbox_key_role = sandbox_key.role
        request.state.user_role = sandbox_key.role

        return await call_next(request)
```

### 5.4 Sandbox Keys Info Endpoint

Add to sandbox-specific router `src/api/routers/sandbox.py`:

```python
"""Sandbox management endpoints."""
from fastapi import APIRouter, Depends

router = APIRouter(prefix="/api/sandbox", tags=["Sandbox"])

@router.get(
    "/keys",
    summary="List available sandbox API keys",
    description="Returns all pre-generated sandbox API keys with their roles. "
                "Use these keys in the X-API-Key header to authenticate.",
)
async def list_sandbox_keys(db: Session = Depends(get_db)):
    """
    Returns the sandbox API keys for testing.

    These keys are pre-generated and reset every 24 hours along with the
    rest of the sandbox data. They have no access to production data.

    **No authentication required** — this endpoint is public so new
    users can discover the available keys.
    """
    keys = db.execute(
        text("SELECT name, key_value, role, description FROM sandbox_api_keys "
             "WHERE is_active = TRUE ORDER BY role")
    ).fetchall()

    return {
        "keys": [
            {
                "name": k.name,
                "key": k.key_value,
                "role": k.role,
                "description": k.description,
                "header": "X-API-Key",
                "example": f"curl -H 'X-API-Key: {k.key_value}' http://localhost:8001/api/findings",
            }
            for k in keys
        ],
        "usage": {
            "swagger_ui": "Click 'Authorize' button → Enter key in 'X-API-Key' field",
            "curl": "curl -H 'X-API-Key: agh_sandbox_admin' http://localhost:8001/api/findings",
            "python": "requests.get('http://localhost:8001/api/findings', headers={'X-API-Key': 'agh_sandbox_admin'})",
        }
    }

@router.post(
    "/reset",
    summary="Reset sandbox to initial state",
    description="Drops and recreates all sandbox data. Requires admin key.",
)
async def reset_sandbox(request: Request, db: Session = Depends(get_db)):
    """
    Reset the sandbox database to its initial seeded state.

    All custom data created during testing will be removed.
    Pre-generated API keys and dummy data will be restored.

    **Required role:** super_admin (use agh_sandbox_admin key)
    """
    if getattr(request.state, 'sandbox_key_role', None) != 'super_admin':
        raise HTTPException(status_code=403, detail="Admin key required for sandbox reset")

    from src.api.sandbox_seed import reset_and_seed
    await reset_and_seed(db)
    return {"success": True, "message": "Sandbox reset to initial state"}

@router.get(
    "/status",
    summary="Sandbox environment status",
    description="Returns sandbox configuration and next auto-reset time.",
)
async def sandbox_status():
    """
    Returns the current sandbox environment status including:
    - Whether sandbox mode is active
    - Database name being used
    - Next scheduled auto-reset time
    - Data statistics (org count, repo count, finding count)
    """
    from src.api.sandbox import SANDBOX_AUTO_RESET_HOURS
    return {
        "sandbox_mode": True,
        "database": "auditgh_sandbox",
        "auto_reset_hours": SANDBOX_AUTO_RESET_HOURS,
        "production_access": False,
        "github_api_access": False,
        "ai_provider": "mock",
    }
```

### 5.5 OpenAPI Security Scheme for Sandbox

Configure in `src/api/main.py` (sandbox mode):

```python
if is_sandbox():
    # Override OpenAPI schema for sandbox auth
    def sandbox_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        from fastapi.openapi.utils import get_openapi
        openapi_schema = get_openapi(
            title="AuditGH Sandbox API",
            version="2.0.0-sandbox",
            description=SANDBOX_DESCRIPTION,  # See Phase 6
            routes=app.routes,
            tags=app.openapi_tags,
        )

        openapi_schema["components"]["securitySchemes"] = {
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": (
                    "Sandbox API Key. Available keys:\n\n"
                    "| Key | Role | Access |\n"
                    "|-----|------|--------|\n"
                    "| `agh_sandbox_admin` | super_admin | Full access |\n"
                    "| `agh_sandbox_analyst` | analyst | Read/write |\n"
                    "| `agh_sandbox_readonly` | user | Read-only |\n\n"
                    "Enter any key above in the value field."
                ),
            }
        }

        openapi_schema["security"] = [{"ApiKeyAuth": []}]

        openapi_schema["servers"] = [
            {"url": "http://localhost:8001", "description": "Sandbox (local)"},
        ]

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = sandbox_openapi
```

---

## 6. Phase 3 — Dummy Data Seed Engine

**Goal:** Realistic, comprehensive dataset covering every endpoint domain.
**Effort:** 3-5 days

### 6.1 Seed Data Overview

| Entity | Count | Coverage |
|--------|-------|----------|
| Organizations | 3 | `acme-corp`, `globex-labs`, `initech-systems` |
| Repositories | 54 | 18 per org (mix of languages, sizes, risk levels) |
| Findings | 540 | 10 per repo (across all severities and scanners) |
| Scan Runs | 108 | 2 per repo (1 completed, 1 in-progress) |
| Scan Schedules | 9 | 3 per org (daily, weekly, monthly) |
| Contributors | 162 | 3 per repo (mix of risk levels) |
| File Commits | 540 | 10 per repo |
| Attack Surface Items | 27 | 9 per org (secrets, abandoned repos, stale contributors) |
| Attack Paths | 18 | 6 per org |
| AI Analysis Results | 54 | 1 architecture + 1 threat model per repo |
| Users | 6 | 2 per role tier (admin, analyst, readonly) |
| SLA Metrics | 9 | 3 per org |
| Projects | 9 | 3 per org |
| API Audit Endpoints | 270 | 5 discovered endpoints per repo |
| Secrets | 27 | Mix of active, resolved, false_positive |
| Feedback Entries | 5 | Sample feedback items |
| Cribl Settings | 1 | Mock Cribl configuration |

**Total: ~1,800+ records across all tables**

### 6.2 Seed Script Architecture

Create `src/api/sandbox_seed.py`:

```python
"""
Sandbox data seed engine.

Generates a full, realistic dataset for the AuditGH sandbox environment.
All data uses clearly fake identifiers (acme-corp, globex, initech)
to prevent confusion with real organizations.
"""
import uuid
import hashlib
from datetime import datetime, timedelta
import random
import json

# ── Organization templates ──────────────────────────────────
ORGANIZATIONS = [
    {
        "name": "acme-corp",
        "display_name": "Acme Corporation",
        "github_org": "acme-corp",
    },
    {
        "name": "globex-labs",
        "display_name": "Globex Laboratories",
        "github_org": "globex-labs",
    },
    {
        "name": "initech-systems",
        "display_name": "Initech Systems",
        "github_org": "initech-systems",
    },
]

# ── Repository templates (per org) ─────────────────────────
REPO_TEMPLATES = [
    {"name": "web-frontend", "language": "TypeScript", "description": "Customer-facing React web application"},
    {"name": "api-gateway", "language": "Python", "description": "FastAPI API gateway and orchestration layer"},
    {"name": "auth-service", "language": "Go", "description": "Authentication and authorization microservice"},
    {"name": "payment-processor", "language": "Java", "description": "Payment processing and billing engine"},
    {"name": "mobile-app", "language": "Kotlin", "description": "Android mobile application"},
    {"name": "ios-app", "language": "Swift", "description": "iOS mobile application"},
    {"name": "data-pipeline", "language": "Python", "description": "ETL data processing pipeline"},
    {"name": "ml-models", "language": "Python", "description": "Machine learning model training and serving"},
    {"name": "infrastructure", "language": "HCL", "description": "Terraform infrastructure-as-code"},
    {"name": "kubernetes-configs", "language": "YAML", "description": "Kubernetes deployment manifests"},
    {"name": "docs-site", "language": "JavaScript", "description": "Documentation website (Docusaurus)"},
    {"name": "shared-ui", "language": "TypeScript", "description": "Shared UI component library"},
    {"name": "notification-service", "language": "Go", "description": "Push notification and email service"},
    {"name": "search-engine", "language": "Rust", "description": "Full-text search indexing service"},
    {"name": "analytics-dashboard", "language": "TypeScript", "description": "Internal analytics dashboard"},
    {"name": "ci-cd-pipelines", "language": "YAML", "description": "GitHub Actions CI/CD workflows"},
    {"name": "legacy-monolith", "language": "Java", "description": "Legacy monolithic application (migration in progress)"},
    {"name": "config-service", "language": "Go", "description": "Centralized configuration management"},
]

# ── Finding templates ───────────────────────────────────────
FINDING_TEMPLATES = [
    {"title": "Hardcoded AWS Access Key", "severity": "critical", "scanner": "gitleaks", "cwe": "CWE-798"},
    {"title": "SQL Injection in User Input", "severity": "critical", "scanner": "semgrep", "cwe": "CWE-89"},
    {"title": "Known CVE in lodash@4.17.20", "severity": "high", "scanner": "grype", "cwe": "CWE-1321"},
    {"title": "Insecure TLS Configuration", "severity": "high", "scanner": "trivy", "cwe": "CWE-295"},
    {"title": "Missing CSRF Token Validation", "severity": "high", "scanner": "semgrep", "cwe": "CWE-352"},
    {"title": "Open S3 Bucket Policy", "severity": "high", "scanner": "checkov", "cwe": "CWE-284"},
    {"title": "Weak Password Hashing (MD5)", "severity": "medium", "scanner": "bandit", "cwe": "CWE-328"},
    {"title": "Unvalidated Redirect", "severity": "medium", "scanner": "semgrep", "cwe": "CWE-601"},
    {"title": "Debug Mode Enabled", "severity": "low", "scanner": "semgrep", "cwe": "CWE-489"},
    {"title": "Outdated Dependency (minor)", "severity": "info", "scanner": "osv", "cwe": "CWE-1104"},
]

# ── Contributor templates ───────────────────────────────────
CONTRIBUTOR_NAMES = [
    "alice.johnson", "bob.smith", "carol.williams", "dave.brown",
    "eve.davis", "frank.wilson", "grace.lee", "henry.taylor",
    "iris.martinez", "jack.anderson", "kate.thomas", "leo.jackson",
]

# ── Scan schedule templates ─────────────────────────────────
SCHEDULE_TEMPLATES = [
    {"name": "Nightly Full Scan", "cron": "0 2 * * *", "scan_type": "full"},
    {"name": "Weekly Secrets Scan", "cron": "0 6 * * 1", "scan_type": "secrets"},
    {"name": "Monthly Dependency Audit", "cron": "0 3 1 * *", "scan_type": "dependencies"},
]

async def initialize_sandbox():
    """Initialize sandbox database with dummy data if empty."""
    ...

async def reset_and_seed(db):
    """Drop all data and re-seed from scratch."""
    ...

def _seed_organizations(db): ...
def _seed_repositories(db, orgs): ...
def _seed_findings(db, repos): ...
def _seed_scan_runs(db, repos): ...
def _seed_schedules(db, orgs): ...
def _seed_contributors(db, repos): ...
def _seed_attack_surface(db, orgs): ...
def _seed_attack_paths(db, orgs): ...
def _seed_ai_results(db, repos): ...
def _seed_users(db): ...
def _seed_sla_metrics(db, orgs): ...
def _seed_projects(db, orgs, repos): ...
def _seed_api_audit(db, repos): ...
def _seed_secrets(db, repos): ...
def _seed_sandbox_api_keys(db): ...
def _seed_feedback(db): ...
```

### 6.3 Sandbox API Key Seed

```python
def _seed_sandbox_api_keys(db):
    """Seed pre-generated sandbox API keys."""
    keys = [
        {
            "name": "Sandbox Admin Key",
            "key_value": "agh_sandbox_admin",
            "role": "super_admin",
            "description": "Full administrative access. Can reset sandbox, manage all data.",
        },
        {
            "name": "Sandbox Analyst Key",
            "key_value": "agh_sandbox_analyst",
            "role": "analyst",
            "description": "Security analyst access. Read/write findings, execute scans, read repos.",
        },
        {
            "name": "Sandbox Readonly Key",
            "key_value": "agh_sandbox_readonly",
            "role": "user",
            "description": "Read-only access. View all data, cannot modify or create.",
        },
    ]

    for key_data in keys:
        key_hash = hashlib.sha256(key_data["key_value"].encode()).hexdigest()
        db.execute(
            text("""
                INSERT INTO sandbox_api_keys (name, key_hash, key_value, role, description)
                VALUES (:name, :hash, :value, :role, :desc)
                ON CONFLICT (key_hash) DO NOTHING
            """),
            {
                "name": key_data["name"],
                "hash": key_hash,
                "value": key_data["key_value"],
                "role": key_data["role"],
                "desc": key_data["description"],
            }
        )
    db.commit()
```

### 6.4 Mock AI Response Provider

Create `src/api/mock_ai.py`:

```python
"""Mock AI provider for sandbox mode. Returns realistic canned responses."""

MOCK_ARCHITECTURE = {
    "summary": "Three-tier web application with React frontend, FastAPI backend, and PostgreSQL database.",
    "components": [
        {"name": "Frontend", "type": "web", "technology": "React/TypeScript", "risk": "medium"},
        {"name": "API Gateway", "type": "service", "technology": "FastAPI/Python", "risk": "high"},
        {"name": "Database", "type": "datastore", "technology": "PostgreSQL", "risk": "critical"},
    ],
    "data_flows": [
        {"from": "Frontend", "to": "API Gateway", "protocol": "HTTPS", "data": "User requests"},
        {"from": "API Gateway", "to": "Database", "protocol": "TCP/5432", "data": "SQL queries"},
    ],
}

MOCK_REMEDIATION = {
    "recommendation": "Rotate the exposed credential immediately and store secrets in a vault.",
    "steps": [
        "1. Revoke the compromised credential in the provider dashboard",
        "2. Generate a new credential with minimal required permissions",
        "3. Store the new credential in HashiCorp Vault or AWS Secrets Manager",
        "4. Update application code to read from the secrets manager",
        "5. Add a pre-commit hook to prevent future credential commits",
    ],
    "estimated_effort": "2-4 hours",
    "priority": "immediate",
}

MOCK_EXECUTIVE_SUMMARY = {
    "overall_risk": "medium",
    "critical_findings": 12,
    "high_findings": 34,
    "top_risks": [
        "Hardcoded credentials in 3 repositories",
        "Known CVEs in production dependencies",
        "Misconfigured IAM policies in Terraform",
    ],
    "recommendations": [
        "Implement secrets management across all repositories",
        "Enable automated dependency updates via Dependabot",
        "Conduct IAM access review for infrastructure-as-code",
    ],
}

def get_mock_response(endpoint_type: str, **kwargs) -> dict:
    """Return a mock AI response based on endpoint type."""
    responses = {
        "architecture": MOCK_ARCHITECTURE,
        "remediation": MOCK_REMEDIATION,
        "executive_summary": MOCK_EXECUTIVE_SUMMARY,
        "triage": {"verdict": "true_positive", "confidence": 0.87,
                   "reasoning": "Pattern matches known AWS key format."},
        "zero_day": {"risk_level": "high", "exploitability": "moderate",
                     "affected_components": ["api-gateway", "auth-service"]},
        "risk_score": {"score": 72, "grade": "C", "trend": "improving"},
    }
    return responses.get(endpoint_type, {"mock": True, "message": "Sandbox mock response"})
```

---

## 7. Phase 4 — OpenAPI Spec Enrichment

**Goal:** Every endpoint has complete documentation visible in Swagger UI.
**Effort:** See [OpenAPI_PLAN.md](OpenAPI_PLAN.md) for the full 12-20 day plan.

This phase executes the enrichment plan from `docs/OpenAPI_PLAN.md`. The key deliverables relevant to the sandbox:

### 7.1 App-Level Metadata (from OpenAPI_PLAN Phase 1)

```python
# Applied to sandbox via sandbox_openapi() override
tags_metadata = [
    {"name": "Sandbox", "description": "Sandbox management: keys, reset, status"},
    {"name": "Authentication", "description": "User login, token refresh, and OAuth 2.0 Device Flow"},
    {"name": "Organizations", "description": "Multi-organization management and configuration"},
    {"name": "Repositories", "description": "GitHub repository management and metadata"},
    {"name": "Findings", "description": "Security findings: listing, filtering, status updates"},
    {"name": "Scans", "description": "Security scan orchestration, status, and results"},
    # ... all 27 tags from OpenAPI_PLAN.md Phase 1, Section 4.2
]
```

### 7.2 Common Response Models (from OpenAPI_PLAN Phase 1)

```python
# src/api/schemas/common.py — shared across sandbox and production
from pydantic import BaseModel, Field
from typing import List

class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Error message", example="Resource not found")

STANDARD_ERRORS = {
    400: {"model": ErrorResponse, "description": "Bad request"},
    401: {"model": ErrorResponse, "description": "Unauthorized — API key required"},
    403: {"model": ErrorResponse, "description": "Forbidden — insufficient role"},
    404: {"model": ErrorResponse, "description": "Not found"},
    429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    500: {"model": ErrorResponse, "description": "Internal server error"},
}
```

### 7.3 Router Enrichment (from OpenAPI_PLAN Phase 2)

Every endpoint in all 28 routers gets:
- `summary=` (short label for Swagger UI sidebar)
- `response_model=` (Pydantic response schema)
- `responses=STANDARD_ERRORS` (error code documentation)
- Detailed docstring with permissions and behavior
- All parameters with `description=`

### 7.4 Field Descriptions (from OpenAPI_PLAN Phase 3)

All 463+ undocumented Pydantic fields get `Field(description=..., example=...)`.

---

## 8. Phase 5 — Swagger Editor & Redoc Services

**Goal:** Three documentation views — Swagger UI for testing, Swagger Editor for spec editing, Redoc for reading.
**Effort:** 1-2 days

### 8.1 Swagger Editor Service

Add to `docker-compose.yml`:

```yaml
  # ─────────────────────────────────────────────────
  # Developer Portal: Swagger Editor (port 8080)
  # ─────────────────────────────────────────────────
  swagger-editor:
    container_name: auditgh_swagger_editor
    image: swaggerapi/swagger-editor:latest
    ports:
      - "8080:8080"
    environment:
      - URL=http://localhost:8001/openapi.json
    restart: unless-stopped
    depends_on:
      sandbox:
        condition: service_healthy
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 512M
```

### 8.2 Enhanced Swagger UI Configuration

In `src/api/main.py` (sandbox mode):

```python
if is_sandbox():
    app = FastAPI(
        title="AuditGH Sandbox API",
        description=SANDBOX_DESCRIPTION,
        version="2.0.0-sandbox",
        openapi_tags=tags_metadata,
        docs_url="/docs",
        redoc_url="/redoc",
        swagger_ui_parameters={
            "docExpansion": "none",
            "filter": True,
            "persistAuthorization": True,
            "tryItOutEnabled": True,
            "displayRequestDuration": True,
            "defaultModelsExpandDepth": 2,
            "syntaxHighlight.theme": "monokai",
            "requestSnippetsEnabled": True,
        },
        swagger_ui_oauth2_redirect_url=None,
    )
```

### 8.3 Redoc Configuration

Redoc is built into FastAPI at `/redoc`. No additional configuration needed beyond the enriched OpenAPI spec — Redoc automatically renders all tags, schemas, and examples.

### 8.4 Custom Swagger UI with Branding (Optional Enhancement)

For custom branding, override the Swagger UI HTML:

```python
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui():
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title="AuditGH Sandbox — API Explorer",
        swagger_favicon_url="/static/favicon.ico",
        swagger_ui_parameters={
            "persistAuthorization": True,
            "tryItOutEnabled": True,
            "filter": True,
            "displayRequestDuration": True,
        },
        swagger_css_url="/static/swagger-custom.css",
    )
```

---

## 9. Phase 6 — Developer Portal Landing Page

**Goal:** A welcoming landing page at `http://localhost:8001/` that guides users to the right tool.
**Effort:** 1 day

### 9.1 Landing Page Endpoint

Override the root endpoint in sandbox mode:

```python
from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def developer_portal():
    """Developer Portal landing page."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AuditGH Developer Portal</title>
        <style>
            /* Clean, professional styling */
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                   max-width: 900px; margin: 0 auto; padding: 40px 20px;
                   background: #0f172a; color: #e2e8f0; }
            h1 { color: #38bdf8; font-size: 2rem; }
            .subtitle { color: #94a3b8; font-size: 1.1rem; margin-bottom: 2rem; }
            .cards { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
            .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
                    padding: 24px; text-decoration: none; color: inherit;
                    transition: border-color 0.2s; }
            .card:hover { border-color: #38bdf8; }
            .card h2 { color: #f8fafc; margin-top: 0; font-size: 1.2rem; }
            .card p { color: #94a3b8; font-size: 0.9rem; line-height: 1.5; }
            .card .url { color: #38bdf8; font-size: 0.85rem; }
            .keys { background: #1e293b; border: 1px solid #334155; border-radius: 12px;
                    padding: 24px; margin-top: 2rem; }
            .keys h2 { color: #f8fafc; }
            .key-row { display: flex; justify-content: space-between; align-items: center;
                       padding: 8px 0; border-bottom: 1px solid #334155; }
            .key-value { font-family: 'SF Mono', 'Fira Code', monospace;
                         background: #0f172a; padding: 4px 10px; border-radius: 6px;
                         color: #34d399; font-size: 0.9rem; }
            .key-role { color: #94a3b8; font-size: 0.85rem; }
            .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
                     font-size: 0.75rem; font-weight: 600; }
            .badge-admin { background: #7c3aed20; color: #a78bfa; }
            .badge-analyst { background: #2563eb20; color: #60a5fa; }
            .badge-readonly { background: #16a34a20; color: #4ade80; }
            .notice { background: #422006; border: 1px solid #92400e; border-radius: 8px;
                      padding: 12px 16px; margin-top: 2rem; font-size: 0.9rem; color: #fbbf24; }
        </style>
    </head>
    <body>
        <h1>AuditGH Developer Portal</h1>
        <p class="subtitle">
            Explore, test, and integrate with the AuditGH Security Platform API.
            This sandbox environment uses dummy data — no production impact.
        </p>

        <div class="cards">
            <a class="card" href="/docs">
                <h2>Swagger UI</h2>
                <p>Interactive API explorer. Test endpoints directly with
                   "Try It Out". Authenticate with sandbox API keys.</p>
                <span class="url">localhost:8001/docs</span>
            </a>
            <a class="card" href="http://localhost:8080" target="_blank">
                <h2>Swagger Editor</h2>
                <p>Edit and validate the OpenAPI specification.
                   Generate client SDKs in Python, TypeScript, Go, and more.</p>
                <span class="url">localhost:8080</span>
            </a>
            <a class="card" href="/redoc">
                <h2>Redoc</h2>
                <p>Beautiful read-only API reference documentation.
                   Ideal for architects and reviewers.</p>
                <span class="url">localhost:8001/redoc</span>
            </a>
        </div>

        <div class="keys">
            <h2>Sandbox API Keys</h2>
            <p style="color:#94a3b8; font-size:0.9rem; margin-bottom:16px;">
                Use these keys in the <code>X-API-Key</code> header to authenticate.
                Click "Authorize" in Swagger UI and paste a key.
            </p>
            <div class="key-row">
                <div>
                    <span class="key-value">agh_sandbox_admin</span>
                    <span class="badge badge-admin">super_admin</span>
                </div>
                <span class="key-role">Full access — can reset sandbox</span>
            </div>
            <div class="key-row">
                <div>
                    <span class="key-value">agh_sandbox_analyst</span>
                    <span class="badge badge-analyst">analyst</span>
                </div>
                <span class="key-role">Read/write findings, execute scans</span>
            </div>
            <div class="key-row" style="border-bottom:none;">
                <div>
                    <span class="key-value">agh_sandbox_readonly</span>
                    <span class="badge badge-readonly">user</span>
                </div>
                <span class="key-role">Read-only access to all data</span>
            </div>
        </div>

        <div class="notice">
            This is a sandbox environment with dummy data.
            Data resets automatically every 24 hours.
            To reset manually: <code>POST /api/sandbox/reset</code> (admin key required).
        </div>
    </body>
    </html>
    """
```

---

## 10. Phase 7 — Auto-Reset & Lifecycle Management

**Goal:** Sandbox data automatically resets every 24 hours; on-demand reset available.
**Effort:** 1-2 days

### 10.1 Reset Scheduler

Add to sandbox startup in `src/api/main.py`:

```python
if is_sandbox():
    from apscheduler.schedulers.asyncio import AsyncIOScheduler

    sandbox_scheduler = AsyncIOScheduler()

    async def auto_reset_sandbox():
        """Reset sandbox data to initial state."""
        from src.api.sandbox_seed import reset_and_seed
        from src.api.database import SessionLocal
        db = SessionLocal()
        try:
            await reset_and_seed(db)
            logger.info("Sandbox auto-reset completed")
        except Exception as e:
            logger.error(f"Sandbox auto-reset failed: {e}")
        finally:
            db.close()

    sandbox_scheduler.add_job(
        auto_reset_sandbox,
        "interval",
        hours=SANDBOX_AUTO_RESET_HOURS,
        id="sandbox_auto_reset",
        name="Sandbox Data Auto-Reset",
    )
    sandbox_scheduler.start()
```

### 10.2 Reset Logic

```python
async def reset_and_seed(db):
    """Drop all sandbox data and re-seed from scratch."""
    from src.api.models import Base
    from src.api.database import engine

    # Drop all tables
    Base.metadata.drop_all(bind=engine)

    # Recreate all tables
    Base.metadata.create_all(bind=engine)

    # Re-seed
    _seed_sandbox_api_keys(db)
    orgs = _seed_organizations(db)
    repos = _seed_repositories(db, orgs)
    _seed_findings(db, repos)
    _seed_scan_runs(db, repos)
    _seed_schedules(db, orgs)
    _seed_contributors(db, repos)
    _seed_attack_surface(db, orgs)
    _seed_attack_paths(db, orgs)
    _seed_ai_results(db, repos)
    _seed_users(db)
    _seed_sla_metrics(db, orgs)
    _seed_projects(db, orgs, repos)
    _seed_api_audit(db, repos)
    _seed_secrets(db, repos)
    _seed_feedback(db)

    # Seed RBAC
    from src.rbac.seeds import seed_rbac_data
    seed_rbac_data(db)

    db.commit()
```

### 10.3 Redis Cleanup on Reset

```python
async def _flush_sandbox_redis():
    """Clear sandbox Redis DB (DB 1)."""
    import redis
    r = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/1"))
    r.flushdb()
```

---

## 11. Phase 8 — CI/CD & Validation

**Goal:** Automated testing, spec validation, and SDK generation.
**Effort:** 2-3 days

### 11.1 OpenAPI Schema Export

Create `scripts/export_openapi.py`:

```python
"""Export the sandbox OpenAPI schema for Swagger Editor and SDK generation."""
import json
import yaml
import sys
sys.path.insert(0, "/app")

# Simulate sandbox mode for export
import os
os.environ["SANDBOX_MODE"] = "true"
os.environ["AI_PROVIDER"] = "mock"

from src.api.main import app

def export():
    schema = app.openapi()

    with open("openapi.json", "w") as f:
        json.dump(schema, f, indent=2)

    with open("openapi.yaml", "w") as f:
        yaml.dump(schema, f, default_flow_style=False, sort_keys=False)

    paths = schema.get("paths", {})
    endpoints = sum(len(m) for m in paths.values() if isinstance(m, dict))
    schemas = len(schema.get("components", {}).get("schemas", {}))
    print(f"Exported: {endpoints} endpoints, {schemas} schemas")
    print(f"Files: openapi.json, openapi.yaml")

if __name__ == "__main__":
    export()
```

### 11.2 Spec Validation CI Workflow

Create `.github/workflows/openapi-validation.yml`:

```yaml
name: OpenAPI Validation
on:
  push:
    paths:
      - 'src/api/**'
      - 'swagger/**'
  pull_request:
    paths:
      - 'src/api/**'

jobs:
  validate-openapi:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15-alpine
        env:
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: auditgh_sandbox
        ports:
          - 5432:5432
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install dependencies
        run: pip install -r requirements.txt pyyaml

      - name: Export OpenAPI schema
        env:
          SANDBOX_MODE: "true"
          AI_PROVIDER: mock
          POSTGRES_HOST: localhost
          POSTGRES_DB: auditgh_sandbox
          REDIS_URL: redis://localhost:6379/1
          SESSION_SECRET: ci-test-secret-key-at-least-32-chars
          JWT_SECRET_KEY: ci-test-jwt-secret
        run: python scripts/export_openapi.py

      - name: Validate schema
        run: |
          npm install -g @apidevtools/swagger-cli
          swagger-cli validate openapi.json

      - name: Check documentation coverage
        run: python scripts/check_openapi_coverage.py

      - name: Upload schema artifact
        uses: actions/upload-artifact@v4
        with:
          name: openapi-schema
          path: |
            openapi.json
            openapi.yaml
```

### 11.3 Documentation Coverage Script

Create `scripts/check_openapi_coverage.py`:

```python
"""Validate that all endpoints meet documentation standards."""
import json
import sys

def check():
    with open("openapi.json") as f:
        schema = json.load(f)

    issues = []
    endpoint_count = 0

    for path, methods in schema.get("paths", {}).items():
        for method, spec in methods.items():
            if method in ("parameters", "servers"):
                continue
            endpoint_count += 1
            endpoint = f"{method.upper()} {path}"

            # Check required documentation
            if not spec.get("summary"):
                issues.append(f"  MISSING summary: {endpoint}")
            if not spec.get("description") and not spec.get("summary"):
                issues.append(f"  MISSING description: {endpoint}")
            if "responses" not in spec or not spec["responses"]:
                issues.append(f"  MISSING responses: {endpoint}")
            if not spec.get("tags"):
                issues.append(f"  MISSING tags: {endpoint}")

    print(f"\nOpenAPI Coverage Report")
    print(f"======================")
    print(f"Total endpoints: {endpoint_count}")
    print(f"Issues found: {len(issues)}")

    if issues:
        print(f"\nIssues:")
        for issue in sorted(issues):
            print(issue)
        print(f"\n{len(issues)} documentation gaps found.")
        sys.exit(1)
    else:
        print("\nAll endpoints fully documented!")
        sys.exit(0)

if __name__ == "__main__":
    check()
```

### 11.4 SDK Generation Makefile Targets

Add to `Makefile`:

```makefile
# ── Developer Portal ─────────────────────────────────
.PHONY: sandbox-up sandbox-down sandbox-reset sandbox-export sandbox-sdk

sandbox-up:  ## Start sandbox API, Swagger Editor, and Redoc
	docker-compose up -d sandbox swagger-editor
	@echo ""
	@echo "Developer Portal ready:"
	@echo "  Sandbox API:     http://localhost:8001/docs"
	@echo "  Swagger Editor:  http://localhost:8080"
	@echo "  Redoc:           http://localhost:8001/redoc"
	@echo "  Landing Page:    http://localhost:8001/"
	@echo ""
	@echo "API Keys:"
	@echo "  Admin:    agh_sandbox_admin"
	@echo "  Analyst:  agh_sandbox_analyst"
	@echo "  Readonly: agh_sandbox_readonly"

sandbox-down:  ## Stop sandbox services
	docker-compose stop sandbox swagger-editor

sandbox-reset:  ## Reset sandbox dummy data
	curl -s -X POST http://localhost:8001/api/sandbox/reset \
		-H "X-API-Key: agh_sandbox_admin" | python -m json.tool

sandbox-export:  ## Export OpenAPI schema to files
	docker exec auditgh_sandbox python scripts/export_openapi.py
	docker cp auditgh_sandbox:/app/openapi.json ./openapi.json
	docker cp auditgh_sandbox:/app/openapi.yaml ./openapi.yaml
	@echo "Exported: openapi.json, openapi.yaml"

sandbox-sdk-python:  ## Generate Python client SDK
	$(MAKE) sandbox-export
	docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
		-i /local/openapi.json -g python -o /local/clients/python \
		--additional-properties=packageName=auditgh_client,projectName=auditgh-client
	@echo "Python SDK generated in clients/python/"

sandbox-sdk-typescript:  ## Generate TypeScript client SDK
	$(MAKE) sandbox-export
	docker run --rm -v ${PWD}:/local openapitools/openapi-generator-cli generate \
		-i /local/openapi.json -g typescript-axios -o /local/clients/typescript
	@echo "TypeScript SDK generated in clients/typescript/"

sandbox-validate:  ## Validate OpenAPI schema
	$(MAKE) sandbox-export
	npx @apidevtools/swagger-cli validate openapi.json
```

---

## 12. Database Schema

### 12.1 New Table: `sandbox_api_keys`

This table exists **only in the sandbox database** (`auditgh_sandbox`), not in production.

```sql
CREATE TABLE sandbox_api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    key_hash    VARCHAR(64) NOT NULL UNIQUE,
    key_value   VARCHAR(64) NOT NULL,
    role        VARCHAR(50) NOT NULL DEFAULT 'analyst',
    description TEXT,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sandbox_api_keys_hash ON sandbox_api_keys(key_hash);

-- Seed data (inserted by sandbox_seed.py)
INSERT INTO sandbox_api_keys (name, key_hash, key_value, role, description) VALUES
('Sandbox Admin Key',
 'c29e...',  -- SHA-256 of 'agh_sandbox_admin'
 'agh_sandbox_admin', 'super_admin',
 'Full administrative access. Can reset sandbox, manage all data.'),
('Sandbox Analyst Key',
 'a4b7...',  -- SHA-256 of 'agh_sandbox_analyst'
 'agh_sandbox_analyst', 'analyst',
 'Security analyst access. Read/write findings, execute scans.'),
('Sandbox Readonly Key',
 '9f12...',  -- SHA-256 of 'agh_sandbox_readonly'
 'agh_sandbox_readonly', 'user',
 'Read-only access to all data.');
```

### 12.2 Sandbox-Specific SQLAlchemy Model

Add to `src/api/models.py` (conditionally loaded in sandbox mode):

```python
class SandboxApiKey(Base):
    """API keys for sandbox authentication. Only exists in sandbox database."""
    __tablename__ = "sandbox_api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    key_hash = Column(String(64), nullable=False, unique=True, index=True)
    key_value = Column(String(64), nullable=False)
    role = Column(String(50), nullable=False, default="analyst")
    description = Column(Text)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, server_default=func.now())
```

---

## 13. File Inventory

### New Files to Create

| File | Purpose | Phase |
|------|---------|-------|
| `src/api/sandbox.py` | Sandbox mode detection and configuration | 1 |
| `src/api/sandbox_seed.py` | Dummy data seed engine (~800 lines) | 3 |
| `src/api/mock_ai.py` | Mock AI provider for sandbox (~150 lines) | 3 |
| `src/api/middleware/sandbox_auth.py` | Sandbox API key authentication middleware | 2 |
| `src/api/routers/sandbox.py` | Sandbox management endpoints (keys, reset, status) | 2 |
| `src/api/schemas/common.py` | Shared ErrorResponse, STANDARD_ERRORS | 4 |
| `src/api/schemas/__init__.py` | Schemas package init | 4 |
| `scripts/init_sandbox_db.py` | Create sandbox database | 1 |
| `scripts/export_openapi.py` | Export OpenAPI schema to JSON/YAML | 8 |
| `scripts/check_openapi_coverage.py` | CI documentation coverage validation | 8 |
| `.github/workflows/openapi-validation.yml` | CI workflow for spec validation | 8 |
| `static/swagger-custom.css` | Custom Swagger UI styling (optional) | 5 |

### Files to Modify

| File | Changes | Phase |
|------|---------|-------|
| `docker-compose.yml` | Add `sandbox` and `swagger-editor` services | 1, 5 |
| `src/api/main.py` | Sandbox mode branching, custom OpenAPI schema, landing page, tags | 1, 2, 6 |
| `src/api/models.py` | Add `SandboxApiKey` model (conditional) | 2 |
| `src/api/routers/*.py` (28 files) | Enrichment: summary, response_model, responses, docstrings | 4 |
| `Makefile` | Add sandbox-* targets | 8 |
| `.env.sample` | Add SANDBOX_MODE, SANDBOX_AUTO_RESET_HOURS | 1 |
| `src/auth/config.py` | Add `http://localhost:8001` and `http://localhost:8080` to CORS | 1 |
| `README.md` | Add Developer Portal section | 6 |

### Files Unchanged (Reference Only)

| File | Relationship |
|------|-------------|
| `swagger/` directory | Archived reference; spec quality standards applied to code instead |
| `Dockerfile.api` | Reused as-is for sandbox container |
| `src/auth/tokens.py` | Production JWT system unchanged; sandbox uses API keys |
| `src/rbac/seeds.py` | Reused by sandbox seed to initialize RBAC roles |

---

## 14. Environment Variables

### New Variables for Sandbox

| Variable | Default | Description |
|----------|---------|-------------|
| `SANDBOX_MODE` | `false` | Enable sandbox mode (separate DB, mock AI, API key auth) |
| `SANDBOX_AUTO_RESET_HOURS` | `24` | Hours between automatic data resets |
| `AUTH_SANDBOX_KEYS` | `false` | Enable sandbox API key authentication (replaces JWT/OIDC) |
| `AI_PROVIDER=mock` | (none) | Use mock AI responses instead of real LLM calls |

### Existing Variables Overridden in Sandbox

| Variable | Production | Sandbox |
|----------|-----------|---------|
| `POSTGRES_DB` | `auditgh_kb` | `auditgh_sandbox` |
| `REDIS_URL` | `redis://redis:6379/0` | `redis://redis:6379/1` |
| `AUTH_REQUIRED` | `true` | `true` (but via API keys, not OIDC) |
| `GITHUB_TOKEN` | `ghp_xxx` | (empty — no GitHub access) |
| `OPENAI_API_KEY` | `sk-xxx` | (empty — mock provider) |
| `ANTHROPIC_API_KEY` | `sk-ant-xxx` | (empty — mock provider) |
| `SCHEDULER_ENABLED` | `true` | `false` |

---

## 15. Testing Plan

### 15.1 Unit Tests

| Test | File | Validates |
|------|------|-----------|
| Sandbox API key auth | `tests/test_sandbox_auth.py` | Keys authenticate, invalid keys rejected, roles enforced |
| Sandbox seed | `tests/test_sandbox_seed.py` | All entities created, correct counts, no FK violations |
| Mock AI provider | `tests/test_mock_ai.py` | All endpoint types return valid mock responses |
| Sandbox reset | `tests/test_sandbox_reset.py` | Reset drops and recreates all data correctly |
| OpenAPI coverage | `tests/test_openapi_coverage.py` | All endpoints have summary, responses, tags |

### 15.2 Integration Tests

| Test | Validates |
|------|-----------|
| `test_sandbox_e2e.py` | Full workflow: get keys → authenticate → CRUD operations → reset |
| `test_swagger_ui_loads.py` | Swagger UI at /docs loads and renders all endpoints |
| `test_redoc_loads.py` | Redoc at /redoc loads and renders |
| `test_openapi_json_valid.py` | `/openapi.json` returns valid OpenAPI 3.0 schema |
| `test_sandbox_isolation.py` | Sandbox DB operations don't affect production DB |
| `test_sdk_generation.py` | openapi-generator produces compilable Python/TS clients |

### 15.3 Manual Acceptance Tests

| # | Test | Expected Result |
|---|------|-----------------|
| 1 | Navigate to `localhost:8001/` | Landing page with links to all three views and API keys |
| 2 | Navigate to `localhost:8001/docs` | Swagger UI with all 315+ endpoints organized by tags |
| 3 | Click "Authorize" → enter `agh_sandbox_admin` | Auth persists across page reloads |
| 4 | Try `GET /api/organizations` | Returns 3 orgs (acme-corp, globex-labs, initech-systems) |
| 5 | Try `GET /api/findings?severity=critical` | Returns critical findings from dummy data |
| 6 | Try `POST /api/sandbox/reset` with admin key | Returns success, data reset to initial state |
| 7 | Try any endpoint with `agh_sandbox_readonly` key | POST/PUT/DELETE returns 403 |
| 8 | Navigate to `localhost:8080` | Swagger Editor loads with the OpenAPI spec |
| 9 | Navigate to `localhost:8001/redoc` | Redoc renders complete API reference |
| 10 | Try `GET /api/ai/architecture/{repo_id}` | Returns mock AI architecture response |
| 11 | Wait 24 hours (or manual reset) | All data returns to known-good state |
| 12 | Run `make sandbox-sdk-python` | Generates compilable Python client |

---

## 16. Security Considerations

### 16.1 What the Sandbox Cannot Do

| Action | Prevention |
|--------|-----------|
| Access production database | Different `POSTGRES_DB` env var; no connection string to `auditgh_kb` |
| Call GitHub API | `GITHUB_TOKEN` is empty; all sync endpoints return mock data |
| Call AI providers | `AI_PROVIDER=mock`; no API keys for OpenAI/Anthropic |
| Run actual scans | Scanner service not started for sandbox; scan endpoints return mock |
| Send emails | SMTP not configured for sandbox container |
| Access MinIO/S3 | No MinIO credentials configured |
| Escalate to production | Sandbox API keys are `SHA-256(agh_sandbox_xxx)` — will never match production key hashes |

### 16.2 Sandbox API Key Security

| Aspect | Implementation |
|--------|---------------|
| Key storage | SHA-256 hashed in DB (key_value also stored for display in sandbox only) |
| No production access | Keys only exist in `auditgh_sandbox` database |
| No OIDC bypass | Sandbox disables OIDC entirely; only API keys accepted |
| Rate limiting | Standard slowapi rate limits still apply |
| CORS restrictions | Only allows `localhost:8001`, `localhost:8080`, `localhost:3000` |

### 16.3 Network Isolation

```
# Production API (port 8000) — NEVER accepts sandbox keys
# Sandbox API (port 8001) — NEVER connects to production DB
# Swagger Editor (port 8080) — Only talks to sandbox API
```

### 16.4 Deployment Recommendation

For team-shared environments (not just local dev), add:
- HTTP Basic Auth or VPN requirement before reaching ports 8001/8080
- Disable sandbox service in production docker-compose profile
- Use Docker Compose profiles: `docker-compose --profile dev up`

---

## 17. Phased Rollout Timeline

```
Week 1                    Week 2                    Week 3
├─────────────────────────┼─────────────────────────┼──────────────────┤
│                         │                         │                  │
│  Phase 1: Infrastructure│  Phase 3: Seed Engine   │  Phase 6: Portal │
│  - docker-compose       │  - All entity seeds     │  - Landing page  │
│  - sandbox DB creation  │  - Mock AI provider     │  - Branding      │
│  - sandbox mode flag    │  - 1,800+ records       │                  │
│                         │                         │  Phase 7: Reset  │
│  Phase 2: Auth          │  Phase 4: OpenAPI       │  - Auto-reset    │
│  - sandbox_api_keys     │  - App metadata         │  - Scheduler     │
│  - Auth middleware       │  - Common schemas       │                  │
│  - Keys endpoint        │  - Router enrichment    │  Phase 8: CI/CD  │
│  - Sandbox router       │  (P1 routers: auth,     │  - Export script │
│                         │   orgs, repos, findings,│  - Validation    │
│  Phase 5: Swagger+Redoc │   scans)                │  - Coverage check│
│  - Swagger Editor svc   │                         │  - SDK targets   │
│  - Enhanced /docs       │  Phase 4 continued:     │                  │
│  - Redoc at /redoc      │  (P2-P4 routers)        │  TESTING &       │
│                         │                         │  ACCEPTANCE      │
└─────────────────────────┴─────────────────────────┴──────────────────┘

Total estimated effort: 3 weeks (1-2 developers)
```

### Phase Dependencies

```
Phase 1 (Infrastructure)
    ├── Phase 2 (Auth) ────────┐
    ├── Phase 5 (Editor/Redoc) │
    │                          ▼
    │               Phase 3 (Seed Engine)
    │                          │
    │               Phase 4 (OpenAPI Enrichment) ← from OpenAPI_PLAN.md
    │                          │
    ├── Phase 6 (Landing Page) │
    │                          │
    ▼                          ▼
Phase 7 (Auto-Reset) ──► Phase 8 (CI/CD)
```

### Quick Start After Implementation

```bash
# Start the entire developer portal
make sandbox-up

# Or with docker-compose directly
docker-compose up -d sandbox swagger-editor

# Access points:
#   http://localhost:8001/       — Landing page
#   http://localhost:8001/docs   — Swagger UI (interactive testing)
#   http://localhost:8001/redoc  — Redoc (reference docs)
#   http://localhost:8080        — Swagger Editor

# API Keys:
#   agh_sandbox_admin    — Full access (super_admin)
#   agh_sandbox_analyst  — Read/write (analyst)
#   agh_sandbox_readonly — Read-only (user)

# Reset sandbox data
make sandbox-reset

# Generate client SDK
make sandbox-sdk-python
make sandbox-sdk-typescript
```

---

*This implementation plan delivers a complete, self-service developer portal where developers, DevOps engineers, and security analysts can explore, test, and integrate with all 315+ AuditGH API endpoints — safely isolated from production with realistic dummy data, simplified API key authentication, and three documentation views (Swagger UI, Swagger Editor, Redoc).*

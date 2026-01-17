# Architecture

**Analysis Date:** 2026-01-17

## Pattern Overview

**Overall:** Multi-Layered Microservices-Oriented Monolith with AI Integration

**Key Characteristics:**
- Layered architecture with specialized service components
- Multi-tenant support with organization-based isolation
- Plugin-based AI provider system (Claude, OpenAI, Gemini, Ollama)
- Background job execution for scanning operations
- DOE (Design of Experiments) Self-Annealing for AI config auto-correction

## Layers

**Presentation Layer:**
- Purpose: User interface and client-side rendering
- Contains: React components, pages, context providers
- Location: `src/web-ui/`
- Depends on: API layer via HTTP/REST
- Used by: End users via browser

**API Layer:**
- Purpose: REST endpoints and request handling
- Contains: FastAPI routers, middleware, request validation
- Location: `src/api/main.py`, `src/api/routers/`
- Depends on: Service layer, data layer
- Used by: Web UI, CLI tools

**Business Logic / Service Layer:**
- Purpose: Core business logic, AI orchestration, scanning engines
- Contains: AI agents, scanner modules, analysis engines
- Location: `src/ai_agent/`, `src/scanners/`, `execution/`
- Depends on: Data layer, external APIs
- Used by: API layer, CLI entry points

**Data Layer:**
- Purpose: Database operations and data persistence
- Contains: SQLAlchemy models, database connections
- Location: `src/api/models.py`, `src/api/database.py`
- Depends on: PostgreSQL, Redis
- Used by: Service layer, API layer

**Authentication & Authorization Layer:**
- Purpose: User authentication, session management, RBAC
- Contains: OAuth providers, JWT handling, permission checking
- Location: `src/auth/`, `src/rbac/`
- Depends on: Redis (token storage), database (user data)
- Used by: API middleware, route handlers

## Data Flow

**API Request Flow:**

1. HTTP request arrives at FastAPI app
2. `RequestLoggingMiddleware` logs request
3. `OrganizationContextMiddleware` extracts org context
4. `TenantMiddleware` sets tenant scope (if multi-tenant enabled)
5. `SecurityHeadersMiddleware` adds security headers
6. `SessionActivityMiddleware` tracks session
7. Route handler processes request
8. Database query via SQLAlchemy
9. Response returned with CORS headers

**Scanning Flow:**

1. `scan_repos.py` orchestrator invoked
2. `AIModelSelfAnnealing` validates provider/model config
3. Repository enumeration via GitHub API (`src/github/api.py`)
4. Parallel scanner execution (`execution/*.py` scripts):
   - `scan_secrets.py` (gitleaks, trufflehog)
   - `scan_sast.py` (semgrep, bandit)
   - `scan_deps.py` (grype, trivy)
   - `scan_iac.py` (checkov)
   - `scan_api.py` (API discovery & fuzzing)
5. `ingest_scans.py` / `ingest_reports.py` stores results
6. Findings persisted to database

**AI Agent Analysis Flow:**

1. Finding/Repository submitted for analysis
2. AI Agent (`src/ai_agent/agent.py`) receives request
3. Provider selection (Claude/OpenAI/Ollama/Gemini)
4. `DiagnosticCollector` gathers context
5. `ReasoningEngine` analyzes findings
6. `RemediationEngine` generates fixes
7. `LearningSystem` improves recommendations
8. Analysis/remediation returned

**State Management:**
- Database: PostgreSQL for persistent data
- Cache: Redis for sessions, permissions, tokens (5-minute TTL)
- File-based: Scan reports in `vulnerability_reports/`

## Key Abstractions

**AI Provider Pattern:**
- Purpose: Pluggable AI/LLM provider system
- Location: `src/ai_agent/providers/`
- Examples: `claude.py`, `openai.py`, `ollama.py`, `gemini.py`, `anthropic_foundry.py`
- Pattern: Strategy pattern with base class (`base.py`) and failover (`failover.py`)

**Scanner Pattern:**
- Purpose: Pluggable security scanner system
- Location: `src/scanners/`
- Examples: `src/scanners/base.py`, `src/scanners/python/safety.py`, `src/scanners/python/pip_audit.py`
- Pattern: Factory pattern in `src/__main__.py` (`get_scanners` function)

**Self-Annealing Pattern:**
- Purpose: Auto-correction of misconfigurations
- Location: `scan_repos.py`, `ingest_scans.py`
- Examples: `AIModelSelfAnnealing`, `IngestionOrgSelfAnnealing`
- Pattern: DOE (Design of Experiments) with anomaly detection and audit trails

**Multi-Tenant Pattern:**
- Purpose: Organization-based data isolation
- Location: `src/api/middleware/tenant.py`, `src/api/database.py`
- Implementation: `organization_id` column filtering, request-scoped context
- Functions: `set_request_org_id()`, `get_request_org_id()`

**RBAC Dependency Pattern:**
- Purpose: Permission-based access control
- Location: `src/rbac/dependencies.py`
- Usage: `@require_permissions()` decorator on route handlers
- Cache: Redis-backed permission caching

## Entry Points

**CLI Entry:**
- Location: `src/__main__.py`
- Triggers: `python -m src` or package invocation
- Responsibilities: Parse args, orchestrate scanning, generate reports

**API Entry:**
- Location: `src/api/main.py`
- Triggers: `uvicorn src.api.main:app --host 0.0.0.0 --port 8000`
- Responsibilities: Initialize routers, middleware, database; serve REST API
- Endpoints: `/health`, `/docs` (Swagger), `/redoc`

**Web UI Entry:**
- Location: `src/web-ui/app/layout.tsx`
- Triggers: `npm dev` (development) or `npm start` (production)
- Port: 3000 (default)
- Responsibilities: Render React UI, manage tenant context

**Background Jobs:**
- Location: `execution/*.py`
- Triggers: Scheduled via APScheduler (`src/api/scheduler.py`)
- Examples: `ai_org_agent.py`, `ai_credential_url_agent.py`, `scan_*.py`

## Error Handling

**Strategy:** Throw errors at source, catch at boundaries, log with context

**Patterns:**
- API routes: try/catch with HTTPException for client errors
- Services: raise custom exceptions, logged at service boundary
- Background jobs: catch all, log to Cribl/MinIO, update scan status
- 162 broad exception handlers across API routers (area for improvement)

## Cross-Cutting Concerns

**Logging:**
- Framework: loguru with HTTP transport to Cribl
- Fallback: MinIO object storage when Cribl unavailable
- Pattern: Structured JSON logging with request context

**Validation:**
- API: Pydantic models for request/response schemas
- Auto OpenAPI documentation via FastAPI

**Authentication:**
- OAuth2 + JWT via authlib and python-jose
- Session management with Redis-backed token storage
- CORS preflight handling for cross-origin requests

**Rate Limiting:**
- slowapi middleware on protected routes
- Configurable limits per endpoint

---

*Architecture analysis: 2026-01-17*
*Update when major patterns change*

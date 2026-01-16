# Architecture

**Analysis Date:** 2026-01-12

## Pattern Overview

**Overall:** Hybrid Monolith with Separated UI Layer

**Key Characteristics:**
- Backend: Python monolith with FastAPI
- Frontend: Next.js React SPA
- Shared database: PostgreSQL with multi-tenant support
- Plugin architecture: Extensible scanners and AI providers
- Service separation: API, Scanner, UI as distinct containers

## Layers

**API Gateway Layer:**
- Purpose: Central routing and request handling
- Contains: FastAPI application, middleware, CORS configuration
- Location: `src/api/main.py`
- Depends on: Routers, database, middleware
- Used by: Web UI, CLI tools, external clients

**Router/Controller Layer:**
- Purpose: API endpoint handlers organized by domain
- Contains: 22+ router modules with REST endpoints
- Location: `src/api/routers/*.py` (findings, projects, organizations, scans, ai, attack_surface, etc.)
- Depends on: Models, database sessions, service layer
- Used by: API gateway (FastAPI app)

**Data Model Layer:**
- Purpose: Database schema and ORM models
- Contains: 25+ SQLAlchemy models (Organization, Repository, Finding, Remediation, etc.)
- Location: `src/api/models.py`
- Depends on: SQLAlchemy ORM
- Used by: All routers, database operations

**Database/Persistence Layer:**
- Purpose: Database connection and session management
- Contains: SQLAlchemy engine, session factory, organization-scoped filtering
- Location: `src/api/database.py`, `src/api/database_router.py`
- Depends on: PostgreSQL, environment configuration
- Used by: All routers via dependency injection

**Business Logic/Service Layer:**
- Purpose: Core domain logic and orchestration
- Contains:
  - AI Agent - `src/ai_agent/agent.py` (provider orchestration, remediation)
  - Scanner plugins - `src/scanners/base.py`, `src/scanners/python/*.py`
  - GitHub client - `src/github/api.py`, `src/github/github_client.py`
  - Report generator - `src/reports/generator.py`, `src/reporting/pdf_generator.py`
- Depends on: External APIs, database models
- Used by: Routers, CLI scripts

**Utility/Helper Layer:**
- Purpose: Shared utilities and cross-cutting concerns
- Contains: Risk scoring, code extraction, architecture analysis, logging
- Location: `src/api/utils/*.py` (risk_scoring, repo_context, architecture_preprocessor, code_extractors, cribl_logger, diagram_executor)
- Depends on: Core libraries only
- Used by: Service layer, routers

**Frontend/UI Layer:**
- Purpose: User interface and client-side logic
- Contains: Next.js App Router, React components, hooks, contexts
- Location: `src/web-ui/app/*.tsx`, `src/web-ui/components/*.tsx`
- Depends on: Backend API via HTTP
- Used by: End users via browser

**CLI/Script Layer:**
- Purpose: Batch operations and automation
- Contains: Repository scanning, data ingestion, maintenance scripts
- Location: Root-level Python scripts (`scan_repos.py`, `ingest_scans.py`, etc.), `src/__main__.py`
- Depends on: Database, GitHub API, scanners
- Used by: Administrators, scheduled jobs

## Data Flow

**HTTP API Request:**
1. Client sends HTTP request to API (port 8000)
2. FastAPI receives request in `src/api/main.py`
3. OrganizationContextMiddleware extracts org context from headers - `src/api/middleware/tenant.py`
4. Router handler matched and invoked - `src/api/routers/*.py`
5. Database session created with org filter - `src/api/database.py`
6. Service layer logic executed (AI, scanners, GitHub, etc.)
7. Database query/mutation performed
8. JSON response returned to client

**Repository Scan Execution:**
1. CLI or API triggers scan - `scan_repos.py` or `src/api/routers/scans.py`
2. Repository cloned to temp directory - `src/api/utils/repo_context.py`
3. Scanner plugins dispatched - `src/scanners/base.py`
4. External security tools executed (Gitleaks, Semgrep, Grype, etc.)
5. Raw findings extracted and parsed
6. Findings normalized to `Finding` model - `src/api/models.py`
7. Risk scores calculated - `src/api/utils/risk_scoring.py`
8. AI remediation generated - `src/ai_agent/agent.py`, `src/ai_agent/remediation.py`
9. Results persisted to database
10. Temp repository cleaned up

**Multi-Tenant Data Isolation:**
- Request headers pass organization context (`X-Organization-ID`, `X-Organization-Name`)
- Middleware extracts org and stores in request state
- All database queries filtered by `organization_id`
- Organization-specific credentials stored in `Organization` model
- Per-organization scan scheduling and quotas

**State Management:**
- Backend: Stateless API with database persistence
- Frontend: React Context API for global state (TenantContext, ThemeProvider)
- No in-memory caching layer

## Key Abstractions

**Scanner Plugin:**
- Purpose: Abstract interface for security tools
- Location: `src/scanners/base.py`
- Pattern: Template method pattern
  - `is_applicable(repo_path)` - Check if scanner applies
  - `scan(repo_path)` - Execute scan and return results
- Examples: `src/scanners/python/safety.py`, `src/scanners/python/pip_audit.py`

**AI Provider:**
- Purpose: Abstract interface for LLM services
- Location: `src/ai_agent/providers/base.py`
- Pattern: Strategy pattern with failover chain
- Implementations: `claude.py`, `openai.py`, `gemini.py`, `ollama.py`, `anthropic_foundry.py`
- Orchestration: `src/ai_agent/agent.py` (AIAgent class)

**Repository Context Manager:**
- Purpose: Clone and manage temporary repository access
- Location: `src/api/utils/repo_context.py`
- Pattern: Context manager with cleanup
- Features: Clone, metadata extraction, temp directory management

**Risk Scoring Engine:**
- Purpose: Calculate vulnerability risk scores
- Location: `src/api/utils/risk_scoring.py`
- Pattern: Calculation service
- Inputs: Severity, exploitability, asset criticality
- Outputs: Risk level (CRITICAL, HIGH, MEDIUM, LOW)

**Database Router:**
- Purpose: Multi-tenant database management
- Location: `src/api/database_router.py`
- Pattern: Connection routing based on organization
- Features: Dynamic database creation, organization isolation

## Entry Points

**Backend API:**
- Location: `src/api/main.py`
- Triggers: HTTP requests on port 8000
- Responsibilities: Route to domain routers, apply middleware, manage sessions

**CLI Entry:**
- Location: `src/__main__.py`
- Triggers: Command-line invocation
- Responsibilities: Argument parsing, GitHub org scanning, report generation

**Scan Scripts:**
- Location: `scan_repos.py`, `scan_gitleaks.py`, etc.
- Triggers: Manual execution or scheduled jobs
- Responsibilities: Batch repository scanning, direct database insertion

**Frontend:**
- Location: `src/web-ui/app/layout.tsx`, `src/web-ui/app/page.tsx`
- Triggers: Browser navigation
- Responsibilities: Render UI, fetch API data, manage client state

**Docker Compose:**
- Location: `docker-compose.yml`
- Triggers: `docker compose up`
- Responsibilities: Orchestrate API, Scanner, UI, PostgreSQL, MinIO containers

## Error Handling

**Strategy:** Exception bubbling with router-level catching (inconsistently implemented)

**Patterns:**
- Intended: Services throw exceptions, routers catch and return HTTP error responses
- Reality: 50+ bare `except: pass` blocks silently swallow errors (see CONCERNS.md)
- Logging: Loguru with Cribl integration - `src/api/utils/cribl_logger.py`
- HTTP errors: FastAPI HTTPException for client errors

## Cross-Cutting Concerns

**Logging:**
- Loguru with custom Cribl logger - `src/api/utils/cribl_logger.py`
- Structured logging with context objects
- HTTP event streaming to Cribl endpoint

**Validation:**
- Pydantic models for API request/response validation - `src/api/models.py`
- TypeScript type checking in frontend - `src/web-ui/tsconfig.json`
- Environment validation via Pydantic Settings - `src/api/config.py`

**Authentication:**
- Organization context in request headers
- Middleware extraction - `src/api/middleware/tenant.py`
- Database-backed organization management

**Multi-Tenancy:**
- Organization ID in all data models
- Request-scoped context filtering
- Per-tenant database isolation option - `src/api/database_router.py`

---

*Architecture analysis: 2026-01-12*
*Update when major patterns change*

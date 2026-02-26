# API-First Architecture — AuditGitHub Security Platform

**Version:** 1.0
**Date:** 2026-02-26
**Audience:** Solution Architects, Platform Engineers, Directors, Executive Leadership

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [What Is API-First Architecture?](#2-what-is-api-first-architecture)
3. [AuditGitHub Architecture Overview](#3-auditgithub-architecture-overview)
4. [The API Contract](#4-the-api-contract)
5. [Multi-Client Topology](#5-multi-client-topology)
6. [API Layer Deep Dive](#6-api-layer-deep-dive)
7. [Authentication and Authorization](#7-authentication-and-authorization)
8. [Multi-Tenant Data Isolation](#8-multi-tenant-data-isolation)
9. [Integration Patterns](#9-integration-patterns)
10. [Observability and Audit](#10-observability-and-audit)
11. [Deployment Architecture](#11-deployment-architecture)
12. [API Governance — Current State and Recommendations](#12-api-governance--current-state-and-recommendations)
13. [Appendix A — Full Endpoint Inventory](#appendix-a--full-endpoint-inventory)
14. [Appendix B — Gemini 3 Diagram Generation Prompt](#appendix-b--gemini-3-diagram-generation-prompt)

---

## 1. Executive Summary

### For Directors and Executive Leadership

**API-First architecture** is a design philosophy where every capability in a software system is exposed through a well-defined programmatic interface (API) *before* any user interface is built. The API is the product. The web dashboard, the command-line tool, the CI/CD integration, and every future client are all equal consumers of that same API.

**Why this matters to the business:**

- **Faster integration development.** When a new tool (Jira, Cribl, a SIEM, a compliance platform) needs to connect to AuditGitHub, the integration surface already exists. There is no custom backend work required — only an API client. This reduces integration timelines from weeks to days.

- **Parallel team velocity.** Frontend, backend, scanner, and AI teams can work independently against the API contract. A change to the dashboard does not require a backend deployment. A new scanner does not require a UI change. This eliminates cross-team blocking and accelerates delivery.

- **Reduced vendor lock-in.** Because every capability is accessible via standard HTTP/REST, AuditGitHub is not locked to any single UI framework, deployment model, or client technology. The Next.js frontend could be replaced with a mobile app, a Slack bot, or a Power BI dashboard — all consuming the same API.

- **Breach cost avoidance.** The API layer enforces authentication, authorization, rate limiting, and audit logging uniformly across every client. There is no "back door" through a direct database connection. Every action — whether from a human analyst, an automated scanner, or an AI agent — passes through the same security controls.

- **Engineering hour savings.** API-first eliminates the class of bugs where "the UI does X but the API does Y." There is one source of truth for business logic. Testing is centralized. Documentation is auto-generated from the contract.

### How AuditGitHub Implements API-First

AuditGitHub is a security scanning platform for GitHub organizations. Its architecture follows API-first as a core design principle:

1. **The API is the single entry point.** The FastAPI backend on port 8000 serves 80+ endpoints across 28 routers. No client — including the web dashboard — has direct database access.

2. **Six distinct clients** consume the same API: the Next.js web dashboard, a CLI tool (OAuth 2.0 Device Flow), the scanner engine, AI agents (Claude, GPT-4, Gemini, Ollama), external integrations (Jira, Cribl, GitHub), and programmatic scripts/CI pipelines.

3. **The contract is documented.** A hand-maintained OpenAPI 3.0.3 specification in `swagger/openapi.yaml` defines every endpoint, schema, and response. FastAPI also auto-generates interactive documentation at `/docs`.

4. **Security is enforced at the API layer.** JWT authentication, OIDC (Entra ID, Okta), RBAC with 5 role tiers, per-endpoint rate limiting, tenant isolation, and structured audit logging are all implemented in the API middleware stack — not in any individual client.

---

## 2. What Is API-First Architecture?

### Definition

API-First is a development methodology where APIs are designed, documented, and treated as first-class products before any implementation begins. The API contract is the source of truth.

### Contrast with Traditional Approaches

| Approach | How it works | Risk |
|----------|-------------|------|
| **UI-First** | Build the screens, then bolt on a backend | Backend becomes a grab-bag of UI-specific endpoints; hard to reuse |
| **Code-First** | Build the backend, then figure out the interface | API shape is dictated by implementation details; poor developer experience |
| **API-First** | Design the contract, then build backend and clients in parallel | Requires discipline, but produces the most maintainable and extensible system |

### Core Principles in AuditGitHub

| Principle | AuditGitHub Implementation |
|-----------|---------------------------|
| **API is the product** | Every capability — scanning, findings, AI analysis, scheduling — is an API endpoint first |
| **Contract before code** | OpenAPI 3.0.3 spec (`swagger/openapi.yaml`) with 50+ path definitions and reusable schemas |
| **Clients are equal consumers** | Web UI, CLI, scanner, AI agent all use the same endpoints with the same auth |
| **No client has privileged access** | Zero direct database connections from any client; all queries go through the API |
| **Security at the boundary** | Auth, RBAC, rate limiting, and audit enforced uniformly in the API middleware stack |

---

## 3. AuditGitHub Architecture Overview

### Textual Architecture Diagram

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                          AuditGitHub Platform                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║   CLIENTS (All equal API consumers — no direct DB access)                      ║
║   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐  ║
║   │  Web UI      │ │  CLI Tool    │ │  Scanner     │ │  AI Agents           │  ║
║   │  (Next.js)   │ │  (Python)    │ │  (Docker)    │ │  (Claude/GPT/Gemini) │  ║
║   │  :3000       │ │  Device Flow │ │  On-demand   │ │  Multi-provider      │  ║
║   └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────────┬───────────┘  ║
║          │                │                │                     │              ║
║   ┌──────┴────────┐ ┌────┴────────┐ ┌─────┴─────────┐  ┌───────┴───────┐      ║
║   │  External     │ │  CI/CD      │ │  Jira         │  │  Cribl        │      ║
║   │  Scripts      │ │  Pipelines  │ │  Integration  │  │  Stream       │      ║
║   └──────┬────────┘ └────┬────────┘ └─────┬─────────┘  └───────┬───────┘      ║
║          │               │                │                     │              ║
║  ════════╪═══════════════╪════════════════╪═════════════════════╪══════════     ║
║          │               │                │                     │              ║
║          └───────────────┴────────┬───────┴─────────────────────┘              ║
║                                   │                                            ║
║                                   ▼                                            ║
║   ╔══════════════════════════════════════════════════════════════════════╗      ║
║   ║              FastAPI Backend — The API Layer (:8000)                ║      ║
║   ╠══════════════════════════════════════════════════════════════════════╣      ║
║   ║                                                                    ║      ║
║   ║   MIDDLEWARE PIPELINE (executes top-to-bottom for every request)   ║      ║
║   ║   ┌────────────────────────────────────────────────────────────┐   ║      ║
║   ║   │  1. Request Logging    — UUID correlation, performance     │   ║      ║
║   ║   │  2. Tenant Isolation   — Schema routing (multi-tenant)     │   ║      ║
║   ║   │  3. Security Headers   — CSP, HSTS, X-Frame-Options       │   ║      ║
║   ║   │  4. Authentication     — JWT / OIDC / Session / API Key    │   ║      ║
║   ║   │  5. Session Activity   — Idle timeout tracking (Redis)     │   ║      ║
║   ║   │  6. Organization Ctx   — Multi-org context extraction      │   ║      ║
║   ║   │  7. CORS               — Cross-origin policy enforcement   │   ║      ║
║   ║   │  8. Rate Limiting      — Per-user/IP with Redis counters   │   ║      ║
║   ║   └────────────────────────────────────────────────────────────┘   ║      ║
║   ║                                                                    ║      ║
║   ║   API ROUTERS (28 modules, 80+ endpoints)                         ║      ║
║   ║   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐  ║      ║
║   ║   │ Findings    │ │ Scans       │ │ Repos       │ │ Analytics │  ║      ║
║   ║   │ Secrets     │ │ Attack Sfc  │ │ Attack Path │ │ SLA       │  ║      ║
║   ║   │ Auth        │ │ Device Flow │ │ Users       │ │ Invites   │  ║      ║
║   ║   │ AI / Chat   │ │ Orgs        │ │ Tenants     │ │ Scheduler │  ║      ║
║   ║   │ Jira        │ │ Cribl       │ │ GitHub Sync │ │ Git Sync  │  ║      ║
║   ║   │ CI/CD       │ │ Projects    │ │ Settings    │ │ Feedback  │  ║      ║
║   ║   │ API Audit   │ │ Schedules   │ │ Contributors│ │ Secrets   │  ║      ║
║   ║   └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘  ║      ║
║   ║                                                                    ║      ║
║   ║   SERVICE LAYER                                                    ║      ║
║   ║   ┌────────────────────────────────────────────────────────────┐   ║      ║
║   ║   │  CommitAnalyzer · ScheduleRecommender · ScheduleExecutor  │   ║      ║
║   ║   │  RiskScoring · ArchitecturePreprocessor · CodeExtractors  │   ║      ║
║   ║   │  Redaction · Instrumentation · TenantProvisioning         │   ║      ║
║   ║   └────────────────────────────────────────────────────────────┘   ║      ║
║   ║                                                                    ║      ║
║   ╚══════════════════════════════════════════════════════════════════════╝      ║
║                          │              │              │                        ║
║                  ┌───────┴──────┐ ┌─────┴──────┐ ┌────┴───────┐               ║
║                  │ PostgreSQL   │ │   Redis    │ │   MinIO    │               ║
║                  │ (Multi-org)  │ │ (Cache,    │ │ (Logs, S3) │               ║
║                  │ :5432        │ │  Sessions, │ │ :9009      │               ║
║                  │              │ │  Tokens)   │ │            │               ║
║                  │              │ │ :6379      │ │            │               ║
║                  └──────────────┘ └────────────┘ └────────────┘               ║
║                                                                                ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

### Key Architectural Invariants

1. **Every arrow passes through the API layer.** No client connects directly to PostgreSQL, Redis, or MinIO.
2. **The middleware pipeline is the security perimeter.** Every request — regardless of client type — traverses the same 8-layer middleware stack.
3. **Data stores are internal.** PostgreSQL, Redis, and MinIO are private services with no exposed ports in production.

---

## 4. The API Contract

### OpenAPI 3.0.3 Specification

The API contract is defined in `swagger/openapi.yaml` with a modular structure:

```
swagger/
├── openapi.yaml                 ← Root specification (version, servers, security, paths)
├── components/
│   ├── schemas.yaml             ← Reusable data models (Organization, Repository, Finding, etc.)
│   ├── responses.yaml           ← Standard error responses (400, 401, 403, 404, 500)
│   └── parameters.yaml          ← Reusable query parameters (skip, limit, org filter)
├── paths/
│   ├── organizations/           ← 10 path definitions
│   ├── repositories/            ← 4 path definitions
│   ├── findings/                ← 4 path definitions
│   ├── scans/                   ← 3 path definitions
│   ├── github/                  ← 4 path definitions
│   ├── auth/                    ← 4 path definitions
│   ├── tenants/                 ← 2 path definitions
│   ├── analytics/               ← 2 path definitions
│   ├── ai/                      ← 1 path definition
│   └── ... (15+ more domains)
└── README.md                    ← Specification maintenance guide
```

### Contract Characteristics

| Property | Value |
|----------|-------|
| Spec version | OpenAPI 3.0.3 |
| API version | 2.0.0 |
| Authentication | JWT Bearer token (global security scheme) |
| Pagination | `skip` / `limit` (default 100, max 1000) |
| Rate limiting | Per-user, exposed via `X-RateLimit-*` headers |
| Content type | `application/json` (all endpoints) |
| Server environments | `http://localhost:8000/api` (dev), `https://api.auditgh.local/api` (prod) |

### Auto-Generated Documentation

FastAPI generates interactive API documentation at runtime:

- **Swagger UI**: `http://localhost:8000/docs` — Interactive endpoint testing
- **ReDoc**: `http://localhost:8000/redoc` — Clean reference documentation
- **OpenAPI JSON**: `http://localhost:8000/openapi.json` — Machine-readable spec

---

## 5. Multi-Client Topology

AuditGitHub serves **six distinct client types**, all consuming the same API:

### Client Inventory

```
┌────────────────────────────────────────────────────────────────────┐
│                     API CLIENT TOPOLOGY                            │
├───────────────┬──────────────┬──────────────┬─────────────────────┤
│   Client      │  Auth Method │  Transport   │  Primary Endpoints  │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ Web UI        │ Session      │ fetch() +    │ /analytics/*        │
│ (Next.js)     │ (OIDC)       │ credentials  │ /findings/*         │
│ :3000         │              │ :include     │ /repositories/*     │
│               │              │              │ /settings/*         │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ CLI Tool      │ Device Flow  │ HTTP client  │ /auth/device/*      │
│ (Python)      │ (RFC 8628)   │ (requests)   │ /repositories/*     │
│               │              │              │ /scans/*            │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ Scanner       │ Internal     │ Direct DB +  │ /scans/*            │
│ (Docker)      │ (service)    │ API calls    │ /findings/*         │
│ On-demand     │              │              │ /repositories/*     │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ AI Agents     │ Internal     │ Service-to-  │ /ai/*               │
│ (Multi-LLM)   │ (service)    │ service      │ /ai/chat/*          │
│               │              │              │ /findings/*         │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ Integrations  │ JWT Bearer   │ REST/Webhook │ /jira/*             │
│ (Jira, Cribl) │              │              │ /cribl/*            │
│               │              │              │ /github/*           │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ CI/CD &       │ JWT Bearer / │ HTTP client  │ /scans/*            │
│ Scripts       │ API Key      │              │ /organizations/*    │
│               │ (planned)    │              │ /findings/*         │
└───────────────┴──────────────┴──────────────┴─────────────────────┘
```

### Frontend as Pure API Consumer

The Next.js web dashboard has **zero database connectivity**. Every piece of data displayed in the UI flows through the API:

```
Browser → Next.js (:3000) → fetch("http://localhost:8000/...") → FastAPI (:8000) → PostgreSQL
                                                                                 → Redis
                                                                                 → MinIO
```

**Evidence of decoupling:**

- `Dockerfile.ui` installs only Node.js — no database drivers
- `docker-compose.yml` web-ui service has `depends_on: api` — not `db`
- Every page component uses `fetch()` with `credentials: 'include'` against `API_BASE`
- The `useWidgetData` hook centralizes API consumption with auto-refresh and org-scoping

### CLI as Device Flow Client

The CLI (`cli/auditgh-cli.py`) authenticates using OAuth 2.0 Device Authorization Grant (RFC 8628):

```
CLI                    API                     Browser              OIDC Provider
 │                      │                        │                       │
 │ POST /auth/device/   │                        │                       │
 │      code            │                        │                       │
 │─────────────────────>│                        │                       │
 │                      │                        │                       │
 │ { device_code,       │                        │                       │
 │   user_code,         │                        │                       │
 │   verification_uri } │                        │                       │
 │<─────────────────────│                        │                       │
 │                      │                        │                       │
 │ Display: "Go to      │                        │                       │
 │ {url} and enter      │                        │                       │
 │ code {user_code}"    │                        │                       │
 │                      │                        │                       │
 │                      │  GET /auth/device/     │                       │
 │                      │      verify            │                       │
 │                      │<───────────────────────│                       │
 │                      │                        │                       │
 │                      │  Redirect to OIDC      │                       │
 │                      │───────────────────────>│──────────────────────>│
 │                      │                        │  Authenticate         │
 │                      │                        │<─────────────────────│
 │                      │  POST /auth/device/    │                       │
 │                      │       approve          │                       │
 │                      │<───────────────────────│                       │
 │                      │                        │                       │
 │ POST /auth/device/   │                        │                       │
 │      token (polling) │                        │                       │
 │─────────────────────>│                        │                       │
 │                      │                        │                       │
 │ { access_token,      │                        │                       │
 │   refresh_token }    │                        │                       │
 │<─────────────────────│                        │                       │
 │                      │                        │                       │
 │ GET /repositories    │                        │                       │
 │ Authorization:       │                        │                       │
 │   Bearer {token}     │                        │                       │
 │─────────────────────>│                        │                       │
```

---

## 6. API Layer Deep Dive

### 6.1 Middleware Pipeline

Every request traverses an 8-layer middleware stack. Middleware executes in the order listed below (first added = outermost = runs first):

```
REQUEST IN ──────────────────────────────────────────────────> RESPONSE OUT
    │                                                              ▲
    ▼                                                              │
┌──────────────────────────────────────────────────────────────────┐
│ 1. RequestLoggingMiddleware                                      │
│    • Generates UUID request_id for correlation                   │
│    • Logs REQUEST_START, REQUEST_END, REQUEST_ERROR               │
│    • Categorizes performance: FAST(<100ms), NORMAL, SLOW, CRIT   │
│    • Injects X-Request-ID response header                        │
│    • Sends structured JSON to Cribl logger                       │
├──────────────────────────────────────────────────────────────────┤
│ 2. TenantMiddleware (if MULTI_TENANT_ENABLED=true)               │
│    • Extracts tenant from: JWT claim → X-Tenant-ID → cookie      │
│    • Validates tenant is_active and is_provisioned                │
│    • Sets request.state.tenant_id for downstream                 │
│    • Exempt paths: /, /health, /docs, /tenants/*                 │
├──────────────────────────────────────────────────────────────────┤
│ 3. SecurityHeadersMiddleware                                     │
│    • Content-Security-Policy                                     │
│    • Strict-Transport-Security (production only)                 │
│    • X-Frame-Options: DENY                                       │
│    • X-Content-Type-Options: nosniff                             │
│    • Referrer-Policy: strict-origin-when-cross-origin            │
├──────────────────────────────────────────────────────────────────┤
│ 4. AuthenticationMiddleware                                      │
│    • Controlled by AUTH_REQUIRED env var                          │
│    • Public paths: /auth/*, /invite/*, /docs, /static/*          │
│    • API requests → 401 JSON with login_url                      │
│    • UI requests → Redirect to /login?next={path}                │
├──────────────────────────────────────────────────────────────────┤
│ 5. SessionActivityMiddleware                                     │
│    • Updates last_activity in Redis for idle timeout              │
│    • Absolute timeout: 8 hours                                   │
│    • Idle timeout: 30 minutes                                    │
│    • Non-blocking (logs warning on failure)                      │
├──────────────────────────────────────────────────────────────────┤
│ 6. OrganizationContextMiddleware                                 │
│    • Extracts org from: X-Organization-ID → X-Organization-Name  │
│    •   → org query param                                         │
│    • Resolves org name to UUID via DB lookup                     │
│    • Sets request.state.org_id for query scoping                 │
├──────────────────────────────────────────────────────────────────┤
│ 7. CORSMiddleware                                                │
│    • Origins: localhost:3000, :3001 + FRONTEND_URL env            │
│    • Credentials: true (cookies flow cross-origin)               │
│    • Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS             │
│    • Headers: Authorization, Content-Type, X-Organization-*      │
│    • Exposes: X-RateLimit-Limit, -Remaining, -Reset              │
├──────────────────────────────────────────────────────────────────┤
│ 8. SessionMiddleware (Starlette)                                 │
│    • Secret key: SESSION_SECRET env var                           │
│    • Max age: 3600 seconds (1 hour)                              │
│    • HTTPS-only: false (dev), true (production)                  │
└──────────────────────────────────────────────────────────────────┘
    │                                                              ▲
    ▼                                                              │
         ┌──────────────────────────────────┐
         │     Route Handler (28 routers)   │
         │     + RBAC Dependency Injection  │
         └──────────────────────────────────┘
```

### 6.2 Router Organization

28 router modules organized by domain:

| Domain | Router Files | Prefix | Endpoints |
|--------|-------------|--------|-----------|
| **Core Security** | findings, secrets, scans, attack_surface, attack_paths | `/findings`, `/secrets`, `/scans`, `/attack-surface`, `/attack-paths` | ~20 |
| **Repository Mgmt** | repositories, projects, github_sync, git_sync | `/repositories`, `/projects`, `/github`, `/git-sync` | ~15 |
| **Organization** | organizations, tenants | `/organizations`, `/tenants` | ~14 |
| **Auth & Users** | auth, device_flow, users, invitations | `/auth`, `/api/users`, `/api/invitations` | ~20 |
| **AI & Analysis** | ai, ai_chat, contributor_profiles | `/api/ai`, `/api/projects/.../ai-chat`, `/contributor-profiles` | ~10 |
| **Integrations** | jira, cribl, cicd | `/integrations/jira`, `/cribl`, `/cicd` | ~12 |
| **Operations** | analytics, sla, scheduler, schedules, settings, feedback, api_audit | `/analytics`, `/sla`, `/scheduler`, `/schedules`, `/settings`, `/feedback`, `/api-audit` | ~25 |

### 6.3 Service Layer

Business logic is encapsulated in service classes, not in route handlers:

```
Route Handler (thin)
    │
    ▼
Service Layer (business logic)
    │
    ├── CommitAnalyzer        — GitHub commit pattern extraction with 24h/7d caching
    ├── ScheduleRecommender   — AI-powered scan scheduling with heuristic fallback
    ├── ScheduleExecutor      — APScheduler integration for recurring scans
    ├── RiskScoring           — Composite 0-100 risk score (severity + exposure + age + context)
    ├── ArchitecturePreprocessor — 3-stage pipeline: extract → AI summarize → unified model
    ├── CodeExtractors        — Regex-based extraction (FastAPI, Flask, Express, Spring, Django)
    ├── Redaction             — Sensitive pattern masking (passwords, tokens, PII)
    ├── Instrumentation       — External call monitoring with performance categorization
    └── TenantProvisioning    — Schema-per-tenant database isolation
    │
    ▼
Data Access (SQLAlchemy ORM)
    │
    ▼
PostgreSQL / Redis / MinIO
```

### 6.4 Dependency Injection Pattern

FastAPI's `Depends()` system provides clean separation of concerns:

```python
@router.get("/findings", dependencies=[Depends(require_permissions("findings:read"))])
async def list_findings(
    request: Request,
    db: Session = Depends(get_db),              # Database session (tenant-aware)
    user: User = Depends(get_current_user),      # Authenticated user
    skip: int = 0,
    limit: int = 100
):
    # Route handler only contains orchestration logic
    # Auth, RBAC, DB session, and tenant scoping handled by dependencies
```

**Dependency chain:**

```
get_current_user
  ├── Check X-API-Key header      → validate_api_key()
  ├── Check Authorization: Bearer → get_current_user_from_token()
  ├── Check session cookie         → get_current_user_from_session()
  └── AUTH_DISABLED bypass         → anonymous user

get_db
  ├── MULTI_TENANT_ENABLED=true   → tenant-scoped session (SET search_path)
  └── MULTI_TENANT_ENABLED=false  → master database session

require_permissions("resource:action")
  ├── Get user's role in tenant   → UserRole table
  ├── Get role's permissions      → RolePermission table (Redis cached, 5min TTL)
  ├── Check permission match      → Wildcard support (*:*, resource:*)
  └── Audit log the decision      → AUTHORIZATION_GRANTED or AUTHORIZATION_DENIED
```

---

## 7. Authentication and Authorization

### 7.1 Authentication Methods

AuditGitHub supports four authentication methods, all resolved at the API layer:

| Method | Use Case | Token Type | Lifetime |
|--------|----------|------------|----------|
| **OIDC (Entra ID / Okta)** | Web UI login | Session cookie | 1 hour (8h absolute, 30min idle) |
| **JWT Bearer** | API clients | Access token (HS256) | 1 hour |
| **Refresh Token** | Token renewal | Refresh token (HS256) | 7 days (one-time use, Redis-tracked) |
| **Device Flow (RFC 8628)** | CLI / devices | Access + Refresh token | Same as JWT |
| **Break Glass** | Emergency access | Session cookie | 1 hour |

### 7.2 RBAC — Role-Based Access Control

Five-tier role hierarchy with 13 permissions:

```
Level 1: super_admin ──── *:* (full system access, all tenants)
Level 2: admin ────────── findings:*, scans:*, repositories:*, organizations:*, users:*, reports:read
Level 3: analyst ──────── findings:read/write, scans:read/execute, repositories:read, reports:read
Level 4: manager ──────── findings:read, scans:read, repositories:read, reports:read
Level 5: user ─────────── findings:read, repositories:read, reports:read
```

**Tenant-scoped roles:** A user can hold different roles in different organizations. The `UserRole` model enforces `UNIQUE(user_sub, tenant_id)` — one role per user per tenant.

**Permission evaluation** supports wildcards:

- `*:*` matches any permission (super_admin)
- `resource:*` matches any action on that resource
- Exact match otherwise

### 7.3 Rate Limiting

| Scope | Default | Storage |
|-------|---------|---------|
| Global (per user/IP) | 100 requests/minute | Redis |
| `/auth/login` | 5/minute | Redis |
| `/auth/register` | 3/minute | Redis |
| `/auth/refresh` | 10/minute | Redis |
| `/auth/reset-password` | 3/minute | Redis |

Rate limit status is exposed via response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.

---

## 8. Multi-Tenant Data Isolation

### Isolation Model

AuditGitHub uses **organization-scoped row filtering** with optional **schema-per-tenant isolation**:

```
Request with X-Organization-ID: {uuid}
    │
    ▼
OrganizationContextMiddleware
    │  Sets request.state.org_id
    ▼
TenantMiddleware (if multi-tenant enabled)
    │  Sets PostgreSQL search_path to tenant_{slug}
    ▼
Route Handler
    │  All queries scoped by organization_id
    ▼
PostgreSQL
    ├── public schema (shared: tenants, roles, permissions)
    └── tenant_{slug} schema (isolated: repos, findings, scans)
```

### Database Architecture

```
PostgreSQL (:5432)
├── Database: auditgh_kb
│   ├── public schema
│   │   ├── organizations          ← Tenant registry
│   │   ├── roles                  ← RBAC role definitions
│   │   ├── permissions            ← RBAC permission definitions
│   │   ├── role_permissions       ← Role-permission mappings
│   │   ├── user_roles             ← User-role-tenant assignments
│   │   └── users                  ← User accounts
│   │
│   ├── tenant_sleepnumber schema  ← Isolated per-org
│   │   ├── repositories
│   │   ├── findings
│   │   ├── scan_runs
│   │   ├── scan_schedules
│   │   └── ... (all operational tables)
│   │
│   └── tenant_sealmindset schema  ← Another org
│       ├── repositories
│       ├── findings
│       └── ...
```

---

## 9. Integration Patterns

### 9.1 Outbound Integrations (API as Client)

| Integration | Protocol | Authentication | Purpose |
|-------------|----------|----------------|---------|
| **GitHub API** | REST | PAT (per-org) | Repository metadata sync, file commits, workflow runs |
| **Jira** | REST v3 | Basic Auth (API token) | Create security tickets, sync status updates |
| **AI Providers** | REST | API keys | Claude, GPT-4, Gemini, Ollama for analysis |
| **Cribl Stream** | HTTP | Token-based | Forward structured logs for SIEM correlation |
| **MinIO (S3)** | S3 API | Access key/secret | Log storage, report archival |

### 9.2 Inbound Integrations (API as Server)

| Integration | Mechanism | Endpoint |
|-------------|-----------|----------|
| **Jira Webhooks** | POST webhook | `/integrations/jira/webhook` |
| **CI/CD Pipelines** | REST calls | `/scans/*`, `/findings/*` |
| **GitHub Actions** | REST calls | `/cicd/sync` |
| **External Scripts** | REST calls | Any endpoint with Bearer token |

### 9.3 Instrumentation Pattern

All external service calls are instrumented:

```python
@instrument_external_call(service_name="jira", operation="create_issue", endpoint=url)
async def create_jira_ticket(finding):
    # Automatically logs:
    # - EXTERNAL_CALL_START (service, operation, endpoint)
    # - EXTERNAL_CALL_END (duration_ms, perf_category)
    # - EXTERNAL_CALL_ERROR (exception details, if failed)
    # Performance categories: FAST(<200ms), NORMAL, SLOW(1-5s), CRITICAL(>5s)
```

---

## 10. Observability and Audit

### 10.1 Structured Logging

Every request generates structured JSON logs sent to Cribl Stream (with MinIO fallback):

```json
{
    "timestamp": "2026-02-26T14:30:00.000Z",
    "level": "INFO",
    "event_type": "REQUEST_END",
    "request_id": "550e8400-e29b-41d4-a716-446655440000",
    "method": "GET",
    "path": "/findings",
    "status_code": 200,
    "duration_ms": 45.2,
    "perf_category": "FAST",
    "app_context": {
        "org_id": "uuid-of-org",
        "org_name": "sleepnumber",
        "user_id": "user@sleepnumber.com",
        "session_id": "abc123"
    },
    "client_ip": "10.0.1.50",
    "user_agent": "Mozilla/5.0..."
}
```

### 10.2 Audit Trail

Three audit log types capture security-relevant events:

| Audit Log | Table | Events |
|-----------|-------|--------|
| **Auth Audit** | `auth_audit_log` | login, logout, token refresh, device approval, break-glass access |
| **Authorization Audit** | via Cribl logger | permission granted/denied, role assignment changes |
| **Data Access Audit** | via Cribl logger | resource reads, writes, deletes with user and tenant context |

### 10.3 Health Monitoring

The `/health` endpoint checks all dependencies:

```json
{
    "status": "healthy",
    "timestamp": "2026-02-26T14:30:00.000Z",
    "checks": {
        "database": "healthy",
        "redis": "healthy"
    },
    "multi_tenant": true
}
```

Docker Compose health checks poll this endpoint every 30 seconds with 3 retries.

---

## 11. Deployment Architecture

### 11.1 Local Development (Docker Compose)

```
docker-compose.yml
├── api          FastAPI           :8000   (Dockerfile.api)
├── web-ui       Next.js           :3000   (Dockerfile.ui)
├── scanner      Security tools    on-demand (Dockerfile.scanner)
├── db           PostgreSQL 15     :5432
├── redis        Redis 7           :6379
├── minio        MinIO (S3)        :9009 / :9001 (console)
├── mailhog      SMTP testing      :1025 / :8025 (web)
└── session-cleanup  Redis cleanup  periodic
```

### 11.2 Production (AWS ECS Fargate)

```
                    ┌───────────────────────────────────────────┐
                    │              AWS Cloud                     │
                    │                                           │
                    │  ┌─────────────────────────────────────┐  │
                    │  │       Application Load Balancer     │  │
                    │  │   ┌──────────┐  ┌──────────────┐   │  │
                    │  │   │ :443/api │  │ :443 (root)  │   │  │
                    │  │   └────┬─────┘  └──────┬───────┘   │  │
                    │  └────────┼────────────────┼───────────┘  │
                    │           │                │              │
                    │  ┌────────▼────────┐ ┌────▼──────────┐   │
                    │  │  ECS Service    │ │ ECS Service   │   │
                    │  │  API (Fargate)  │ │ WebUI(Fargate)│   │
                    │  │  2 tasks        │ │ 2 tasks       │   │
                    │  │  Auto-scaling   │ │ Auto-scaling  │   │
                    │  └────────┬────────┘ └───────────────┘   │
                    │           │                               │
                    │  ┌────────▼──────────────────────────┐   │
                    │  │         Private Subnets            │   │
                    │  │  ┌──────────┐  ┌──────────────┐   │   │
                    │  │  │  RDS     │  │ ElastiCache  │   │   │
                    │  │  │ Postgres │  │ Redis        │   │   │
                    │  │  │ Multi-AZ │  │ Failover     │   │   │
                    │  │  └──────────┘  └──────────────┘   │   │
                    │  │  ┌──────────┐                     │   │
                    │  │  │  S3      │                     │   │
                    │  │  │ Reports  │                     │   │
                    │  │  │ & Logs   │                     │   │
                    │  │  └──────────┘                     │   │
                    │  └───────────────────────────────────┘   │
                    │                                           │
                    │  ┌───────────────────────────────────┐   │
                    │  │  ECR Repositories                 │   │
                    │  │  ├── auditgh-api                  │   │
                    │  │  ├── auditgh-webui                │   │
                    │  │  └── auditgh-scanner              │   │
                    │  └───────────────────────────────────┘   │
                    └───────────────────────────────────────────┘
```

**Infrastructure as Code:** Terraform modules in `infrastructure/terraform/modules/` cover VPC, security groups, IAM, ECR, RDS, ElastiCache, S3, ALB, ECS cluster, and ECS services.

**CI/CD:** GitHub Actions workflow (`.github/workflows/deploy-ecs.yml`) builds all three container images, pushes to ECR, and deploys to ECS with health verification.

---

## 12. API Governance — Current State and Recommendations

### 12.1 What Exists Today

| Governance Area | Current State |
|----------------|---------------|
| **API Specification** | OpenAPI 3.0.3 in `swagger/openapi.yaml` (hand-maintained, modular) |
| **Auto-generated docs** | FastAPI `/docs` (Swagger UI) and `/redoc` at runtime |
| **Authentication** | JWT Bearer, OIDC, Device Flow, Session — enforced at middleware |
| **Authorization** | RBAC with 5 roles, 13 permissions, wildcard support, Redis-cached |
| **Rate limiting** | Per-user/IP, endpoint-specific overrides, Redis-backed |
| **Audit logging** | Structured JSON via Cribl logger, auth audit table, authorization audit |
| **Health checks** | `/health` endpoint with dependency status |
| **Error responses** | Consistent HTTPException with status codes and detail messages |
| **Pagination** | `skip`/`limit` pattern (default 100, max 1000) |
| **CORS** | Configurable origins, credentials, methods, headers |

### 12.2 Recommended Governance Additions

The following governance practices are recommended for long-term API health. A detailed gap analysis with prioritized remediation is available in [API_First_GAP.md](API_First_GAP.md).

| Practice | Recommendation | Priority |
|----------|---------------|----------|
| **API Versioning** | Adopt URL-prefix versioning (`/v1/`, `/v2/`) for breaking changes | High |
| **Deprecation Policy** | Define sunset headers, minimum notice periods (90 days), and migration guides | High |
| **Contract Testing** | Add Schemathesis or Dredd for spec-vs-implementation drift detection | High |
| **Changelog** | Maintain a per-version API changelog separate from product changelog | Medium |
| **SDK Generation** | Use OpenAPI Generator to produce typed Python/TypeScript clients | Medium |
| **API Review Process** | Require spec-level PR review before implementation for new endpoints | Medium |
| **SLA Definitions** | Define latency (p99 < 500ms), availability (99.9%), and error rate targets | Medium |
| **Breaking Change Policy** | Define what constitutes a breaking change; require version bump | High |

---

## Appendix A — Full Endpoint Inventory

### Core Security

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/findings` | Paginated findings with filters (severity, status, repo, scanner) |
| GET | `/findings/{id}` | Finding details with risk score, AI triage, remediations |
| PATCH | `/findings/{id}/status` | Update finding status |
| POST | `/findings/{id}/snooze` | Snooze finding for specified duration |
| GET | `/secrets` | Secret findings with filtering |
| GET | `/secrets/dashboard` | Secrets dashboard with active/high-risk secrets |
| POST | `/secrets/{id}/validate` | Validate if secret is still active |
| POST | `/scans` | Trigger security scan (background task) |
| GET | `/scans/{id}` | Get scan status |
| GET | `/attack-surface/*` | Summary, secrets, abandoned repos, stale contributors, high-risk repos |
| GET | `/attack-paths` | Attack path visualization for high-risk repos |

### Repository Management

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/repositories` | List repositories with pagination |
| POST | `/repositories` | Register new repository |
| GET | `/repositories/{name}` | Get repository by name |
| GET | `/projects` | List projects with summary stats |
| POST | `/github/repos/{name}/sync` | Sync repository metadata from GitHub |
| POST | `/github/sync-all` | Sync all repositories (background) |
| GET | `/github/sync-status` | Get sync status |

### Organization & Tenant

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/organizations` | List organizations |
| POST | `/organizations` | Create organization with database |
| POST | `/organizations/{id}/select` | Switch organization context |
| PATCH | `/organizations/{id}/credentials` | Update GitHub token |
| GET | `/tenants` | List tenants |
| POST | `/tenants` | Create tenant with schema isolation |
| POST | `/tenants/{slug}/provision` | Trigger database provisioning |

### Authentication & Users

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/auth/login/{provider}` | Initiate OIDC login (Entra ID / Okta) |
| POST | `/auth/break-glass/login` | Emergency local password login |
| GET | `/auth/me` | Get current user info |
| POST | `/auth/refresh` | Refresh tokens (one-time use rotation) |
| POST | `/auth/revoke` | Revoke access token |
| POST | `/auth/device/code` | Initiate device flow |
| POST | `/auth/device/token` | Poll for device token |
| GET | `/auth/device/authorizations` | List authorized devices |
| GET | `/api/users` | List users (admin) |
| POST | `/api/invitations` | Send user invitation |

### AI & Analysis

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/projects/{id}/repositories/{id}/ai-chat` | AI security conversation |
| GET | `/api/projects/{id}/repositories/{id}/ai-context` | AI context summary |

### Integrations

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/integrations/jira/webhook` | Jira status webhook |
| POST | `/cribl/forward` | Forward log entry to Cribl Stream |
| POST | `/cribl/test` | Test Cribl connectivity |
| POST | `/cicd/sync` | Sync CI/CD data from GitHub Actions |
| GET | `/cicd/stats` | Deployment and workflow statistics |

### Operations

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/analytics/*` | Hero metrics, threat radar, AI insights, trends |
| GET | `/sla/dashboard` | SLA compliance dashboard |
| GET | `/sla/mttr` | Mean Time to Remediate statistics |
| GET | `/scheduler/status` | Scheduler status and job info |
| POST | `/scheduler/jobs/{name}/trigger` | Manually trigger scheduled job |
| GET | `/schedules` | List scan schedules |
| PUT | `/schedules/{repoId}` | Update scan schedule |
| GET | `/settings` | Get system settings |
| POST | `/settings` | Save system settings |

---

## Appendix B — Gemini 3 Diagram Generation Prompt

Use the following prompt with Google Gemini 3 to generate a complete set of architecture diagrams for AuditGitHub. The prompt is designed to produce 7 diagrams that together explain the API-first architecture visually.

---

### Prompt

```
You are a technical diagram designer creating architecture documentation for AuditGitHub,
an enterprise API-first security scanning platform. Generate 7 professional diagrams
using clean, modern styling with a dark blue (#1e3a5f) and teal (#2dd4bf) color palette
on white backgrounds. Use standard UML/C4 notation where applicable.

All diagrams should include a title, a brief caption, and a legend.

=== DIAGRAM 1: System Context (C4 Level 1) ===

Show AuditGitHub as a central system box with these external actors/systems around it:

USERS:
- Security Analyst (uses Web Dashboard and CLI)
- Platform Admin (manages organizations, users, API keys)
- CI/CD Pipeline (automated scan triggers)

EXTERNAL SYSTEMS:
- GitHub (repository source, metadata, Actions workflows)
- Jira (ticket creation for findings)
- Cribl Stream (log forwarding to SIEM)
- Identity Providers (Microsoft Entra ID, Okta — OIDC authentication)
- AI Providers (Anthropic Claude, OpenAI GPT-4, Google Gemini, Ollama local)
- MinIO / S3 (log and report storage)

Draw arrows showing data flow direction with labels.
AuditGitHub should be shown as containing: "FastAPI Backend (API Layer)", with the tagline
"All clients access capabilities exclusively through REST API endpoints."

=== DIAGRAM 2: Container Diagram (C4 Level 2) ===

Show the internal containers of the AuditGitHub platform:

CONTAINERS:
1. Web UI (Next.js, port 3000) — "Pure API consumer, zero DB access"
2. FastAPI Backend (Python, port 8000) — "API layer: 28 routers, 80+ endpoints"
3. CLI Tool (Python) — "OAuth 2.0 Device Flow (RFC 8628)"
4. Scanner Engine (Docker, on-demand) — "20+ security tools"
5. PostgreSQL (port 5432) — "Multi-org with schema-per-tenant isolation"
6. Redis (port 6379) — "Sessions, RBAC cache, rate limits, token blacklist"
7. MinIO (port 9009) — "S3-compatible log and report storage"

Draw all client containers (Web UI, CLI, Scanner) connecting ONLY to the FastAPI Backend.
Draw the FastAPI Backend connecting to PostgreSQL, Redis, and MinIO.
Add a note: "No client has direct database access — the API is the single entry point."

=== DIAGRAM 3: API Request Flow Sequence Diagram ===

Show a sequence diagram for a typical authenticated API request:

PARTICIPANTS: Browser, Next.js UI, FastAPI API, Middleware Pipeline, RBAC Engine,
  Redis Cache, PostgreSQL

SEQUENCE:
1. Browser → Next.js UI: Navigate to /findings
2. Next.js UI → FastAPI API: GET /findings (credentials: include, cookie)
3. FastAPI API → Middleware Pipeline: Request enters pipeline
4. Middleware Pipeline: 1. RequestLogging (generate request_id)
5. Middleware Pipeline: 2. SecurityHeaders (CSP, HSTS)
6. Middleware Pipeline: 3. Authentication (validate session cookie)
7. Middleware Pipeline: 4. OrganizationContext (extract org_id)
8. Middleware Pipeline → RBAC Engine: Check "findings:read" permission
9. RBAC Engine → Redis Cache: Check cached permissions
10. Redis Cache → RBAC Engine: Cache hit (permissions list)
11. RBAC Engine → Middleware Pipeline: Permission granted
12. Middleware Pipeline → PostgreSQL: SELECT findings WHERE org_id = ?
13. PostgreSQL → Middleware Pipeline: Results
14. Middleware Pipeline → FastAPI API: Attach X-Request-ID, rate limit headers
15. FastAPI API → Next.js UI: 200 OK {findings: [...]}
16. Next.js UI → Browser: Render findings table

=== DIAGRAM 4: Authentication Methods Topology ===

Show a diagram with the FastAPI Backend in the center and four authentication
paths converging on it:

PATH 1 - Web UI (OIDC):
  Browser → /auth/login/entra → Entra ID (PKCE + S256) → /auth/callback → Session Cookie

PATH 2 - CLI (Device Flow):
  CLI → POST /auth/device/code → Display user_code → Browser verifies →
  CLI polls /auth/device/token → JWT access + refresh tokens

PATH 3 - API Client (Bearer Token):
  Script → Authorization: Bearer {jwt} → Token validation →
  Check blacklist (Redis) → Resolve user

PATH 4 - Emergency (Break Glass):
  Admin → POST /auth/break-glass/login → Local password (bcrypt) →
  Session cookie → Full audit logging

Show all four paths merging into a single box:
"Unified Identity → RBAC Permission Check → Route Handler"

=== DIAGRAM 5: Multi-Tenant Data Flow ===

Show how data is isolated per organization:

TOP: Three API requests arrive with different org headers:
  - Request A: X-Organization-ID: org-uuid-sleepnumber
  - Request B: X-Organization-ID: org-uuid-sealmindset
  - Request C: No organization header

MIDDLE: OrganizationContextMiddleware resolves org_id for each request

BOTTOM: PostgreSQL database with:
  - public schema (shared): organizations, roles, permissions, users
  - tenant_sleepnumber schema (isolated): repositories, findings, scans
  - tenant_sealmindset schema (isolated): repositories, findings, scans

Show Request A routed to tenant_sleepnumber, Request B to tenant_sealmindset,
Request C rejected with 400 "Missing organization context."

=== DIAGRAM 6: Middleware Pipeline (Layered) ===

Show a vertical layered diagram with 8 horizontal bands, one per middleware layer.
Each band should show:
- Layer number and name
- What it does (2-3 words)
- What it sets on request.state

Layer stack (top to bottom, matching request flow):
1. RequestLoggingMiddleware — Correlation ID, performance tracking
2. TenantMiddleware — Schema routing, tenant validation
3. SecurityHeadersMiddleware — CSP, HSTS, X-Frame-Options
4. AuthenticationMiddleware — Session/JWT/API Key validation
5. SessionActivityMiddleware — Idle timeout tracking (Redis)
6. OrganizationContextMiddleware — Org extraction from headers/params
7. CORSMiddleware — Cross-origin policy enforcement
8. SessionMiddleware — Encrypted cookie management

Show a REQUEST arrow entering at the top and a RESPONSE arrow exiting at the bottom.
Between layers, show the request.state accumulating context:
  After layer 2: request.state.tenant_id
  After layer 4: request.state.user
  After layer 6: request.state.org_id

=== DIAGRAM 7: Deployment Topology ===

Show two deployment environments side by side:

LEFT: Local Development (Docker Compose)
  - 7 containers in a single Docker network
  - api (FastAPI :8000), web-ui (Next.js :3000), scanner (on-demand)
  - db (PostgreSQL :5432), redis (:6379), minio (:9009), mailhog (:1025)
  - Show docker-compose.yml as the orchestrator

RIGHT: Production (AWS ECS Fargate)
  - VPC with public and private subnets
  - ALB in public subnet (HTTPS :443, path-based routing)
  - ECS Fargate tasks in private subnet: API (2 tasks), WebUI (2 tasks)
  - RDS PostgreSQL (Multi-AZ) in private subnet
  - ElastiCache Redis (failover) in private subnet
  - S3 buckets for reports and logs
  - ECR for container images
  - GitHub Actions CI/CD pipeline deploying to ECS

Show that in BOTH environments, the API layer is the single entry point.
No client connects directly to databases in either environment.

=== STYLE GUIDELINES ===
- Use Mermaid, PlantUML, or draw.io XML format (specify which you're using)
- Primary color: #1e3a5f (dark blue)
- Accent color: #2dd4bf (teal)
- Background: white
- Font: Inter or system sans-serif
- Line style: solid for data flow, dashed for async/optional
- Arrow labels should be concise (verb + noun, e.g., "fetch findings")
- Each diagram should be self-contained and printable on A4/letter paper
- Include a brief 1-sentence caption below each diagram title
```

---

*This document describes the architecture of AuditGitHub as of version 2.0.0. For a detailed gap analysis and remediation roadmap, see [API_First_GAP.md](API_First_GAP.md).*

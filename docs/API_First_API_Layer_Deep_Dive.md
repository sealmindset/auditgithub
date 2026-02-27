# API Layer Deep Dive

**Source:** [API_First.md](API_First.md) - Section 6

---

## 6.1 Middleware Pipeline

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

## 6.2 Router Organization

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

## 6.3 Service Layer

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

## 6.4 Dependency Injection Pattern

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

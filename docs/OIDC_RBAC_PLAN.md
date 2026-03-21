# OIDC + RBAC Implementation Plan

## Reverse-engineered from Audit GitHub Hub (AGH) repository and operational experience

---

## Section 0: First Actions (Pre-Plan Analysis)

### 0.1 CHANGELOG Auth/RBAC Entries Summary

From `docs/CHANGELOG.md`, the following entries are directly relevant:

| Entry | Implied Requirement |
|-------|-------------------|
| Multi-Org Token Support (`orchestrate_scans.py`) | Dynamic org-specific GitHub token switching; org context must propagate through auth |
| Multi-Tenant Organization Scanning | Org-scoped RBAC enforcement on scan results and repositories |
| Multi-Tenant Framework Fix | Complete overhaul of organization scoping for all data |
| API Multi-Tenant Database Routing Fix | API querying wrong database for org context; session must carry org reliably |
| Request-Scoped Organization Context | `OrganizationContextMiddleware` extracting org from headers/query params |
| Cribl Stream Log Management Integration | `user_id`, `org_id` in request-scoped context for security auditing |
| AI Credential-URL Testing Agent | Credential authentication with service-specific auth headers |

**Implied Requirements:**
- Organization context must survive across proxy boundaries (Next.js -> FastAPI)
- RBAC must enforce at the organization level, not just route level
- Audit logging must capture auth method, user identity, and org context on every request
- Token/session must carry role + org assignment, not just identity

### 0.2 Repo Conventions (from project structure)

| Convention | Constraint |
|-----------|-----------|
| Backend: FastAPI (Python 3.11+) | Use FastAPI dependency injection for auth |
| Frontend: Next.js 14+ (TypeScript) | API route proxy pattern at `app/api/proxy/[...path]/route.ts` |
| Session: Starlette SessionMiddleware + Redis | Cookie-based sessions with dual timeouts |
| Database: PostgreSQL + SQLAlchemy | Models in `src/api/models.py` |
| Container: Docker Compose | Services: api, web-ui, redis, postgres, mock-oidc |
| Testing: pytest (backend), no formal frontend tests yet | Tests should be added for auth flows |

### 0.3 Repo Auth Inventory

| Aspect | Current State | Location |
|--------|--------------|----------|
| **Identity determination** | OIDC callback -> session -> `get_current_user()` dependency chain | `src/auth/dependencies.py:256` |
| **Auth approach** | OIDC Authorization Code + PKCE (Entra, Okta, mock-oidc) + break glass + API keys | `src/auth/providers.py`, `src/api/routers/auth.py` |
| **Session management** | Starlette SessionMiddleware + Redis metadata with dual timeout (8h absolute / 30m idle) | `src/auth/session.py`, `src/auth/config.py:56-58` |
| **Authorization enforcement** | FastAPI dependencies: `require_role()`, `require_admin()`, `check_repository_access()` | `src/auth/dependencies.py:352-535` |
| **Frontend guards** | `AuthShell` component + `AuthContext` + `rbac.ts` nav permissions | `src/web-ui/components/AuthShell.tsx`, `src/web-ui/lib/rbac.ts` |
| **Role model** | 6 roles: super_admin, admin, manager, analyst, developer, user | `src/api/models.py:409+`, `src/auth/dependencies.py:561-568` |
| **Org-scoped access** | `UserOrganizationAccess` table; non-admin roles filtered to assigned orgs | `src/api/models.py:514`, `src/api/routers/organizations.py` |
| **API key auth** | SHA256 hashed keys, org-scoped, rate-limited, tool/repo scoped | `src/auth/api_key_auth.py` |
| **Configuration** | Env vars: `OIDC_*`, `ENTRA_*`, `OKTA_*`, `SESSION_SECRET`, `JWT_SECRET_KEY` | `src/auth/config.py` |

---

## A) Executive Summary

### What Will Be Built

A hardened, production-grade OIDC authentication and RBAC authorization system for Audit GitHub Hub (AGH) that:

1. **Authenticates** users via Microsoft Entra ID (primary) and Okta (secondary) using OAuth 2.0 Authorization Code + PKCE
2. **Authorizes** access through a 6-tier role hierarchy (super_admin > admin > manager > analyst > developer > user) with organization-scoped and repository-scoped access controls
3. **Provides** API key authentication for programmatic/CLI access with granular tool and repository scoping
4. **Includes** break glass emergency access, invitation-based onboarding, and device flow for headless clients
5. **Enforces** least privilege, MFA (via IdP), session security, and comprehensive audit logging

### What "Done" Means

- All browser-based access requires OIDC authentication (no anonymous access)
- All API access requires either a valid session, JWT, or scoped API key
- Role-based access is enforced at every API endpoint and UI route
- Organization isolation is enforced: non-admin users see only their assigned orgs
- Every auth event (login, logout, failure, role change, key creation) is audit-logged
- Break glass access works when IdP is unavailable, with prominent audit trail
- Session security: dual timeouts, Redis-backed, CSRF-safe
- Zero regression: existing mock-oidc dev flow, API key flow, and proxy routing all work

### Key Risks and Mitigation Themes

| Risk | Mitigation |
|------|-----------|
| **Proxy strips auth context** | Custom API route proxy preserves cookies, auth headers, and org context headers |
| **Redirect URI mismatch across envs** | `APP_URL` env var controls all redirect URIs; callback routes through frontend proxy |
| **Session cookie not forwarded** | Proxy explicitly forwards `cookie` header and `set-cookie` responses |
| **Role not in session** | User pydantic model includes `role` and `access_type` with defaults |
| **Org filtering breaks for new roles** | Graceful fallback: if no org assignments, return empty list (not 500) |
| **JWKS rotation breaks validation** | 24h cache TTL with automatic refresh on key-not-found |
| **IdP outage** | Break glass authentication for super admin emergency access |

### Dependencies and Decision Points

1. **Entra ID App Registration** - requires Azure AD admin to configure app, redirect URIs, and group claims
2. **Okta Application** - requires Okta admin to create OIDC app with correct redirect URIs
3. **Redis availability** - sessions and rate limiting depend on Redis; must be HA in production
4. **DNS and TLS** - production `APP_URL` must be set correctly for OAuth callbacks
5. **Decision: Group claims vs. DB roles** - currently using DB-stored roles (recommended to keep)

---

## B) Reverse-Engineered Requirements

### B.1 Functional Requirements

| ID | Requirement | Status | Source |
|----|------------|--------|--------|
| FR-01 | Users authenticate via OIDC (Entra ID, Okta) | Implemented | `src/auth/providers.py` |
| FR-02 | OIDC uses Authorization Code + PKCE (S256) | Implemented | `src/api/routers/auth.py:94` |
| FR-03 | Session persists via encrypted cookie + Redis metadata | Implemented | `src/auth/session.py` |
| FR-04 | Session has dual timeout: 8h absolute, 30m idle | Implemented | `src/auth/config.py:56-58` |
| FR-05 | `/auth/me` returns current user identity + role | Implemented | `src/api/routers/auth.py` |
| FR-06 | Logout clears session and redirects to login | Implemented | `src/api/routers/auth.py` |
| FR-07 | Token refresh via `/auth/refresh` with rotation | Implemented | `src/auth/tokens.py` |
| FR-08 | API key auth via `X-API-Key` header | Implemented | `src/auth/api_key_auth.py` |
| FR-09 | Device flow auth for CLI (RFC 8628) | Implemented | `src/api/routers/device_flow.py` |
| FR-10 | Break glass auth for emergency super admin access | Implemented | `src/auth/break_glass.py` |
| FR-11 | Invitation-based user onboarding with role pre-assignment | Implemented | `src/auth/invitations.py` |
| FR-12 | OIDC callback must route through frontend proxy | Implemented | `src/web-ui/app/api/proxy/[...path]/route.ts` |
| FR-13 | 303 redirect after OIDC callback must be forwarded to browser | Implemented | Proxy handles 300-399 range |

### B.2 Authorization Requirements

| ID | Requirement | Status | Source |
|----|------------|--------|--------|
| AZ-01 | 6-tier role hierarchy: super_admin > admin > manager > analyst > developer > user | Implemented | `src/auth/dependencies.py:561-568` |
| AZ-02 | Org-scoped access: non-admin roles see only assigned organizations | Implemented | `src/api/routers/organizations.py` |
| AZ-03 | Repository-scoped access: non-admin roles need explicit repo grants | Implemented | `src/api/models.py:486` |
| AZ-04 | API key scoping: tool categories, specific tools, repository IDs | Implemented | `src/api/models.py:593-601` |
| AZ-05 | Nav sidebar filters by role via `meetsMinimumRole()` | Implemented | `src/web-ui/lib/rbac.ts` |
| AZ-06 | Settings visible only to admin+; API Keys to analyst+ | Implemented | `src/web-ui/lib/rbac.ts:32-43` |
| AZ-07 | User role cannot generate API keys (403) | Implemented | `src/api/routers/api_keys.py` |
| AZ-08 | Permission matrix per role per action | Implemented | `src/auth/dependencies.py:538-571` |
| AZ-09 | Tenant list accessible to all authenticated roles (not admin-only) | Implemented | `src/api/routers/tenants.py` |

### B.3 Constraints

| Constraint | Detail |
|-----------|--------|
| Hosting | Docker Compose (dev), potentially Kubernetes (prod) |
| Proxy | Next.js API route proxy at `/api/proxy/*` replaces framework rewrites |
| CI/CD | No formal CI pipeline documented; tests via pytest |
| Libraries | authlib (OIDC), itsdangerous (session signing), pyjwt (JWT), bcrypt (break glass) |
| Runtime | Python 3.11+ (FastAPI), Node.js 20+ (Next.js 14+) |
| Multi-tenant | Single database with org-scoped rows; `OrganizationContextMiddleware` extracts org per request |

### B.4 Lessons Learned (Pitfalls That Previously Blocked Progress)

| Lesson | Root Cause | Resolution |
|--------|-----------|------------|
| **Next.js rewrite strips trailing slashes** | `:path*` capture pattern drops trailing `/`; FastAPI 307 redirects to internal Docker URL | Replaced Next.js rewrites with custom API route proxy handler |
| **`redirect_slashes=False` broke routes** | Routes defined with `@router.get("/")` on prefix `/organizations` returned 404 for `/organizations/` | Keep FastAPI defaults; proxy follows internal 307s transparently |
| **303 redirect not forwarded from OIDC callback** | Proxy only handled [301, 302, 307, 308]; OIDC callback returns 303 See Other | Extended proxy to handle all 300-399 status codes |
| **`User` model missing `role` field** | Auth `User` pydantic model only had identity fields; org filtering accessed `current_user.role` | Added `role` and `access_type` fields with defaults to `src/auth/models.py` |
| **Tenants endpoint 403 for non-admin** | `GET /tenants` required `require_admin`; `TenantContext` loads for all users | Changed to `get_current_user` (any authenticated user) |
| **`new URL()` with relative path** | `useWidgetData` hook used `new URL(API_BASE + endpoint)` where `API_BASE=/api/proxy` (relative) | Replaced with string concatenation + `URLSearchParams` |
| **Session cookie not set after login** | Proxy wasn't forwarding `Set-Cookie` headers from backend | Added explicit `set-cookie` header forwarding in proxy |
| **Org context lost across proxy** | Next.js rewrite didn't forward custom headers (`X-Organization-ID`) | Proxy explicitly forwards org context headers |

---

## C) Target Architecture

### C.1 OIDC Authentication Flow

```
Browser                    Next.js Proxy              FastAPI API              Identity Provider
  |                            |                          |                        (Entra/Okta)
  |  GET /login               |                          |                          |
  |--------------------------->|                          |                          |
  |  [Show provider buttons]  |                          |                          |
  |                            |                          |                          |
  |  Click "Login with Entra" |                          |                          |
  |--------------------------->|                          |                          |
  |  GET /api/proxy/auth/login/entra                     |                          |
  |                            |------- proxy --------->  |                          |
  |                            |                          |  Generate PKCE verifier  |
  |                            |                          |  Store state + nonce     |
  |                            |                          |  in session              |
  |                            |<------ 302 -------------|                          |
  |<--- 302 to IdP authorize --|                          |                          |
  |                            |                          |                          |
  |  Redirect to IdP -------->|                          |                          |
  |                            |                          |                     [User authenticates]
  |                            |                          |                     [MFA if configured]
  |                            |                          |                          |
  |  GET /api/proxy/auth/callback/entra?code=xxx&state=yyy                         |
  |--------------------------->|                          |                          |
  |                            |------- proxy --------->  |                          |
  |                            |                          |  Validate state          |
  |                            |                          |  Exchange code for tokens|
  |                            |                          |  Validate id_token       |
  |                            |                          |  Create/update user in DB|
  |                            |                          |  Store session (Redis)   |
  |                            |                          |  Log to auth_audit_log   |
  |                            |<------ 303 + Set-Cookie--|                          |
  |<--- 303 to / + cookie ----|                          |                          |
  |                            |                          |                          |
  |  GET / (with session cookie)                         |                          |
  |--------------------------->|                          |                          |
  |  GET /api/proxy/auth/me   |                          |                          |
  |                            |------- proxy --------->  |                          |
  |                            |                          |  Validate session        |
  |                            |                          |  Check dual timeouts     |
  |                            |<------ 200 User --------|                          |
  |<--- { email, role, ... }  |                          |                          |
```

### C.2 Token Validation Path

```
Request with Bearer JWT
  |
  v
get_current_user_from_token()
  |
  +---> Try decode as self-signed (HS256, JWT_SECRET_KEY)
  |       |
  |       +---> Check blacklist (Redis)
  |       +---> Return User if valid
  |
  +---> Try each registered OIDC provider
          |
          +---> Fetch JWKS (cached 24h)
          +---> Validate signature (RS256/384/512 only)
          +---> Validate claims: iss, aud, exp
          +---> Map claims to User model
          +---> Return User if valid
```

### C.3 RBAC Enforcement Path

```
Incoming Request
  |
  v
OrganizationContextMiddleware
  |  Extract org from: X-Organization-ID | X-Organization-Name | ?org=
  |  Store in request.state.org_id
  |
  v
get_current_user() [Dependency]
  |  Priority: API Key -> AUTH_DISABLED bypass -> Session -> JWT
  |  Returns: User(email, name, sub, provider, role, access_type)
  |
  v
Route-level Guard [Dependency]
  |  require_role("admin", "super_admin")   -- role check
  |  require_admin()                         -- admin+ shortcut
  |  check_repository_access(repo_id, action) -- repo + action check
  |
  v
Query-level Filtering
  |  Organizations: filter by UserOrganizationAccess for non-admin
  |  Repositories: filter by UserRepositoryAccess for non-admin
  |  Findings: scoped to accessible repos within accessible orgs
  |
  v
Permission Matrix Evaluation
  |  super_admin/admin: ['*']
  |  manager: ['manage_findings', 'run_scan', 'view', 'view_details']
  |  analyst: ['submit_jira', 'mark_exception', 'delete_finding', 'run_scan', 'view', 'view_details']
  |  developer: ['run_scan', 'view_details', 'view']
  |  user: ['view']
```

### C.4 Data Model (Auth-Related Tables)

```
users
  +-- id (UUID PK)
  +-- email (unique, indexed)
  +-- full_name
  +-- role (enum: super_admin|admin|manager|analyst|developer|user)
  +-- access_type (enum: ui_only|api_only|both)
  +-- oidc_subject
  +-- oidc_issuer
  +-- local_password_hash (break glass only)
  +-- is_active
  +-- last_login_at
  |
  +--< user_organization_access (user_id FK, organization_id FK, assigned_by FK)
  +--< user_repository_access (user_id FK, repository_id FK, organization_id FK)
  +--< api_keys (user_id FK, key_hash, scopes, rate_limit, expires_at)
  +--< user_invitations (email, invite_token, invited_role, status, expires_at)
  +--< auth_audit_log (user_id, event_type, auth_method, success, is_break_glass)
  +--< api_key_audit_log (api_key_id, actor_user_id, event_type)
```

---

## D) OIDC Implementation Details

### D.1 Chosen OIDC Flow

**Authorization Code + PKCE (S256)** via authlib OAuth client.

**Why:**
- PKCE prevents authorization code interception (no client_secret in browser)
- Authorization Code flow keeps tokens server-side (not exposed to browser JS)
- Compatible with both Entra ID and Okta
- Supports `email_verified` claim validation

### D.2 Configuration Matrix

| Setting | Development | Staging | Production |
|---------|------------|---------|-----------|
| **Provider** | mock-oidc | Entra ID + Okta | Entra ID + Okta |
| **Issuer** | `http://mock-oidc:10090` | Entra tenant URL | Entra tenant URL |
| **Client ID** | `auditgh-dev-client` | App registration ID | App registration ID |
| **Client Secret** | `auditgh-dev-secret` | Azure Key Vault | Azure Key Vault |
| **Redirect URI** | `http://localhost:3000/api/proxy/auth/callback/{provider}` | `https://staging.example.com/api/proxy/auth/callback/{provider}` | `https://audit.example.com/api/proxy/auth/callback/{provider}` |
| **APP_URL** | `http://localhost:3000` | `https://staging.example.com` | `https://audit.example.com` |
| **SESSION_SECRET** | Dev value (32+ chars) | Generated secret | Generated secret (Key Vault) |
| **JWT_SECRET_KEY** | Dev value (32+ chars) | Generated secret | Generated secret (Key Vault) |
| **AUTH_DISABLED** | `true` (optional) | `false` | `false` |

### D.3 Token Handling Policy

| Token | Usage | Storage | Lifetime |
|-------|-------|---------|----------|
| **ID Token** | Extract identity claims (email, name, sub) at callback only | Not stored long-term | Used once at callback |
| **Access Token** | Stored in session for potential API calls to IdP | `request.session['access_token']` | IdP-determined (typically 1h) |
| **Refresh Token** | Self-signed HS256 JWT for session extension | Redis-backed blacklist for revocation | 24h with rotation |
| **Session Cookie** | Browser authentication on every request | Encrypted cookie (itsdangerous) + Redis metadata | 8h absolute / 30m idle |
| **API Key** | Programmatic access | SHA256 hash in database | User-set expiry |

### D.4 Claim Mapping Strategy

| IdP Claim | Internal Field | Fallback |
|-----------|---------------|----------|
| `email` | `User.email` | Required (reject if missing) |
| `email_verified` | Validation gate | Must be `true` |
| `name` / `preferred_username` | `User.name` | Use email prefix |
| `sub` | `User.sub` | Required |
| `iss` | `User.provider` (mapped) | Determined from provider config |
| `groups` / `roles` | Not used (DB-managed) | N/A |

**Decision: DB-managed roles over IdP group claims.** This avoids group overage issues (Entra ID limits groups in token to 200), nested group resolution complexity, and provides a single source of truth within AGH.

### D.5 Error Handling and Recovery

| Error | Detection | Recovery |
|-------|-----------|----------|
| `invalid_state` | State param mismatch on callback | Log, redirect to `/login` with error message |
| Redirect URI mismatch | 400 from IdP | Check `APP_URL` env var matches registered redirect URI |
| Nonce replay | Nonce already consumed in session | Reject, redirect to `/login` |
| JWKS key not found | `kid` not in cached JWKS | Force JWKS refresh, retry validation once |
| Key rotation | All tokens fail validation | Automatic: JWKS cache expires in 24h; manual: restart to clear cache |
| Token expired | `exp` claim in past | Return 401, frontend redirects to `/login` |
| IdP outage | Timeout on OIDC discovery/token exchange | Break glass login for super admin; queue retry for others |

### D.6 Local Dev + Test Strategy

- **mock-oidc** container provides a fake OIDC provider with pre-configured test users
- Test users map to different roles: Mock Super Admin, Mock Admin, Mock Manager, Mock Analyst, Mock Developer, Mock User
- `AUTH_DISABLED=true` env var bypasses all auth checks (for rapid backend dev)
- Session cookie can be crafted programmatically for integration testing (base64 JSON + itsdangerous TimestampSigner)
- API keys can be generated via break glass super admin for automated testing

---

## E) RBAC Model + Mapping Strategy

### E.1 Role Definitions

| Role | Level | Purpose | Permission Set |
|------|-------|---------|---------------|
| `super_admin` | 1 | Platform owner, break glass | `['*']` — all actions on all resources |
| `admin` | 2 | Organization administrator | `['*']` — all actions within org scope |
| `manager` | 3 | Team lead, finding triage | `manage_findings`, `run_scan`, `view`, `view_details` |
| `analyst` | 4 | Security analyst, Jira integration | `submit_jira`, `mark_exception`, `delete_finding`, `run_scan`, `view`, `view_details` |
| `developer` | 5 | Repository contributor | `run_scan`, `view_details`, `view` |
| `user` | 6 | Read-only stakeholder | `view` |

### E.2 Role Assignment

Roles are **assigned in the database**, not derived from IdP group claims.

**Assignment flow:**
1. Admin/super_admin sends invitation via `POST /invitations` with `invited_role` and `invited_access_type`
2. User accepts invitation → account created with assigned role
3. Admin can update role via `PUT /users/{id}` (users router)
4. Bootstrap creates initial super_admin users on first run

**Organization assignment:**
1. Admin assigns user to org via `user_organization_access` table
2. Super_admin/admin see all orgs implicitly
3. Non-admin roles see only explicitly assigned orgs

**Repository assignment:**
1. Admin assigns user to repos via `user_repository_access` table
2. Super_admin/admin access all repos implicitly
3. Non-admin roles need explicit grants

### E.3 Edge Cases

| Edge Case | Handling |
|-----------|---------|
| Group overage (Entra >200 groups) | Not applicable: roles are DB-managed, not from IdP claims |
| Nested groups | Not applicable: no group claim dependency |
| Missing claims (no email) | Reject login with 400; log to `auth_audit_log` |
| Disabled user (`is_active=false`) | Session validation checks `is_active`; API key validation checks owner `is_active` |
| User with no org assignments | `list_organizations` returns empty list (no crash) |
| User with no repo assignments | Repository queries return empty results |
| Role change mid-session | New role takes effect on next login (session stores role at login time) |

### E.4 Admin and Change Management

| Action | Required Role | Audit |
|--------|--------------|-------|
| Create invitation | admin+ | `auth_audit_log` |
| Change user role | admin+ (cannot elevate above own role) | `auth_audit_log` |
| Assign org access | admin+ | `user_organization_access.assigned_by` |
| Create API key | analyst+ | `api_key_audit_log` |
| Revoke API key | key owner or admin+ | `api_key_audit_log` |
| Break glass login | super_admin only (hardcoded email) | `auth_audit_log` with `is_break_glass=true` |
| Deactivate user | admin+ | `auth_audit_log` |

### E.5 Enforcement Patterns

**Backend (FastAPI):**
```python
# Route-level: dependency injection
@router.get("/settings", dependencies=[Depends(require_admin)])

# Role check: flexible role list
@router.post("/scans", dependencies=[Depends(require_role("analyst", "manager", "admin", "super_admin"))])

# Resource check: per-repository + action
current_user = Depends(get_current_user)
check_repository_access(repo_id, "run_scan", current_user, db)

# Query filtering: org-scoped
if current_user.role not in ("super_admin", "admin"):
    query = query.filter(Model.org_id.in_(assigned_org_ids))
```

**Frontend (Next.js):**
```typescript
// Sidebar filtering
const visible = meetsMinimumRole(user.role, NAV_PERMISSIONS[path] ?? "user");

// Component-level guard
{meetsMinimumRole(user.role, "admin") && <AdminPanel />}

// Route redirect
if (!meetsMinimumRole(user.role, requiredRoleForPath(pathname))) {
  redirect("/");
}
```

---

## F) Pitfalls & Blockers

| # | Pitfall/Blocker | Symptom | Root Cause | Detection Signal | Preventative Design | Runbook Fix | Owner |
|---|----------------|---------|-----------|-----------------|-------------------|-------------|-------|
| 1 | **Redirect URI mismatch** | 400 error from IdP on login | `APP_URL` doesn't match registered redirect URI in IdP | IdP error page or 400 in callback | `APP_URL` env var controls all redirect URIs; validate at startup | Check `APP_URL`, update IdP app registration | Platform |
| 2 | **Callback route drift** | 404 on OIDC callback | Frontend route or proxy path changed but IdP not updated | `auth_audit_log` shows no callback events | Callback path is `APP_URL + /api/proxy/auth/callback/{provider}` — centralized | Update IdP redirect URIs | Platform |
| 3 | **Issuer/audience mismatch** | JWT validation fails silently | Different `iss` or `aud` in staging vs prod tokens | 401 errors in logs, `validate_jwt_token()` returns None | Config per environment; validate at startup | Check `ENTRA_TENANT_ID`, `OIDC_CLIENT_ID` per env | Platform |
| 4 | **JWKS cache stale after rotation** | All JWT validations fail | IdP rotated keys but cache hasn't expired | Spike in 401 errors | 24h cache TTL + force-refresh on unknown `kid` | Restart API to clear cache, or wait for TTL | Platform |
| 5 | **Clock skew / token expiry** | Intermittent 401 errors | Server clock drifts from IdP | Failures cluster around token expiry boundaries | NTP sync on all containers; `leeway` param in JWT decode | Sync clocks, check NTP | Infra |
| 6 | **ID token used as access token** | Security: token sent to wrong audience | Confusion between id_token and access_token purposes | N/A (design review) | ID token used ONLY at callback for claim extraction; never stored or sent to APIs | Code review | Dev |
| 7 | **Missing consent / wrong permission type** | Token missing expected claims | Delegated vs app-only permissions confused in Entra | Missing `email` or `groups` in token | Document exact Entra API permissions needed (User.Read for delegated) | Check Entra app permissions and admin consent | IAM Admin |
| 8 | **Inconsistent claim mapping** | User created with wrong email/name | Different IdPs use different claim names | Users with `None` email or name | Centralized claim extraction in callback handler with fallbacks | Fix claim mapping in `src/api/routers/auth.py` | Dev |
| 9 | **Multi-tenant org confusion** | User sees wrong org's data | `X-Organization-ID` header not forwarded through proxy | Data from wrong org appears | Proxy explicitly forwards all org context headers | Check proxy header forwarding list | Dev |
| 10 | **CI config divergence** | Tests pass locally, fail in CI | Missing env vars in CI environment | CI test failures on auth endpoints | Document all required env vars; mock-oidc in CI docker-compose | Add missing env vars to CI config | DevOps |
| 11 | **Local dev secrets handling** | Auth broken in dev after fresh clone | `SESSION_SECRET` or `JWT_SECRET_KEY` not set | 500 errors on any auth endpoint | `.env.example` with all required vars; docker-compose defaults | Copy `.env.example` to `.env`, set values | Dev |
| 12 | **Assignment Required not set in Entra** | Any Entra user can access AGH | App registration allows unassigned users | Unexpected users appearing in auth_audit_log | Document: "Assignment Required = Yes" in Entra enterprise app | Enable Assignment Required in Entra portal | IAM Admin |
| 13 | **Proxy strips trailing slashes** | 307 redirect to internal Docker URL | Next.js rewrite `:path*` drops trailing `/` | Browser shows `http://api:8000/...` in URL bar | Use API route proxy (not rewrites); proxy follows 307 internally | Already fixed: `src/web-ui/app/api/proxy/[...path]/route.ts` | Dev |
| 14 | **303 redirect not forwarded** | Browser stays at callback URL after login | Proxy only handled [301,302,307,308], not 303 | User stuck at `/api/proxy/auth/callback/...` | Proxy handles all 300-399 redirects | Already fixed in proxy | Dev |
| 15 | **User model missing fields** | 500 error: `'User' object has no attribute 'role'` | Auth `User` pydantic model lacked `role` and `access_type` | 500 errors when org filtering runs | User model includes all session fields with defaults | Already fixed in `src/auth/models.py` | Dev |
| 16 | **`new URL()` with relative path** | "Failed to construct 'URL': Invalid URL" | `API_BASE=/api/proxy` (relative); `new URL()` requires absolute | Console errors on all dashboard widgets | Use string concatenation, not `new URL()` for relative paths | Already fixed in `src/web-ui/hooks/useWidgetData.ts` | Dev |
| 17 | **Tenant endpoint 403 for non-admin** | "Failed to fetch tenants: Forbidden" | `GET /tenants` used `require_admin` but TenantContext loads for all | Console 403 errors for manager/analyst/user | Tenant list uses `get_current_user` (any authenticated user) | Already fixed in `src/api/routers/tenants.py` | Dev |
| 18 | **Session cookie not set** | User appears unauthenticated after login | Proxy didn't forward `Set-Cookie` from backend | `/auth/me` returns 401 right after callback | Proxy uses `getSetCookie()` to forward all Set-Cookie headers | Already fixed in proxy | Dev |

---

## G) Implementation Plan (Phased)

### Phase 1: Foundation (Complete)

**Status: IMPLEMENTED**

**Goals:** Core OIDC login, session management, basic role model

**What was delivered:**
- OIDC provider registry (Entra, Okta, mock-oidc) — `src/auth/providers.py`
- Authorization Code + PKCE flow — `src/api/routers/auth.py`
- Session middleware with Redis metadata — `src/auth/session.py`
- User model with role/access_type — `src/auth/models.py`, `src/api/models.py`
- JWT validation with JWKS caching — `src/auth/middleware.py`
- Break glass authentication — `src/auth/break_glass.py`
- Frontend AuthContext + AuthShell — `src/web-ui/contexts/AuthContext.tsx`
- Login page with dynamic provider buttons — `src/web-ui/app/login/page.tsx`

### Phase 2: Proxy & Redirect Fixes (Complete)

**Status: IMPLEMENTED**

**Goals:** Fix proxy issues that broke auth flow

**What was delivered:**
- API route proxy replacing Next.js rewrites — `src/web-ui/app/api/proxy/[...path]/route.ts`
- Trailing slash handling (follow internal 307 redirects)
- 303 redirect forwarding for OIDC callback
- Cookie and Set-Cookie forwarding
- Org context header forwarding (X-Organization-ID, X-Organization-Name)

### Phase 3: RBAC Enforcement (Complete)

**Status: IMPLEMENTED**

**Goals:** Role-based access on all endpoints and UI routes

**What was delivered:**
- `require_role()`, `require_admin()`, `require_super_admin()` dependencies
- `check_repository_access()` with action-based permission matrix
- Nav sidebar filtering via `meetsMinimumRole()` + `NAV_PERMISSIONS`
- API key creation blocked for user role
- Tenant listing accessible to all authenticated users

### Phase 4: Organization-Scoped Access (Complete)

**Status: IMPLEMENTED**

**Goals:** Non-admin roles see only assigned organizations

**What was delivered:**
- `UserOrganizationAccess` model and table
- Organization list filtering in `list_organizations()`
- Seeded test data: manager/analyst/user → example-orglabs org

### Phase 5: Hardening & Production Readiness (Planned)

**Goals:** Security hardening, audit completeness, operational readiness

**Scope:**
1. **Session security hardening**
   - Enforce `Secure` and `SameSite=Lax` on session cookie in production
   - Add CSRF token for state-changing operations
   - Implement session revocation on role/permission change
   - Files: `src/auth/config.py`, `src/api/main.py`

2. **Audit logging completeness**
   - Log all role changes, org assignments, and repo access grants
   - Add `auth_audit_log` entries for failed permission checks (not just login)
   - Structured logging with correlation IDs
   - Files: `src/auth/dependencies.py`, `src/api/routers/users.py`

3. **API key security**
   - Add API key expiry enforcement (currently stored but not always checked)
   - Add API key rotation support (create new, grace period, revoke old)
   - Rate limit response headers (X-RateLimit-Remaining, X-RateLimit-Reset)
   - Files: `src/auth/api_key_auth.py`, `src/api/routers/api_keys.py`

4. **Token security**
   - Add `jti` (JWT ID) claim to all self-signed tokens for revocation tracking
   - Implement token replay detection
   - Add audience validation for self-signed tokens
   - Files: `src/auth/tokens.py`, `src/auth/dependencies.py`

**Exit Criteria:**
- All OWASP auth top-10 mitigated
- Audit log captures every auth event type
- Session cookie secure in production

**Test Plan:**
- Unit: token generation/validation with edge cases
- Integration: session lifecycle (create, idle timeout, absolute timeout, revocation)
- Security: token tampering, replay, role escalation, CSRF

### Phase 6: Entra ID Production Integration (Planned)

**Goals:** Connect to real Entra ID tenant for production use

**Scope:**
1. **App Registration**
   - Register AGH in Azure AD with correct redirect URIs
   - Configure API permissions: `User.Read` (delegated)
   - Enable "Assignment Required" on enterprise app
   - Document admin roles needed: Application Administrator + Cloud Application Administrator

2. **Conditional Access**
   - MFA enforcement policy for AGH app
   - Location-based access restrictions (if applicable)
   - Sign-in risk policy integration

3. **PIM/JIT Guidance**
   - Document elevation procedure for admin role changes
   - Blast radius controls: time-limited admin sessions
   - Operational runbook for emergency access

4. **Group/Role Mapping**
   - Create Entra security groups: `AGH-Admins`, `AGH-Managers`, `AGH-Analysts`, `AGH-Users`
   - Document group → role mapping (but continue using DB as source of truth)
   - Optional: sync Entra groups to DB roles via background job

**Exit Criteria:**
- Users can authenticate via Entra ID in staging
- Assignment Required prevents unauthorized access
- MFA enforced for all AGH users
- Admin access documented in operational runbook

### Phase 7: Observability & Incident Response (Planned)

**Goals:** Monitoring, alerting, and incident response capabilities

**Scope:**
1. **Metrics**
   - Auth success/failure rates by provider
   - Session creation/expiry rates
   - API key usage by key and endpoint
   - Rate limit hit rates

2. **Alerts**
   - Spike in auth failures (brute force detection)
   - Break glass login (any usage)
   - Role escalation events
   - API key creation/revocation

3. **Dashboards**
   - Active sessions count
   - Auth method distribution (session vs API key vs JWT)
   - Failed auth attempts by IP/user
   - Org access patterns

4. **Incident Runbooks**
   - IdP outage → break glass procedure
   - Compromised session → revocation steps
   - Compromised API key → revocation + audit
   - Suspicious role escalation → investigation steps

---

## H) Validation & Acceptance Criteria

### H.1 Functional Validation

| Check | Method | Pass Criteria |
|-------|--------|-------------|
| OIDC login works (Entra) | Manual: click "Login with Entra" | User redirected to Entra, authenticates, returns to AGH with session |
| OIDC login works (Okta) | Manual: click "Login with Okta" | User redirected to Okta, authenticates, returns to AGH with session |
| OIDC login works (mock-oidc) | Automated: test script | Mock users authenticate and receive correct roles |
| Session persists across pages | Manual: navigate after login | No re-authentication required |
| Session expires after idle | Wait 30m+ | Redirected to login on next request |
| Session expires after absolute | Wait 8h+ | Redirected to login on next request |
| Logout clears session | Click logout | Redirected to login; `/auth/me` returns 401 |
| API key auth works | `curl -H "X-API-Key: ..."` | 200 response with correct user context |
| Break glass works when IdP down | Stop mock-oidc, use break glass form | Super admin can access platform |

### H.2 RBAC Validation

| Check | Method | Pass Criteria |
|-------|--------|-------------|
| Super admin sees all orgs | Login as super admin | All organizations listed |
| Admin sees all orgs | Login as admin | All organizations listed |
| Manager sees assigned orgs only | Login as manager | Only assigned organization(s) listed |
| User sees assigned orgs only | Login as user | Only assigned organization(s) listed |
| User cannot create API keys | POST /api-keys as user | 403 Forbidden |
| Manager can create API keys | POST /api-keys as manager | 201 Created |
| Sidebar hides Settings for user | Login as user | Settings nav group not visible |
| Sidebar shows API Keys for analyst | Login as analyst | Settings > API Keys visible |
| Sidebar shows all Settings for admin | Login as admin | Full Settings group visible |
| Role escalation blocked | User tries admin endpoint | 403 Forbidden, logged in audit |

### H.3 Security Test Cases

| Test | Technique | Expected |
|------|-----------|----------|
| Token tampering | Modify JWT payload, keep signature | 401 Unauthorized |
| Token replay | Reuse revoked refresh token | 401 Unauthorized |
| Role escalation via session | Modify session cookie role field | Session validation fails (signed cookie) |
| CSRF via cookie | Cross-origin POST with session cookie | Blocked by SameSite=Lax |
| API key brute force | Rapid key attempts | Rate limited after threshold |
| Expired token | Use token past `exp` | 401 Unauthorized |
| Wrong audience | Token for different app | 401 Unauthorized |
| Break glass password spray | Multiple wrong passwords | Account lockout after N attempts |
| SQL injection in API key | `X-API-Key: ' OR 1=1 --` | No SQL injection (parameterized queries) |
| Path traversal via proxy | `/api/proxy/../../../etc/passwd` | 404 or 403 |

### H.4 Operational Readiness

| Check | Criteria |
|-------|---------|
| Audit log populated | All login/logout/failure/role-change events present in `auth_audit_log` |
| Redis failure graceful | API returns 503 (not 500) if Redis unavailable; sessions degrade gracefully |
| Break glass documented | Runbook exists for emergency access procedure |
| Secret rotation documented | Procedure for rotating SESSION_SECRET, JWT_SECRET_KEY without downtime |
| Monitoring in place | Auth failure rate alert configured |

---

## I) Work Items / Tickets

### Epic 1: OIDC Foundation (COMPLETE)

| Story | Tasks | Size | Status | Owner |
|-------|-------|------|--------|-------|
| OIDC provider registry | Configure authlib for Entra/Okta/mock | M | Done | Dev |
| Auth Code + PKCE flow | Login/callback endpoints | L | Done | Dev |
| Session management | Starlette middleware + Redis metadata | M | Done | Dev |
| JWT validation | JWKS fetch/cache, claim validation | M | Done | Dev |
| Break glass auth | Emergency login for super admin | S | Done | Dev |
| Frontend auth context | AuthContext, AuthShell, login page | M | Done | Dev |

### Epic 2: Proxy & Routing (COMPLETE)

| Story | Tasks | Size | Status | Owner |
|-------|-------|------|--------|-------|
| API route proxy | Replace Next.js rewrites with route handler | L | Done | Dev |
| Redirect handling | Follow 307s, forward 303s | M | Done | Dev |
| Cookie forwarding | Forward Set-Cookie and cookies | S | Done | Dev |
| Org header forwarding | Forward X-Organization-ID/Name | S | Done | Dev |

### Epic 3: RBAC Enforcement (COMPLETE)

| Story | Tasks | Size | Status | Owner |
|-------|-------|------|--------|-------|
| Role dependency injection | require_role, require_admin, require_super_admin | M | Done | Dev |
| Permission matrix | Action-based permissions per role | M | Done | Dev |
| Org-scoped access | UserOrganizationAccess model + filtering | M | Done | Dev |
| Repo-scoped access | UserRepositoryAccess model + filtering | M | Done | Dev |
| Frontend nav filtering | meetsMinimumRole + NAV_PERMISSIONS | S | Done | Dev |
| API key role restriction | Block user role from creating keys | S | Done | Dev |

### Epic 4: Security Hardening (PLANNED)

| Story | Tasks | Size | Deps | Owner |
|-------|-------|------|------|-------|
| Session cookie security | Secure flag, SameSite, CSRF token | M | None | Dev |
| Audit log completeness | Log all permission checks, role changes | M | None | Dev |
| API key hardening | Expiry enforcement, rotation, rate limit headers | M | None | Dev |
| Token replay prevention | jti claim, replay detection | S | None | Dev |
| Password policies | Break glass password complexity, lockout | S | None | Security |

### Epic 5: Entra ID Production (PLANNED)

| Story | Tasks | Size | Deps | Owner |
|-------|-------|------|------|-------|
| App registration | Register in Azure AD, configure permissions | M | IAM Admin | Platform |
| Assignment Required | Enable and configure user assignment | S | App registration | IAM Admin |
| Conditional Access | MFA policy, location restrictions | M | App registration | Security |
| PIM/JIT documentation | Elevation procedures, blast radius | S | None | Security |
| Redirect URI management | Per-environment URI configuration | S | App registration | Platform |

### Epic 6: Okta Integration (PLANNED)

| Story | Tasks | Size | Deps | Owner |
|-------|-------|------|------|-------|
| Okta app creation | OIDC app in Okta with correct config | M | Okta Admin | Platform |
| Claim mapping validation | Verify Okta claims map correctly | S | Okta app | Dev |
| Testing | End-to-end Okta login flow | S | Okta app | Dev |

### Epic 7: Observability (PLANNED)

| Story | Tasks | Size | Deps | Owner |
|-------|-------|------|------|-------|
| Auth metrics | Success/failure rates, session counts | M | None | DevOps |
| Alerting | Failure spikes, break glass usage | M | Metrics | DevOps |
| Dashboard | Auth overview dashboard | M | Metrics | DevOps |
| Incident runbooks | IdP outage, session compromise, key revocation | S | None | Security |

---

## Appendix: File Reference

| Component | File Path | Key Lines |
|-----------|-----------|-----------|
| OIDC Config | `src/auth/config.py` | Full file |
| Provider Registry | `src/auth/providers.py` | Full file |
| User Pydantic Model | `src/auth/models.py` | 10-35 |
| JWT Middleware | `src/auth/middleware.py` | 87-173 |
| Auth Dependencies | `src/auth/dependencies.py` | 19-572 |
| Session Management | `src/auth/session.py` | Full file |
| Token Management | `src/auth/tokens.py` | Full file |
| API Key Auth | `src/auth/api_key_auth.py` | Full file |
| Break Glass | `src/auth/break_glass.py` | Full file |
| Invitations | `src/auth/invitations.py` | Full file |
| Bootstrap | `src/auth/bootstrap.py` | Full file |
| Auth Router | `src/api/routers/auth.py` | Full file |
| API Keys Router | `src/api/routers/api_keys.py` | Full file |
| Device Flow Router | `src/api/routers/device_flow.py` | Full file |
| DB Auth Models | `src/api/models.py` | 409-646 |
| Org Router | `src/api/routers/organizations.py` | Full file |
| Tenants Router | `src/api/routers/tenants.py` | Full file |
| API Main | `src/api/main.py` | 19-96 (org middleware) |
| Auth Context (React) | `src/web-ui/contexts/AuthContext.tsx` | Full file |
| Auth Shell (React) | `src/web-ui/components/AuthShell.tsx` | Full file |
| Login Page (React) | `src/web-ui/app/login/page.tsx` | Full file |
| RBAC Utils (React) | `src/web-ui/lib/rbac.ts` | Full file |
| Proxy Handler | `src/web-ui/app/api/proxy/[...path]/route.ts` | Full file |
| Next.js Config | `src/web-ui/next.config.ts` | Full file |

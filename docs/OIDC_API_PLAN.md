# OIDC Authentication, RBAC & API Key Implementation Plan

This plan describes how to add OIDC authentication, role-based access control (RBAC), session management, API key generation, and PostgreSQL persistence to a **FastAPI + Next.js** application running in Docker.

**Target Project:** AGH (FastAPI backend with `authlib`, Next.js frontend, PostgreSQL `security_portal` database, Redis-backed sessions)

**Approach:** Gap analysis against AGH's existing auth infrastructure. Each phase identifies what already exists vs. what needs to be built or enhanced.

**Tech Stack:** FastAPI (backend), Next.js (frontend), PostgreSQL (`security_portal`), Redis (sessions), Docker Compose, `authlib` (OIDC), Python 3.12+

**Architecture:** The FastAPI backend serves the API (`/api/*`). Authentication flows through middleware with cascading priority. The existing mock-oidc server at `../mocksvcs/mock_oidc/` provides local development IdP.

---

## Phase Overview

| Phase | Description | Approach | Dependencies |
|-------|-------------|----------|-------------|
| 1 | Mock OIDC Server Enhancement | Enhance existing `mocksvcs/mock_oidc/` | None |
| 2 | OIDC Login Flow | Gap analysis against existing `src/auth/` | Phase 1 |
| 3 | RBAC User Management | Gap analysis against existing models/invitations | Phase 2 |
| 4 | Frontend Login & Auth Gate | Gap analysis against existing frontend | Phase 2, 3 |
| 5 | Directory Integration & Pre-staging | Enhance existing `invitations.py` | Phase 3, 4 |
| 6 | Session Timeout Settings (admin-configurable) | Enhance existing `session.py` + `config.py` | Phase 3, 4 |
| 7 | API Key Management | Enhance existing `api_key_auth.py` | Phase 3 |
| 8 | PostgreSQL Persistence | Use existing `security_portal` database | Phase 3, 6, 7 |
| 9 | End-to-End Testing & Verification | Validate all capabilities | All |

---

## Phase 1: Mock OIDC Server Enhancement

**Goal:** Verify and enhance the existing mock-oidc server at `../mocksvcs/mock_oidc/` to support all required OIDC flows.

### Existing Infrastructure

The mock-oidc server already implements:
- OpenID Connect Discovery (`/.well-known/openid-configuration`)
- Authorization endpoint (`/authorize`)
- Token endpoint (`/token`)
- UserInfo endpoint (`/userinfo`)
- JWKS endpoint (`/jwks`)
- Users endpoint (`/users`)
- Logout endpoint (`/logout`)
- Health endpoint (`/health`)
- Debug endpoints

Docker Compose already references this service.

### Gap Analysis Checklist

Review the existing mock-oidc and verify/enhance:

1. **PKCE Support (S256)** -- Does the token endpoint validate `code_verifier` against `code_challenge` with S256 method? If not, add PKCE validation.

2. **Split URL Pattern** -- Does the discovery document return separate internal vs. external URLs?
   - `token_endpoint`, `userinfo_endpoint`, `jwks_uri` -> **internal** (`http://mock-oidc:10090`)
   - `authorization_endpoint` -> **external** (`http://localhost:<port>`)
   - `issuer` -> **internal**
   - If not, add `MOCK_OIDC_INTERNAL_BASE_URL` and `MOCK_OIDC_EXTERNAL_BASE_URL` environment variables.

3. **Predefined Users** -- Are there at least 5 test users with `sub`, `email`, `name`, `email_verified`, `preferred_username`? Do they include users matching `DEFAULT_SUPER_ADMIN_EMAIL` and `ADDITIONAL_SUPER_ADMIN_EMAILS`?

4. **Client Registration** -- Does it accept configurable client credentials via `MOCK_OIDC_DEFAULT_CLIENT_ID` and `MOCK_OIDC_DEFAULT_CLIENT_SECRET`?

5. **Directory Endpoint** -- Does `GET /users` return all mock users (for directory lookup in Phase 5)?

### Key Design: Split URLs

If not already implemented, the discovery document must return two different base URLs for Docker networking:

```python
# Inside Docker, server-to-server calls use internal hostname
internal_base = os.environ.get("MOCK_OIDC_INTERNAL_BASE_URL", "http://mock-oidc:10090")
# Browser redirects use external URL
external_base = os.environ.get("MOCK_OIDC_EXTERNAL_BASE_URL", "http://localhost:3007")

discovery = {
    "issuer": internal_base,
    "authorization_endpoint": f"{external_base}/authorize",  # browser redirect
    "token_endpoint": f"{internal_base}/token",              # server-to-server
    "userinfo_endpoint": f"{internal_base}/userinfo",        # server-to-server
    "jwks_uri": f"{internal_base}/jwks",                     # server-to-server
    # ...
}
```

### Verification

```bash
docker compose up -d mock-oidc
curl http://localhost:3007/.well-known/openid-configuration | jq .
curl http://localhost:3007/users | jq .
curl http://localhost:3007/health
```

Verify the discovery document has split URLs (external for `authorization_endpoint`, internal for `token_endpoint`/`userinfo_endpoint`/`jwks_uri`).

---

## Phase 2: OIDC Login Flow (Backend)

**Goal:** Verify and enhance the OIDC Authorization Code flow with PKCE in FastAPI, including session management.

### Existing Infrastructure

AGH already has:
- `src/auth/providers.py` -- Multi-provider OIDC registration (mock-oidc, Entra, Okta)
- `src/auth/config.py` -- Settings with session timeouts, JWT config, CORS
- `src/auth/session.py` -- Redis-backed sessions with cleanup service
- `src/auth/tokens.py` -- Token handling
- `src/auth/middleware.py` -- Auth middleware
- `src/auth/dependencies.py` -- FastAPI dependency injection for auth

### Gap Analysis Checklist

Review and verify each component:

#### 2.1 -- Role Enum

Does the codebase define three hierarchical roles?

```python
from enum import Enum

class AppRole(str, Enum):
    USER = "User"
    ADMIN = "Admin"
    SUPER_ADMIN = "SuperAdmin"
```

If `src/auth/models.py` has `role` or `access_type` but not this exact hierarchy, add or map to it.

#### 2.2 -- Session Data Model

Does the session store include these fields?

```python
class SessionData:
    user_email: str
    user_name: str
    user_sub: str
    provider: str
    roles: list[str]
    user_id: str | None
    created_at: float        # absolute timeout tracking
    last_activity: float     # inactivity timeout tracking
    oidc_state: str | None
    oidc_code_verifier: str | None
    oidc_provider: str | None
    return_to: str | None
```

If `created_at` and `last_activity` are missing from the session model, add them.

#### 2.3 -- OIDC Service / Provider Registration

Verify `src/auth/providers.py` handles:

1. **Discovery** -- Uses `authlib` to discover OIDC providers from discovery URL
2. **Multiple providers** -- Supports mock-oidc + Entra + Okta via env vars
3. **PKCE** -- Generates `code_verifier` and `code_challenge` (S256)
4. **Split URL awareness** -- Uses internal URL for server-to-server (token exchange, userinfo) and external URL for browser redirects

If PKCE is not implemented, add it:

```python
import hashlib, base64, secrets

def generate_pkce():
    code_verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return code_verifier, code_challenge
```

#### 2.4 -- Auth Controller / Routes

Verify these endpoints exist in the FastAPI router:

- **`GET /api/auth/providers`** -- Returns list of available OIDC providers. No auth required.
- **`GET /api/auth/login/{provider}`** -- Generates PKCE pair, stores state/verifier/provider in session, redirects to OIDC authorize URL. The `redirect_uri` must use `OIDC_EXTERNAL_BASE_URL` (browser-facing URL, not Docker internal).
- **`GET /api/auth/callback/{provider}`** -- Validates state, exchanges code for tokens, gets userInfo. Then:
  1. Looks up user in managed users by email.
  2. If found and `status != 'disabled'`: use their managed roles, call `record_login()`.
  3. If not found and `AUTH_ENABLED != 'true'` (dev mode): assign `[AppRole.USER]` default role.
  4. If not found and `AUTH_ENABLED == 'true'` (production): redirect to `/login/?error=not_invited`.
  5. If found but disabled: redirect to `/login/?error=account_disabled`.
  6. Create session with `created_at` and `last_activity` timestamps.
- **`GET /api/auth/me`** -- Returns current user info from session, or `{ "authenticated": false }`.
- **`POST /api/auth/logout`** -- Destroys session, clears cookie.

#### 2.5 -- Auth Middleware Priority Chain

Verify `src/auth/middleware.py` implements cascading auth:

```
Priority 1: Session -- check session cookie (Redis-backed)
Priority 2: API Key -- check X-API-Key or Authorization: Bearer cpln_... header (Phase 7)
Priority 3: Entra ID Header -- check X-MS-CLIENT-PRINCIPAL (Azure Container Apps)
Priority 4: Dev bypass -- if AUTH_ENABLED=false
```

For Priority 1, enforce both timeout checks:
- **Absolute timeout:** if `now - created_at > absolute_timeout_seconds` -> destroy session
- **Inactivity timeout:** if `now - last_activity > inactivity_timeout_seconds` -> destroy session
- On valid session: update `last_activity = now`

#### 2.6 -- Session Configuration

Verify `src/auth/config.py` or equivalent includes:

```python
SESSION_SECRET: str = "change-this-in-production"
SESSION_COOKIE_NAME: str = "session_id"  # or similar
SESSION_COOKIE_SECURE: bool = False       # True in production
SESSION_COOKIE_HTTPONLY: bool = True
SESSION_COOKIE_SAMESITE: str = "lax"      # not 'strict' -- OIDC redirects are cross-origin
```

### Environment Variables

Verify these are configured in `.env` and/or docker-compose:

```env
OIDC_PROVIDER_NAME=mock-oidc
OIDC_CLIENT_ID=mock-oidc-client
OIDC_CLIENT_SECRET=mock-oidc-secret
OIDC_EXTERNAL_BASE_URL=http://localhost:8001
SESSION_SECRET=change-this-in-production
AUTH_ENABLED=false
```

**Critical:** In docker-compose, `OIDC_DISCOVERY_URL` must default to the Docker-internal URL:
```yaml
OIDC_DISCOVERY_URL: ${OIDC_DISCOVERY_URL:-http://mock-oidc:10090/.well-known/openid-configuration}
```

Do NOT set `OIDC_DISCOVERY_URL=http://localhost:3007/...` in `.env` when running inside Docker -- it won't resolve.

### Verification

```bash
docker compose up -d --build
# Initiate login
curl -s -D - http://localhost:8001/api/auth/login/mock-oidc  # Should 302 to mock-oidc
# After completing flow with session cookie:
curl -s -b cookies.txt http://localhost:8001/api/auth/me  # Should return authenticated user
```

---

## Phase 3: RBAC User Management (Backend)

**Goal:** Verify and enhance the user management system where admins invite users and assign roles.

### Existing Infrastructure

AGH already has:
- `src/auth/models.py` -- User model with role/access_type
- `src/auth/invitations.py` -- Invitation system
- `src/auth/dependencies.py` -- Auth dependency injection

### Gap Analysis Checklist

#### 3.1 -- Managed User Model

Does the user model include all required fields?

```python
class ManagedUser:
    id: str               # UUID
    email: str
    display_name: str
    roles: list[AppRole]   # [User, Admin, SuperAdmin]
    status: str            # 'pending' | 'active' | 'disabled'
    invited_by: str
    invited_at: datetime
    activated_at: datetime | None
    last_login_at: datetime | None
    notes: str | None
```

If the existing model uses `role` (singular) or `access_type`, map or extend to support the `roles` list with `AppRole` enum.

#### 3.2 -- User Management Service

Verify or create a service with:

- **`seed_default_super_admins()`** -- Reads `DEFAULT_SUPER_ADMIN_EMAIL` / `DEFAULT_SUPER_ADMIN_NAME` and `ADDITIONAL_SUPER_ADMIN_EMAILS` (comma-separated `email:Display Name` pairs) from env. Creates users with `SuperAdmin` role and `active` status if they don't already exist.
- **`find_all()`**, **`find_by_id(id)`**, **`find_by_email(email)`** -- Lookups.
- **`invite(dto, inviter_email)`** -- Creates user with `status: 'pending'`.
- **`update(id, dto)`** -- Updates fields. If status changes to `'active'` and no `activated_at`, sets it.
- **`remove(id)`** -- Deletes user.
- **`record_login(email)`** -- Sets `last_login_at`, auto-activates pending users.
- **`get_roles_for_email(email)`** -- Returns roles list (used by auth middleware on every request, must be fast) or `None` if not found. Returns `[]` for disabled users.
- **`get_stats()`** -- Returns counts by status and role.
- **`can_manage_user(actor_roles, target_roles)`** -- SuperAdmin can manage anyone; Admin can only manage Users.
- **`get_assignable_roles(actor_roles)`** -- SuperAdmin returns all roles; Admin returns `[User]` only.

#### 3.3 -- User Management API Routes

Verify or create a router with admin-only access:

- **`GET /api/admin/users`** -- List all users + assignable roles for actor.
- **`GET /api/admin/users/stats`** -- User statistics.
- **`GET /api/admin/users/directory`** -- Fetch users from OIDC directory (Phase 5). Accepts `?q=search` and `?all=true` query params.
- **`POST /api/admin/users`** -- Invite user (validate email, display_name, roles non-empty; check `can_manage_user`).
- **`PUT /api/admin/users/{id}`** -- Update user (check actor can manage both existing and new roles).
- **`DELETE /api/admin/users/{id}`** -- Remove user (prevent self-deletion).
- **`POST /api/admin/users/{id}/resend`** -- Resend invitation (placeholder for email integration).

#### 3.4 -- Roles Guard / Dependency

Verify or create a FastAPI dependency for role-based access:

```python
from fastapi import Depends, HTTPException

def require_roles(*required_roles: AppRole):
    def dependency(current_user = Depends(get_current_user)):
        if not current_user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        user_roles = set(current_user.roles)
        if not any(role in user_roles for role in required_roles):
            # Also allow higher roles (SuperAdmin can access Admin endpoints)
            if AppRole.SUPER_ADMIN not in user_roles:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return dependency
```

Usage:
```python
@router.get("/api/admin/users")
async def list_users(user = Depends(require_roles(AppRole.ADMIN))):
    ...
```

In dev mode (`AUTH_ENABLED != 'true'`), bypass role checks.

### Environment Variables

```env
DEFAULT_SUPER_ADMIN_EMAIL=your.admin@company.com
DEFAULT_SUPER_ADMIN_NAME=Admin Name
ADDITIONAL_SUPER_ADMIN_EMAILS=other.admin@company.com:Other Admin
```

### Verification

```bash
# With session:
curl -s -b cookies.txt http://localhost:8001/api/admin/users | jq .
curl -s -b cookies.txt -X POST http://localhost:8001/api/admin/users \
  -H "Content-Type: application/json" \
  -d '{"email":"test@company.com","displayName":"Test User","roles":["User"]}' | jq .
```

---

## Phase 4: Frontend Login & Auth Gate

**Goal:** Verify and enhance the login page and authentication gating in the frontend.

### Gap Analysis Checklist

#### 4.1 -- Login Page

Verify or create `app/login/page.tsx` (or equivalent) that:

1. Checks if already authenticated (`GET /api/auth/me`) -- if so, redirects to `/`.
2. Fetches available providers (`GET /api/auth/providers`).
3. Displays a button for each provider. Clicking redirects to `/api/auth/login/{providerName}`.
4. Reads `?error=` query param and displays human-readable error messages:
   - `session_expired` -> "Your session has expired. Please sign in again."
   - `not_invited` -> "Your account has not been invited to this application."
   - `account_disabled` -> "Your account has been disabled."

#### 4.2 -- Main App Auth Gate

Verify or add to the main app page:

1. **State:** `authChecked`, `isAuthenticated`.
2. **On mount:** `GET /api/auth/me`. If authenticated, set `isAuthenticated = true`. If not authenticated AND providers exist, redirect to `/login/`.
3. **Periodic check:** Every 5 minutes, re-check `/api/auth/me`. If session expired, redirect to login.
4. **Loading state:** Show a spinner/skeleton until `authChecked` is true.
5. **Logout button:** In the app header, add a logout button that POSTs to `/api/auth/logout` and redirects to `/login/`.

### Verification

1. Open the app URL -- should redirect to `/login/`.
2. Click the provider button -- should redirect to mock-oidc user picker.
3. Select a user -- should redirect back to the app, authenticated.
4. Click logout -- should return to login page.

---

## Phase 5: Directory Integration & Pre-staging

**Goal:** Enhance the existing invitation system (`src/auth/invitations.py`) to support directory lookup and pre-staging of users not yet in the IdP.

### Existing Infrastructure

AGH has `src/auth/invitations.py` which handles user invitations. This phase enhances it with:
- Directory cross-referencing against the OIDC provider's user list
- Pre-staging workflow with IdP enrollment warnings

### Backend Enhancements

#### 5.1 -- Directory Fetch Capability

Add a method to the OIDC service (or providers module) that fetches all users from each provider's `/users` endpoint:

```python
async def fetch_directory_users() -> list[dict]:
    """Fetch users from each OIDC provider's directory endpoint."""
    all_users = []
    for provider_name, provider_config in self.providers.items():
        base_url = provider_config.get("base_url")  # e.g., http://mock-oidc:10090
        if base_url:
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(f"{base_url}/users")
                    if resp.status_code == 200:
                        users = resp.json()
                        for u in users:
                            u["provider"] = provider_name
                        all_users.extend(users)
            except Exception:
                pass  # provider unavailable
    return all_users
```

#### 5.2 -- Directory API Endpoint

Add to the user management router:

```python
@router.get("/api/admin/users/directory")
async def get_directory_users(
    q: str | None = None,
    all: bool = False,
    user = Depends(require_roles(AppRole.ADMIN))
):
```

- `?q=search` -- filter by name/email
- `?all=true` -- return all directory users (including already-managed ones). Default filters out already-managed users (for the invite modal).
- Returns `{ "success": true, "users": [...], "source": "oidc" | "none" }`

### Frontend Enhancements

#### 5.3 -- Invite Modal Redesign

Replace the invite modal with a tabbed interface:

- **Directory tab** (default) -- Search bar that calls `GET /api/admin/users/directory?q=...`. Shows a scrollable list of directory users. Clicking one pre-fills the invite form (email + displayName). Selected user shown as a chip.
- **Pre-stage tab** -- Manual email/name entry with a prominent **amber warning banner**:
  > "Pre-staging requires IdP enrollment. This user must be added to the Azure AD group assigned to this application before they can sign in. Use Directory mode above if the user already exists in your identity provider."
- Both tabs share the **Roles** selector and **Notes** field.

#### 5.4 -- Directory Verification in User Table

When the User Management tab loads:
1. Fetch `GET /api/admin/users/directory?all=true` to get all directory emails.
2. Store in a `Set<string>` of lowercase emails.
3. Add a "Directory" column to the users table.
4. For each user row, show:
   - Green "Verified" badge (checkmark) if their email exists in the directory set.
   - Amber "Not in IdP" badge (warning icon) if not found.

Only show the Directory column when `directoryAvailable` is true (`source === 'oidc'`).

---

## Phase 6: Session Timeout Settings

**Goal:** Allow SuperAdmins to configure session inactivity and absolute timeout via the admin UI.

### Existing Infrastructure

AGH has:
- `src/auth/config.py` -- Already has session timeout settings
- `src/auth/session.py` -- Redis-backed sessions with cleanup service

### Backend Enhancements

#### 6.1 -- App Settings Service

Create or enhance a settings service with:

- **In-memory cache** for fast reads (auth middleware calls this on every request)
- **Defaults:** `inactivity_timeout_minutes: 15`, `absolute_timeout_hours: 16`
- **Bounds:** inactivity 5-480 min, absolute 1-72 hours
- **`get_session_settings()`** -- returns from cache (must be synchronous/fast)
- **`update_session_settings(update)`** -- validates against bounds, updates cache, persists to DB (Phase 8)

```python
class SessionSettings:
    inactivity_timeout_minutes: int = 15
    absolute_timeout_hours: int = 16

BOUNDS = {
    "inactivity_timeout_minutes": {"min": 5, "max": 480},
    "absolute_timeout_hours": {"min": 1, "max": 72},
}
```

#### 6.2 -- Settings API Routes

Create a router at `/api/admin/settings` with SuperAdmin-only access:

- **`GET /api/admin/settings`** -- Returns current settings + bounds.
- **`PUT /api/admin/settings/session`** -- Updates session settings. Returns updated values.

```python
@router.get("/api/admin/settings")
async def get_settings(user = Depends(require_roles(AppRole.SUPER_ADMIN))):
    return {
        "success": True,
        "settings": settings_service.get_settings(),
        "bounds": settings_service.get_bounds(),
    }

@router.put("/api/admin/settings/session")
async def update_session_settings(
    body: SessionSettingsUpdate,
    user = Depends(require_roles(AppRole.SUPER_ADMIN))
):
    try:
        session = await settings_service.update_session_settings(body.dict(exclude_unset=True))
        return {"success": True, "session": session}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
```

#### 6.3 -- Auth Middleware Integration

The auth middleware reads timeout values dynamically from the settings service on every request:

```python
settings = app_settings_service.get_session_settings()
inactivity_ms = settings["inactivity_timeout_minutes"] * 60 * 1000
absolute_ms = settings["absolute_timeout_hours"] * 3600 * 1000

now = time.time() * 1000
if session.get("created_at") and (now - session["created_at"]) > absolute_ms:
    # Destroy session -- absolute timeout exceeded
    ...
if session.get("last_activity") and (now - session["last_activity"]) > inactivity_ms:
    # Destroy session -- inactivity timeout exceeded
    ...
# Update last_activity
session["last_activity"] = now
```

### Frontend

#### 6.4 -- Settings Sub-tab

Add a "Settings" tab to the Admin section (visible only to SuperAdmins):

- **Inactivity Timeout** -- Range slider + number input (5-480 min).
- **Maximum Session Duration** -- Range slider + number input (1-72 hours).
- **Effective Policy** summary box showing human-readable timeout descriptions.
- **Save** button with loading/success/error states.
- Fetch settings on tab load (`GET /api/admin/settings`), save via `PUT /api/admin/settings/session`.

---

## Phase 7: API Key Management

**Goal:** Enable admins to generate API keys for programmatic/CLI access to the API.

### Existing Infrastructure

AGH has `src/auth/api_key_auth.py`. Review it for the following capabilities and enhance as needed.

### Design Decisions

- **Key format:** `cpln_` prefix + 32 random hex bytes (e.g., `cpln_a846263dabbaa119...`). Customize the prefix for your app (e.g., `agh_`).
- **Storage:** Store SHA-256 hash of the key, never the plaintext. Plaintext shown only once at creation.
- **Auth headers:** Accept both `X-API-Key: cpln_...` and `Authorization: Bearer cpln_...`.
- **Roles:** Keys default to `User` role. Admins can create keys with `Admin` role. Only SuperAdmins can create `SuperAdmin` keys or create keys on behalf of other users (service accounts).
- **Expiration:** 30, 60, 90, 180, 365 days, or no expiration (0).
- **Usage tracking:** `last_used_at` timestamp and `request_count` updated on each API call.
- **Rate limiting:** Configurable `rate_limit_per_minute` per key (0 = unlimited). Stored but not enforced in initial implementation.

### Backend Enhancements

#### 7.1 -- API Key Service

Enhance or create an API key service with in-memory `dict` for keys and a hash-to-id index:

```python
import hashlib, secrets

class ApiKeyService:
    def __init__(self):
        self.keys: dict[str, ApiKey] = {}          # id -> ApiKey
        self.hash_index: dict[str, str] = {}       # sha256_hash -> id

    def generate_key(self, name, roles, owner_email, created_by, expiration_days, rate_limit=0):
        """Generate a new API key. Returns (key_record, plaintext)."""
        raw = secrets.token_hex(32)
        plaintext = f"cpln_{raw}"
        key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
        prefix = plaintext[:12]
        # ... create record, store in maps
        return key_record, plaintext  # plaintext shown ONCE

    def validate_key(self, plaintext: str) -> ApiKey | None:
        """Validate a key, update usage stats. Returns None if invalid/expired/disabled."""
        key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
        key_id = self.hash_index.get(key_hash)
        if not key_id:
            return None
        key = self.keys.get(key_id)
        if not key or not key.enabled:
            return None
        if key.expires_at and key.expires_at < datetime.utcnow():
            return None
        key.last_used_at = datetime.utcnow()
        key.request_count += 1
        return key

    def revoke(self, key_id: str) -> bool: ...
    def toggle_enabled(self, key_id: str, enabled: bool) -> ApiKey | None: ...
    def update_rate_limit(self, key_id: str, rate_limit: int) -> ApiKey | None: ...
    def find_all(self) -> list[ApiKey]: ...
    def find_by_owner(self, email: str) -> list[ApiKey]: ...
```

**Important:** Always strip `key_hash` before returning key records to the API (sanitize method).

#### 7.2 -- API Key Routes

Create a router at `/api/admin/api-keys` with Admin+ access:

- **`GET /api/admin/api-keys`** -- List keys. SuperAdmins see all; Admins see only their own.
- **`POST /api/admin/api-keys`** -- Create key. Validate role escalation (Admin can't create SuperAdmin keys). Only SuperAdmins can set `owner_email` to a different user.
- **`PUT /api/admin/api-keys/{id}/toggle`** -- Enable/disable key.
- **`PUT /api/admin/api-keys/{id}/rate-limit`** -- Update rate limit.
- **`DELETE /api/admin/api-keys/{id}`** -- Revoke key permanently.

#### 7.3 -- Auth Middleware Integration

Add API key check as Priority 2 in the auth middleware:

```python
def extract_api_key(request: Request) -> str | None:
    """Extract API key from headers."""
    x_api_key = request.headers.get("x-api-key")
    if x_api_key and x_api_key.startswith("cpln_"):
        return x_api_key
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer cpln_"):
        return auth[7:]  # strip "Bearer "
    return None

# In middleware:
api_key_plaintext = extract_api_key(request)
if api_key_plaintext:
    key_record = api_key_service.validate_key(api_key_plaintext)
    if key_record:
        request.state.user = AuthUser(
            object_id=f"apikey:{key_record.id}",
            name=f"API Key: {key_record.name}",
            email=key_record.owner_email,
            roles=key_record.roles,
        )
        return  # authenticated via API key
```

### Frontend

#### 7.4 -- API Keys Sub-tab

Add an "API Keys" tab to the Admin section (visible to Admins and SuperAdmins):

- **Key table** with columns: Name, Key (prefix only), Owner, Roles, Status (Active/Disabled/Expired), Usage (request count + last used), Expires, Actions (Disable/Enable, Revoke).
- **"Generate Key" button** -> opens a modal with:
  - Key Name (required)
  - Owner Email (SuperAdmin only, optional -- defaults to self)
  - Roles selector (User/Admin/SuperAdmin based on actor's roles)
  - Expiration dropdown (30/60/90/180/365 days or No expiration)
  - Rate Limit input (requests/minute, 0 = unlimited)
- **Key display** -- After creation, show the plaintext key ONCE with:
  - Amber warning: "Copy this key now. It will not be shown again."
  - Read-only input with click-to-select
  - Copy button with "Copied!" feedback
  - Key metadata (name, roles, expiration)
- **Usage hint** at bottom: `curl -H "X-API-Key: cpln_..." http://...`

---

## Phase 8: PostgreSQL Persistence

**Goal:** Persist all managed data to the existing `security_portal` PostgreSQL database so data survives restarts. Keep `.env` as the bootstrap fallback.

### Existing Infrastructure

AGH already uses PostgreSQL (`security_portal` database). New tables will be added to this existing database.

### Architecture

```
.env values -> used for initial seeding (super admin emails, defaults)
     |
PostgreSQL (security_portal) -> single source of truth after first write
     |
In-memory dicts -> read cache (loaded from DB on startup, updated on mutations)
```

Every service follows the same pattern:
1. On startup, load all rows from DB into in-memory cache.
2. If DB unavailable, fall back to in-memory only (graceful degradation).
3. On mutations, write to DB AND update in-memory cache.
4. On reads, always read from in-memory cache (fast, no async).

### Database Schema

Add these tables to the `security_portal` database (auto-migrate with `CREATE TABLE IF NOT EXISTS`):

```sql
CREATE TABLE IF NOT EXISTS app_settings (
  key VARCHAR(255) PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS managed_users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  display_name VARCHAR(255) NOT NULL,
  roles TEXT[] NOT NULL DEFAULT '{}',
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  invited_by VARCHAR(255),
  invited_at TIMESTAMPTZ,
  activated_at TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  notes TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
  id VARCHAR(32) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  prefix VARCHAR(20) NOT NULL,
  key_hash VARCHAR(128) NOT NULL,
  roles TEXT[] NOT NULL DEFAULT '{}',
  owner_email VARCHAR(255) NOT NULL,
  created_by VARCHAR(255) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  enabled BOOLEAN NOT NULL DEFAULT true,
  last_used_at TIMESTAMPTZ,
  request_count INTEGER NOT NULL DEFAULT 0,
  rate_limit_per_minute INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(owner_email);
```

**Note:** If AGH already has user/invitation tables, evaluate whether `managed_users` should extend the existing table or be a new one. Prefer extending existing tables to avoid data fragmentation.

### Database Service

Create or enhance a database utility for the `security_portal` connection:

```python
import asyncpg

class DatabaseService:
    def __init__(self, database_url: str):
        self.pool: asyncpg.Pool | None = None

    async def connect(self):
        self.pool = await asyncpg.create_pool(self.database_url)

    async def run_migrations(self):
        """Execute CREATE TABLE IF NOT EXISTS statements."""
        async with self.pool.acquire() as conn:
            await conn.execute(MIGRATION_SQL)

    def is_available(self) -> bool:
        return self.pool is not None

    async def fetch(self, query: str, *args) -> list[asyncpg.Record]:
        async with self.pool.acquire() as conn:
            return await conn.fetch(query, *args)

    async def fetchrow(self, query: str, *args) -> asyncpg.Record | None:
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def execute(self, query: str, *args) -> str:
        async with self.pool.acquire() as conn:
            return await conn.execute(query, *args)
```

### Service Migration Patterns

**AppSettingsService:**
- On startup: query `app_settings` WHERE key = 'session'. If found, parse JSONB and update in-memory cache.
- On update: after validation + in-memory update, UPSERT to `app_settings` with `ON CONFLICT (key) DO UPDATE`.

**UserManagementService:**
- On startup: query all from `managed_users`, populate in-memory dict. Then call `seed_default_super_admins()` (which only seeds if user doesn't already exist).
- `invite()`, `update()`, `remove()` -- write-through to DB.
- `record_login()` -- fire-and-forget DB update (don't block the request).
- `seed_super_admin()` -- INSERT with `ON CONFLICT (email) DO NOTHING` for idempotent seeding.

**ApiKeysService:**
- On startup: query all from `api_keys`, populate both `keys` dict and `hash_index` dict.
- `generate_key()` -- after in-memory insert, fire-and-forget INSERT to DB.
- `revoke()` -- after in-memory delete, fire-and-forget DELETE from DB.
- `toggle_enabled()`, `update_rate_limit()` -- after in-memory update, fire-and-forget UPDATE to DB.
- `validate_key()` -- usage stats updated in-memory immediately, flushed to DB periodically or fire-and-forget.

### Docker Compose

Ensure the app service has access to the existing `security_portal` database:
```yaml
DATABASE_URL: postgresql://${POSTGRES_USER:-postgres}:${POSTGRES_PASSWORD}@db:5432/security_portal
```

### Verification

```bash
# After startup, check tables exist:
docker compose exec db psql -U postgres -d security_portal -c '\dt'
docker compose exec db psql -U postgres -d security_portal -c 'SELECT email, roles, status FROM managed_users;'

# Create data, restart, verify it survives:
# 1. Change session settings via API
# 2. Create an API key
# 3. Invite a user
# 4. docker compose restart app
# 5. Verify all data loaded from DB in startup logs
# 6. Verify API key still authenticates
```

---

## Phase 9: End-to-End Testing & Verification

Run through these test scenarios to verify the complete system:

### 9.1 -- OIDC Login Flow
```bash
docker compose up -d --build

# Check providers
curl -s http://localhost:8001/api/auth/providers | jq .

# Full login flow (browser or curl)
# 1. GET /api/auth/login/mock-oidc -> 302 to mock-oidc
# 2. Select user on mock-oidc -> 302 to callback
# 3. Callback exchanges code -> 302 to / with session cookie
# 4. GET /api/auth/me -> authenticated user with roles
```

### 9.2 -- User Management
```bash
curl -s -b cookies.txt http://localhost:8001/api/admin/users | jq .

curl -s -b cookies.txt -X POST http://localhost:8001/api/admin/users \
  -H "Content-Type: application/json" \
  -d '{"email":"test@company.com","displayName":"Test User","roles":["User"]}' | jq .

# Directory lookup
curl -s -b cookies.txt 'http://localhost:8001/api/admin/users/directory?all=true' | jq .
```

### 9.3 -- Session Settings
```bash
curl -s -b cookies.txt http://localhost:8001/api/admin/settings | jq .

curl -s -b cookies.txt -X PUT http://localhost:8001/api/admin/settings/session \
  -H "Content-Type: application/json" \
  -d '{"inactivityTimeoutMinutes":30,"absoluteTimeoutHours":24}' | jq .

# Verify bounds validation
curl -s -b cookies.txt -X PUT http://localhost:8001/api/admin/settings/session \
  -H "Content-Type: application/json" \
  -d '{"inactivityTimeoutMinutes":1}' | jq .  # Should 400
```

### 9.4 -- API Keys
```bash
# Create a key
RESULT=$(curl -s -b cookies.txt -X POST http://localhost:8001/api/admin/api-keys \
  -H "Content-Type: application/json" \
  -d '{"name":"CLI Access","roles":["User"],"expirationDays":90}')
KEY=$(echo $RESULT | jq -r '.plaintext')

# Use the key (no session needed)
curl -s -H "X-API-Key: $KEY" http://localhost:8001/api/auth/me | jq .
curl -s -H "Authorization: Bearer $KEY" http://localhost:8001/api/auth/me | jq .

# Verify role enforcement
curl -s -H "X-API-Key: $KEY" http://localhost:8001/api/admin/settings | jq .  # Should 403

# Disable key
KEY_ID=$(echo $RESULT | jq -r '.key.id')
curl -s -b cookies.txt -X PUT "http://localhost:8001/api/admin/api-keys/$KEY_ID/toggle" \
  -H "Content-Type: application/json" -d '{"enabled":false}' | jq .

# Verify disabled key fails
curl -s -H "X-API-Key: $KEY" http://localhost:8001/api/auth/me | jq .  # Should be unauthenticated
```

### 9.5 -- Persistence Across Restarts
```bash
# 1. Create test data (settings, users, keys)
# 2. Verify in database:
docker compose exec db psql -U postgres -d security_portal -c "SELECT * FROM app_settings;"
docker compose exec db psql -U postgres -d security_portal -c "SELECT email, status FROM managed_users;"
docker compose exec db psql -U postgres -d security_portal -c "SELECT name, prefix, enabled FROM api_keys;"

# 3. Restart app:
docker compose restart app

# 4. Check startup logs:
docker compose logs app --tail 20 | grep -E "Loaded|settings|API key|users"

# 5. Verify data survived
```

---

## Common Pitfalls & Troubleshooting

### OIDC Discovery URL in Docker
The `OIDC_DISCOVERY_URL` must be the Docker-internal URL (e.g., `http://mock-oidc:10090/...`) for server-to-server communication. Browser redirects use `OIDC_EXTERNAL_BASE_URL`. Do NOT set `OIDC_DISCOVERY_URL=http://localhost:3007/...` in `.env` when running inside Docker -- it won't resolve.

### Session Cookie SameSite
Use `samesite="lax"` (not `"strict"`) -- OIDC redirects are cross-origin and strict mode will drop the cookie on the callback redirect.

### Session Cookie Secure Flag
Set `secure=False` in development. Cookies won't be sent over HTTP if `secure=True`. Only enable in production with HTTPS.

### PostgreSQL Password Mismatch
If the DB volume was created before setting a password, the existing volume won't pick up the new `POSTGRES_PASSWORD`. Either:
- `docker compose exec db psql -U postgres -c "ALTER USER postgres WITH PASSWORD 'yourpassword';"`
- Or delete the volume and recreate: `docker compose down -v && docker compose up -d`

### Redis Session Cleanup
With Redis-backed sessions, ensure the cleanup service properly handles expired sessions. The `created_at` and `last_activity` fields must be persisted in the Redis session data so timeout checks work after app restarts.

### Existing Table Conflicts
When adding `managed_users` to `security_portal`, check for existing user/invitation tables. If similar tables exist, prefer ALTER TABLE to add missing columns rather than creating duplicate tables. Run `\dt` and `\d table_name` to inspect existing schema before migration.

### Fire-and-Forget DB Writes
For non-critical writes (usage tracking, last_login_at), use fire-and-forget pattern to avoid blocking requests:

```python
import asyncio

def fire_and_forget(coro):
    """Schedule a coroutine without awaiting it."""
    loop = asyncio.get_event_loop()
    task = loop.create_task(coro)
    task.add_done_callback(lambda t: t.exception() if t.done() and not t.cancelled() else None)
```

---

## Production Checklist

When deploying to production (Azure Container Apps with Entra ID):

- [ ] Set `AUTH_ENABLED=true`
- [ ] Set real `SESSION_SECRET` (long random string)
- [ ] Configure Entra ID OIDC provider (`ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_TENANT_ID`)
- [ ] Remove mock-oidc from docker-compose (or don't start the profile)
- [ ] Set `OIDC_EXTERNAL_BASE_URL` to production URL
- [ ] Set session cookie `secure=True` (handled by production config)
- [ ] Set `DEFAULT_SUPER_ADMIN_EMAIL` to the production admin
- [ ] Ensure `DATABASE_URL` points to production PostgreSQL (`security_portal`)
- [ ] Review session timeout defaults (15 min inactivity, 16h absolute)
- [ ] Ensure Redis is configured for session storage
- [ ] Rotate API key prefix if customized (e.g., `agh_` instead of `cpln_`)

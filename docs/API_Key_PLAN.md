# API Key Management — Implementation Plan

**Version:** 1.0
**Date:** 2026-02-26
**Status:** Draft — Awaiting Approval

---

## Table of Contents

1. [Overview](#1-overview)
2. [Design Decisions](#2-design-decisions)
3. [Database Schema](#3-database-schema)
4. [Backend Implementation](#4-backend-implementation)
5. [Frontend Implementation](#5-frontend-implementation)
6. [Authentication Flow](#6-authentication-flow)
7. [Migration Plan](#7-migration-plan)
8. [Security Considerations](#8-security-considerations)
9. [Testing Plan](#9-testing-plan)
10. [File Inventory](#10-file-inventory)
11. [Phased Rollout](#11-phased-rollout)

---

## 1. Overview

### Purpose

Add API key management to AuditGitHub, enabling programmatic access to the platform with fine-grained controls over:

- **Who** — Keys tied to a person (User) or a service account
- **What tools** — Keys scoped to scanner categories and/or individual tools
- **Which repos** — Keys restricted to specific repositories or selected repos, or all repos (granted by admin only)
- **How long** — Keys with configurable expiration (including no expiration, granted by admin only) in days - 30d, 90d, 180d, 365d
- **What permissions** — Keys inherit RBAC from their owner, with optional per-key restriction (override by admin only)
- **How much** — Per-key rate limiting (requests per hour) - 1000/hr default, 100/hr minimum, 10000/hr maximum (granted by admin only)
- **What** - API keys are a new auth method, not replacing JWT/OIDC
- **Where** - API keys can be stored in the database for local development, or in the JWT for production, or in an external key management system (KMS)
- **What** - API Keys can be preconfigured profiles for expiration, permissions, rate limiting, tool scoping, but not repository scoping

### What This IS

- This is NOT replacing the existing JWT/OIDC authentication — API keys are an additional auth method
- This is NOT changing the existing RBAC system — API keys plug into it
- This is NOT a new identity provider — service accounts reuse the User model

---

## 2. Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Tool scoping | Hierarchical (category + individual tool) | Maximum flexibility; categories for simple cases, individual tools for precision |
| Service accounts | `is_service_account` flag on existing `User` model | Reuses RBAC, UserRepositoryAccess, and audit logging; avoids model duplication |
| RBAC on keys | Inherit from owner + optional per-key override | Keys inherit all owner permissions by default; can optionally restrict to a subset (never escalate) |
| Rate limiting | Per-key configurable (requests/hour) | Prevents abuse from compromised keys; defaults to 1000/hr |
| Key storage | SHA-256 hash of key; only prefix shown after creation | Key shown exactly once at creation; only `key_prefix` (first 8 chars) stored for identification |
| Key format | `agh_` prefix + 40 random hex chars (48 chars total) | Identifiable as AuditGH keys; sufficient entropy (160 bits) |
| UI location | Settings > API Keys tab | Consistent with existing Settings > Devices pattern; admins see all keys, users see their own |
| Expiration | Configurable: 30d, 90d, 180d, 365d, never | Common industry options; `expires_at = NULL` means no expiration |

---

## 3. Database Schema

### 3.1 New Table: `api_keys`

```sql
CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id          INTEGER NOT NULL UNIQUE DEFAULT nextval('api_keys_api_id_seq'),

    -- Ownership
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Key identity
    name            VARCHAR(255) NOT NULL,           -- Human-readable label
    key_hash        VARCHAR(64) NOT NULL UNIQUE,     -- SHA-256 hex digest
    key_prefix      VARCHAR(12) NOT NULL,            -- "agh_" + first 8 hex chars for display

    -- Tool scoping (hierarchical)
    -- NULL = all tools allowed; otherwise, explicit allowlist
    allowed_tool_categories JSONB DEFAULT NULL,      -- e.g. ["sast", "secrets", "dependencies"]
    allowed_tools           JSONB DEFAULT NULL,      -- e.g. ["semgrep", "trivy"] (overrides category)

    -- Repository scoping
    -- NULL = all repos the owner has access to; otherwise, explicit allowlist
    allowed_repository_ids  JSONB DEFAULT NULL,      -- e.g. ["uuid1", "uuid2"]

    -- RBAC override (optional per-key restriction)
    -- NULL = inherit all owner permissions; otherwise, restrict to these
    permission_overrides    JSONB DEFAULT NULL,      -- e.g. ["findings:read", "scans:read"]

    -- Rate limiting
    rate_limit_per_hour     INTEGER NOT NULL DEFAULT 1000,

    -- Lifecycle
    is_active       BOOLEAN NOT NULL DEFAULT true,
    expires_at      TIMESTAMP WITH TIME ZONE,        -- NULL = no expiration
    last_used_at    TIMESTAMP WITH TIME ZONE,
    last_used_ip    VARCHAR(45),                     -- IPv4 or IPv6

    -- Timestamps
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT uq_api_keys_user_name UNIQUE (user_id, organization_id, name)
);

-- Indexes
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_org_id ON api_keys(organization_id);
CREATE INDEX idx_api_keys_active ON api_keys(is_active) WHERE is_active = true;
CREATE INDEX idx_api_keys_expires ON api_keys(expires_at) WHERE expires_at IS NOT NULL;
```

### 3.2 New Table: `api_key_audit_log`

```sql
CREATE TABLE api_key_audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id          INTEGER NOT NULL UNIQUE DEFAULT nextval('api_key_audit_log_api_id_seq'),

    api_key_id      UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    actor_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,

    event_type      VARCHAR(50) NOT NULL,            -- created, revoked, rotated, used, expired, permission_denied
    event_detail    JSONB DEFAULT '{}',              -- Flexible metadata

    ip_address      VARCHAR(45),
    user_agent      VARCHAR(500),

    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_key_audit_key ON api_key_audit_log(api_key_id);
CREATE INDEX idx_api_key_audit_type ON api_key_audit_log(event_type);
CREATE INDEX idx_api_key_audit_created ON api_key_audit_log(created_at);
```

### 3.3 Modified Table: `users`

Add one column to the existing `users` table:

```sql
ALTER TABLE users ADD COLUMN is_service_account BOOLEAN NOT NULL DEFAULT false;
```

### 3.4 Tool Category Reference

The following canonical categories and tools are defined. This is stored as application constants (not a database table) for simplicity and version control.

```python
TOOL_CATEGORIES = {
    "sast": {
        "display_name": "Static Analysis (SAST)",
        "tools": ["semgrep", "bandit", "codeql"]
    },
    "secrets": {
        "display_name": "Secrets Detection",
        "tools": ["gitleaks", "trufflehog", "whispers"]
    },
    "dependencies": {
        "display_name": "Dependency Scanning",
        "tools": ["grype", "trivy", "osv"]
    },
    "iac": {
        "display_name": "Infrastructure as Code",
        "tools": ["checkov", "trivy", "terrascan"]
    },
    "containers": {
        "display_name": "Container Security",
        "tools": ["dockle", "trivy"]
    },
    "go_security": {
        "display_name": "Go Security",
        "tools": ["gosec", "govulncheck"]
    },
    "api_discovery": {
        "display_name": "API Discovery",
        "tools": ["api_scanner", "ai_api_discovery"]
    }
}
```

---

## 4. Backend Implementation

### 4.1 New Files

#### `src/api/routers/api_keys.py` — API Key CRUD Router

**Endpoints:**

| Method | Path | Auth | Permission | Description |
|--------|------|------|------------|-------------|
| `POST` | `/api/api-keys` | Session/JWT | `users:write` or own keys | Create a new API key |
| `GET` | `/api/api-keys` | Session/JWT | Varies | List keys (own keys for users; all keys for admins) |
| `GET` | `/api/api-keys/{key_id}` | Session/JWT | Owner or admin | Get key details (never returns raw key) |
| `PATCH` | `/api/api-keys/{key_id}` | Session/JWT | Owner or admin | Update name, tool scope, repo scope, permissions, rate limit |
| `DELETE` | `/api/api-keys/{key_id}` | Session/JWT | Owner or admin | Revoke (soft-delete: sets `is_active = false`) |
| `POST` | `/api/api-keys/{key_id}/rotate` | Session/JWT | Owner or admin | Revoke old key, generate new key with same config |
| `GET` | `/api/api-keys/tool-categories` | Session/JWT | Any authenticated | Returns TOOL_CATEGORIES constant for UI dropdowns |

**Pydantic Schemas:**

```python
class CreateApiKeyRequest(BaseModel):
    name: str                                      # Required, 1-255 chars
    allowed_tool_categories: list[str] | None = None
    allowed_tools: list[str] | None = None
    allowed_repository_ids: list[str] | None = None
    permission_overrides: list[str] | None = None  # Must be subset of owner's permissions
    rate_limit_per_hour: int = 1000                # 1-100000
    expires_in_days: int | None = None             # None = no expiration

class CreateApiKeyResponse(BaseModel):
    id: str
    name: str
    key: str                                       # ONLY returned on creation — never again
    key_prefix: str
    expires_at: datetime | None
    created_at: datetime

class ApiKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str                                # "agh_XXXXXXXX"
    user_id: str
    user_email: str                                # Joined from User
    is_service_account: bool                       # From User
    organization_id: str
    allowed_tool_categories: list[str] | None
    allowed_tools: list[str] | None
    allowed_repository_ids: list[str] | None
    permission_overrides: list[str] | None
    rate_limit_per_hour: int
    is_active: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    updated_at: datetime

class UpdateApiKeyRequest(BaseModel):
    name: str | None = None
    allowed_tool_categories: list[str] | None = None
    allowed_tools: list[str] | None = None
    allowed_repository_ids: list[str] | None = None
    permission_overrides: list[str] | None = None
    rate_limit_per_hour: int | None = None
    is_active: bool | None = None
```

**Key generation logic:**

```python
import secrets
import hashlib

def generate_api_key() -> tuple[str, str, str]:
    """Returns (raw_key, key_hash, key_prefix)."""
    random_part = secrets.token_hex(20)              # 40 hex chars
    raw_key = f"agh_{random_part}"                   # 44 chars total
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = f"agh_{random_part[:8]}"            # "agh_" + first 8 hex chars
    return raw_key, key_hash, key_prefix
```

**Permission validation on create/update:**

```python
async def validate_permission_overrides(
    overrides: list[str],
    owner_permissions: list[str]
) -> None:
    """Ensure overrides are a subset of the owner's actual permissions.
    Prevents privilege escalation."""
    for perm in overrides:
        if not has_permission(owner_permissions, perm):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot grant permission '{perm}' — owner does not have it"
            )
```

#### `src/auth/api_key_auth.py` — API Key Validation Middleware

This module is the core authentication handler for API key-based requests.

```python
async def validate_api_key(request: Request) -> User | None:
    """
    Extract and validate API key from X-API-Key header.
    Returns the owning User if valid, None if no API key header present.
    Raises HTTPException if key is present but invalid.

    Validation steps:
    1. Extract X-API-Key header
    2. SHA-256 hash the key
    3. Look up hash in api_keys table
    4. Check is_active, expires_at, organization_id
    5. Check rate limit (Redis counter: apikey_rate:{key_id})
    6. Update last_used_at and last_used_ip
    7. Return the owning User with effective permissions attached to request.state
    """
```

**Effective permissions resolution:**

```python
def resolve_effective_permissions(
    owner_permissions: list[str],
    key_permission_overrides: list[str] | None
) -> list[str]:
    """
    If key has permission_overrides, return intersection of
    owner_permissions and overrides. Otherwise, return owner_permissions.
    This ensures a key can NEVER escalate beyond the owner's permissions.
    """
    if key_permission_overrides is None:
        return owner_permissions
    return [p for p in key_permission_overrides if has_permission(owner_permissions, p)]
```

**Tool scope enforcement:**

```python
def is_tool_allowed(
    tool_name: str,
    key_allowed_categories: list[str] | None,
    key_allowed_tools: list[str] | None
) -> bool:
    """
    Check if a specific tool is allowed by this API key.
    Priority: allowed_tools (explicit) > allowed_tool_categories > None (all allowed).
    """
    # No restrictions = all tools allowed
    if key_allowed_categories is None and key_allowed_tools is None:
        return True
    # Explicit tool allowlist takes precedence
    if key_allowed_tools is not None and tool_name in key_allowed_tools:
        return True
    # Check category membership
    if key_allowed_categories is not None:
        for category, config in TOOL_CATEGORIES.items():
            if category in key_allowed_categories and tool_name in config["tools"]:
                return True
    # If tools list is set but tool not in it, and categories don't cover it
    return False
```

**Repository scope enforcement:**

```python
def is_repository_allowed(
    repository_id: str,
    key_allowed_repository_ids: list[str] | None
) -> bool:
    """
    Check if a specific repository is allowed by this API key.
    None = all repos the owner has access to.
    """
    if key_allowed_repository_ids is None:
        return True
    return repository_id in key_allowed_repository_ids
```

**Rate limiting (Redis):**

```python
async def check_api_key_rate_limit(key_id: str, limit: int) -> bool:
    """
    Uses Redis sliding window counter.
    Key: apikey_rate:{key_id}
    Window: 1 hour
    Returns True if within limit, False if exceeded.
    """
    redis_key = f"apikey_rate:{key_id}"
    current = redis_client.incr(redis_key)
    if current == 1:
        redis_client.expire(redis_key, 3600)  # 1 hour window
    return current <= limit
```

#### `src/api/models.py` — Model additions

Add the `ApiKey` and `ApiKeyAuditLog` SQLAlchemy models to the existing models file.

```python
class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    api_id = Column(Integer, unique=True, nullable=False,
                    server_default=Sequence('api_keys_api_id_seq'))

    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)

    name = Column(String(255), nullable=False)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    key_prefix = Column(String(12), nullable=False)

    allowed_tool_categories = Column(JSONB, nullable=True)
    allowed_tools = Column(JSONB, nullable=True)
    allowed_repository_ids = Column(JSONB, nullable=True)
    permission_overrides = Column(JSONB, nullable=True)

    rate_limit_per_hour = Column(Integer, nullable=False, default=1000)

    is_active = Column(Boolean, nullable=False, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    last_used_ip = Column(String(45), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    user = relationship("User", back_populates="api_keys")
    organization = relationship("Organization")

    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", "name", name="uq_api_keys_user_name"),
    )
```

### 4.2 Modified Files

#### `src/auth/dependencies.py` — Add API key to auth chain

Modify `get_current_user` to check for `X-API-Key` header before falling back to session/JWT:

```python
async def get_current_user(request: Request) -> User:
    """
    Authentication chain:
    1. Check X-API-Key header → validate_api_key()
    2. Check Authorization: Bearer → get_current_user_from_token()
    3. Check session cookie → get_current_user_from_session()
    4. If AUTH_DISABLED, return anonymous
    5. Raise 401
    """
```

When authenticated via API key, attach scoping metadata to `request.state`:

```python
request.state.auth_method = "api_key"
request.state.api_key_id = key.id
request.state.api_key_tool_categories = key.allowed_tool_categories
request.state.api_key_tools = key.allowed_tools
request.state.api_key_repository_ids = key.allowed_repository_ids
request.state.effective_permissions = resolve_effective_permissions(...)
```

#### `src/api/routers/scans.py` — Enforce tool scope

Before executing a scan, check if the requesting API key allows the selected tools:

```python
# In scan trigger endpoint
if request.state.auth_method == "api_key":
    for tool in requested_tools:
        if not is_tool_allowed(tool, request.state.api_key_tool_categories, request.state.api_key_tools):
            raise HTTPException(403, f"API key does not permit tool: {tool}")
```

#### `src/api/routers/repositories.py` — Enforce repo scope

Filter repository access based on API key scope:

```python
# In repository list/detail endpoints
if request.state.auth_method == "api_key" and request.state.api_key_repository_ids:
    query = query.filter(Repository.id.in_(request.state.api_key_repository_ids))
```

#### `src/api/main.py` — Register new router

```python
from .routers import api_keys
app.include_router(api_keys.router)
```

#### `src/rbac/permissions.py` — Add API key-aware permission check

When `request.state.effective_permissions` is set (API key auth), use those instead of fetching from database:

```python
async def get_user_permissions(user, tenant_id, session) -> list[str]:
    # If request has pre-resolved effective permissions (API key), use those
    if hasattr(request.state, 'effective_permissions') and request.state.effective_permissions:
        return request.state.effective_permissions
    # ... existing logic
```

### 4.3 Constants File

#### `src/api/constants/tool_categories.py`

```python
TOOL_CATEGORIES = {
    "sast": {
        "display_name": "Static Analysis (SAST)",
        "tools": ["semgrep", "bandit", "codeql"]
    },
    "secrets": {
        "display_name": "Secrets Detection",
        "tools": ["gitleaks", "trufflehog", "whispers"]
    },
    "dependencies": {
        "display_name": "Dependency Scanning",
        "tools": ["grype", "trivy", "osv"]
    },
    "iac": {
        "display_name": "Infrastructure as Code",
        "tools": ["checkov", "trivy_iac", "terrascan"]
    },
    "containers": {
        "display_name": "Container Security",
        "tools": ["dockle", "trivy_container"]
    },
    "go_security": {
        "display_name": "Go Security",
        "tools": ["gosec", "govulncheck"]
    },
    "api_discovery": {
        "display_name": "API Discovery",
        "tools": ["api_scanner", "ai_api_discovery"]
    }
}

# Flat lookup: tool_name -> category
TOOL_TO_CATEGORY = {}
for cat, config in TOOL_CATEGORIES.items():
    for tool in config["tools"]:
        TOOL_TO_CATEGORY[tool] = cat

ALL_TOOL_NAMES = list(TOOL_TO_CATEGORY.keys())
ALL_CATEGORY_NAMES = list(TOOL_CATEGORIES.keys())
```

---

## 5. Frontend Implementation

### 5.1 New Files

#### `src/web-ui/app/settings/api-keys/page.tsx` — API Keys Management Page

**Layout:** Full page under Settings, accessible via sidebar sub-link or tab.

**Sections:**

1. **Header** — Title "API Keys", description, "Generate New Key" button
2. **Active Keys Table** — DataTable with columns:
   - Name
   - Key Prefix (`agh_XXXXXXXX...`)
   - Owner (email, with service account badge if applicable)
   - Tool Scope (category badges or "All Tools")
   - Repo Scope (repo count or "All Repositories")
   - Rate Limit (requests/hr)
   - Expires (date or "Never")
   - Last Used (relative date)
   - Status (Active/Expired badge)
   - Actions (Edit, Rotate, Revoke)
3. **Revoked Keys** — Collapsible section showing inactive keys

**Component patterns** (matching existing codebase):
- `Card` / `CardHeader` / `CardContent` from shadcn
- `DataTable` from `@tanstack/react-table` (per existing `data-table.tsx`)
- `Badge` for status/scope indicators
- `Dialog` for create/edit/revoke confirmations
- `useToast` for success/error notifications
- `fetch()` with `credentials: 'include'` (per existing pattern)

#### `src/web-ui/components/api-keys/CreateApiKeyDialog.tsx`

**Dialog flow:**

1. **Step 1 — Basics**
   - Key name (Input, required)
   - Expiration (Select: 30 days, 90 days, 180 days, 1 year, No expiration)
   - Rate limit (Input number, default 1000)

2. **Step 2 — Tool Scope**
   - Radio: "All Tools" or "Restrict to specific tools"
   - If restricted: Checkbox group of categories, with expandable individual tools per category
   - Visual: Category checkboxes with indented tool checkboxes underneath

3. **Step 3 — Repository Scope**
   - Radio: "All Repositories" or "Restrict to specific repositories"
   - If restricted: Multi-select searchable list of repositories (fetched from `/repositories`)

4. **Step 4 — Permission Override (Optional)**
   - Toggle: "Use owner's full permissions" or "Restrict permissions"
   - If restricted: Checkbox group of permissions (filtered to only show the current user's permissions)

5. **Step 5 — Confirmation & Key Display**
   - Summary of configuration
   - On submit: POST to `/api/api-keys`
   - **Critical UX**: Display raw key in a highlighted box with copy-to-clipboard button
   - Warning: "This key will only be shown once. Copy it now."

#### `src/web-ui/components/api-keys/EditApiKeyDialog.tsx`

Similar to create, but pre-populated. Cannot change the key itself (only metadata/scope).

#### `src/web-ui/components/api-keys/RevokeApiKeyDialog.tsx`

Confirmation dialog with yellow warning box (matching device revocation pattern from `devices/page.tsx`).

#### `src/web-ui/components/api-keys/RotateApiKeyDialog.tsx`

Confirmation dialog explaining that the old key will be immediately invalidated and a new key generated with the same configuration. Displays new key on success.

### 5.2 Modified Files

#### `src/web-ui/components/app-sidebar.tsx` — Add navigation link

Add "API Keys" as a sub-item under the Settings/Configuration section:

```tsx
{
  title: "API Keys",
  url: "/settings/api-keys",
  icon: KeyRound,   // from lucide-react
}
```

#### `src/web-ui/app/admin/users/page.tsx` — Service account support

Add ability to create service accounts from the admin user management page:
- "Create Service Account" button alongside "Invite User"
- Service accounts get a distinct badge (e.g., `bg-gray-600` "Service Account")
- Service accounts do not require email invitations — they are created directly

---

## 6. Authentication Flow

### 6.1 API Key Authentication Sequence

```
Client                          API Server                      Redis / PostgreSQL
  │                                │                                │
  │  GET /api/findings             │                                │
  │  X-API-Key: agh_abc123...     │                                │
  │──────────────────────────────>│                                │
  │                                │                                │
  │                                │  1. SHA-256 hash the key       │
  │                                │  2. SELECT * FROM api_keys     │
  │                                │     WHERE key_hash = ?         │
  │                                │────────────────────────────────>│
  │                                │<────────────────────────────────│
  │                                │                                │
  │                                │  3. Validate:                  │
  │                                │     - is_active = true         │
  │                                │     - expires_at > NOW()       │
  │                                │     - organization_id matches  │
  │                                │                                │
  │                                │  4. Check rate limit           │
  │                                │     INCR apikey_rate:{key_id}  │
  │                                │────────────────────────────────>│
  │                                │<────────────────────────────────│
  │                                │                                │
  │                                │  5. Fetch owner User + RBAC    │
  │                                │  6. Resolve effective perms    │
  │                                │  7. Attach to request.state    │
  │                                │                                │
  │                                │  8. Update last_used_at/ip     │
  │                                │     (async, non-blocking)      │
  │                                │────────────────────────────────>│
  │                                │                                │
  │                                │  9. Execute route handler      │
  │                                │     (with tool/repo filtering) │
  │                                │                                │
  │  200 OK { findings: [...] }   │                                │
  │<──────────────────────────────│                                │
```

### 6.2 Auth Priority Chain

The `get_current_user` dependency resolves in this order:

1. **`X-API-Key` header** → `validate_api_key()` — immediate validation against DB
2. **`Authorization: Bearer` header** → `get_current_user_from_token()` — self-signed JWT or OIDC
3. **Session cookie** → `get_current_user_from_session()` — browser sessions
4. **`AUTH_DISABLED=true`** → anonymous user bypass
5. **None matched** → `401 Unauthorized`

API keys are checked first because they are the simplest/cheapest to validate (single hash lookup) and are the expected auth method for programmatic clients.

---

## 7. Migration Plan

### 7.1 Alembic Migration: `019_add_api_keys.py`

Located at `migrations/versions/019_add_api_keys.py`, following the existing numbering pattern.

**Upgrade operations:**

1. Create sequence `api_keys_api_id_seq`
2. Create sequence `api_key_audit_log_api_id_seq`
3. Create table `api_keys` (all columns and constraints from Section 3.1)
4. Create table `api_key_audit_log` (all columns from Section 3.2)
5. Add column `users.is_service_account` (Boolean, default false)
6. Create all indexes listed in Section 3.1 and 3.2

**Downgrade operations:**

1. Drop table `api_key_audit_log`
2. Drop table `api_keys`
3. Drop column `users.is_service_account`
4. Drop sequences

### 7.2 Seed Data

No seed data required. API keys are user-created. The migration is purely structural.

---

## 8. Security Considerations

### 8.1 Key Generation & Storage

- **Entropy**: `secrets.token_hex(20)` = 160 bits of entropy (cryptographically secure)
- **Storage**: Only SHA-256 hash stored in database — raw key never persisted
- **Display**: Raw key shown exactly once at creation, then only `key_prefix` visible
- **Format**: `agh_` prefix enables automated secret scanning tools (Gitleaks, TruffleHog) to detect leaked AuditGH keys with a custom pattern rule

### 8.2 Privilege Escalation Prevention

- `permission_overrides` is validated as a **subset** of the owner's current permissions at creation time AND at request time
- If the owner's permissions are later reduced, the key's effective permissions are automatically reduced (intersection is computed at request time, not stored)
- Service accounts can only be created by `admin` or `super_admin` roles

### 8.3 Key Compromise Mitigation

- **Immediate revocation**: Setting `is_active = false` takes effect on the next request (no cache delay)
- **Rate limiting**: Per-key rate limits contain blast radius of compromised keys
- **Repository scoping**: Compromised key can only access repos it was scoped to
- **Tool scoping**: Compromised key cannot trigger scans with tools beyond its scope
- **Expiration**: Keys with expiration dates auto-expire without intervention
- **Audit trail**: All key usage logged to `api_key_audit_log` and existing auth audit system
- **Rotation**: One-click rotation invalidates old key and generates new one atomically

### 8.4 Secret Scanning Integration

Add a Gitleaks rule to detect leaked AuditGH API keys:

```yaml
# semgrep-rules/auditgh-api-keys.yaml
rules:
  - id: auditgh-api-key
    description: "AuditGH API key detected"
    regex: 'agh_[0-9a-f]{40}'
    tags:
      - key
      - auditgh
    allowlist:
      regexes:
        - 'agh_[x]{8,}'   # Placeholder patterns in docs
```

### 8.5 Service Account Governance

- Service accounts are visible in the Admin > Users page with a clear badge
- Service accounts cannot log in via OIDC or break-glass — API key is their only auth method
- Service accounts require `admin` or `super_admin` to create
- All service account actions are audited identically to user actions

---

## 9. Testing Plan

### 9.1 Backend Unit Tests

**File: `tests/test_api_keys.py`**

| Test | Description |
|------|-------------|
| `test_generate_api_key_format` | Key starts with `agh_`, is 44 chars, hash is 64 hex chars |
| `test_create_api_key` | POST /api/api-keys returns key once, stores hash |
| `test_create_api_key_duplicate_name` | 409 Conflict on duplicate name per user+org |
| `test_authenticate_with_api_key` | X-API-Key header resolves to correct user |
| `test_invalid_api_key` | Unknown key returns 401 |
| `test_revoked_api_key` | Revoked key returns 401 |
| `test_expired_api_key` | Expired key returns 401 |
| `test_rate_limit_exceeded` | Returns 429 after exceeding rate limit |
| `test_tool_scope_category` | Key with `["sast"]` allows semgrep, blocks trufflehog |
| `test_tool_scope_individual` | Key with `["trivy"]` allows trivy, blocks grype |
| `test_tool_scope_hierarchical` | Individual tool overrides category |
| `test_repo_scope_allowed` | Key with repo IDs can access those repos |
| `test_repo_scope_denied` | Key without repo ID cannot access that repo |
| `test_permission_override_subset` | Override must be subset of owner permissions |
| `test_permission_escalation_blocked` | Cannot set overrides beyond owner's permissions |
| `test_permission_inheritance` | No overrides = full owner permissions |
| `test_owner_permission_reduced` | If owner loses permission, key loses it too (runtime check) |
| `test_rotate_key` | Old key stops working, new key works, same config |
| `test_list_keys_user_sees_own` | Non-admin only sees their own keys |
| `test_list_keys_admin_sees_all` | Admin sees all keys in org |
| `test_service_account_creation` | Admin can create service account user |
| `test_service_account_cannot_oidc` | Service accounts cannot use OIDC login |
| `test_audit_log_on_create` | Key creation logged to api_key_audit_log |
| `test_audit_log_on_revoke` | Key revocation logged |
| `test_audit_log_on_use` | Key usage logged (event_type = "used") |

### 9.2 Frontend Tests

| Test | Description |
|------|-------------|
| Create key dialog renders all steps | Multi-step form navigation works |
| Key shown once after creation | Raw key displayed with copy button |
| Tool category selection expands tools | Hierarchical checkbox behavior |
| Repository multi-select works | Search and select repos |
| Revoke confirmation dialog | Shows warning, calls DELETE |
| Rotate shows new key | Old key invalidated, new key displayed |
| Admin sees all keys | Admin role sees keys from all users |
| User sees only own keys | Non-admin filtered to own keys |

### 9.3 Integration Tests

| Test | Description |
|------|-------------|
| End-to-end key lifecycle | Create → use → rotate → use new → revoke → use fails |
| Scan with tool-scoped key | Trigger scan with allowed tools succeeds, disallowed fails |
| Cross-org isolation | Key from org A cannot access org B data |
| Service account full flow | Create service account → create API key → use key for scan |

---

## 10. File Inventory

### New Files (13)

| File | Purpose |
|------|---------|
| `src/api/routers/api_keys.py` | API key CRUD endpoints |
| `src/auth/api_key_auth.py` | API key validation, tool/repo scope enforcement, rate limiting |
| `src/api/constants/__init__.py` | Constants package init |
| `src/api/constants/tool_categories.py` | TOOL_CATEGORIES definition |
| `migrations/versions/019_add_api_keys.py` | Alembic migration for new tables/columns |
| `src/web-ui/app/settings/api-keys/page.tsx` | API Keys management page |
| `src/web-ui/components/api-keys/CreateApiKeyDialog.tsx` | Multi-step key creation dialog |
| `src/web-ui/components/api-keys/EditApiKeyDialog.tsx` | Key configuration editor |
| `src/web-ui/components/api-keys/RevokeApiKeyDialog.tsx` | Revocation confirmation |
| `src/web-ui/components/api-keys/RotateApiKeyDialog.tsx` | Key rotation dialog |
| `tests/test_api_keys.py` | Backend unit tests |
| `tests/test_api_key_auth.py` | Auth middleware tests |
| `swagger/paths/api-keys/list.yaml` | OpenAPI spec for key endpoints |

### Modified Files (9)

| File | Change |
|------|--------|
| `src/api/models.py` | Add `ApiKey`, `ApiKeyAuditLog` models; add `is_service_account` to `User`; add `api_keys` relationship to `User` |
| `src/api/main.py` | Register `api_keys.router` |
| `src/auth/dependencies.py` | Add API key check to `get_current_user` auth chain |
| `src/rbac/permissions.py` | Use `request.state.effective_permissions` when present |
| `src/api/routers/scans.py` | Enforce tool scope on scan trigger |
| `src/api/routers/repositories.py` | Filter repos by API key scope |
| `src/api/routers/findings.py` | Filter findings by API key repo scope |
| `src/web-ui/components/app-sidebar.tsx` | Add "API Keys" navigation link |
| `src/web-ui/app/admin/users/page.tsx` | Add service account creation support |

---

## 11. Phased Rollout

### Phase 1 — Foundation (Backend Core)

**Goal:** Database schema, models, key generation, and basic CRUD.

1. Create Alembic migration `019_add_api_keys.py`
2. Add `ApiKey` and `ApiKeyAuditLog` models to `src/api/models.py`
3. Add `is_service_account` column to `User` model
4. Create `src/api/constants/tool_categories.py`
5. Create `src/api/routers/api_keys.py` (all CRUD endpoints)
6. Write unit tests for key generation and CRUD

**Deliverable:** API keys can be created, listed, updated, rotated, and revoked via API.

### Phase 2 — Authentication Integration (Backend Auth)

**Goal:** API keys work as an authentication method with full scoping.

1. Create `src/auth/api_key_auth.py` (validation, scoping, rate limiting)
2. Modify `src/auth/dependencies.py` (add API key to auth chain)
3. Modify `src/rbac/permissions.py` (effective permissions from request.state)
4. Modify `src/api/routers/scans.py` (tool scope enforcement)
5. Modify `src/api/routers/repositories.py` (repo scope enforcement)
6. Modify `src/api/routers/findings.py` (repo scope enforcement)
7. Write integration tests for auth chain and scope enforcement

**Deliverable:** Requests with `X-API-Key` header are authenticated, scoped, and rate-limited.

### Phase 3 — Frontend (UI)

**Goal:** Full management UI for API keys and service accounts.

1. Create `src/web-ui/app/settings/api-keys/page.tsx`
2. Create all dialog components in `src/web-ui/components/api-keys/`
3. Modify sidebar navigation to include API Keys link
4. Modify admin users page for service account creation
5. Write frontend tests

**Deliverable:** Users can manage API keys from the web UI.

### Phase 4 — Hardening & Documentation

**Goal:** Production readiness.

1. Add Gitleaks/secret scanning rule for `agh_` prefix
2. Add OpenAPI spec entries in `swagger/`
3. Add API key expiration cleanup job (periodic task to log/alert on expired keys)
4. Update `README.md` and create `docs/API_KEYS.md` user guide
5. Full end-to-end integration test suite

**Deliverable:** Feature is documented, scanning for leaked keys is active, and operational monitoring is in place.

---

## Appendix A — API Key Lifecycle Diagram

```
                    ┌─────────────┐
                    │   Created   │
                    │  (active)   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │  Rotated  │ │ Expired  │ │ Revoked  │
        │(new key)  │ │(auto)    │ │(manual)  │
        └─────┬────┘ └──────────┘ └──────────┘
              │
              ▼
        ┌──────────┐
        │  Active   │
        │ (new key) │
        └──────────┘
```

## Appendix B — Effective Permission Resolution

```
Owner Permissions: [findings:read, findings:write, scans:read, scans:execute, repos:read]

Key with NO overrides:
  Effective: [findings:read, findings:write, scans:read, scans:execute, repos:read]
  (inherits all)

Key with overrides: [findings:read, scans:read]
  Effective: [findings:read, scans:read]
  (intersection — can only restrict, never escalate)

Owner permissions later REDUCED to: [findings:read, scans:read]
  Key with overrides [findings:read, findings:write, scans:read]:
  Effective: [findings:read, scans:read]
  (findings:write dropped because owner lost it — computed at runtime)
```

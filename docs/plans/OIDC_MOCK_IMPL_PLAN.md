# AuditGH Mock OIDC Integration — Implementation Plan

> **Goal:** Integrate the mock OIDC provider from `mocksvcs` into AuditGH so that the full OIDC authentication flow (login → callback → user creation via invitation → RBAC → token management) works identically in development and production. The only difference between environments is the OIDC provider URL and credentials.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Phase 1 — Docker Compose Integration](#2-phase-1--docker-compose-integration)
3. [Phase 2 — Unified OIDC Provider Abstraction](#3-phase-2--unified-oidc-provider-abstraction)
4. [Phase 3 — Auth Router Refactoring](#4-phase-3--auth-router-refactoring)
5. [Phase 4 — Invitation Flow with Mock OIDC](#5-phase-4--invitation-flow-with-mock-oidc)
6. [Phase 5 — Token Validation Unification](#6-phase-5--token-validation-unification)
7. [Phase 6 — Environment Configuration](#7-phase-6--environment-configuration)
8. [Phase 7 — Seed Data & Bootstrap](#8-phase-7--seed-data--bootstrap)
9. [Phase 8 — E2E Testing](#9-phase-8--e2e-testing)
10. [Phase 9 — Production Hardening](#10-phase-9--production-hardening)
11. [Migration Checklist](#11-migration-checklist)
12. [Appendix A — Split URL Architecture](#appendix-a--split-url-architecture)
13. [Appendix B — Mock OIDC Users & Client](#appendix-b--mock-oidc-users--client)
14. [Appendix C — Comparison Matrix](#appendix-c--comparison-matrix)

---

## 1. Architecture Overview

### Current State (AuditGH)

```
Browser → GET /auth/login/entra → Authlib → Entra ID (Microsoft)
                                          → Okta
       ← 303 redirect ←─────────────────────┘
       → GET /auth/callback/entra → token exchange → session creation
```

- **Library:** Authlib (`starlette_client.OAuth`)
- **Providers:** Hardcoded `entra` and `okta` with `server_metadata_url` discovery
- **Token validation:** JWKS-based (RS256/384/512) with 24h TTL cache
- **Auth chain:** API key → AUTH_DISABLED bypass → session → Bearer token
- **User onboarding:** Invitation-gated (admin creates invitation → user clicks link → OIDC login → user created with assigned role)
- **RBAC:** 5-tier roles (super_admin > admin > analyst > manager > user), tenant-scoped permissions

### Target State

```
                         ┌─── mock-oidc (dev)        port 3007:10090
Browser → /auth/login/   │
          {provider}  ───┤─── Entra ID (production)  login.microsoftonline.com
                         │
                         └─── Okta (production)      *.okta.com
```

- **Same auth code** handles all three providers via a unified OIDC provider registry
- **Mock OIDC** runs as a Docker sidecar (like Zapper's approach)
- **Split URL architecture** handles Docker internal vs external routing
- **Invitation system preserved** — mock OIDC pre-seeds users whose emails match invitation targets
- **JWKS validation** works with mock OIDC's RS256 keys (no skipping verification)

### Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| OIDC library | **Keep Authlib** | Already integrated, supports `server_metadata_url`, handles PKCE automatically. Switching to httpx (Zapper's approach) gains nothing and risks regressions. |
| ID token verification | **Full JWKS verification** | Unlike Zapper's unverified decode, AuditGH already does JWKS verification. Mock OIDC issues real RS256 tokens with a JWKS endpoint, so verification works naturally. |
| Provider registration | **Dynamic from env** | Instead of hardcoded `entra`/`okta`, register providers from `OIDC_PROVIDERS` config. In dev, register `mock-oidc`. In prod, register `entra` + `okta`. |
| User creation | **Keep invitation-gated** | Don't adopt Zapper's auto-upsert pattern. AuditGH's admin-invited model is more secure for a SaaS product. |
| Session management | **Keep dual session+token** | AuditGH's session-based auth with refresh token rotation is more robust than Zapper's token-only approach. |

---

## 2. Phase 1 — Docker Compose Integration

### 2.1 Add mock-oidc service to `docker-compose.yml`

```yaml
  # =============================================================================
  # Mock OIDC Provider — Development authentication (port 3007)
  # =============================================================================
  # Full OIDC 1.0 compliant provider for local development.
  # Eliminates dependency on Entra ID / Okta during development.
  # Pre-seeded with test users matching common invitation emails.
  # Split URL architecture: external (browser) vs internal (container).
  # =============================================================================
  mock-oidc:
    build:
      context: ../mocksvcs/mock_oidc
    container_name: auditgh_mock_oidc
    ports:
      - "3007:10090"
    environment:
      - MOCK_OIDC_EXTERNAL_BASE_URL=http://localhost:3007
      - MOCK_OIDC_INTERNAL_BASE_URL=http://mock-oidc:10090
      - MOCK_OIDC_DEFAULT_CLIENT_ID=${OIDC_CLIENT_ID:-auditgh-dev-client}
      - MOCK_OIDC_DEFAULT_CLIENT_SECRET=${OIDC_CLIENT_SECRET:-auditgh-dev-secret}
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:10090/health')"]
      interval: 10s
      timeout: 5s
      retries: 3
    restart: unless-stopped
    profiles:
      - dev
      - mock-oidc
```

### 2.2 Add `api` dependency on mock-oidc (dev profile)

The API service should wait for mock-oidc when running in dev profile. This is handled via environment variables (the API starts regardless, and OIDC discovery is lazy).

### 2.3 Makefile targets

```makefile
# Start development environment with mock OIDC
dev-up:
	docker compose --profile dev up -d
	@echo ""
	@echo "API:            http://localhost:8000"
	@echo "Web UI:         http://localhost:3000"
	@echo "Mock OIDC:      http://localhost:3007"
	@echo "MailHog:        http://localhost:8025"
	@echo ""

dev-down:
	docker compose --profile dev down
```

### Files Modified
- `docker-compose.yml` — add `mock-oidc` service
- `Makefile` — add `dev-up` / `dev-down` targets

---

## 3. Phase 2 — Unified OIDC Provider Abstraction

### 3.1 Replace hardcoded providers with dynamic registration

**Current** (`src/auth/providers.py`):
```python
oauth.register(name='entra', ...)
oauth.register(name='okta', ...)
```

**Target** (`src/auth/providers.py`):
```python
from authlib.integrations.starlette_client import OAuth
from .config import settings

oauth = OAuth()


def init_oauth():
    """
    Register OIDC providers dynamically from configuration.

    In development: registers 'mock-oidc' pointing to the local mock provider.
    In production: registers 'entra' and/or 'okta' from env vars.
    """
    for provider_config in settings.oidc_providers:
        name = provider_config["name"]
        oauth.register(
            name=name,
            client_id=provider_config["client_id"],
            client_secret=provider_config["client_secret"],
            server_metadata_url=provider_config["discovery_url"],
            client_kwargs={"scope": "openid profile email"},
        )
```

### 3.2 Provider configuration model

**Add to `src/auth/config.py`**:

```python
from typing import Optional

class OIDCProviderConfig:
    """Configuration for a single OIDC provider."""
    name: str
    client_id: str
    client_secret: str
    discovery_url: str  # .well-known/openid-configuration URL (uses internal URL for Docker)
    external_discovery_url: Optional[str] = None  # Browser-facing URL (for Docker split-URL)
    display_name: str = ""  # Human-readable name for login page


class Settings(BaseSettings):
    # ... existing fields ...

    # New: Generic OIDC provider (for mock-oidc in dev, or any single OIDC provider)
    oidc_provider_name: str = ""         # e.g., "mock-oidc"
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_discovery_url: str = ""          # Internal URL (container-to-container)
    oidc_external_base_url: str = ""      # External URL (browser-facing)

    @property
    def oidc_providers(self) -> list[dict]:
        """Build the list of OIDC providers from environment variables."""
        providers = []

        # Register generic OIDC provider (mock-oidc in dev, or any provider)
        if self.oidc_provider_name and self.oidc_client_id:
            providers.append({
                "name": self.oidc_provider_name,
                "client_id": self.oidc_client_id,
                "client_secret": self.oidc_client_secret,
                "discovery_url": self.oidc_discovery_url,
                "external_base_url": self.oidc_external_base_url,
            })

        # Register Entra ID if configured
        if self.entra_client_id and self.entra_tenant_id:
            providers.append({
                "name": "entra",
                "client_id": self.entra_client_id,
                "client_secret": self.entra_client_secret,
                "discovery_url": self.entra_discovery_url,
                "external_base_url": "",  # Same URL for internal and external
            })

        # Register Okta if configured
        if self.okta_client_id and self.okta_domain:
            providers.append({
                "name": "okta",
                "client_id": self.okta_client_id,
                "client_secret": self.okta_client_secret,
                "discovery_url": self.okta_discovery_url,
                "external_base_url": "",
            })

        return providers

    @property
    def registered_provider_names(self) -> list[str]:
        """Return list of registered provider names for whitelist validation."""
        return [p["name"] for p in self.oidc_providers]
```

### 3.3 Split URL handling

The mock OIDC provider uses split URLs:
- **Internal** (`http://mock-oidc:10090`): Used by the API container for token exchange and discovery
- **External** (`http://localhost:3007`): Used by the browser for authorization redirects

Authlib fetches `server_metadata_url` from the **internal** URL. The discovery document from mock-oidc returns the **external** `authorization_endpoint` (browser-facing) and the **internal** `token_endpoint` (back-channel). This is handled naturally by the mock-oidc provider's split URL architecture — no custom code needed in AuditGH.

**Key insight from mocksvcs:** The discovery document at the internal URL returns:
- `authorization_endpoint` → external URL (browser redirects here)
- `token_endpoint` → internal URL (API server calls this)
- `jwks_uri` → internal URL (API server validates tokens)
- `userinfo_endpoint` → internal URL (API server fetches claims)
- `issuer` → external URL (must match `iss` claim in tokens)

This means Authlib will automatically:
1. Redirect browser to external authorization endpoint ✓
2. Exchange code at internal token endpoint ✓
3. Fetch JWKS from internal JWKS URI ✓

### Files Modified
- `src/auth/providers.py` — dynamic provider registration
- `src/auth/config.py` — add `oidc_*` env vars, `oidc_providers` property

---

## 4. Phase 3 — Auth Router Refactoring

### 4.1 Dynamic provider whitelist

**Current** (`src/api/routers/auth.py`):
```python
if provider not in ["entra", "okta"]:
    raise HTTPException(status_code=400, detail="Invalid provider")
```

**Target**:
```python
from src.auth.config import settings

if provider not in settings.registered_provider_names:
    raise HTTPException(status_code=400, detail=f"Invalid provider. Available: {settings.registered_provider_names}")
```

### 4.2 Provider-agnostic callback

The current callback hardcodes `auth_method='entra'` in audit logging. Make it provider-aware:

```python
# Current:
auth_method='entra' if provider == 'entra' else 'oauth'

# Target:
auth_method=provider  # 'entra', 'okta', or 'mock-oidc'
```

### 4.3 Provider-agnostic user creation in `accept_invitation()`

The current `accept_invitation()` in `src/auth/invitations.py` hardcodes Entra-specific fields:

```python
# Current:
user = User(
    entra_id_object_id=entra_user_info.get('sub'),
    entra_id_upn=entra_user_info.get('upn'),
    auth_provider='entra',
    ...
)
```

**Target** — make provider-agnostic:

```python
def accept_invitation(
    db: Session,
    invite_token: str,
    user_info: dict,        # Renamed from entra_user_info
    provider: str = "entra" # New parameter
) -> User:
    # ...
    user = User(
        oidc_subject=user_info.get('sub'),          # Universal OIDC claim
        entra_id_object_id=user_info.get('sub') if provider == 'entra' else None,
        entra_id_upn=user_info.get('upn') if provider == 'entra' else None,
        auth_provider=provider,                      # 'entra', 'okta', or 'mock-oidc'
        ...
    )
```

### 4.4 Add `oidc_subject` field to User model

The User model needs a provider-agnostic OIDC subject field (like Zapper's approach):

```python
# In src/api/models.py, add to User model:
oidc_subject = Column(String, nullable=True, unique=True, index=True,
                      comment="OIDC 'sub' claim — stable identifier across providers")
oidc_issuer = Column(String, nullable=True,
                     comment="OIDC issuer URL (identifies which provider authenticated the user)")
```

This field is provider-agnostic (works for Entra, Okta, and mock-oidc), while the existing `entra_id_object_id` field is preserved for backward compatibility.

### 4.5 Callback flow with invitation check

The callback should pass the provider name to `accept_invitation`:

```python
# In callback():
user = accept_invitation(db, invite_token, user_info, provider=provider)
```

### 4.6 Login page provider listing

Add an endpoint that returns available providers for the frontend login page:

```python
@router.get("/providers", summary="List available OIDC providers")
async def list_providers():
    """Return list of available authentication providers."""
    return {
        "providers": [
            {"name": p["name"], "display_name": p.get("display_name", p["name"])}
            for p in settings.oidc_providers
        ]
    }
```

### Files Modified
- `src/api/routers/auth.py` — dynamic whitelist, provider-agnostic audit logging, pass provider to invitation
- `src/auth/invitations.py` — provider-agnostic user creation, `oidc_subject` field
- `src/api/models.py` — add `oidc_subject`, `oidc_issuer` columns to User

---

## 5. Phase 4 — Invitation Flow with Mock OIDC

### 5.1 Complete invitation → OIDC → user creation flow

```
Admin                          System                    Mock OIDC              Invitee Browser
  │                              │                          │                        │
  ├──POST /api/invitations──────►│                          │                        │
  │  {email, role, access_type}  │                          │                        │
  │                              ├──send email──────────────┼───────────────────────►│
  │                              │  (via MailHog in dev)     │                        │
  │                              │                          │                        │
  │                              │                          │  ◄────click link───────┤
  │                              │                          │                        │
  │                              │◄─GET /auth/accept-invite─┤                        │
  │                              │  ?token=abc123           │                        │
  │                              │                          │                        │
  │                              ├──store invite_token──────┤                        │
  │                              │  in session              │                        │
  │                              │                          │                        │
  │                              ├──redirect to OIDC login──┤                        │
  │                              │  /auth/login/mock-oidc   │                        │
  │                              │                          │                        │
  │                              │                          ├──user picker page─────►│
  │                              │                          │  (or login_hint auto)   │
  │                              │                          │                        │
  │                              │                          │  ◄───select user────────┤
  │                              │                          │                        │
  │                              │◄──callback with code─────┤                        │
  │                              │                          │                        │
  │                              ├──exchange code───────────►│                        │
  │                              │◄──id_token + access_token─┤                        │
  │                              │                          │                        │
  │                              ├──validate id_token (JWKS)│                        │
  │                              ├──check invitation────────│                        │
  │                              ├──accept_invitation()─────│                        │
  │                              │  create User with role   │                        │
  │                              ├──create session──────────│                        │
  │                              │                          │                        │
  │                              ├──303 redirect to /───────┼───────────────────────►│
```

### 5.2 Invitation acceptance endpoint

Add an explicit invitation acceptance route that stores the token in the session before redirecting to OIDC login:

```python
@router.get("/accept-invite", summary="Accept invitation and redirect to OIDC login")
async def accept_invite(token: str, request: Request, provider: str = ""):
    """
    First step of invitation acceptance — stores invite token in session
    and redirects to OIDC login.

    The callback handler will check for this token and create the user.
    """
    db = SessionLocal()
    try:
        invitation = get_invitation_by_token(db, token)
        if not invitation or invitation.status != 'pending':
            raise HTTPException(status_code=400, detail="Invalid or expired invitation")

        # Store invite token in session for callback to find
        request.session['invite_token'] = token

        # Determine which provider to use
        if not provider:
            # Use first available provider
            provider = settings.registered_provider_names[0] if settings.registered_provider_names else "entra"

        # Redirect to OIDC login with login_hint for mock-oidc
        login_url = f"/auth/login/{provider}"
        if provider == "mock-oidc":
            # Pass email as login_hint so mock-oidc auto-selects the right user
            login_url += f"?login_hint={invitation.email}"

        return RedirectResponse(url=login_url, status_code=303)
    finally:
        db.close()
```

### 5.3 Pass `login_hint` to authorization URL

When using mock-oidc, pass `login_hint` so it auto-selects the matching user (skipping the user picker):

```python
# In login() endpoint:
extra_params = {}
if request.query_params.get("login_hint"):
    extra_params["login_hint"] = request.query_params["login_hint"]

return await provider_client.authorize_redirect(
    request,
    redirect_uri,
    code_challenge_method='S256',
    **extra_params
)
```

### 5.4 Email matching with mock OIDC users

The mock OIDC provider has pre-seeded users. For the invitation flow to work, the mock OIDC user's email must match the invitation email. Two approaches:

**Option A (Recommended):** Create mock OIDC users dynamically via the mock-oidc management API:
```bash
# When creating an invitation for user@example.com:
curl -X POST http://mock-oidc:10090/api/users \
  -H "Content-Type: application/json" \
  -d '{"username": "user-example", "email": "user@example.com", "name": "Test User"}'
```

**Option B:** Pre-seed mock OIDC users that match common test invitation emails.

**Recommendation:** Use Option A. Add a development-only hook in `create_invitation()` that auto-provisions a matching mock OIDC user when `OIDC_PROVIDER_NAME=mock-oidc`:

```python
# In create_invitation(), after creating the invitation:
if os.getenv("OIDC_PROVIDER_NAME") == "mock-oidc":
    _provision_mock_oidc_user(email, role)
```

### Files Modified
- `src/api/routers/auth.py` — add `accept-invite` endpoint, `login_hint` support
- `src/auth/invitations.py` — optional mock user provisioning hook

---

## 6. Phase 5 — Token Validation Unification

### 6.1 JWKS validation for mock OIDC

The current `validate_jwt_token()` in `src/auth/middleware.py` fetches JWKS from hardcoded Entra/Okta providers. Extend it to support any registered OIDC provider:

```python
# Current approach in get_jwks():
# Hardcoded provider name → discovery URL → jwks_uri

# Target:
async def get_jwks(provider: str) -> dict:
    """Fetch JWKS for any registered OIDC provider."""
    provider_config = next(
        (p for p in settings.oidc_providers if p["name"] == provider),
        None
    )
    if not provider_config:
        raise ValueError(f"Unknown provider: {provider}")

    discovery_url = provider_config["discovery_url"]
    # ... fetch discovery document, extract jwks_uri, fetch JWKS ...
```

### 6.2 Token validation in `get_current_user_from_token()`

The current `get_current_user_from_token()` iterates over hardcoded `["entra", "okta"]`. Change to iterate over `settings.registered_provider_names`:

```python
# Current:
for provider in ["entra", "okta"]:

# Target:
for provider in settings.registered_provider_names:
```

### 6.3 Issuer validation

The mock OIDC provider sets `iss` to its external URL (e.g., `http://localhost:3007`). The JWT validation must accept this issuer. The current `validate_jwt_token()` validates `iss` against the provider's configured issuer — this will work automatically if the provider's discovery document returns the correct issuer.

### Files Modified
- `src/auth/middleware.py` — dynamic provider JWKS fetching
- `src/auth/dependencies.py` — dynamic provider iteration in token validation

---

## 7. Phase 6 — Environment Configuration

### 7.1 Development `.env` additions

```bash
# =============================================================================
# Mock OIDC Provider (development only)
# =============================================================================
OIDC_PROVIDER_NAME=mock-oidc
OIDC_CLIENT_ID=auditgh-dev-client
OIDC_CLIENT_SECRET=auditgh-dev-secret
OIDC_DISCOVERY_URL=http://mock-oidc:10090/.well-known/openid-configuration
OIDC_EXTERNAL_BASE_URL=http://localhost:3007

# Disable Entra ID and Okta in development (leave blank)
ENTRA_TENANT_ID=
ENTRA_CLIENT_ID=
ENTRA_CLIENT_SECRET=
OKTA_DOMAIN=
OKTA_CLIENT_ID=
OKTA_CLIENT_SECRET=

# Keep AUTH_DISABLED=false to test real OIDC flow
AUTH_DISABLED=false
AUTH_REQUIRED=true
```

### 7.2 Production `.env` (unchanged pattern)

```bash
# =============================================================================
# Production OIDC (Entra ID + Okta)
# =============================================================================
# No mock OIDC — leave blank:
OIDC_PROVIDER_NAME=
OIDC_CLIENT_ID=
OIDC_CLIENT_SECRET=

# Entra ID (Microsoft Azure AD)
ENTRA_TENANT_ID=ed8aabd5-...
ENTRA_CLIENT_ID=0d060870-...
ENTRA_CLIENT_SECRET=RRS8Q~...

# Okta (if used)
OKTA_DOMAIN=company.okta.com
OKTA_CLIENT_ID=...
OKTA_CLIENT_SECRET=...

AUTH_DISABLED=false
AUTH_REQUIRED=true
```

### 7.3 Docker Compose environment passthrough

Add new OIDC env vars to the `api` service:

```yaml
  api:
    environment:
      # ... existing vars ...
      # OIDC provider configuration
      - OIDC_PROVIDER_NAME=${OIDC_PROVIDER_NAME:-}
      - OIDC_CLIENT_ID=${OIDC_CLIENT_ID:-}
      - OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET:-}
      - OIDC_DISCOVERY_URL=${OIDC_DISCOVERY_URL:-}
      - OIDC_EXTERNAL_BASE_URL=${OIDC_EXTERNAL_BASE_URL:-}
```

### 7.4 CORS origins update

Add mock OIDC external URL to CORS origins:

```python
# In Settings.__init__():
if oidc_external := os.getenv("OIDC_EXTERNAL_BASE_URL"):
    if oidc_external not in self.cors_origins:
        self.cors_origins.append(oidc_external)
```

### Files Modified
- `.env.example` (or `.env`) — add OIDC_* variables
- `docker-compose.yml` — pass OIDC env vars to api service
- `src/auth/config.py` — CORS origins update

---

## 8. Phase 7 — Seed Data & Bootstrap

### 8.1 Bootstrap super_admin via invitation

In development, the first user needs to be created. Two approaches:

**Option A (Recommended):** Auto-seed a super_admin invitation on first startup:

```python
# In a startup script or seed function:
def seed_dev_admin_invitation(db: Session):
    """Create a super_admin invitation for the mock-oidc admin user."""
    if os.getenv("OIDC_PROVIDER_NAME") != "mock-oidc":
        return

    # Check if any users exist
    user_count = db.query(User).count()
    if user_count > 0:
        return

    # Create a system invitation for the mock admin user
    invitation = UserInvitation(
        email="admin@zapper.local",  # Matches mock-oidc pre-seeded user
        invite_token="dev-admin-bootstrap-token",
        invited_by=None,  # System-generated
        invited_role="super_admin",
        invited_access_type="both",
        status="pending",
        expires_at=datetime.utcnow() + timedelta(days=365),
    )
    db.add(invitation)
    db.commit()
    logger.info("Seeded bootstrap admin invitation for admin@zapper.local")
```

**Option B:** Use the existing break-glass mechanism to create the first user, then use invitations for subsequent users.

### 8.2 Mock OIDC client registration

The mock OIDC provider auto-creates a default client on startup. Configure AuditGH's client credentials to match:

| Setting | Value |
|---------|-------|
| `OIDC_CLIENT_ID` | `auditgh-dev-client` |
| `OIDC_CLIENT_SECRET` | `auditgh-dev-secret` |
| `MOCK_OIDC_DEFAULT_CLIENT_ID` | `auditgh-dev-client` |
| `MOCK_OIDC_DEFAULT_CLIENT_SECRET` | `auditgh-dev-secret` |

### 8.3 Mock OIDC pre-seeded users

The mock OIDC provider comes with pre-seeded users. Configure additional users for AuditGH testing:

| Username | Email | Intended Role |
|----------|-------|---------------|
| `mock-admin` | `admin@zapper.local` | super_admin |
| `mock-analyst` | `analyst@zapper.local` | analyst |
| `mock-user` | `user@zapper.local` | user |

These emails should match invitation emails created by the dev seed script.

### Files Modified
- `scripts/seed_dev_auth.py` (new) — bootstrap invitation + mock user provisioning
- `src/api/main.py` — call seed on startup if dev mode

---

## 9. Phase 8 — E2E Testing

### 9.1 Automated login test with `login_hint`

The mock OIDC provider supports `login_hint` parameter to auto-select a user without showing the interactive picker. This enables automated testing:

```python
# In tests/e2e/test_oidc_flow.py:
import httpx

async def test_full_oidc_login_flow():
    """Test complete OIDC login flow with mock provider."""
    async with httpx.AsyncClient(base_url="http://localhost:8000", follow_redirects=False) as client:
        # 1. Initiate login with login_hint
        resp = await client.get("/auth/login/mock-oidc?login_hint=admin@zapper.local")
        assert resp.status_code == 302  # Redirect to mock-oidc authorization endpoint
        auth_url = resp.headers["location"]
        assert "localhost:3007" in auth_url
        assert "login_hint=admin" in auth_url

        # 2. Follow redirect to mock-oidc (auto-approves via login_hint)
        resp2 = await client.get(auth_url)
        assert resp2.status_code == 302  # Redirect back with code
        callback_url = resp2.headers["location"]
        assert "code=" in callback_url

        # 3. Follow callback redirect
        resp3 = await client.get(callback_url)
        assert resp3.status_code == 303  # Redirect to homepage

        # 4. Verify session
        resp4 = await client.get("/auth/me")
        assert resp4.status_code == 200
        user = resp4.json()
        assert user["email"] == "admin@zapper.local"
```

### 9.2 Invitation flow E2E test

```python
async def test_invitation_oidc_flow():
    """Test invitation acceptance via mock OIDC."""
    async with httpx.AsyncClient(base_url="http://localhost:8000") as client:
        # 1. Admin creates invitation (using API key or session)
        resp = await client.post("/api/invitations", json={
            "email": "newuser@test.com",
            "role": "analyst",
            "access_type": "both"
        }, headers={"X-API-Key": "admin-api-key"})
        invite_token = resp.json()["invite_token"]

        # 2. New user clicks invitation link
        resp = await client.get(f"/auth/accept-invite?token={invite_token}")
        # Should redirect to mock-oidc login

        # 3. After OIDC callback, user should be created with correct role
        resp = await client.get("/auth/me")
        assert resp.json()["role"] == "analyst"
```

### 9.3 Token validation test

```python
async def test_jwt_validation_with_mock_oidc():
    """Verify JWKS-based token validation works with mock OIDC RS256 tokens."""
    # Login via mock OIDC, get session
    # Request a refresh token
    # Verify the refresh token rotation works
    # Verify token revocation works
```

### Files Created
- `tests/e2e/test_oidc_flow.py` — E2E tests for the full OIDC flow
- `tests/e2e/test_invitation_oidc.py` — invitation + OIDC integration tests

---

## 10. Phase 9 — Production Hardening

### 10.1 Ensure no mock-oidc code in production

The mock OIDC provider should never run in production. Safeguards:

1. **Docker profile:** mock-oidc is only in `dev` and `mock-oidc` profiles
2. **No fallback:** If `OIDC_PROVIDER_NAME` is empty, no generic provider is registered
3. **Startup validation:** Log a warning if no providers are registered
4. **CSP headers:** Only allow connections to configured provider URLs

### 10.2 JWKS verification strictness

Verify that the `validate_jwt_token()` function:
- Always validates signatures (never falls back to unverified decode)
- Validates `aud` claim matches `client_id`
- Validates `iss` claim matches provider's issuer
- Validates `exp` claim (token not expired)
- Uses RS256/384/512 algorithm whitelist (no HS256 for external tokens)

### 10.3 Callback redirect URL validation

Ensure the callback redirect URL is always the same origin:

```python
# In callback():
redirect_uri = str(request.url_for('callback', provider=provider))
# Validate it's same-origin to prevent open redirect
```

### 10.4 Session security in production

- `SESSION_SECRET` must be a strong random value (not the default)
- `SECURE_COOKIES=true` in production (HTTPS only)
- `SAME_SITE=lax` cookie attribute
- HSTS header enforced

### 10.5 Audit logging

All OIDC events should be logged:
- Login initiated (provider, client_id)
- Callback received (provider, email, success/failure)
- Invitation accepted (email, role, provider)
- Token validation failures (provider, reason)

### Files Modified
- `src/auth/middleware.py` — CSP header updates for provider URLs
- `src/api/main.py` — startup validation of auth configuration

---

## 11. Migration Checklist

### Database Migration

```sql
-- Add oidc_subject and oidc_issuer columns to users table
ALTER TABLE users ADD COLUMN oidc_subject VARCHAR UNIQUE;
ALTER TABLE users ADD COLUMN oidc_issuer VARCHAR;

-- Backfill from existing entra_id_object_id
UPDATE users SET oidc_subject = entra_id_object_id WHERE entra_id_object_id IS NOT NULL;
UPDATE users SET oidc_issuer = 'https://login.microsoftonline.com/' || (
    SELECT value FROM app_settings WHERE key = 'entra_tenant_id'
) || '/v2.0' WHERE auth_provider = 'entra';

-- Create index
CREATE INDEX idx_users_oidc_subject ON users(oidc_subject);
```

### Deployment Steps

1. **Run database migration** — add `oidc_subject`, `oidc_issuer` columns
2. **Deploy code** — all auth changes
3. **Update environment variables** — add `OIDC_*` vars (empty in prod initially)
4. **Verify** — existing Entra/Okta logins still work (backward compatible)
5. **Test** — in dev environment, verify mock-oidc flow works end-to-end

### Rollback Plan

All changes are backward compatible:
- New `oidc_*` env vars default to empty (no change in behavior)
- Provider registration falls back to `entra` + `okta` when `OIDC_PROVIDER_NAME` is empty
- New DB columns are nullable (no breaking changes)
- `entra_id_object_id` field is preserved (no data loss)

---

## Appendix A — Split URL Architecture

The mock OIDC provider uses a **split URL architecture** to handle Docker networking:

```
                    ┌──────────────────────────┐
                    │      Docker Network       │
                    │                           │
  Browser           │   API          Mock OIDC  │
  (localhost)       │   (api:8000)   (mock-oidc │
                    │                 :10090)    │
       │            │      │              │     │
       │  ◄─────────│──────┤              │     │  1. API redirects browser
       │  redirect  │      │              │     │     to EXTERNAL auth URL
       │  to        │      │              │     │     http://localhost:3007/authorize
       │  localhost │      │              │     │
       │  :3007    │      │              │     │
       │            │      │              │     │
       ├────────────│──────┼──────────────►     │  2. Browser opens EXTERNAL URL
       │  GET       │      │              │     │     http://localhost:3007/authorize
       │  /authorize│      │              │     │
       │            │      │              │     │
       │  ◄─────────│──────┼──────────────┤     │  3. Mock OIDC redirects browser
       │  redirect  │      │              │     │     back to API callback
       │  with code │      │              │     │     http://localhost:8000/auth/callback
       │            │      │              │     │
       ├────────────│──────►              │     │  4. Browser hits API callback
       │  GET       │      │              │     │
       │  /callback │      │              │     │
       │            │      ├──────────────►     │  5. API exchanges code via
       │            │      │  POST /token │     │     INTERNAL URL
       │            │      │  http://mock │     │     http://mock-oidc:10090/token
       │            │      │  -oidc:10090 │     │
       │            │      │              │     │
       │            │      ◄──────────────┤     │  6. Mock OIDC returns tokens
       │            │      │  id_token +  │     │
       │            │      │  access_token│     │
       │            │      │              │     │
       │            │      ├──────────────►     │  7. API validates JWT via
       │            │      │  GET /jwks   │     │     INTERNAL JWKS URL
       │            │      │              │     │     http://mock-oidc:10090/jwks
       │            │      ◄──────────────┤     │
                    │                           │
                    └──────────────────────────┘
```

**Why this matters:** Without split URLs, the browser would be redirected to `http://mock-oidc:10090/authorize` — a URL that doesn't resolve on the host machine. The split URL architecture ensures the browser always uses `localhost:3007` while the API container uses the Docker-internal `mock-oidc:10090`.

---

## Appendix B — Mock OIDC Users & Client

### Pre-seeded Client

| Field | Value |
|-------|-------|
| Client ID | `auditgh-dev-client` |
| Client Secret | `auditgh-dev-secret` |
| Redirect URIs | `http://localhost:8000/auth/callback/mock-oidc` |
| Grant Types | `authorization_code`, `refresh_token` |

### Pre-seeded Users

| Username | Email | Password | Intended AuditGH Role |
|----------|-------|----------|----------------------|
| `mock-admin` | `admin@zapper.local` | (N/A — OIDC flow) | super_admin |
| `mock-analyst` | `analyst@zapper.local` | (N/A) | analyst |
| `mock-user` | `user@zapper.local` | (N/A) | user |
| `mock-manager` | `manager@auditgh.local` | (N/A) | manager |

### User Provisioning API

Create additional mock OIDC users for testing:

```bash
# Create a user matching an invitation
curl -X POST http://localhost:3007/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test-analyst",
    "email": "analyst@company.com",
    "name": "Test Analyst",
    "password": "not-used"
  }'
```

---

## Appendix C — Comparison Matrix

| Feature | AuditGH (Current) | Zapper | AuditGH (Target) |
|---------|-------------------|--------|-------------------|
| OIDC Library | Authlib | httpx (manual) | Authlib |
| ID Token Verification | JWKS (RS256) | Unverified decode | JWKS (RS256) |
| PKCE | S256 (via Authlib) | Not implemented | S256 (via Authlib) |
| User Creation | Invitation-gated | Auto-upsert | Invitation-gated |
| Internal JWT | HS256 (refresh/access) | HS256 (24h) | HS256 (refresh/access) |
| Session Management | Cookie + Redis | JWT cookie | Cookie + Redis |
| Token Rotation | One-time use | None | One-time use |
| Token Blacklist | Redis | None (planned) | Redis |
| RBAC | 5-tier + permissions | 5-tier hierarchy | 5-tier + permissions |
| Multi-tenant | Yes (UserRole.tenant_id) | Yes (Organization) | Yes (UserRole.tenant_id) |
| Mock OIDC | Not available | Via mocksvcs | Via mocksvcs |
| Provider Config | Hardcoded entra/okta | Single provider env | Dynamic from env |
| Break Glass | Yes (ravance@gmail.com) | No | Yes (unchanged) |
| Audit Logging | Full | Basic | Full |

---

## Summary of Files to Modify

| File | Change |
|------|--------|
| `docker-compose.yml` | Add mock-oidc service, pass OIDC env vars to API |
| `Makefile` | Add dev-up / dev-down targets |
| `src/auth/config.py` | Add OIDC_* env vars, `oidc_providers` property, CORS update |
| `src/auth/providers.py` | Dynamic provider registration from config |
| `src/api/routers/auth.py` | Dynamic provider whitelist, `accept-invite` endpoint, `login_hint`, provider-agnostic audit |
| `src/auth/invitations.py` | Provider-agnostic user creation, optional mock user provisioning |
| `src/auth/dependencies.py` | Dynamic provider list in token validation |
| `src/auth/middleware.py` | Dynamic JWKS fetching, CSP header updates |
| `src/api/models.py` | Add `oidc_subject`, `oidc_issuer` columns |
| `src/api/main.py` | Startup validation, dev seed call |
| `.env.example` | Add OIDC_* variables with documentation |

## New Files

| File | Purpose |
|------|---------|
| `scripts/seed_dev_auth.py` | Bootstrap invitation + mock OIDC user provisioning |
| `tests/e2e/test_oidc_flow.py` | E2E tests for OIDC login flow |
| `tests/e2e/test_invitation_oidc.py` | E2E tests for invitation + OIDC |
| `alembic/versions/xxx_add_oidc_subject.py` | Database migration |

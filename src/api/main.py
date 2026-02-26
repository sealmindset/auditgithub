from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from starlette.middleware.base import BaseHTTPMiddleware
import logging
import os
from loguru import logger as loguru_logger

from src.api.sandbox import is_sandbox

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class OrganizationContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware to extract organization context from request headers or query params.
    
    Supports:
    - X-Organization-ID header (UUID)
    - X-Organization-Name header (org name, will be resolved to ID)
    - org query parameter (org name, will be resolved to ID)
    """
    
    async def dispatch(self, request: Request, call_next):
        from .database import set_request_org_id, SessionLocal
        from . import models

        org_id = None
        org_name = None

        # Check for X-Organization-ID header first (direct UUID)
        org_id_header = request.headers.get("X-Organization-ID")
        if org_id_header:
            org_id = org_id_header

        # Check for X-Organization-Name header (resolve to ID)
        if not org_id:
            org_name_header = request.headers.get("X-Organization-Name")
            if org_name_header:
                org_name = org_name_header
                org_id = await self._resolve_org_name(org_name_header)

        # Check for org query parameter (resolve to ID)
        if not org_id:
            org_param = request.query_params.get("org")
            if org_param:
                org_name = org_param
                org_id = await self._resolve_org_name(org_param)

        # Set the request-scoped org ID
        set_request_org_id(org_id)

        # Store org context in request.state for downstream middleware
        request.state.org_id = org_id
        request.state.org_name = org_name

        # Log organization context extraction
        if org_id:
            loguru_logger.bind(
                middleware="OrganizationContextMiddleware",
                org_id=org_id,
                org_name=org_name
            ).debug(f"Organization context: {org_id}")
        else:
            loguru_logger.bind(
                middleware="OrganizationContextMiddleware"
            ).warning("Request missing organization context")

        try:
            response = await call_next(request)
            return response
        finally:
            # Clear the request-scoped org ID after request completes
            set_request_org_id(None)
    
    async def _resolve_org_name(self, org_name: str) -> str:
        """Resolve organization name to ID."""
        from .database import SessionLocal
        from . import models
        
        try:
            db = SessionLocal()
            org = db.query(models.Organization).filter(
                models.Organization.name == org_name
            ).first()
            db.close()
            if org:
                return str(org.id)
        except Exception as e:
            logger.debug(f"Failed to resolve org name '{org_name}': {e}")
        return None

# =============================================================================
# OpenAPI tag metadata — provides descriptions for each tag group in /docs
# =============================================================================
tags_metadata = [
    {"name": "authentication", "description": "User login, logout, token refresh, and OAuth 2.0 flows"},
    {"name": "device-flow", "description": "OAuth 2.0 Device Authorization Grant (RFC 8628) for CLI/headless authentication"},
    {"name": "user-management", "description": "User CRUD, profile management, and service account operations"},
    {"name": "invitations", "description": "Email-based user invitation management with RBAC-scoped access"},
    {"name": "api-keys", "description": "Programmatic API key management with tool scoping, repository scoping, and rate limiting"},
    {"name": "organizations", "description": "Multi-organization management, GitHub credentials, and repository import"},
    {"name": "Tenants", "description": "Multi-tenant organization provisioning and isolated database management"},
    {"name": "repositories", "description": "GitHub repository management, metadata, and scan history"},
    {"name": "findings", "description": "Security findings: listing, filtering, status updates, comments, and statistics"},
    {"name": "scans", "description": "Security scan orchestration, status tracking, and result retrieval"},
    {"name": "schedules", "description": "Scan schedule management with cron expressions and AI-powered recommendations"},
    {"name": "analytics", "description": "Security metrics, hero dashboards, threat radar, executive summaries, and trend analysis"},
    {"name": "ai", "description": "AI-powered architecture analysis, remediation guidance, triage, and zero-day assessment"},
    {"name": "ai-chat", "description": "Interactive AI assistant for security analysis conversations"},
    {"name": "api-audit", "description": "API endpoint discovery, OpenAPI analysis, and Swagger documentation extraction"},
    {"name": "attack-surface", "description": "Attack surface mapping: exposed secrets, abandoned repos, stale contributors, and risk scoring"},
    {"name": "attack-paths", "description": "Attack path visualization and remediation priority analysis"},
    {"name": "Contributor Profiles", "description": "Git contributor activity analysis, risk scoring, and commit pattern detection"},
    {"name": "secrets", "description": "Detected secrets management, credential lifecycle, and remediation tracking"},
    {"name": "sla", "description": "Service level agreement tracking, compliance metrics, and violation reporting"},
    {"name": "projects", "description": "Project grouping, tagging, cross-repository management, and aggregate statistics"},
    {"name": "github", "description": "GitHub API synchronization for repository metadata, files, and contributor data"},
    {"name": "git-sync", "description": "Git push operations for README generation and architecture diagram sync"},
    {"name": "settings", "description": "System configuration key-value pairs and tool integration settings"},
    {"name": "scheduler", "description": "Background job scheduling, APScheduler management, and cron status"},
    {"name": "cribl", "description": "Cribl Stream log forwarding configuration, testing, and status monitoring"},
    {"name": "integrations", "description": "Third-party integrations including Jira ticket creation and synchronization"},
    {"name": "feedback", "description": "User feedback submission for features, bugs, and platform improvement"},
] + ([{"name": "Sandbox", "description": "Sandbox environment management: API keys, reset, and status"}] if is_sandbox() else [])

_sandbox_description = """
**SANDBOX ENVIRONMENT** — This is an isolated developer sandbox with synthetic data.
All mutations are safe and reset every 24 hours. No production data is used.

## Quick Start
Use one of the pre-generated API keys below in the `X-API-Key` header:

| Key Name | Role | Value |
|----------|------|-------|
| sandbox-admin-key | super_admin | `sbx_admin_4a8b2c1d3e5f6789` |
| sandbox-analyst-key | analyst | `sbx_analyst_9f8e7d6c5b4a3210` |
| sandbox-readonly-key | viewer | `sbx_readonly_1a2b3c4d5e6f7890` |

## Sandbox Endpoints
- `GET /api/sandbox/keys` — List all sandbox keys with usage examples
- `POST /api/sandbox/reset` — Reset all data (admin key required)
- `GET /api/sandbox/status` — Current sandbox configuration

## What's Different from Production
- **Auth**: API key only (no OAuth/JWT/sessions)
- **AI**: Returns canned mock responses (no external AI calls)
- **Data**: 3 orgs, 54 repos, 540 findings, 162 contributors (all synthetic)
- **Scheduler**: Disabled
- **GitHub**: No real GitHub API calls
"""

_production_description = """
Comprehensive API for GitHub organization security auditing, vulnerability scanning,
and threat assessment. The AuditGH platform provides multi-organization support with
isolated data, automated security scanning, and AI-powered threat analysis.

## Features
- Multi-organization GitHub repository management
- Automated security scanning (Gitleaks, Semgrep, Grype, Trivy, Bandit, Checkov)
- Vulnerability tracking and remediation workflows
- AI-powered architecture analysis and threat assessment
- Attack surface mapping and path analysis
- SLA tracking and compliance reporting

## Authentication
Most API endpoints require authentication via one of:
- **Session cookie** (browser-based, set during OAuth login)
- **Bearer token** (`Authorization: Bearer <jwt>`)
- **API key** (`X-API-Key: agh_...`)

Obtain tokens via `POST /auth/break-glass/login` or the OAuth 2.0 Device Flow.

## Rate Limiting
API requests are rate-limited per user. Check response headers:
- `X-RateLimit-Limit`: Maximum requests per window
- `X-RateLimit-Remaining`: Remaining requests
- `X-RateLimit-Reset`: Window reset timestamp

## Pagination
List endpoints support `skip` and `limit` query parameters:
- `skip`: Records to skip (default: 0)
- `limit`: Records to return (default: 100, max: 1000)
"""

app = FastAPI(
    title="AuditGH Sandbox API" if is_sandbox() else "AuditGH Security Portal API",
    description=_sandbox_description if is_sandbox() else _production_description,
    version="2.0.0-sandbox" if is_sandbox() else "2.0.0",
    contact={"name": "AuditGH Support", "email": "support@auditgh.local"},
    license_info={"name": "GPL-3.0", "url": "https://www.gnu.org/licenses/gpl-3.0.html"},
    openapi_tags=tags_metadata,
    swagger_ui_parameters={
        "docExpansion": "none",
        "filter": True,
        "persistAuthorization": True,
        "tryItOutEnabled": True,
        "displayRequestDuration": True,
        "defaultModelsExpandDepth": 2,
    },
)

# Add rate limiting
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from src.auth.rate_limit import limiter

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add SessionMiddleware for OAuth flow state management
from starlette.middleware.sessions import SessionMiddleware
from src.auth.providers import init_oauth
from src.auth.config import settings as auth_settings

app.add_middleware(
    SessionMiddleware,
    secret_key=auth_settings.session_secret,
    max_age=3600,  # 1 hour session
    https_only=False  # Set to False for local dev, change to True in production
)

# Initialize OAuth providers with OIDC discovery
init_oauth()

from .database import engine
from . import models

# Create database tables (includes Tenant model)
models.Base.metadata.create_all(bind=engine)

# Import routers
from .routers import repositories, jira, ai, scans, analytics, findings, projects, settings, github_sync, attack_surface, contributor_profiles, feedback, secrets, sla, attack_paths, api_audit, tenants, organizations, scheduler, cribl, auth, schedules, git_sync, ai_chat, device_flow, invitations, users, api_keys

# Multi-tenant support
MULTI_TENANT_ENABLED = os.environ.get("MULTI_TENANT_ENABLED", "false").lower() == "true"

if MULTI_TENANT_ENABLED:
    from .middleware.tenant import TenantMiddleware
    logger.info("Multi-tenant mode ENABLED")
else:
    logger.info("Multi-tenant mode DISABLED (single tenant)")

# Include routers
app.include_router(auth.router)  # Authentication endpoints
app.include_router(device_flow.router)  # Device flow authentication (OAuth 2.0 RFC 8628)
app.include_router(invitations.router)  # User invitation management (RBAC)
app.include_router(users.router)  # User management (RBAC)
app.include_router(tenants.router)  # Tenant management (always available)
app.include_router(repositories.router)
app.include_router(jira.router)
app.include_router(ai.router)
app.include_router(scans.router)
app.include_router(analytics.router)
app.include_router(findings.router)
app.include_router(projects.router)
app.include_router(settings.router)
app.include_router(github_sync.router)
app.include_router(attack_surface.router)
app.include_router(contributor_profiles.router)
app.include_router(feedback.router)
app.include_router(secrets.router)
app.include_router(sla.router)
app.include_router(attack_paths.router)
app.include_router(api_audit.router)
app.include_router(api_audit.global_router)
app.include_router(organizations.router)
app.include_router(scheduler.router)
app.include_router(schedules.router)
app.include_router(cribl.router)
app.include_router(git_sync.router)
app.include_router(ai_chat.router)
app.include_router(api_keys.router)  # API key management

# Register sandbox router (only active when SANDBOX_MODE=true)
if is_sandbox():
    from .routers import sandbox as sandbox_router
    app.include_router(sandbox_router.router)
    logger.info("Sandbox router registered")


# =============================================================================
# Custom OpenAPI schema — adds security schemes and server info
# =============================================================================
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

    # Add security schemes
    openapi_schema.setdefault("components", {})
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token obtained from POST /auth/break-glass/login, POST /auth/refresh, or OAuth 2.0 Device Flow",
        },
        "ApiKeyAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key obtained from POST /api/api-keys (format: agh_xxxx...)",
        },
        "SessionAuth": {
            "type": "apiKey",
            "in": "cookie",
            "name": "session",
            "description": "Session cookie set during OAuth login callback",
        },
    }

    # Apply security globally (any one of these methods)
    openapi_schema["security"] = [
        {"BearerAuth": []},
        {"ApiKeyAuth": []},
        {"SessionAuth": []},
    ]

    # Add servers
    openapi_schema["servers"] = [
        {"url": "http://localhost:8000", "description": "Local development"},
        {"url": "https://api.auditgh.local", "description": "Production"},
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

if is_sandbox():
    def sandbox_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
            tags=app.openapi_tags,
        )

        # Sandbox uses API key auth only
        openapi_schema.setdefault("components", {})
        openapi_schema["components"]["securitySchemes"] = {
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "Sandbox API key (see GET /api/sandbox/keys for available keys)",
            },
        }
        openapi_schema["security"] = [{"ApiKeyAuth": []}]
        openapi_schema["servers"] = [
            {"url": "http://localhost:8001", "description": "Sandbox"},
        ]

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = sandbox_openapi
else:
    app.openapi = custom_openapi


# Startup event to initialize secrets from environment
@app.on_event("startup")
async def startup_event():
    """Initialize secrets manager, scheduler, and Cribl logger on API startup."""
    # Initialize secrets manager
    try:
        import sys
        sys.path.insert(0, '/app/execution')
        from secrets_manager import initialize_secrets_from_env
        await initialize_secrets_from_env()
        logger.info("Secrets manager initialized from environment")
    except Exception as e:
        logger.warning(f"Failed to initialize secrets manager: {e}")
    
    # Initialize and start scheduler
    try:
        from .scheduler import get_scheduler
        sched = get_scheduler()
        sched.configure()
        await sched.start()
        logger.info("Scheduler service started")
    except Exception as e:
        logger.warning(f"Failed to start scheduler: {e}")
    
    # Initialize Cribl logger
    try:
        from .utils.cribl_logger import setup_cribl_logger
        setup_cribl_logger()
        logger.info("Cribl logger initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize Cribl logger: {e}")

    # Initialize RBAC roles and permissions
    try:
        from src.rbac.seeds import init_rbac_if_needed
        from .database import SessionLocal
        db = SessionLocal()
        init_rbac_if_needed(db)
        db.close()
        logger.info("RBAC initialization complete")
    except Exception as e:
        logger.warning(f"Failed to initialize RBAC: {e}")

    # Sandbox initialization — seed dummy data on first boot
    if is_sandbox():
        try:
            from .sandbox_seed import initialize_sandbox
            await initialize_sandbox()
            logger.info("Sandbox initialization complete")
        except Exception as e:
            logger.warning(f"Failed to initialize sandbox: {e}")

        # Schedule periodic auto-reset
        try:
            from .sandbox import SANDBOX_AUTO_RESET_HOURS
            if SANDBOX_AUTO_RESET_HOURS > 0:
                import asyncio
                from .sandbox_seed import reset_and_seed as _sandbox_reset

                async def _auto_reset_loop():
                    while True:
                        await asyncio.sleep(SANDBOX_AUTO_RESET_HOURS * 3600)
                        try:
                            db = SessionLocal()
                            await _sandbox_reset(db)
                            db.close()
                            logger.info("Sandbox auto-reset completed")
                        except Exception as exc:
                            logger.warning(f"Sandbox auto-reset failed: {exc}")

                asyncio.get_event_loop().create_task(_auto_reset_loop())
                logger.info(f"Sandbox auto-reset scheduled every {SANDBOX_AUTO_RESET_HOURS}h")
        except Exception as e:
            logger.warning(f"Failed to schedule sandbox auto-reset: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    try:
        from .scheduler import get_scheduler
        sched = get_scheduler()
        await sched.stop()
        logger.info("Scheduler service stopped")
    except Exception as e:
        logger.warning(f"Error stopping scheduler: {e}")
    
    # Shutdown Cribl logger
    try:
        from .utils.cribl_logger import shutdown_cribl_logger
        shutdown_cribl_logger()
        logger.info("Cribl logger stopped")
    except Exception as e:
        logger.warning(f"Error stopping Cribl logger: {e}")


# CORS Configuration - Environment-based origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=auth_settings.cors_origins,
    allow_credentials=auth_settings.cors_allow_credentials,
    allow_methods=auth_settings.cors_allow_methods,
    allow_headers=auth_settings.cors_allow_headers,
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"]
)

# Add organization context middleware (extracts org from headers/params)
app.add_middleware(OrganizationContextMiddleware)

# Add session activity tracking middleware (updates last_activity for idle timeout)
from src.auth.middleware import SessionActivityMiddleware, SecurityHeadersMiddleware
app.add_middleware(SessionActivityMiddleware)

# Add authentication middleware (sandbox uses simplified API-key-only auth)
if is_sandbox():
    from src.api.middleware.sandbox_auth import SandboxAuthMiddleware
    app.add_middleware(SandboxAuthMiddleware)
    logger.info("Sandbox auth middleware active (API key only)")
else:
    from src.api.middleware.auth import AuthenticationMiddleware
    app.add_middleware(AuthenticationMiddleware)

# Add security headers middleware (CSP, HSTS, X-Frame-Options, etc.)
app.add_middleware(
    SecurityHeadersMiddleware,
    enforce_https=(os.getenv("ENVIRONMENT") == "production")
)

# Add tenant middleware if multi-tenant is enabled
# Note: Add AFTER CORS middleware so it runs first
if MULTI_TENANT_ENABLED:
    app.add_middleware(TenantMiddleware)

# Add request logging middleware (wraps all other middleware for full lifecycle logging)
from src.api.middleware.logging import RequestLoggingMiddleware
app.add_middleware(RequestLoggingMiddleware)

if is_sandbox():
    @app.get("/", summary="Sandbox Developer Portal", tags=["default"], include_in_schema=False, response_class=HTMLResponse)
    async def root():
        """Sandbox developer portal landing page."""
        return HTMLResponse(content="""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuditGH Sandbox</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:2rem}
h1{font-size:2rem;margin-bottom:.5rem;color:#38bdf8}
.subtitle{color:#94a3b8;margin-bottom:2rem;font-size:1.1rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1.5rem;max-width:960px;width:100%;margin-bottom:2rem}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:1.5rem;transition:border-color .2s}
.card:hover{border-color:#38bdf8}
.card h2{font-size:1.2rem;margin-bottom:.5rem;color:#f1f5f9}
.card p{color:#94a3b8;margin-bottom:1rem;font-size:.9rem}
.card a{display:inline-block;background:#0ea5e9;color:#fff;padding:.5rem 1rem;border-radius:6px;text-decoration:none;font-size:.9rem}
.card a:hover{background:#0284c7}
table{border-collapse:collapse;max-width:960px;width:100%;margin-top:1rem}
th,td{text-align:left;padding:.6rem 1rem;border-bottom:1px solid #334155}
th{color:#38bdf8;font-size:.85rem;text-transform:uppercase;letter-spacing:.05em}
td{font-size:.9rem}
code{background:#334155;padding:.15rem .4rem;border-radius:4px;font-size:.85rem;color:#7dd3fc}
.note{color:#64748b;font-size:.8rem;margin-top:1.5rem;text-align:center}
</style>
</head>
<body>
<h1>AuditGH Sandbox</h1>
<p class="subtitle">Isolated developer environment with synthetic data &mdash; resets every 24 hours</p>
<div class="cards">
  <div class="card">
    <h2>Swagger UI</h2>
    <p>Interactive API explorer with try-it-out. Paste a sandbox API key to authenticate.</p>
    <a href="/docs">Open /docs</a>
  </div>
  <div class="card">
    <h2>Swagger Editor</h2>
    <p>Edit and validate the OpenAPI spec live. Runs on port 8080.</p>
    <a href="http://localhost:8080" target="_blank">Open Editor</a>
  </div>
  <div class="card">
    <h2>ReDoc</h2>
    <p>Beautiful, responsive API documentation. Great for reading and sharing.</p>
    <a href="/redoc">Open /redoc</a>
  </div>
</div>
<h2 style="color:#f1f5f9;margin-bottom:.5rem">Sandbox API Keys</h2>
<table>
<tr><th>Name</th><th>Role</th><th>Key</th></tr>
<tr><td>sandbox-admin-key</td><td>super_admin</td><td><code>sbx_admin_4a8b2c1d3e5f6789</code></td></tr>
<tr><td>sandbox-analyst-key</td><td>analyst</td><td><code>sbx_analyst_9f8e7d6c5b4a3210</code></td></tr>
<tr><td>sandbox-readonly-key</td><td>viewer</td><td><code>sbx_readonly_1a2b3c4d5e6f7890</code></td></tr>
</table>
<p class="note">Data resets automatically every 24 hours. Admin key can trigger an immediate reset via POST /api/sandbox/reset.</p>
</body>
</html>""")
else:
    @app.get("/", summary="API root", tags=["default"], include_in_schema=False)
    async def root():
        """Return API welcome message and links."""
        return {
            "message": "Welcome to AuditGH Security Portal API",
            "docs": "/docs",
            "redoc": "/redoc",
            "version": "2.0.0",
            "multi_tenant": MULTI_TENANT_ENABLED
        }

@app.get(
    "/health",
    summary="Health check",
    tags=["default"],
    response_model=None,
    responses={
        200: {"description": "All systems healthy"},
        503: {"description": "One or more dependencies unhealthy"},
    },
)
async def health_check():
    """Health check endpoint reporting database, Redis, and overall system status."""
    from datetime import datetime
    from sqlalchemy import text
    from .database import SessionLocal

    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "checks": {},
        "multi_tenant": MULTI_TENANT_ENABLED
    }

    # Check database
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        health_status["checks"]["database"] = "healthy"
    except Exception as e:
        health_status["checks"]["database"] = f"unhealthy: {str(e)}"
        health_status["status"] = "unhealthy"

    # Check Redis
    try:
        from src.auth.tokens import redis_client
        redis_client.ping()
        health_status["checks"]["redis"] = "healthy"
    except Exception as e:
        health_status["checks"]["redis"] = f"unhealthy: {str(e)}"
        health_status["status"] = "unhealthy"

    # Log health check result
    if health_status["status"] == "healthy":
        loguru_logger.bind(event_type="HEALTH_CHECK", checks=health_status["checks"]).info("Health check: all systems healthy")
    else:
        loguru_logger.bind(event_type="HEALTH_CHECK", checks=health_status["checks"]).warning(f"Health check: {health_status['status']}")

    return health_status

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# Authentication Module

This module provides OIDC/SSO authentication for the AuditGitHub platform with support for multiple identity providers (Entra ID and Okta).

## Components

### Models (`models.py`)
- **User**: Pydantic model representing an authenticated user with `email`, `name`, `sub`, and `provider` fields

### Middleware (`middleware.py`)
- **JWT Validation**: Validates Bearer tokens using cached JWKS public keys
- **JWKS Caching**: 24-hour cache to prevent performance issues
- **Security Features**:
  - Explicit algorithm whitelist (RS256, RS384, RS512) prevents "none" algorithm attack
  - Validates aud/iss/exp claims to prevent confused deputy attacks

### Dependencies (`dependencies.py`)
- **get_current_user_from_session**: Session-based auth (cookies) for browser apps
- **get_current_user_from_token**: Token-based auth (Bearer) for API clients
- **get_current_user**: Alias for session-based auth (default)

### Configuration (`config.py`)
- **Settings**: OIDC provider configurations (Entra ID, Okta)
- **Discovery URLs**: Automatic OIDC discovery endpoint resolution

### Providers (`providers.py`)
- **OAuth Registry**: Registers identity providers with Authlib
- **init_oauth()**: Initializes OAuth providers with OIDC discovery

## Protecting Routes

To require authentication on a route, add the `current_user` dependency:

```python
from fastapi import APIRouter, Depends
from src.auth.dependencies import get_current_user
from src.auth.models import User

router = APIRouter()

@router.get("/protected-endpoint")
async def protected_endpoint(current_user: User = Depends(get_current_user)):
    """This endpoint requires authentication."""
    return {
        "message": "You are authenticated",
        "user": current_user.email
    }
```

### For Session-Based Auth (Browser Apps)

Use the default `get_current_user`:

```python
@router.get("/my-data")
async def get_my_data(
    current_user: User = Depends(get_current_user)
):
    """Requires cookie-based session authentication."""
    return {"user_email": current_user.email}
```

### For Token-Based Auth (API Clients)

Explicitly use `get_current_user_from_token`:

```python
from src.auth.dependencies import get_current_user_from_token

@router.get("/api/data")
async def get_api_data(
    current_user: User = Depends(get_current_user_from_token)
):
    """Requires Bearer token authentication."""
    return {"data": "protected", "user": current_user.sub}
```

## Authentication Flow

1. **Login**: User visits `/auth/login/{provider}` (entra or okta)
2. **Authorization**: Redirected to identity provider for authentication
3. **Callback**: Provider redirects to `/auth/callback/{provider}` with authorization code
4. **Token Exchange**: Backend exchanges code for access token and ID token (with PKCE)
5. **Session**: User info stored in session cookie
6. **Protected Routes**: Subsequent requests include session cookie or Bearer token

## Future Enhancements

### Phase 3: RBAC System
Role-based access control will be added to filter resources based on user roles:
- Super Admin: Full platform access
- Admin: Organization-level access
- Analyst: Read-only security data
- Manager: Team-level access
- User: Limited access

Routes will be updated to check roles:
```python
# Example for Phase 3
from src.auth.dependencies import require_role

@router.delete("/admin/data")
async def admin_only(
    current_user: User = Depends(require_role("admin"))
):
    """Only admins can access this."""
    return {"message": "Admin access granted"}
```

### Phase 4: Multi-Tenant Architecture
Tenant filtering will be added to isolate data by organization:
```python
# Example for Phase 4
@router.get("/findings")
async def get_findings(
    current_user: User = Depends(get_current_user),
    tenant: Tenant = Depends(get_current_tenant)
):
    """Filter findings by tenant automatically."""
    # Findings filtered by tenant.id in database query
    return findings
```

## Security Considerations

### DO
- Always use `get_current_user` or `get_current_user_from_token` on protected routes
- Validate email_verified claim before trusting email addresses
- Use HTTPS in production (set `https_only=True` in SessionMiddleware)
- Rotate session secrets regularly

### DON'T
- Don't skip authentication on sensitive endpoints
- Don't expose token validation errors (information leakage)
- Don't allow "none" algorithm in JWT validation
- Don't trust client-provided user data without authentication

## References

- See `.planning/phases/02-authentication-foundation/02-RESEARCH.md` for security patterns
- See `.planning/phases/02-authentication-foundation/02-03-PLAN.md` for implementation plan

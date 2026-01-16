# RBAC Implementation Research for FastAPI

**Research Date**: 2026-01-12
**Phase**: Phase 3 - RBAC System
**Context**: AuditGH Enterprise Security Platform - 5-tier RBAC with multi-tenant support

## Executive Summary

This research covers comprehensive RBAC (Role-Based Access Control) implementation for FastAPI enterprise applications. Key findings:

1. **Standard Stack**: FastAPI has no dominant RBAC library. Best practice is custom implementation using FastAPI's dependency injection + external policy engines (Casbin/OPA) for complex authorization logic. Avoid `fastapi-users` for RBAC (no built-in role support).

2. **Architecture**: Dependency injection-based permission decorators are the FastAPI-native pattern. For 5-tier hierarchy with multi-tenant isolation, use hybrid RBAC+ABAC approach with tenant context in JWT claims.

3. **Don't Hand-Roll**: Use policy engines (Casbin, OPA) for complex permission evaluation. Don't build custom JWT validation (use `python-jose`), don't build audit logging from scratch (use structured logging + external service).

4. **Security**: Top risks are permission bypass through authorization code bugs, role confusion in hierarchies, and missing audit trails. OWASP ranks broken access control as #1 vulnerability for 2025.

5. **Production Patterns**: Real-world implementations use FastAPI Depends() for permission checks, database-backed roles/permissions with caching (Redis), and JWT claims for tenant context.

---

## 1. Standard Stack: Authoritative RBAC Libraries for FastAPI

### Key Finding: No Dominant FastAPI RBAC Library

Unlike authentication (where `python-jose`, `authlib` are standard), **RBAC in FastAPI has no authoritative library**. The ecosystem is fragmented with multiple approaches:

#### ❌ **fastapi-users**: Not Recommended for RBAC
- **Status**: Popular for authentication (user registration, login, password reset)
- **RBAC Support**: None built-in, explicitly out of scope per maintainer
- **Verdict**: Use for auth foundation, but build RBAC separately
- **Source**: [FastAPI Users GitHub Discussion #454](https://github.com/fastapi-users/fastapi-users/discussions/454) - maintainer states "it would be better if another library implements this kind of logic"

#### ⚠️ **fastapi-permissions**: Row-Level Security, Not Enterprise RBAC
- **PyPI**: `fastapi_permissions` by holgi
- **Focus**: Row-level permissions based on resource state
- **Limitation**: Not designed for hierarchical roles or complex RBAC
- **Use Case**: Good for simple "can user X access resource Y" checks
- **Verdict**: Too limited for 5-tier enterprise RBAC
- **GitHub**: https://github.com/holgi/fastapi-permissions

#### ✅ **Recommended Approach**: Custom Implementation + External Policy Engine

**For Enterprise RBAC (5-tier hierarchy, multi-tenant), build custom using**:

1. **FastAPI Native Patterns**:
   - Dependency injection (`Depends()`) for permission checks
   - Custom decorators wrapping dependencies
   - JWT claims for roles and tenant context

2. **External Policy Engines** (for complex authorization logic):
   - **Casbin**: Lightweight, supports RBAC/ABAC/ACL, Python SDK available
   - **Open Policy Agent (OPA)**: Enterprise-grade, declarative policy language (Rego), more complex setup
   - **Commercial Services**: Permit.io, Auth0 FGA, Cerbos (for offloading authorization)

### Policy Engine Comparison

| Feature | Casbin | Open Policy Agent (OPA) | Commercial (Permit.io, Auth0 FGA) |
|---------|--------|-------------------------|-----------------------------------|
| **Language** | Python native | Go (Python client) | API-based (language agnostic) |
| **Policy DSL** | CSV/PERM (simpler) | Rego (more flexible) | Web UI + API |
| **Complexity** | Low | Medium-High | Low (managed service) |
| **Performance** | Excellent (in-process) | Good (HTTP API) | Network latency |
| **Multi-tenancy** | Manual | Manual | Built-in |
| **Audit Logging** | Manual | Manual | Built-in |
| **Cost** | Free (open source) | Free (open source) | $$ (per user/MAU) |
| **Best For** | 5-tier RBAC with moderate complexity | Complex attribute-based policies | Rapid development, compliance-heavy |

**Recommendation for AuditGH**:
- **Start with Casbin** for 5-tier RBAC (simpler, Python-native, sufficient for role hierarchy)
- **Consider OPA** if you need complex attribute-based rules (e.g., "Analyst can view findings if severity > HIGH and tenant matches")
- **Avoid commercial** unless compliance/audit logging is critical and you want to outsource

### FastAPI Integration Libraries

#### ✅ **axioms-fastapi**: OAuth2 + JWT + Claims-Based Authorization
- **PyPI**: `axioms-fastapi`
- **Features**: Validates JWT from AWS Cognito, Auth0, Okta, Microsoft Entra; supports scopes, roles, permissions
- **Use Case**: If you want claims-based authorization (roles in JWT) without external policy engine
- **Limitation**: No hierarchical roles, no resource-level permissions
- **Verdict**: Good for simple RBAC, integrate with Casbin for complex logic
- **Docs**: https://www.abhishek-tiwari.com/securing-fastapi-applications-with-jwt-tokens-and-oauth2-using-axioms-fastapi/

#### ✅ **fast-api-jwt-middleware**: OIDC + RBAC Decorator
- **PyPI**: `fast-api-jwt-middleware`
- **Features**: Validates OIDC tokens, supports `@secure_route(roles=["admin"])` decorator
- **Use Case**: Simple role checks from JWT claims
- **Limitation**: No permission granularity beyond roles
- **Verdict**: Use for route-level role checks, not sufficient for fine-grained permissions
- **Docs**: https://pypi.org/project/fast-api-jwt-middleware/

### Dependency Injection Patterns for Role Checking

**FastAPI's canonical pattern** for RBAC: reusable dependencies with nested composition.

#### Pattern 1: Permission Dependency Factory

```python
from fastapi import Depends, HTTPException, status
from typing import List

def require_permissions(required_permissions: List[str]):
    """
    Factory function to create permission-checking dependency.

    Usage:
        @app.get("/admin/users", dependencies=[Depends(require_permissions(["users:read", "users:write"]))])
        async def list_users():
            return {"users": [...]}
    """
    async def permission_checker(user: User = Depends(get_current_user)):
        # Get user's permissions from database or JWT claims
        user_permissions = await get_user_permissions(user.id)

        # Check if user has all required permissions
        if not all(perm in user_permissions for perm in required_permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )

        return user

    return permission_checker
```

#### Pattern 2: Role Hierarchy Dependency

```python
from enum import IntEnum

class Role(IntEnum):
    """5-tier role hierarchy with numeric ordering for comparison."""
    USER = 1
    MANAGER = 2
    ANALYST = 3
    ADMIN = 4
    SUPER_ADMIN = 5

def require_role(minimum_role: Role):
    """
    Require user to have at least the specified role level.

    Usage:
        @app.delete("/findings/{id}", dependencies=[Depends(require_role(Role.ADMIN))])
        async def delete_finding(id: int):
            return {"deleted": id}
    """
    async def role_checker(user: User = Depends(get_current_user)):
        user_role = Role[user.role.upper()]

        if user_role < minimum_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {minimum_role.name} role or higher"
            )

        return user

    return role_checker
```

#### Pattern 3: Resource-Level Permissions (Multi-Tenant)

```python
async def require_tenant_access(resource_id: int, user: User = Depends(get_current_user)):
    """
    Verify user's tenant has access to the requested resource.

    Usage:
        @app.get("/organizations/{org_id}/findings")
        async def get_findings(
            org_id: int,
            user: User = Depends(require_tenant_access)
        ):
            # User's tenant_id was already validated
            return {"findings": [...]}
    """
    # Get resource's tenant_id from database
    resource = await db.get_resource(resource_id)

    if resource.tenant_id != user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this resource"
        )

    return user
```

---

## 2. Architecture Patterns: How RBAC Should Be Structured

### Permission Decorator Design Patterns

#### Recommended: Decorator + Dependency Injection Hybrid

Combine Python decorators (for readability) with FastAPI dependencies (for testability):

```python
from functools import wraps
from fastapi import Depends

def authorize(*permissions: str):
    """
    Authorization decorator for FastAPI routes.

    Usage:
        @app.put("/users/{user_id}")
        @authorize("users:read", "users:write")
        async def update_user(user_id: int, user_update: UserUpdate):
            ...
    """
    def decorator(func):
        # Create permission dependency
        permission_dependency = require_permissions(list(permissions))

        # Add dependency to function's signature
        # This is a hack but works with FastAPI's dependency injection
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Inject the dependency manually
            user = await permission_dependency(**kwargs)
            kwargs['user'] = user
            return await func(*args, **kwargs)

        # Register dependency with FastAPI
        wrapper.__fastapi_dependencies__ = [Depends(permission_dependency)]
        return wrapper

    return decorator
```

**Better Alternative**: Use `fastapi-decorators` library (see below)

#### fastapi-decorators Library Pattern

```python
from fastapi_decorators import depends

def authorize(*scopes: str):
    def dependency(token: str | None = Depends(oauth2_scheme)):
        if not token:
            raise HTTPException(status_code=401, detail="Unauthenticated")
        if not all(scope in token.scopes for scope in scopes):
            raise HTTPException(status_code=403, detail="Unauthorized")
    return depends(dependency)

@app.put("/users/{user_id}")
@authorize("users:read", "users:write")
def update_user(*, user_id: int, user_update: UserUpdate):
    ...
```

**Source**: [GitHub - Minibrams/fastapi-decorators](https://github.com/Minibrams/fastapi-decorators)

### Role Hierarchy Implementation (5-Tier)

#### Database Schema

```python
# SQLAlchemy models for RBAC

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)  # "super_admin", "admin", etc.
    level = Column(Integer, nullable=False)  # 1-5 for hierarchy
    description = Column(String)

    # Relationships
    permissions = relationship("RolePermission", back_populates="role")
    users = relationship("UserRole", back_populates="role")

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)  # "findings:read", "orgs:delete"
    resource = Column(String, nullable=False)  # "findings", "organizations", "users"
    action = Column(String, nullable=False)  # "read", "write", "delete", "execute"
    description = Column(String)

    # Relationships
    roles = relationship("RolePermission", back_populates="permission")

class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id = Column(Integer, ForeignKey("roles.id"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("permissions.id"), primary_key=True)

    # Relationships
    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")

class UserRole(Base):
    __tablename__ = "user_roles"

    user_id = Column(String, primary_key=True)  # OIDC 'sub' claim
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)

    # Relationships
    role = relationship("Role", back_populates="users")
    tenant = relationship("Tenant")
```

#### 5-Tier Role Definitions

```python
# Role hierarchy for AuditGH
ROLES = {
    "super_admin": {
        "level": 5,
        "description": "Platform administrator with full system access",
        "permissions": [
            "tenants:*",  # Manage all tenants
            "users:*",    # Manage all users across tenants
            "roles:*",    # Manage roles and permissions
            "system:*",   # System configuration
            "*:*"         # Wildcard - full access
        ]
    },
    "admin": {
        "level": 4,
        "description": "Tenant administrator with full tenant access",
        "permissions": [
            "organizations:*",  # Manage organizations within tenant
            "users:*",          # Manage users within tenant
            "findings:*",       # Full access to security findings
            "scans:*",          # Manage scans
            "reports:*",        # Generate and manage reports
            "integrations:*"    # Configure integrations (Jira, etc.)
        ]
    },
    "analyst": {
        "level": 3,
        "description": "Security analyst with read/write access to findings",
        "permissions": [
            "findings:read",
            "findings:write",   # Update finding status, add comments
            "findings:export",  # Export findings data
            "scans:read",
            "scans:execute",    # Trigger new scans
            "reports:read",
            "reports:generate"  # Generate reports but not modify templates
        ]
    },
    "manager": {
        "level": 2,
        "description": "Team manager with read access and reporting",
        "permissions": [
            "findings:read",
            "scans:read",
            "reports:read",
            "reports:generate",
            "dashboards:read"
        ]
    },
    "user": {
        "level": 1,
        "description": "Basic user with read-only access",
        "permissions": [
            "findings:read",
            "scans:read",
            "reports:read",
            "dashboards:read"
        ]
    }
}
```

#### Permission Naming Convention

**Hierarchical Structure**: `resource:action[:scope]`

```
# System-level permissions (super_admin only)
sys:roles:create
sys:roles:delete
sys:tenants:create

# Data-level permissions (tenant-scoped)
findings:read
findings:write
findings:delete
organizations:read
organizations:write

# Action-level permissions
scans:execute
reports:generate
integrations:configure

# Wildcard permissions
findings:*      # All actions on findings
*:read          # Read access to all resources
*:*             # Full access (super_admin)
```

**Source**: [fastapi_best_architecture RBAC Documentation](https://deepwiki.com/fastapi-practices/fastapi_best_architecture/3.2-rbac-system)

### Resource-Level Permissions (Per-Tenant, Per-Resource)

#### Multi-Tenant Isolation Strategy

**Approach**: Combine RBAC (roles) with ABAC (attributes like tenant_id) for resource-level control.

```python
from contextvars import ContextVar

# Global context variable for tenant isolation
current_tenant_context: ContextVar[Optional[int]] = ContextVar('current_tenant_context', default=None)

class TenantMiddleware(BaseHTTPMiddleware):
    """
    Middleware to set tenant context from JWT claims.
    All database queries will be filtered by this tenant_id.
    """
    async def dispatch(self, request: Request, call_next):
        # Extract tenant_id from JWT claims
        user = await get_current_user_from_token(request)

        # Set tenant context for this request
        token = current_tenant_context.set(user.tenant_id)

        try:
            response = await call_next(request)
            return response
        finally:
            # Clear context after request
            current_tenant_context.reset(token)
```

#### SQLAlchemy Query Filter for Tenant Isolation

```python
from sqlalchemy import event
from sqlalchemy.orm import Session

@event.listens_for(Session, "before_flush")
def receive_before_flush(session, flush_context, instances):
    """
    Automatically filter all queries by current tenant context.
    This prevents accidental cross-tenant data leakage.
    """
    tenant_id = current_tenant_context.get()

    if tenant_id is None:
        # No tenant context - this is an error for most operations
        raise RuntimeError("Tenant context not set for database operation")

    # Apply tenant filter to all queries
    for query in session.query_stack:
        if hasattr(query.column_descriptions[0]['entity'], 'tenant_id'):
            query = query.filter_by(tenant_id=tenant_id)
```

**Better Approach**: Use PostgreSQL Row-Level Security (RLS) for database-enforced isolation (see Multi-Tenancy section below).

### Claim-Based vs Role-Based vs Attribute-Based Access Control

#### Comparison Table

| Model | Description | Best For | Implementation Complexity |
|-------|-------------|----------|---------------------------|
| **Role-Based (RBAC)** | Users assigned roles, roles have permissions | Simple hierarchies, stable permissions | Low |
| **Claim-Based** | Permissions stored in JWT claims | Stateless APIs, distributed systems | Low-Medium |
| **Attribute-Based (ABAC)** | Rules based on attributes (user, resource, context) | Complex policies, dynamic access | High |
| **Hybrid (RBAC+ABAC)** | Roles + tenant/resource attributes | Multi-tenant SaaS, enterprise | Medium |

#### Recommended for AuditGH: Hybrid RBAC + ABAC

**Rationale**:
- **RBAC** for role hierarchy (super_admin > admin > analyst > manager > user)
- **ABAC** for tenant isolation (user.tenant_id == resource.tenant_id)
- **Claim-Based** for stateless API authentication (roles in JWT)

```python
async def check_permission(
    user: User,
    resource: str,
    action: str,
    resource_id: Optional[int] = None
) -> bool:
    """
    Hybrid RBAC+ABAC permission check.

    Steps:
    1. Check if user's role has the required permission (RBAC)
    2. Check if user's tenant matches resource's tenant (ABAC)
    3. Check any additional attribute-based rules (e.g., time-based, IP-based)
    """
    # 1. RBAC: Check role permissions
    required_permission = f"{resource}:{action}"
    user_permissions = await get_role_permissions(user.role_id)

    if not matches_permission(required_permission, user_permissions):
        return False

    # 2. ABAC: Check tenant isolation
    if resource_id:
        resource_obj = await db.get_resource(resource, resource_id)
        if resource_obj.tenant_id != user.tenant_id:
            return False

    # 3. Additional ABAC rules (future)
    # - Time-based: user.session_expires_at > now()
    # - IP-based: user.ip_address in allowed_ranges
    # - Context-based: user.location == resource.required_location

    return True

def matches_permission(required: str, user_permissions: List[str]) -> bool:
    """
    Check if user has required permission, supporting wildcards.

    Examples:
        required="findings:read", permissions=["findings:*"] -> True
        required="findings:delete", permissions=["*:*"] -> True
        required="findings:read", permissions=["findings:write"] -> False
    """
    resource_req, action_req = required.split(":")

    for perm in user_permissions:
        resource_perm, action_perm = perm.split(":")

        # Check wildcard matches
        if resource_perm == "*" or resource_perm == resource_req:
            if action_perm == "*" or action_perm == action_req:
                return True

    return False
```

### Integration with JWT Claims and Authentication Middleware

#### JWT Claim Structure for RBAC

```json
{
  "sub": "00u1234567890abcdef",
  "email": "analyst@company.com",
  "name": "Jane Analyst",
  "email_verified": true,
  "iss": "https://tenant.okta.com/oauth2/default",
  "aud": "api://auditgh",
  "iat": 1705075200,
  "exp": 1705078800,

  "tenant_id": 42,
  "role": "analyst",
  "permissions": [
    "findings:read",
    "findings:write",
    "scans:read",
    "scans:execute"
  ]
}
```

**Key Claims**:
- `tenant_id`: Multi-tenant isolation (ABAC attribute)
- `role`: User's role name (RBAC)
- `permissions`: Flattened list of permissions (optional, for performance)

**Security Note**: Don't trust JWT claims blindly. Always validate:
1. Token signature (JWKS verification)
2. `iss` (issuer) matches expected IdP
3. `aud` (audience) matches your API
4. `exp` (expiration) is in future
5. `tenant_id` matches database record

#### Middleware for Permission Validation

```python
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

class RBACMiddleware(BaseHTTPMiddleware):
    """
    Middleware to validate permissions for all routes.
    Runs after authentication, before route handler.
    """

    async def dispatch(self, request: Request, call_next):
        # Skip auth routes
        if request.url.path.startswith("/auth/"):
            return await call_next(request)

        # Get user from token (already validated by auth middleware)
        try:
            user = await get_current_user_from_token(request)
        except HTTPException:
            # Not authenticated, let route handle it
            return await call_next(request)

        # Extract required permissions from route
        # (Set via route dependencies or custom metadata)
        route = request.scope.get("route")
        required_permissions = getattr(route, "required_permissions", [])

        if required_permissions:
            # Check if user has all required permissions
            user_permissions = await get_user_permissions(user.id)

            for perm in required_permissions:
                if not matches_permission(perm, user_permissions):
                    raise HTTPException(
                        status_code=403,
                        detail=f"Missing required permission: {perm}"
                    )

        # Permission check passed, continue to route
        response = await call_next(request)
        return response
```

**Alternative**: Use FastAPI dependencies instead of middleware (more explicit, better for testing):

```python
@app.get(
    "/findings",
    dependencies=[Depends(require_permissions(["findings:read"]))]
)
async def list_findings(user: User = Depends(get_current_user)):
    return {"findings": [...]}
```

---

## 3. Don't Hand-Roll Guidance: What Should NOT Be Custom-Built

### Permission Evaluation Engines

#### ❌ Don't Build: Complex Policy Evaluation Logic

**What to avoid**:
- Custom DSL for permission rules
- Manual evaluation of nested AND/OR conditions
- Complex attribute-based rules engine

**Why**:
- Bug-prone (security-critical code)
- Performance optimization is hard (caching, indexing)
- Difficult to audit and test

**Use instead**: Policy engines like Casbin or OPA

#### ✅ Use Casbin for RBAC/ABAC

**Installation**:
```bash
pip install casbin casbin-sqlalchemy-adapter
```

**Basic Setup**:
```python
import casbin
from casbin_sqlalchemy_adapter import Adapter

# Load policy from database
adapter = Adapter('postgresql://user:pass@localhost/db')
enforcer = casbin.Enforcer('model.conf', adapter)

# Check permission
if enforcer.enforce(user_id, resource, action):
    # User has permission
    pass
```

**Model Configuration** (`model.conf`):
```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

**Policy Examples**:
```csv
# Roles
g, alice, admin
g, bob, analyst

# Permissions
p, admin, findings, read
p, admin, findings, write
p, analyst, findings, read
```

**Sources**:
- [Casbin Official Docs](https://www.casbin.org/)
- [OPA vs Casbin Comparison](https://gist.github.com/StevenACoffman/1644ec1157a793eb7d868aa22b260e91)

### Role Inheritance Systems

#### ❌ Don't Build: Complex Role Hierarchy Resolution

**What to avoid**:
- Recursive role inheritance (roles inheriting from roles)
- Multiple inheritance with conflict resolution
- Dynamic role composition

**Why**:
- Complex edge cases (diamond problem, circular dependencies)
- Hard to visualize and debug
- Performance issues with deep hierarchies

**Use instead**: Flat 5-tier hierarchy with explicit permissions

#### ✅ Recommended: Level-Based Hierarchy

```python
class Role(IntEnum):
    """
    Simple level-based hierarchy.
    Higher level inherits all permissions of lower levels.
    """
    USER = 1
    MANAGER = 2
    ANALYST = 3
    ADMIN = 4
    SUPER_ADMIN = 5

def user_has_role_level(user_role: Role, required_role: Role) -> bool:
    """Simple comparison, no complex inheritance logic."""
    return user_role >= required_role
```

**If you need complex inheritance**, use Casbin's group inheritance (`g, user, role`).

### Audit Logging Frameworks

#### ❌ Don't Build: Custom Audit Log Storage and Querying

**What to avoid**:
- Custom database tables for audit logs
- Custom query interfaces for log analysis
- Custom log retention and archival logic

**Why**:
- Security logs should be immutable and tamper-proof (requires specialized storage)
- Compliance requirements (GDPR, SOC2) need specific log formats
- Log analysis at scale requires specialized tools

**Use instead**: Structured logging + External service

#### ✅ Recommended: Loguru + Cribl/ELK/Datadog

**Pattern**:
```python
import loguru
from loguru import logger

# Configure structured logging
logger.add(
    "audit.log",
    format="{time} {level} {message}",
    serialize=True,  # JSON format
    rotation="1 day",
    retention="90 days"
)

def log_access_control_decision(
    user_id: str,
    resource: str,
    action: str,
    decision: bool,
    reason: str = ""
):
    """
    Log every access control decision for audit trail.
    """
    logger.info(
        "access_control",
        extra={
            "event_type": "authorization",
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "decision": "allow" if decision else "deny",
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
```

**Send logs to external service**:
- **Cribl**: Centralized log management (Phase 6 of AuditGH roadmap)
- **ELK Stack**: Elasticsearch + Logstash + Kibana (self-hosted)
- **Datadog/Splunk**: Commercial SaaS (expensive but powerful)

**Don't use**: Database tables for audit logs (performance, immutability concerns)

### Other Things Not to Hand-Roll

#### ❌ JWT Validation
- **Use**: `python-jose` or `authlib` (already in your stack)
- **Don't**: Parse JWT manually, validate signatures yourself

#### ❌ Password Hashing
- **Use**: `passlib` with bcrypt/argon2
- **Don't**: Implement your own hashing algorithm

#### ❌ CSRF Protection
- **Use**: Starlette's `CSRFMiddleware` or `itsdangerous`
- **Don't**: Roll your own token generation

#### ❌ Rate Limiting
- **Use**: `slowapi` (FastAPI wrapper for flask-limiter)
- **Don't**: Custom request counting logic

---

## 4. Common Pitfalls: Security Vulnerabilities and Mistakes to Avoid

### Permission Bypass Vulnerabilities

#### Pitfall 1: Authorization Check After Data Fetch

**Vulnerable Code**:
```python
@app.get("/findings/{id}")
async def get_finding(id: int, user: User = Depends(get_current_user)):
    # Fetch data first
    finding = await db.get_finding(id)

    # Then check permission (TOO LATE!)
    if user.tenant_id != finding.tenant_id:
        raise HTTPException(403, "Access denied")

    return finding
```

**Problem**: Data already loaded into memory, potential for timing attacks or error leakage.

**Fix**: Check permissions BEFORE data access:
```python
@app.get("/findings/{id}")
async def get_finding(
    id: int,
    user: User = Depends(get_current_user),
    _: None = Depends(require_permissions(["findings:read"]))
):
    # Permission already checked by dependency
    finding = await db.get_finding(id, tenant_id=user.tenant_id)
    return finding
```

#### Pitfall 2: Missing Permission Checks on Update/Delete

**Vulnerable Code**:
```python
@app.put("/findings/{id}")
async def update_finding(
    id: int,
    update: FindingUpdate,
    user: User = Depends(get_current_user)  # Only checks authentication!
):
    finding = await db.update_finding(id, update)
    return finding
```

**Problem**: Any authenticated user can update any finding (missing authorization).

**Fix**: Always check permissions on mutating operations:
```python
@app.put(
    "/findings/{id}",
    dependencies=[Depends(require_permissions(["findings:write"]))]
)
async def update_finding(
    id: int,
    update: FindingUpdate,
    user: User = Depends(get_current_user)
):
    # Verify tenant access
    finding = await db.get_finding(id, tenant_id=user.tenant_id)
    if not finding:
        raise HTTPException(404, "Finding not found")

    updated = await db.update_finding(id, update)
    return updated
```

#### Pitfall 3: Authorization Bypass Through Parameter Tampering

**Vulnerable Code**:
```python
@app.get("/organizations/{org_id}/findings")
async def get_findings(
    org_id: int,  # Attacker can change this!
    user: User = Depends(get_current_user)
):
    # Trusts client-provided org_id
    findings = await db.query(Finding).filter_by(organization_id=org_id).all()
    return findings
```

**Problem**: Attacker can access other organizations' data by changing `org_id` parameter.

**Fix**: Always validate org_id belongs to user's tenant:
```python
@app.get("/organizations/{org_id}/findings")
async def get_findings(
    org_id: int,
    user: User = Depends(get_current_user)
):
    # Verify organization belongs to user's tenant
    org = await db.get_organization(org_id, tenant_id=user.tenant_id)
    if not org:
        raise HTTPException(404, "Organization not found")

    findings = await db.query(Finding).filter_by(
        organization_id=org_id,
        tenant_id=user.tenant_id  # Double-check tenant isolation
    ).all()
    return findings
```

### Role Hierarchy Confusion

#### Pitfall 4: Inverted Hierarchy Checks

**Vulnerable Code**:
```python
def require_role(required_role: Role):
    async def checker(user: User = Depends(get_current_user)):
        if user.role_level < required_role.value:  # WRONG!
            raise HTTPException(403, "Insufficient role")
    return checker

# This means USER (level 1) > ADMIN (level 4) - backwards!
@app.delete("/findings/{id}", dependencies=[Depends(require_role(Role.ADMIN))])
async def delete_finding(id: int):
    ...
```

**Problem**: Logic is inverted - users with LOWER levels pass admin checks.

**Fix**: Use >= for hierarchy (higher number = more privileges):
```python
if user.role_level < required_role.value:  # USER (1) < ADMIN (4) -> deny
    raise HTTPException(403, "Insufficient role")
```

#### Pitfall 5: Role Confusion Across Tenants

**Vulnerable Code**:
```python
# Global role, not tenant-scoped
class User:
    role: str  # "admin"
    tenant_id: int

@app.delete("/tenants/{tenant_id}/data")
async def delete_tenant_data(
    tenant_id: int,
    user: User = Depends(require_role(Role.ADMIN))
):
    # Admin from Tenant A can delete Tenant B's data!
    await db.delete_tenant_data(tenant_id)
```

**Problem**: User's "admin" role in Tenant A applies globally, not just to their tenant.

**Fix**: Always scope roles to tenants:
```python
class UserRole(Base):
    user_id = Column(String, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)

async def get_user_role_for_tenant(user_id: str, tenant_id: int) -> Role:
    user_role = await db.query(UserRole).filter_by(
        user_id=user_id,
        tenant_id=tenant_id
    ).first()
    return user_role.role

@app.delete("/tenants/{tenant_id}/data")
async def delete_tenant_data(
    tenant_id: int,
    user: User = Depends(get_current_user)
):
    # Check user's role IN THIS SPECIFIC TENANT
    role = await get_user_role_for_tenant(user.id, tenant_id)
    if role.level < Role.ADMIN.value:
        raise HTTPException(403, "Must be admin of this tenant")

    await db.delete_tenant_data(tenant_id)
```

#### Pitfall 6: Super Admin Without Audit Logging

**Vulnerable Code**:
```python
@app.delete("/tenants/{tenant_id}")
async def delete_tenant(
    tenant_id: int,
    user: User = Depends(require_role(Role.SUPER_ADMIN))
):
    # No audit log - who deleted what?
    await db.delete_tenant(tenant_id)
    return {"deleted": tenant_id}
```

**Problem**: Super admins have powerful privileges, but no accountability.

**Fix**: Log ALL super admin actions:
```python
@app.delete("/tenants/{tenant_id}")
async def delete_tenant(
    tenant_id: int,
    user: User = Depends(require_role(Role.SUPER_ADMIN))
):
    # Audit log before action
    logger.warning(
        "super_admin_action",
        extra={
            "user_id": user.id,
            "action": "delete_tenant",
            "tenant_id": tenant_id,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

    await db.delete_tenant(tenant_id)
    return {"deleted": tenant_id}
```

### Caching Permission Checks Incorrectly

#### Pitfall 7: Stale Permission Cache

**Vulnerable Code**:
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
async def get_user_permissions(user_id: str) -> List[str]:
    """Cached permission lookup."""
    return await db.query(Permission).filter_by(user_id=user_id).all()

# Problem: Cache never invalidates!
# If admin revokes user's permissions, cache still has old data
```

**Fix 1**: Use short TTL cache:
```python
from cachetools import TTLCache
import asyncio

permission_cache = TTLCache(maxsize=1000, ttl=300)  # 5-minute TTL

async def get_user_permissions(user_id: str) -> List[str]:
    if user_id in permission_cache:
        return permission_cache[user_id]

    permissions = await db.query(Permission).filter_by(user_id=user_id).all()
    permission_cache[user_id] = permissions
    return permissions
```

**Fix 2**: Invalidate cache on permission changes:
```python
@app.post("/admin/users/{user_id}/roles")
async def assign_role(user_id: str, role: Role):
    await db.assign_role(user_id, role)

    # Invalidate permission cache
    if user_id in permission_cache:
        del permission_cache[user_id]

    return {"updated": user_id}
```

**Fix 3**: Use Redis with pub/sub for distributed cache invalidation:
```python
import redis.asyncio as redis

redis_client = redis.Redis(host='localhost', port=6379)

async def get_user_permissions(user_id: str) -> List[str]:
    # Try cache first
    cached = await redis_client.get(f"permissions:{user_id}")
    if cached:
        return json.loads(cached)

    # Cache miss, query database
    permissions = await db.query(Permission).filter_by(user_id=user_id).all()

    # Store in cache with 5-minute TTL
    await redis_client.setex(
        f"permissions:{user_id}",
        300,
        json.dumps(permissions)
    )

    return permissions

async def invalidate_user_permissions(user_id: str):
    """Called when permissions change."""
    await redis_client.delete(f"permissions:{user_id}")

    # Publish invalidation event for other API instances
    await redis_client.publish('permission_invalidate', user_id)
```

### Not Auditing Access Control Decisions

#### Pitfall 8: Silent Authorization Failures

**Vulnerable Code**:
```python
@app.get("/sensitive-data")
async def get_sensitive_data(user: User = Depends(get_current_user)):
    if user.role != Role.ADMIN:
        raise HTTPException(403, "Access denied")  # No audit log!

    return {"data": "sensitive"}
```

**Problem**: No audit trail when authorization fails (can't detect attacks).

**Fix**: Log ALL authorization decisions (success and failure):
```python
def audit_authorization(user_id: str, resource: str, action: str, decision: bool):
    """Audit every authorization decision."""
    logger.info(
        "authorization",
        extra={
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "decision": "allow" if decision else "deny",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

@app.get("/sensitive-data")
async def get_sensitive_data(user: User = Depends(get_current_user)):
    allowed = user.role == Role.ADMIN

    # Audit the decision
    audit_authorization(user.id, "sensitive-data", "read", allowed)

    if not allowed:
        raise HTTPException(403, "Access denied")

    return {"data": "sensitive"}
```

**Better**: Audit in dependency:
```python
def require_permissions(permissions: List[str]):
    async def checker(user: User = Depends(get_current_user)):
        user_perms = await get_user_permissions(user.id)
        allowed = all(p in user_perms for p in permissions)

        # Audit every permission check
        audit_authorization(
            user.id,
            "/".join(permissions),
            "access",
            allowed
        )

        if not allowed:
            raise HTTPException(403, "Insufficient permissions")

        return user

    return checker
```

#### Pitfall 9: Not Logging Data Access

**Vulnerable Code**:
```python
@app.get("/findings/{id}")
async def get_finding(id: int, user: User = Depends(get_current_user)):
    finding = await db.get_finding(id, tenant_id=user.tenant_id)
    return finding  # No audit log of data access
```

**Problem**: Can't track who accessed what data (compliance issue for GDPR, SOC2).

**Fix**: Log all access to sensitive resources:
```python
@app.get("/findings/{id}")
async def get_finding(id: int, user: User = Depends(get_current_user)):
    finding = await db.get_finding(id, tenant_id=user.tenant_id)

    # Audit data access
    logger.info(
        "data_access",
        extra={
            "user_id": user.id,
            "resource_type": "finding",
            "resource_id": id,
            "action": "read",
            "timestamp": datetime.utcnow().isoformat()
        }
    )

    return finding
```

---

## 5. Code Examples: Realistic FastAPI RBAC Implementation Patterns

### Complete RBAC Implementation Example

#### Directory Structure
```
src/
├── auth/
│   ├── __init__.py
│   ├── dependencies.py      # Authentication dependencies (existing)
│   ├── models.py            # User model (existing)
│   └── middleware.py        # JWT validation (existing)
├── rbac/
│   ├── __init__.py
│   ├── models.py            # Role, Permission, UserRole models
│   ├── dependencies.py      # Permission checking dependencies
│   ├── permissions.py       # Permission definitions
│   ├── decorators.py        # Permission decorators
│   └── audit.py             # Audit logging
└── api/
    └── routers/
        └── findings.py      # Example protected routes
```

#### 1. RBAC Models (`src/rbac/models.py`)

```python
from sqlalchemy import Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship
from src.database import Base

class Role(Base):
    """
    Role definition with level-based hierarchy.

    Levels:
    1 = USER (read-only)
    2 = MANAGER (read + reports)
    3 = ANALYST (read + write + scans)
    4 = ADMIN (tenant admin)
    5 = SUPER_ADMIN (platform admin)
    """
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False, index=True)
    level = Column(Integer, nullable=False)
    description = Column(String)

    # Relationships
    permissions = relationship("RolePermission", back_populates="role", cascade="all, delete-orphan")
    user_roles = relationship("UserRole", back_populates="role")


class Permission(Base):
    """
    Permission definition following resource:action pattern.

    Examples:
    - findings:read
    - findings:write
    - scans:execute
    - organizations:delete
    """
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False, index=True)
    resource = Column(String, nullable=False)  # "findings", "scans", "users"
    action = Column(String, nullable=False)    # "read", "write", "delete", "execute"
    description = Column(String)

    # Relationships
    roles = relationship("RolePermission", back_populates="permission")


class RolePermission(Base):
    """
    Many-to-many relationship between roles and permissions.
    """
    __tablename__ = "role_permissions"

    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id = Column(Integer, ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)

    # Relationships
    role = relationship("Role", back_populates="permissions")
    permission = relationship("Permission", back_populates="roles")


class UserRole(Base):
    """
    User role assignment, scoped to tenant.

    Important: Roles are PER-TENANT, not global.
    A user can be admin in Tenant A but user in Tenant B.
    """
    __tablename__ = "user_roles"

    id = Column(Integer, primary_key=True)
    user_id = Column(String, nullable=False, index=True)  # OIDC 'sub' claim
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)

    # Relationships
    role = relationship("Role", back_populates="user_roles")

    # Unique constraint: one role per user per tenant
    __table_args__ = (
        UniqueConstraint('user_id', 'tenant_id', name='unique_user_tenant_role'),
    )
```

#### 2. Permission Definitions (`src/rbac/permissions.py`)

```python
from enum import IntEnum
from typing import List

class Role(IntEnum):
    """
    5-tier role hierarchy with numeric levels.
    Higher number = more privileges.
    """
    USER = 1
    MANAGER = 2
    ANALYST = 3
    ADMIN = 4
    SUPER_ADMIN = 5


# Permission definitions for each role
ROLE_PERMISSIONS = {
    Role.USER: [
        "findings:read",
        "scans:read",
        "reports:read",
        "dashboards:read",
    ],
    Role.MANAGER: [
        "findings:read",
        "scans:read",
        "reports:read",
        "reports:generate",
        "dashboards:read",
    ],
    Role.ANALYST: [
        "findings:read",
        "findings:write",
        "findings:export",
        "scans:read",
        "scans:execute",
        "reports:read",
        "reports:generate",
        "dashboards:read",
    ],
    Role.ADMIN: [
        "findings:*",       # All finding operations
        "scans:*",          # All scan operations
        "reports:*",        # All report operations
        "organizations:*",  # Manage organizations
        "users:read",
        "users:write",      # Manage users in tenant
        "integrations:*",   # Configure integrations
        "dashboards:*",
    ],
    Role.SUPER_ADMIN: [
        "*:*",  # Full access to everything
    ]
}


def get_role_permissions(role: Role) -> List[str]:
    """
    Get all permissions for a role, including inherited permissions.

    Args:
        role: Role enum value

    Returns:
        List of permission strings

    Example:
        get_role_permissions(Role.ANALYST) -> ["findings:read", "findings:write", ...]
    """
    # Start with this role's permissions
    permissions = set(ROLE_PERMISSIONS[role])

    # Add permissions from all lower roles (inheritance)
    for lower_role in Role:
        if lower_role < role:
            permissions.update(ROLE_PERMISSIONS[lower_role])

    return list(permissions)


def matches_permission(required: str, user_permissions: List[str]) -> bool:
    """
    Check if user has required permission, supporting wildcards.

    Args:
        required: Required permission (e.g., "findings:read")
        user_permissions: List of user's permissions (may include wildcards)

    Returns:
        True if user has permission

    Examples:
        matches_permission("findings:read", ["findings:*"]) -> True
        matches_permission("findings:delete", ["*:*"]) -> True
        matches_permission("findings:read", ["findings:write"]) -> False
    """
    # Handle wildcard permission (super admin)
    if "*:*" in user_permissions:
        return True

    resource_req, action_req = required.split(":")

    for perm in user_permissions:
        resource_perm, action_perm = perm.split(":")

        # Check resource match
        resource_match = resource_perm == "*" or resource_perm == resource_req

        # Check action match
        action_match = action_perm == "*" or action_perm == action_req

        if resource_match and action_match:
            return True

    return False
```

#### 3. RBAC Dependencies (`src/rbac/dependencies.py`)

```python
from typing import List, Optional
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from src.auth.dependencies import get_current_user
from src.auth.models import User
from src.database import get_db
from src.rbac.models import UserRole, Role as RoleModel, Permission
from src.rbac.permissions import Role, matches_permission
from src.rbac.audit import audit_authorization
import logging

logger = logging.getLogger(__name__)


async def get_user_role_for_tenant(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Role:
    """
    Get user's role for their current tenant.

    Args:
        user: Authenticated user from JWT
        db: Database session

    Returns:
        Role enum value for this user in this tenant

    Raises:
        HTTPException 403: If user has no role in this tenant
    """
    # Query user's role for this tenant
    user_role = db.query(UserRole).filter_by(
        user_id=user.sub,
        tenant_id=user.tenant_id
    ).first()

    if not user_role:
        logger.warning(f"User {user.sub} has no role in tenant {user.tenant_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User has no role assigned in this tenant"
        )

    # Return role enum
    return Role[user_role.role.name.upper()]


async def get_user_permissions(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> List[str]:
    """
    Get all permissions for user in their current tenant.
    Cached for performance (5-minute TTL).

    Args:
        user: Authenticated user from JWT
        db: Database session

    Returns:
        List of permission strings (e.g., ["findings:read", "scans:execute"])
    """
    # Get user's role
    user_role = await get_user_role_for_tenant(user, db)

    # Get permissions from role
    from src.rbac.permissions import get_role_permissions
    return get_role_permissions(user_role)


def require_permissions(*required_permissions: str):
    """
    Dependency factory to check if user has all required permissions.

    Usage:
        @app.get(
            "/findings",
            dependencies=[Depends(require_permissions("findings:read"))]
        )
        async def list_findings():
            return {"findings": [...]}

    Args:
        *required_permissions: Permission strings to require

    Returns:
        Dependency function that checks permissions

    Raises:
        HTTPException 403: If user lacks any required permission
    """
    async def permission_checker(
        user: User = Depends(get_current_user),
        user_permissions: List[str] = Depends(get_user_permissions)
    ):
        # Check each required permission
        for required in required_permissions:
            if not matches_permission(required, user_permissions):
                # Audit failed authorization
                audit_authorization(
                    user_id=user.sub,
                    resource=required.split(":")[0],
                    action=required.split(":")[1],
                    decision=False,
                    reason=f"User lacks permission: {required}"
                )

                logger.warning(
                    f"User {user.sub} denied access: missing permission {required}"
                )

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required permission: {required}"
                )

        # Audit successful authorization
        audit_authorization(
            user_id=user.sub,
            resource=required_permissions[0].split(":")[0],
            action=required_permissions[0].split(":")[1],
            decision=True
        )

        return user

    return permission_checker


def require_role(minimum_role: Role):
    """
    Dependency factory to check if user has minimum role level.

    Usage:
        @app.delete(
            "/findings/{id}",
            dependencies=[Depends(require_role(Role.ADMIN))]
        )
        async def delete_finding(id: int):
            return {"deleted": id}

    Args:
        minimum_role: Minimum required role level

    Returns:
        Dependency function that checks role

    Raises:
        HTTPException 403: If user's role is below minimum
    """
    async def role_checker(
        user_role: Role = Depends(get_user_role_for_tenant)
    ):
        if user_role < minimum_role:
            logger.warning(
                f"User denied access: role {user_role.name} < required {minimum_role.name}"
            )

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {minimum_role.name} role or higher"
            )

        return user_role

    return role_checker


async def require_tenant_access(
    resource_id: int,
    resource_type: str,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify user's tenant has access to the specified resource.

    Usage:
        @app.get("/findings/{finding_id}")
        async def get_finding(
            finding_id: int,
            _: None = Depends(lambda: require_tenant_access(finding_id, "finding"))
        ):
            ...

    Args:
        resource_id: ID of resource to check
        resource_type: Type of resource ("finding", "scan", "organization")
        user: Authenticated user
        db: Database session

    Raises:
        HTTPException 403: If resource belongs to different tenant
        HTTPException 404: If resource not found
    """
    # Map resource type to model
    from src.api.models import Finding, Scan, Organization
    resource_models = {
        "finding": Finding,
        "scan": Scan,
        "organization": Organization
    }

    model = resource_models.get(resource_type)
    if not model:
        raise ValueError(f"Unknown resource type: {resource_type}")

    # Query resource
    resource = db.query(model).filter_by(id=resource_id).first()

    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource_type} not found"
        )

    # Check tenant isolation
    if resource.tenant_id != user.tenant_id:
        logger.warning(
            f"User {user.sub} (tenant {user.tenant_id}) attempted to access "
            f"{resource_type} {resource_id} (tenant {resource.tenant_id})"
        )

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this resource"
        )
```

#### 4. Audit Logging (`src/rbac/audit.py`)

```python
from loguru import logger
from datetime import datetime
from typing import Optional

def audit_authorization(
    user_id: str,
    resource: str,
    action: str,
    decision: bool,
    reason: str = ""
):
    """
    Log every authorization decision for audit trail.

    Args:
        user_id: User ID (OIDC 'sub' claim)
        resource: Resource being accessed (e.g., "findings")
        action: Action being performed (e.g., "read", "write")
        decision: True if access granted, False if denied
        reason: Optional reason for decision
    """
    logger.info(
        "authorization",
        extra={
            "event_type": "authorization",
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "decision": "allow" if decision else "deny",
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


def audit_data_access(
    user_id: str,
    resource_type: str,
    resource_id: int,
    action: str = "read"
):
    """
    Log access to sensitive data resources.

    Args:
        user_id: User ID (OIDC 'sub' claim)
        resource_type: Type of resource (e.g., "finding", "scan")
        resource_id: ID of resource accessed
        action: Action performed (default: "read")
    """
    logger.info(
        "data_access",
        extra={
            "event_type": "data_access",
            "user_id": user_id,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "action": action,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


def audit_admin_action(
    user_id: str,
    action: str,
    target: str,
    details: Optional[dict] = None
):
    """
    Log administrative actions (super admin, admin).

    Args:
        user_id: Admin user ID
        action: Action performed (e.g., "delete_tenant", "assign_role")
        target: Target of action (e.g., tenant_id, user_id)
        details: Additional details about the action
    """
    logger.warning(  # Use warning level for admin actions (higher severity)
        "admin_action",
        extra={
            "event_type": "admin_action",
            "user_id": user_id,
            "action": action,
            "target": target,
            "details": details or {},
            "timestamp": datetime.utcnow().isoformat()
        }
    )
```

#### 5. Example Protected Routes (`src/api/routers/findings.py`)

```python
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from src.auth.dependencies import get_current_user
from src.auth.models import User
from src.rbac.dependencies import require_permissions, require_role, require_tenant_access
from src.rbac.permissions import Role
from src.rbac.audit import audit_data_access
from src.database import get_db
from src.api.models import Finding
from src.api.schemas import FindingResponse, FindingCreate, FindingUpdate

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get(
    "/",
    response_model=List[FindingResponse],
    dependencies=[Depends(require_permissions("findings:read"))]
)
async def list_findings(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List all findings for user's tenant.

    Required Permission: findings:read
    """
    # Query findings for user's tenant only
    findings = db.query(Finding).filter_by(tenant_id=user.tenant_id).all()

    return findings


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
    dependencies=[Depends(require_permissions("findings:read"))]
)
async def get_finding(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get specific finding by ID.

    Required Permission: findings:read
    Security: Validates tenant access before returning data
    """
    # Check tenant access
    await require_tenant_access(finding_id, "finding", user, db)

    # Get finding
    finding = db.query(Finding).filter_by(
        id=finding_id,
        tenant_id=user.tenant_id
    ).first()

    if not finding:
        raise HTTPException(404, "Finding not found")

    # Audit data access
    audit_data_access(user.sub, "finding", finding_id, "read")

    return finding


@router.post(
    "/",
    response_model=FindingResponse,
    status_code=201,
    dependencies=[Depends(require_permissions("findings:write"))]
)
async def create_finding(
    finding_data: FindingCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create new finding.

    Required Permission: findings:write
    """
    # Create finding with user's tenant_id
    finding = Finding(
        **finding_data.dict(),
        tenant_id=user.tenant_id
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    # Audit action
    audit_data_access(user.sub, "finding", finding.id, "create")

    return finding


@router.put(
    "/{finding_id}",
    response_model=FindingResponse,
    dependencies=[Depends(require_permissions("findings:write"))]
)
async def update_finding(
    finding_id: int,
    update_data: FindingUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update existing finding.

    Required Permission: findings:write
    """
    # Check tenant access
    await require_tenant_access(finding_id, "finding", user, db)

    # Get finding
    finding = db.query(Finding).filter_by(
        id=finding_id,
        tenant_id=user.tenant_id
    ).first()

    if not finding:
        raise HTTPException(404, "Finding not found")

    # Update finding
    for key, value in update_data.dict(exclude_unset=True).items():
        setattr(finding, key, value)

    db.commit()
    db.refresh(finding)

    # Audit action
    audit_data_access(user.sub, "finding", finding_id, "update")

    return finding


@router.delete(
    "/{finding_id}",
    status_code=204,
    dependencies=[Depends(require_role(Role.ADMIN))]
)
async def delete_finding(
    finding_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete finding (admin only).

    Required Role: ADMIN or higher
    """
    # Check tenant access
    await require_tenant_access(finding_id, "finding", user, db)

    # Get finding
    finding = db.query(Finding).filter_by(
        id=finding_id,
        tenant_id=user.tenant_id
    ).first()

    if not finding:
        raise HTTPException(404, "Finding not found")

    # Audit before deletion
    from src.rbac.audit import audit_admin_action
    audit_admin_action(
        user_id=user.sub,
        action="delete_finding",
        target=str(finding_id),
        details={"tenant_id": user.tenant_id}
    )

    # Delete
    db.delete(finding)
    db.commit()
```

---

## Key Recommendations for AuditGH Phase 3

Based on this research, here are the specific recommendations for implementing RBAC in AuditGH:

### 1. Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| **Use FastAPI Depends() for RBAC** | Native FastAPI pattern, testable, explicit |
| **5-tier role hierarchy** | USER < MANAGER < ANALYST < ADMIN < SUPER_ADMIN |
| **Hybrid RBAC + ABAC** | Roles for permissions, tenant_id for isolation |
| **Database-backed permissions** | Flexible, auditable, can change without code deploy |
| **Casbin for complex policies** | If you need more than simple RBAC (defer to Phase 4) |
| **Audit all authorization** | Log every permission check (success and failure) |

### 2. Implementation Plan

1. **Plan 1: RBAC Database Schema**
   - Create Role, Permission, RolePermission, UserRole tables
   - Seed 5 default roles with permissions
   - Add tenant_id to UserRole for multi-tenant scoping

2. **Plan 2: Permission Dependencies**
   - Implement `require_permissions()` and `require_role()` dependencies
   - Add `get_user_permissions()` with caching
   - Create `require_tenant_access()` for resource isolation

3. **Plan 3: Audit Logging**
   - Implement audit logging for all authorization decisions
   - Log data access to sensitive resources
   - Configure log export to Cribl (Phase 6)

4. **Plan 4: Protect API Routes**
   - Add permission dependencies to all API endpoints
   - Update existing routes with RBAC checks
   - Add integration tests for permission enforcement

### 3. Integration with Existing Auth

Your existing JWT authentication (Phase 2) provides:
- ✅ User identity (`sub`, `email`)
- ✅ OIDC provider validation
- ✅ Token validation middleware

For RBAC, add to JWT claims:
```json
{
  "sub": "00u1234567890abcdef",
  "email": "user@company.com",
  "tenant_id": 42,           // ADD THIS
  "role": "analyst",          // ADD THIS
  "permissions": [...]        // OPTIONAL (can query from DB)
}
```

**How to add claims**:
1. After OAuth callback, query user's role from database
2. Store `tenant_id` and `role` in session
3. When issuing JWT, include these claims
4. Validate claims in `get_current_user_from_token()`

### 4. Testing Strategy

```python
# tests/test_rbac.py

def test_user_cannot_delete_finding():
    """USER role should not be able to delete findings."""
    client = TestClient(app)

    # Login as USER
    token = get_test_token(role="user")

    # Try to delete finding
    response = client.delete(
        "/findings/123",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 403
    assert "permission" in response.json()["detail"].lower()


def test_admin_can_delete_finding():
    """ADMIN role should be able to delete findings."""
    client = TestClient(app)

    # Login as ADMIN
    token = get_test_token(role="admin")

    # Delete finding
    response = client.delete(
        "/findings/123",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 204


def test_cannot_access_other_tenant_data():
    """Users should not access data from other tenants."""
    client = TestClient(app)

    # Login as user in Tenant A
    token = get_test_token(tenant_id=1)

    # Try to access Tenant B's finding
    response = client.get(
        "/findings/999",  # Belongs to Tenant B
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code in [403, 404]
```

---

## Sources

### Primary Sources

1. [FastAPI Official Security Documentation](https://fastapi.tiangolo.com/tutorial/security/)
2. [FastAPI RBAC Full Implementation Tutorial - Permit.io](https://www.permit.io/blog/fastapi-rbac-full-implementation-tutorial)
3. [RBAC Implementation - fastapi_best_architecture](https://deepwiki.com/fastapi-practices/fastapi_best_architecture/3.2-rbac-system)
4. [FastAPI Dependency Injection Patterns - PropelAuth](https://www.propelauth.com/post/fastapi-auth-with-dependency-injection)
5. [FastAPI Users GitHub Discussion #454](https://github.com/fastapi-users/fastapi-users/discussions/454)
6. [fastapi-permissions PyPI](https://pypi.org/project/fastapi_permissions/)
7. [axioms-fastapi Documentation](https://www.abhishek-tiwari.com/securing-fastapi-applications-with-jwt-tokens-and-oauth2-using-axioms-fastapi/)
8. [fast-api-jwt-middleware PyPI](https://pypi.org/project/fast-api-jwt-middleware/)

### RBAC vs ABAC

9. [RBAC vs ABAC: Picking Your Access Control Fighter](https://dev.to/lovestaco/rbac-vs-abac-picking-your-access-control-fighter-490n)
10. [ABAC vs RBAC - Kiteworks](https://www.kiteworks.com/risk-compliance-glossary/attribute-based-access-control/)
11. [RBAC vs ABAC - Aserto](https://www.aserto.com/blog/rbac-vs-abac-authorization-models)

### Security Best Practices

12. [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
13. [The Risk of RBAC Vulnerabilities - GBHackers](https://gbhackers.com/risk-of-rbac-vulnerabilities/)
14. [What is Ineffective RBAC? - Aptive](https://www.aptive.co.uk/blog/what-is-ineffective-role-based-access-control/)
15. [Best Practices for Managing Users, Roles, and Permissions](https://dev.to/anna_p_s/best-practices-for-managing-users-roles-and-permissions-5140)

### Policy Engines

16. [Casbin Official Documentation](https://www.casbin.org/)
17. [Open Policy Agent Official Site](https://www.openpolicyagent.org/)
18. [OPA vs Casbin Comparison](https://gist.github.com/StevenACoffman/1644ec1157a793eb7d868aa22b260e91)
19. [Policy Engines: OPA vs Cedar vs Zanzibar - Permit.io](https://www.permit.io/blog/policy-engines)
20. [fastapi-opa PyPI](https://pypi.org/project/fastapi-opa/)

### Multi-Tenancy

21. [Python FastAPI Postgres SqlAlchemy Row Level Security Multitenancy](https://adityamattos.com/multi-tenancy-in-python-fastapi-and-sqlalchemy-using-postgres-row-level-security)
22. [Building Multi-Tenant Knowledge Management with FastAPI and Permit.io](https://medium.com/@nicholasikiroma/building-a-secure-multi-tenant-knowledge-management-system-with-fastapi-and-permit-io-26bebdeb5bd4)
23. [FastAPI Multi-Tenancy Apps](https://medium.com/@sandesh.thakar18/multi-tenancy-apps-in-fastapi-df80c7e7d52f)
24. [Multitenancy with FastAPI - App Generator](https://app-generator.dev/docs/technologies/fastapi/multitenancy.html)

### Performance & Caching

25. [FastAPI Caching at Scale - Hash Block](https://medium.com/@connect.hashblock/fastapi-caching-at-scale-what-worked-for-me-and-what-didnt-510681266f39)
26. [10 Ways to Make FastAPI Blazing Fast - Leapcell](https://leapcell.io/blog/fastapi-performance-hacks)
27. [Caching in FastAPI - DEV Community](https://dev.to/sivakumarmanoharan/caching-in-fastapi-unlocking-high-performance-development-20ej)

### Production Examples

28. [GitHub - teamhide/fastapi-boilerplate](https://github.com/teamhide/fastapi-boilerplate)
29. [GitHub - chrisK824/fastapi-rbac-example](https://github.com/chrisK824/fastapi-rbac-example)
30. [GitHub - 00-Python/FastAPI-Role-and-Permissions](https://github.com/00-Python/FastAPI-Role-and-Permissions)
31. [Auth0 FastAPI RBAC Code Sample](https://developer.auth0.com/resources/code-samples/api/fastapi/basic-role-based-access-control)

### Audit Logging

32. [FastAPI Enterprise Basics: SSO, RBAC, and Auditing - Squash.io](https://www.squash.io/implementing-fastapi-enterprise-functionalities-sso-rbac-and-auditing/)
33. [Monitoring and Logging in FastAPI to Meet SOC2 Requirements - LoadForge](https://loadforge.com/guides/load-testing/monitoring-and-logging-in-fastapi-to-meet-soc2-requirements)

---

**End of Research Document**

# Authentication and Authorization

**Source:** [API_First.md](API_First.md) - Section 7

---

## 7.1 Authentication Methods

AuditGitHub supports four authentication methods, all resolved at the API layer:

| Method | Use Case | Token Type | Lifetime |
|--------|----------|------------|----------|
| **OIDC (Entra ID / Okta)** | Web UI login | Session cookie | 1 hour (8h absolute, 30min idle) |
| **JWT Bearer** | API clients | Access token (HS256) | 1 hour |
| **Refresh Token** | Token renewal | Refresh token (HS256) | 7 days (one-time use, Redis-tracked) |
| **Device Flow (RFC 8628)** | CLI / devices | Access + Refresh token | Same as JWT |
| **Break Glass** | Emergency access | Session cookie | 1 hour |

## 7.2 RBAC — Role-Based Access Control

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

## 7.3 Rate Limiting

| Scope | Default | Storage |
|-------|---------|---------|
| Global (per user/IP) | 100 requests/minute | Redis |
| `/auth/login` | 5/minute | Redis |
| `/auth/register` | 3/minute | Redis |
| `/auth/refresh` | 10/minute | Redis |
| `/auth/reset-password` | 3/minute | Redis |

Rate limit status is exposed via response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.

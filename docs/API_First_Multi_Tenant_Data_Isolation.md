# Multi-Tenant Data Isolation

**Source:** [API_First.md](API_First.md) - Section 8

---

## Isolation Model

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

## Database Architecture

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

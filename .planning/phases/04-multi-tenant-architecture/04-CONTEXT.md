# Phase 4: Multi-Tenant Architecture - Context

**Gathered:** 2026-01-13
**Status:** Ready for research

<vision>
## How This Should Work

Complete data isolation through schema-per-tenant PostgreSQL architecture. Each organization gets its own dedicated database schema with all tables, ensuring zero chance of cross-tenant data leaks. This is non-negotiable for a security auditing platform where organizations' sensitive security findings must never be exposed to each other.

When a user authenticates via OIDC (from Phase 2), their JWT contains a tenant_id claim. The platform uses this to automatically route all their database queries to their organization's schema. It should be seamless and automatic - users never think about schemas, they just see their organization's data.

New tenants are provisioned through an explicit API endpoint (POST /tenants) that creates the schema, applies all migrations, and sets up the initial structure. This gives us control over onboarding and ensures every new organization starts with a clean, complete schema.

</vision>

<essential>
## What Must Be Nailed

- **Seamless schema creation for new tenants** - When POST /tenants is called with organization details, the schema is created automatically with all tables, indexes, constraints, and migrations applied. Onboarding just works without manual intervention.

- **Automatic tenant resolution from JWT** - Extract tenant_id from the authenticated user's JWT claims and use it to route to the correct schema. No manual selection, no configuration - it just works based on who's logged in.

- **Synchronized schema migrations** - When we add columns, tables, or indexes, migrations run across all tenant schemas at once. All tenants stay on the same schema version, ensuring consistency and simplifying deployment.

</essential>

<boundaries>
## What's Out of Scope

- **Billing and subscription management** - Payment processing, plan tiers, usage tracking, subscription lifecycle management - all deferred to a future phase. Focus purely on the multi-tenant architecture.

- **Lazy/gradual migrations** - Not doing on-demand or blue-green per-tenant migrations. Keep it simple: migrations run across all schemas at once during deployment windows.

- **Per-tenant RBAC customization** - Roles and permissions remain global definitions (from Phase 3). UserRole already has tenant_id for assignments. Don't move RBAC tables into tenant schemas or allow tenant-specific role definitions.

</boundaries>

<specifics>
## Specific Ideas

- **Tenant provisioning**: Explicit API endpoint (POST /tenants with org details) rather than automatic-on-first-login. Gives us control over the provisioning process and allows pre-provisioning if needed.

- **RBAC integration**: Keep all RBAC tables (Role, Permission, RolePermission, UserRole) in the global/public schema. They're platform-wide definitions. UserRole already has tenant_id to reference which tenant a user belongs to - this connects to the schema name.

- **Migration strategy**: Run migrations synchronously across all tenant schemas during deployment. Simple and predictable - all tenants stay in sync with the same schema version. Brief platform unavailability acceptable during migrations.

</specifics>

<notes>
## Additional Context

**Architectural decision confirmed**: Schema-per-tenant over shared-tables-with-tenant_id. Maximum isolation is critical for security auditing data where leaks are unacceptable.

**JWT-based tenant resolution**: Natural fit with Phase 2's OIDC authentication. The user's identity already includes their organization context.

**Priority on automation**: The emphasis is on seamless tenant provisioning ("just works") over per-tenant customization features. Get the foundation solid first.

**Integration with existing phases**:
- Phase 2 (OIDC auth): JWT provides tenant_id
- Phase 3 (RBAC): UserRole.tenant_id references tenant schema, but RBAC tables stay global
- All 167 protected API endpoints from Phase 3 will need tenant-aware queries

</notes>

---

*Phase: 04-multi-tenant-architecture*
*Context gathered: 2026-01-13*

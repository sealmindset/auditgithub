# Phase 4: Multi-Tenant Architecture - Research

**Completed:** 2026-01-13
**Status:** Ready for planning

## Executive Summary

Schema-per-tenant PostgreSQL is a valid approach for maximum data isolation in a security auditing platform. Research reveals modern industry trend favors Row-Level Security (RLS) for operational simplicity, but schema-per-tenant provides the explicit isolation required by CONTEXT.md.

**Key Finding:** The codebase already has partial multi-tenancy infrastructure (organization_id filtering, database_router.py) but needs schema-per-tenant implementation using PostgreSQL search_path.

**Recommendation:** Implement schema-per-tenant within a single database using `SET search_path`, rather than separate databases, to balance isolation with operational simplicity.

## Standard Stack

### Core Technologies

**PostgreSQL Schema Management:**
- PostgreSQL schemas provide logical namespaces within a single database
- Each tenant gets a dedicated schema (e.g., `tenant_acme`, `tenant_contoso`)
- Use `SET search_path = tenant_schema, public` to route queries
- Scales efficiently to hundreds of schemas, degrades beyond 1,000-2,000 tenants

**SQLAlchemy 2.0 Multi-Schema:**
- Use `SET LOCAL search_path` for transaction-scoped routing (safe with connection pooling)
- Parameterized queries prevent schema injection: `text("SET search_path = :schema")`
- Table metadata should NOT specify schema - determined by search_path at runtime
- QueuePool with pool_size=20, max_overflow=40 sufficient for <50 concurrent tenants

**Alembic Migrations:**
- No first-class multi-tenancy support - must implement custom runner
- Pattern: Autogenerate migration from one schema, apply to all schemas
- Run migrations synchronously across all tenants during deployment windows
- Use `SET search_path` before running migrations for each tenant

### Required Dependencies

**Already Installed:**
- SQLAlchemy >= 2.0.0 (ORM with schema support)
- psycopg2-binary >= 2.9.0 (PostgreSQL driver with safe identifier quoting)

**Needs Adding:**
```
alembic>=1.13.0  # Database migrations
```

### Configuration Files

**alembic.ini** (root directory):
```ini
[alembic]
script_location = migrations
sqlalchemy.url = postgresql://auditgh:auditgh_secret@db:5432/auditgh_kb

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = INFO
handlers = console

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
datefmt = %H:%M:%S
```

**PostgreSQL Configuration (docker-compose.yml):**
```yaml
db:
  image: postgres:15
  environment:
    POSTGRES_MAX_CONNECTIONS: 200
  command:
    - "postgres"
    - "-c"
    - "max_connections=200"
    - "-c"
    - "shared_buffers=256MB"
```

## Architecture Patterns

### Pattern 1: Schema Provisioning (POST /tenants)

**Approach:** Explicit API endpoint creates schema, applies migrations, initializes structure.

**Implementation:**
```python
# src/api/routers/tenants.py
@router.post("/tenants", status_code=201)
async def create_tenant(
    tenant_data: TenantCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_metadata_db),
    _: None = Depends(require_permissions("admin:manage"))
):
    # 1. Validate slug format
    if not re.match(r'^[a-z0-9-]+$', tenant_data.slug):
        raise HTTPException(400, "Invalid slug format")

    # 2. Create Tenant record
    tenant = Tenant(
        slug=tenant_data.slug,
        name=tenant_data.name,
        is_active=True,
        is_provisioned=False,
        migration_status="pending"
    )
    db.add(tenant)
    db.commit()

    # 3. Queue schema provisioning in background
    background_tasks.add_task(provision_tenant_schema, tenant.slug)

    return {"message": "Tenant created, provisioning in progress"}

def provision_tenant_schema(tenant_slug: str):
    """Background task to create schema and run migrations."""
    schema_name = f"tenant_{tenant_slug}"

    # Create schema (use psycopg2.sql.Identifier for SQL injection safety)
    from psycopg2 import sql
    with engine.connect() as conn:
        query = sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(
            sql.Identifier(schema_name)
        )
        conn.connection.cursor().execute(query)
        conn.connection.commit()

    # Create tables
    with engine.connect() as conn:
        conn.execute(text("SET search_path = :schema"), {"schema": schema_name})
        Base.metadata.create_all(bind=conn)

    # Run Alembic migrations
    alembic_cfg = Config("alembic.ini")
    alembic_cfg.attributes['tenant_schema'] = schema_name
    command.upgrade(alembic_cfg, "head")

    # Update tenant status
    db = SessionLocal()
    tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
    tenant.is_provisioned = True
    tenant.migration_status = "current"
    tenant.last_migration_at = datetime.utcnow()
    db.commit()
```

**Key Points:**
- Background task prevents API timeout during provisioning
- psycopg2.sql.Identifier prevents SQL injection
- Schema name format: `tenant_{slug}` (e.g., `tenant_acme`)
- Alembic runs all migrations to bring schema to current version

### Pattern 2: Tenant Resolution from JWT

**Approach:** Middleware extracts tenant_id from JWT claims, looks up Tenant record, sets request.state.tenant_slug.

**Implementation:**
```python
# src/api/middleware/tenant.py (enhance existing)
class TenantMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Extract tenant from JWT (Phase 2 OIDC integration)
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token:
            try:
                payload = decode_jwt(token)  # Phase 2 JWT validation
                tenant_id = payload.get("tenant_id")  # From OIDC claims

                # Fetch tenant from metadata
                tenant = get_tenant_by_id(tenant_id)
                if tenant and tenant.is_active and tenant.is_provisioned:
                    request.state.tenant_slug = tenant.slug
                    request.state.tenant_id = tenant.id
                else:
                    raise HTTPException(403, "Tenant inactive or not provisioned")
            except JWTError:
                raise HTTPException(401, "Invalid token")

        return await call_next(request)
```

**Key Points:**
- JWT tenant_id (UUID) maps to Tenant.id
- Tenant.slug used for schema name construction
- Validates tenant is active and provisioned before allowing access
- Sets request.state for downstream dependencies

### Pattern 3: Schema Routing via Dependency Injection

**Approach:** FastAPI dependency reads tenant_slug from request.state, sets search_path before queries.

**Implementation:**
```python
# src/api/dependencies.py
def get_tenant_db(
    request: Request,
    db: Session = Depends(get_db)
) -> Session:
    """
    Set search_path based on request tenant context.
    CRITICAL: Uses SET LOCAL for transaction-scoped routing.
    """
    tenant_slug = getattr(request.state, "tenant_slug", None)
    if not tenant_slug:
        raise HTTPException(400, "Tenant context not available")

    # Set search_path for this transaction (safe with connection pooling)
    db.execute(
        text("SET LOCAL search_path = :schema, public"),
        {"schema": f"tenant_{tenant_slug}"}
    )

    return db

# Usage in routers
@router.get("/repositories")
def list_repositories(
    db: Session = Depends(get_tenant_db),  # Sets search_path
    current_user: User = Depends(get_current_user),  # Phase 2 auth
    _: None = Depends(require_permissions("repositories:read"))  # Phase 3 RBAC
):
    # All queries automatically route to tenant schema
    repos = db.query(Repository).all()
    return repos
```

**Key Points:**
- `SET LOCAL` is transaction-scoped - automatically resets when transaction ends
- Prevents search_path "leaking" into next request using same pooled connection
- Parameterized query prevents SQL injection
- Combines with Phase 2 auth and Phase 3 RBAC via dependency composition

### Pattern 4: Migration Orchestration Across Schemas

**Approach:** Custom Alembic runner iterates all tenant schemas, applies migrations synchronously with parallel execution.

**Implementation:**
```python
# migrations/env.py
def run_migrations_online():
    """Run migrations across all tenant schemas."""
    tenant_schema = context.get_x_argument(as_dictionary=True).get('tenant')

    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix='sqlalchemy.',
        poolclass=pool.NullPool,
    )

    if tenant_schema:
        # Single tenant migration
        with connectable.connect() as connection:
            connection.execute(text("SET search_path = :schema"),
                             {"schema": tenant_schema})
            context.configure(
                connection=connection,
                target_metadata=Base.metadata,
                version_table='alembic_version',
                version_table_schema=tenant_schema
            )
            with context.begin_transaction():
                context.run_migrations()
    else:
        # Migrate all tenants
        tenants = db.query(Tenant).filter(
            Tenant.is_active == True,
            Tenant.is_provisioned == True
        ).all()

        for tenant in tenants:
            schema_name = f"tenant_{tenant.slug}"
            with connectable.connect() as connection:
                connection.execute(text("SET search_path = :schema"),
                                 {"schema": schema_name})
                context.configure(connection=connection, target_metadata=Base.metadata)
                with context.begin_transaction():
                    context.run_migrations()

# migrations/run_tenant_migrations.py (CLI wrapper)
def migrate_all_tenants():
    """Run migrations with parallel execution."""
    tenants = get_all_tenants()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(migrate_tenant_schema, t.slug): t.slug
            for t in tenants
        }

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            # Update tenant migration_status
```

**CLI Usage:**
```bash
# Migrate all tenants
alembic upgrade head

# Migrate specific tenant
alembic upgrade head -x tenant=tenant_acme

# Generate new migration
alembic revision --autogenerate -m "add column" -x tenant=tenant_default
```

**Key Points:**
- Autogenerate migration from one schema (they're all identical)
- Apply to all schemas in parallel (10 workers = ~10 tenants/second)
- Track migration status per tenant (Tenant.migration_status)
- Handle partial failures gracefully (mark failed tenants, continue others)

### Pattern 5: Global vs Tenant Tables

**Approach:** RBAC tables in public schema (global), application data in tenant schemas.

**Implementation:**
```python
# Public schema tables (RBAC - Phase 3)
class Role(Base):
    __tablename__ = 'roles'
    __table_args__ = {'schema': 'public'}  # Explicitly in public schema

class Permission(Base):
    __tablename__ = 'permissions'
    __table_args__ = {'schema': 'public'}

# Tenant schema tables (application data)
class Repository(Base):
    __tablename__ = 'repositories'
    # No schema specified - uses search_path at runtime

class Finding(Base):
    __tablename__ = 'findings'
    # No schema specified - uses search_path at runtime
```

**Query Pattern:**
```python
# Query public tables (always available)
roles = db.query(Role).all()  # Reads from public.roles

# Query tenant tables (routed via search_path)
repos = db.query(Repository).all()  # Reads from tenant_acme.repositories

# Join across schemas
results = db.query(Repository, UserRole).join(
    UserRole, UserRole.tenant_id == current_tenant_id
).filter(
    UserRole.user_sub == current_user.sub
).all()
```

**Key Points:**
- UserRole.tenant_id (UUID) references Tenant.id
- UserRole stays in public schema (it's a global table)
- Tenant.slug maps to schema name for routing
- All 167 API endpoints need tenant-aware queries (search_path handles this automatically)

## Common Pitfalls

### Pitfall 1: Connection Pool Search Path Leakage

**Problem:** Connection pooling reuses connections. `SET search_path` persists for the entire session/connection. Next request using same pooled connection = wrong tenant data.

**Solution:** Always use `SET LOCAL` (transaction-scoped):
```python
# WRONG - persists in connection pool
db.execute(text(f"SET search_path = {schema_name}"))

# CORRECT - automatically resets when transaction ends
with db.begin():
    db.execute(text("SET LOCAL search_path = :schema"), {"schema": schema_name})
```

**Impact:** CRITICAL security issue - cross-tenant data leak.

### Pitfall 2: Schema Injection via User Input

**Problem:** Building schema names from user-controlled input allows SQL injection.

**Solution:** Use parameterized queries and psycopg2.sql.Identifier:
```python
# VULNERABLE
tenant_slug = request.query_params.get("tenant")  # User-controlled!
db.execute(text(f"SET search_path = tenant_{tenant_slug}"))

# SAFE - parameterized
tenant_slug = request.state.tenant_slug  # From validated JWT/middleware
db.execute(text("SET search_path = :schema"), {"schema": f"tenant_{tenant_slug}"})

# SAFE - identifier quoting for CREATE SCHEMA
from psycopg2 import sql
query = sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema_name))
```

**Impact:** CRITICAL security issue - unauthorized schema access or deletion.

### Pitfall 3: Migration Version Drift

**Problem:** Migration succeeds on 95 of 100 tenants, fails on 5. Now tenants are on different schema versions.

**Solution:** Track migration status per tenant, mark failures, allow retry:
```python
# Tenant model
class Tenant(Base):
    migration_status = Column(String)  # "current", "behind", "error"
    migration_error = Column(String)  # Error message if failed
    last_migration_at = Column(DateTime)

# Migration runner
def migrate_tenant_schema(tenant_slug: str):
    try:
        # Run migration
        command.upgrade(alembic_cfg, "head")

        # Mark success
        tenant.migration_status = "current"
        tenant.last_migration_at = datetime.utcnow()
    except Exception as e:
        # Mark failure, don't block platform
        tenant.migration_status = "error"
        tenant.migration_error = str(e)
        log.error(f"Migration failed for {tenant_slug}: {e}")
```

**Impact:** Data inconsistency, application errors for tenants on old schema versions.

### Pitfall 4: Performance Degradation with Many Schemas

**Problem:** PostgreSQL performance degrades beyond 1,000-2,000 schemas.

**Solution:** Monitor schema count, consider RLS if exceeding limits:
```sql
-- Check schema count
SELECT count(*) FROM pg_namespace WHERE nspname LIKE 'tenant_%';

-- Monitor schema sizes
SELECT
    schemaname,
    pg_size_pretty(sum(pg_total_relation_size(schemaname||'.'||tablename))::bigint)
FROM pg_tables
WHERE schemaname LIKE 'tenant_%'
GROUP BY schemaname
ORDER BY sum(pg_total_relation_size(schemaname||'.'||tablename)) DESC;
```

**Impact:** Slow query performance, high memory usage, migration timeouts.

### Pitfall 5: Hardcoded Schema Names in Table Metadata

**Problem:** Specifying schema in `__table_args__` breaks search_path routing.

**Solution:** Don't specify schema for tenant tables:
```python
# WRONG - hardcoded schema
class Repository(Base):
    __tablename__ = 'repositories'
    __table_args__ = {'schema': 'tenant_acme'}  # Only works for tenant_acme!

# CORRECT - no schema (uses search_path)
class Repository(Base):
    __tablename__ = 'repositories'
    # Schema determined by search_path at runtime
```

**Impact:** Queries always hit one tenant's schema regardless of search_path.

## What Not to Hand-Roll

### 1. Schema Creation Logic

**Don't:** Write custom DDL generation for CREATE TABLE statements.

**Do:** Use SQLAlchemy `Base.metadata.create_all()` and Alembic migrations.

**Rationale:** ORM already generates correct DDL for all tables, indexes, constraints. Hand-rolling is error-prone and misses updates.

### 2. Connection Pooling

**Don't:** Build custom connection pool management or per-tenant engines.

**Do:** Use SQLAlchemy's QueuePool with shared engine for all tenants.

**Rationale:** SQLAlchemy's pooling is battle-tested. Per-tenant pools waste resources (50 tenants × 10 connections = 500 total).

### 3. JWT Parsing and Validation

**Don't:** Re-implement JWT decoding in tenant middleware.

**Do:** Use existing Phase 2 OIDC integration to extract tenant_id from claims.

**Rationale:** Phase 2 already validates JWT signatures, expiration, audience. Don't duplicate.

### 4. RBAC Permission Checks

**Don't:** Duplicate authorization logic in tenant routing.

**Do:** Keep RBAC (Phase 3) and tenant routing as separate concerns, composed via dependencies.

**Rationale:** Authorization and data access are orthogonal. Mixing them creates tight coupling.

### 5. Migration Orchestration from Scratch

**Don't:** Write custom migration runner that reads SQL files.

**Do:** Extend Alembic's env.py to iterate tenant schemas.

**Rationale:** Alembic handles migration versioning, rollback, autogeneration. Just need to apply it N times.

## SOTA Updates (2026)

### Row-Level Security (RLS) is Now Preferred

**Industry Trend:** RLS has become the recommended approach for multi-tenant SaaS over schema-per-tenant.

**Sources:**
- AWS: "Multi-tenant data isolation with PostgreSQL RLS"
- Crunchy Data: "Designing Your Postgres Database for Multi-tenancy"
- Supabase/Nile: Schema-per-tenant for <100 tenants, RLS for scale

**Why RLS is Favored:**
- Simpler operations: Single schema, no migration orchestration
- Better scalability: Handles millions of tenants (no schema limit)
- Equivalent security: PostgreSQL enforces isolation at engine level
- Easier backups: Single schema to dump/restore
- Better query planner: Statistics across all tenants

**RLS Pattern (for reference):**
```sql
-- Enable RLS
ALTER TABLE repositories ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their tenant's data
CREATE POLICY tenant_isolation ON repositories
    FOR ALL
    USING (organization_id = current_setting('app.current_tenant')::uuid);

-- Set tenant context
SET app.current_tenant = 'tenant-uuid-67890';
SELECT * FROM repositories;  -- Automatically filtered
```

**Decision for This Project:**
CONTEXT.md explicitly requires schema-per-tenant for "maximum isolation." This is valid for a security auditing platform where data breach risk is unacceptable. However:
- Design so you can migrate to RLS later if scaling or operational burden becomes an issue
- RLS provides equivalent security with lower complexity
- Schema-per-tenant limits to ~1,000-2,000 tenants

### SQLAlchemy 2.0 Async Support

**Current:** Project uses synchronous SQLAlchemy (Session, not AsyncSession).

**Future Optimization:** SQLAlchemy 2.0 supports async/await with FastAPI async routes:
```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

engine = create_async_engine(
    "postgresql+asyncpg://user:pass@host/db",
    pool_size=20
)

async def get_async_tenant_db(request: Request) -> AsyncSession:
    async with AsyncSession(engine) as session:
        await session.execute(text("SET LOCAL search_path = :schema"),
                             {"schema": f"tenant_{request.state.tenant_slug}"})
        yield session
```

**When to Consider:** If you need >100 concurrent requests per tenant (currently not a bottleneck).

### FastAPI Dependency Injection Over Middleware

**Trend:** Use dependencies for request-specific logic, not middleware.

**Rationale:**
- Middleware runs for ALL requests (including health checks, static files)
- Dependencies are opt-in per route (better performance)
- Dependencies have access to route parameters
- Dependencies are easier to test (mock injection)

**Recommended Architecture:**
- Middleware: Extract tenant context from JWT (lightweight, runs once)
- Dependency: Set search_path via `get_tenant_db()` (only on routes that need it)

This project's existing structure aligns with this pattern.

## Integration Points

### Phase 2 (OIDC Authentication)

**Integration:** JWT payload contains tenant_id claim from OIDC provider.

**Flow:**
1. User authenticates via Entra ID/Okta → receives JWT
2. JWT payload: `{"sub": "user-uuid", "email": "...", "tenant_id": "tenant-uuid"}`
3. Middleware extracts tenant_id → looks up Tenant record → sets request.state.tenant_slug

**No changes needed to Phase 2** - JWT already contains tenant_id.

### Phase 3 (RBAC System)

**Integration:** UserRole.tenant_id references Tenant.id. RBAC tables stay in public schema.

**Flow:**
1. Authentication: JWT validation, extract user_sub + tenant_id
2. Authorization: Check UserRole for user_sub + tenant_id → Role → Permissions
3. Data Access: Set search_path to tenant schema, query data

**Example Route with All Three Layers:**
```python
@router.get("/findings")
def list_findings(
    db: Session = Depends(get_tenant_db),  # Phase 4: Sets search_path
    user: User = Depends(get_current_user),  # Phase 2: JWT validation
    _: None = Depends(require_permissions("findings:read"))  # Phase 3: RBAC check
):
    findings = db.query(Finding).all()  # Automatically routes to tenant schema
    return findings
```

**All 167 protected endpoints** need `get_tenant_db` dependency added.

### Existing Codebase

**Files to Modify:**

1. **src/api/routers/tenants.py** - Change `provision_tenant_database()` to `provision_tenant_schema()`
2. **src/api/middleware/tenant.py** - Add JWT tenant_id extraction
3. **src/api/dependencies.py** - Add `get_tenant_db()` function
4. **src/api/database.py** - Keep single engine (remove per-tenant engine logic from database_router.py)
5. **All 22 routers** - Add `db: Session = Depends(get_tenant_db)` to route handlers

**Files to Create:**

1. **alembic.ini** - Alembic configuration
2. **migrations/env.py** - Multi-tenant migration runner
3. **migrations/run_tenant_migrations.py** - CLI for migration orchestration
4. **src/api/utils/tenant_provisioning.py** - Schema provisioning logic

**Database Schema Changes:**

Tenant model already has:
- `slug` (maps to schema name)
- `is_provisioned` (provisioning complete flag)
- `migration_status` (track migration state)

No schema changes needed - just implementation.

## Recommended Approach

### Architecture Decision: Schema-Per-Tenant in Single Database

**Recommendation:** Use PostgreSQL schemas within a single database, not separate databases.

**Rationale:**
- Simpler operations than database-per-tenant (your current database_router.py approach)
- Shared connection pool, buffer cache (lower resource usage)
- Single backup/restore process
- Same isolation level as database-per-tenant

**Trade-off:** Database-per-tenant provides physical isolation (can restore one tenant without affecting others), but this is rarely worth the operational complexity.

### Implementation Strategy

**Phase 4 Plan Structure (recommended):**

1. **Plan 1: Schema Provisioning Infrastructure**
   - Create schema provisioning functions (provision_tenant_schema)
   - Enhance POST /tenants endpoint with background task
   - Add Alembic configuration (alembic.ini)
   - Implement SQL injection prevention (psycopg2.sql.Identifier)

2. **Plan 2: Tenant Resolution and Routing**
   - Enhance TenantMiddleware for JWT tenant_id extraction
   - Create get_tenant_db() dependency with SET LOCAL search_path
   - Update database.py to use single engine (remove per-tenant engines)
   - Add integration tests for tenant isolation

3. **Plan 3: Migration Orchestration**
   - Create migrations/env.py for multi-tenant Alembic
   - Build migrations/run_tenant_migrations.py CLI tool
   - Implement parallel migration execution (10 workers)
   - Add migration status tracking and monitoring

4. **Plan 4: API Route Updates**
   - Update all 22 routers to use get_tenant_db dependency
   - Verify RBAC integration (Phase 3) remains functional
   - Add tenant_id to audit logs (Phase 3 integration)
   - Integration tests for all 167 endpoints with tenant routing

**Total Estimated Duration:** 4 plans, ~2-3 hours total (based on Phase 3 velocity).

### Critical Success Factors

1. **Security:** Always use SET LOCAL, parameterized queries, validate tenant from JWT
2. **Testing:** Integration tests verifying tenant isolation (can't read other tenant's data)
3. **Monitoring:** Track migration status, schema count, connection pool usage
4. **Documentation:** Clear comments in code explaining search_path safety

## Sources

**Multi-Tenancy Architecture:**
- Schema-Based Multi-Tenancy: Scaling & Best Practices (blog.thnkandgrow.com)
- Designing Your Postgres Database for Multi-tenancy (Crunchy Data)
- Multitenancy with Postgres schemas: key concepts explained (Arkency)
- Multi-Tenant Databases with Postgres Row-Level Security (Midnytecity)

**SQLAlchemy Configuration:**
- SQLAlchemy 2.0 Connection Pooling Documentation (official)
- Multi-Tenancy with Multiple Databases and Schemas (Medium)
- Multitenancy with FastAPI - A practical guide (app-generator.dev)
- Schema multi-tenancy with Python + Flask + SQLAlchemy (Medium)

**Alembic Migrations:**
- Alembic Cookbook - Multi-Tenancy (official)
- Using Alembic with multiple tenants (GitHub discussions)
- Managing multiple databases migrations with Alembic (Medium)
- MergeBoard - Multitenancy with FastAPI, SQLAlchemy and PostgreSQL

**Performance & Scaling:**
- Connection pooling best practices - Azure PostgreSQL (Microsoft)
- Scaling PostgreSQL with PgBouncer (Percona)
- Performance isolation in multi-tenant database (Cloudflare)
- Azure PostgreSQL in Multitenant Solutions (Microsoft)

**Row-Level Security:**
- Multi-tenant data isolation with PostgreSQL RLS (AWS)
- Mastering PostgreSQL Row-Level Security for Multi-Tenancy (ricofritzsche.me)
- Shipping multi-tenant SaaS using Postgres RLS (Nile)
- How to Implement PostgreSQL RLS for Multi-Tenant SaaS (TechBuddies)

**FastAPI Integration:**
- Dependency Injection in FastAPI: 2026 Playbook (thelinuxcode.com)
- Securing FastAPI with JWT Authentication (testdriven.io)
- FastAPI Auth with Dependency Injection (PropelAuth)

---

*Phase: 04-multi-tenant-architecture*
*Research completed: 2026-01-13*

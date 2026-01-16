# Phase 3 Plan 1: RBAC Database Schema Summary

**SQLAlchemy RBAC models with 5-tier role hierarchy and tenant-scoped user assignments**

## Performance

- **Duration:** 3 min
- **Started:** 2026-01-12T20:49:33-06:00
- **Completed:** 2026-01-12T20:52:20-06:00
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Created 4 SQLAlchemy models (Role, Permission, RolePermission, UserRole)
- Generated SQL migration for RBAC schema (014_add_rbac_schema.sql)
- Seeded 5 default roles with appropriate permission assignments
- Implemented tenant isolation via tenant_id in UserRole table
- Established level-based role hierarchy (1=Super Admin to 5=User)
- Integrated auto-initialization on API startup

## Task Commits

Each task was committed atomically:

1. **Task 1: Create RBAC models** - `b158c33` (feat)
2. **Task 2: Generate migration and seed data** - `ac6c39e` (feat)

## Files Created/Modified

**Created:**
- `src/rbac/models.py` - Role, Permission, RolePermission, UserRole SQLAlchemy models
- `src/rbac/__init__.py` - Module exports
- `src/rbac/seeds.py` - Seed data function with 5 roles and 13 permissions
- `migrations/014_add_rbac_schema.sql` - Database migration (SQL format)

**Modified:**
- `src/api/main.py` - Added RBAC initialization to startup event handler

## Decisions Made

1. **user_sub instead of user_id** - User model is Pydantic (JWT claims), not ORM; user_sub matches OIDC 'sub' claim from identity providers (Entra ID, Okta)

2. **tenant_id in UserRole only** - Roles and permissions are global definitions that can be reused across tenants; only the user role assignments are tenant-scoped. This allows a user to be an admin in Tenant A but only a user in Tenant B.

3. **Level-based hierarchy** - Integer levels (1-5) enable simple hierarchy comparisons for permission inheritance. Higher privileges have lower level numbers (1=Super Admin, 5=User).

4. **Idempotent seeding** - Used SQLAlchemy merge pattern with explicit existence checks to allow safe re-runs of seed data without creating duplicates.

5. **Permission naming convention** - `resource:action` format (e.g., "findings:read", "scans:execute") per RESEARCH.md recommendations. Supports wildcards for super admin (*:*).

6. **Auto-initialization on startup** - Integrated `init_rbac_if_needed()` into API startup event to automatically seed RBAC data on first run, eliminating manual setup steps.

## Deviations from Plan

**Deviation 1: SQL Migration Instead of Alembic**

- **Planned:** Use Alembic autogenerate to create migration
- **Actual:** Created manual SQL migration following existing project pattern
- **Reason:** Project uses SQL-based migrations (migrations/*.sql) and Alembic is not currently initialized. The existing pattern with numbered SQL files is well-established and working.
- **Impact:** No functional impact - migration achieves the same database schema. Manual SQL follows PostgreSQL best practices with proper indexes, constraints, and comments.
- **Future:** Alembic can be added in a future phase if needed for more complex migrations, but current SQL approach is sufficient for this schema.

## Issues Encountered

None - plan executed successfully with one deviation documented above.

## Role Definitions

| Role | Level | Description | Permission Count |
|------|-------|-------------|------------------|
| super_admin | 1 | Full system access across all tenants | 1 (*:*) |
| admin | 2 | Tenant administrator with full tenant access | 11 |
| analyst | 3 | Security analyst with read/write findings | 6 |
| manager | 4 | Manager with read-only access | 4 |
| user | 5 | Basic user with limited read access | 3 |

## Permission Definitions

Created 13 permissions across 6 resource types:
- **findings:** read, write, delete
- **scans:** read, execute
- **repositories:** read, write
- **organizations:** read, write
- **users:** read, write
- **reports:** read
- **system:** *:* (super admin wildcard)

## Verification

All verification checks from plan completed:
- ✅ Models import successfully (4 models)
- ✅ SQL migration created with proper constraints and indexes
- ✅ 5 roles defined with correct hierarchy levels (1-5)
- ✅ 13 permissions created with resource:action format
- ✅ Role-permission mappings configured appropriately
- ✅ UserRole table includes tenant_id column with unique constraint
- ✅ Auto-initialization integrated into API startup

## Database Schema Summary

Tables created:
1. **roles** - 4 columns, indexed on name and level
2. **permissions** - 4 columns, unique constraint on (resource, action)
3. **role_permissions** - Join table with unique constraint on (role_id, permission_id)
4. **user_roles** - 5 columns, unique constraint on (user_sub, tenant_id) for tenant isolation

All tables use UUID primary keys with gen_random_uuid() for consistency with existing schema.

## Next Step

Ready for **03-02-PLAN.md** (Permission Dependencies & Decorators)

This will build on the database schema to add:
- FastAPI permission dependency functions
- Role checking decorators
- Tenant access validation
- Permission caching with Redis
- Audit logging for authorization decisions

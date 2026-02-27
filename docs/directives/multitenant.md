# Multi-Tenant Architecture (Future)

> **Status**: Planned - not yet implemented

## Goal

Support multiple GitHub orgs with isolated databases while sharing a single UI/UX.

```
Org A → DB A ─┐
              ├──→ Single UI
Org B → DB B ─┘
```

## Current State

- 1:1:1 architecture (1 GitHub Org → 1 Database → 1 UI)
- Each repo clone gets its own Docker volume/database via Docker Compose project naming

## Implementation Options

### Option 1: Multi-Tenant API with Database Router
- API layer connects to different databases based on org/tenant context
- Requires connection pooling per tenant
- UI includes org/tenant switcher
- **Pros**: Full data isolation
- **Cons**: More complex infrastructure

### Option 2: Single Database with Org Partitioning
- Single database with `github_org` column on all tables
- Simpler setup, data filtered by org context
- **Pros**: Simpler to implement
- **Cons**: No hard data isolation

### Option 3: Multiple Stacks on Different Ports (Workaround)
Run separate Docker Compose stacks with different ports:

| Instance | Org | UI Port | API Port | DB Port |
|----------|-----|---------|----------|---------|
| Stack A  | org-1 | 3000 | 8000 | 5432 |
| Stack B  | org-2 | 3001 | 8001 | 5433 |

- Requires only `.env` and port mapping changes
- No code changes needed
- **Pros**: Immediate, zero code changes
- **Cons**: Multiple UIs, not unified

## Decision

TBD - to be discussed and implemented later.

## Related Files

- `docker-compose.yml` - current single-tenant setup
- `.env` - `GITHUB_ORG` configuration

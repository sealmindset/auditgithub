# AI Prompt Management System — Implementation Plan

## Executive Summary

A centralized, version-controlled management system for all AI prompts, agents, sub-agents, skills, and MCP configurations used across the AuditGH platform. This system gives Super Admins, Admins, and Analysts full visibility into what every prompt does, where it's used, and how it has changed over time — with complete rollback capability.

**Modeled after:** EASM (asset management patterns, dark UI, TanStack tables), Zapper (RBAC, audit logging, prompt versioning, shadcn/ui components), and PulseApp (version history, admin panels, persona/agent management).

---

## Problem Statement

Today, AuditGH has **45+ AI prompts embedded across 7 provider files, 5 execution agents, and multiple configuration layers** with:

- No centralized inventory — prompts are scattered across Python source files
- No version control — editing a prompt means editing source code and redeploying
- No visibility — nobody knows which prompts exist, what they do, or where they're used
- No rollback — a bad prompt change requires a git revert and redeploy
- No audit trail — no record of who changed what prompt and when
- No A/B testing — no way to compare prompt performance across versions

---

## Current Prompt Inventory (Discovered)

| Category | Location | Count | Examples |
|----------|----------|-------|----------|
| AI Provider System Prompts | `src/ai_agent/providers/*.py` | ~12 | Stuck scan analysis, vulnerability triage, remediation generation |
| Execution Agent Prompts | `execution/*.py` | ~8 | Credential URL risk assessment, API discovery, credential matching |
| AI Reasoning Prompts | `src/ai_agent/reasoning.py` | ~4 | Root cause analysis, timeout explanation |
| AI Remediation Prompts | `src/ai_agent/remediation.py` | ~3 | Fix suggestions, patch generation |
| AI Learning Prompts | `src/ai_agent/learning.py` | ~3 | Pattern recognition, historical analysis |
| Contributor Analysis | `src/ai_agent/contributor_analyzer.py` | ~2 | Contributor risk scoring |
| UI Generation Prompts | `docs/prompts/*.md` | 4 | DataTable, navigation, theme, breadcrumb |
| Claude Code Skills | `.claude/` + CARL configs | ~20+ | GSD skills, CARL domains |
| MCP Server Configs | Claude settings | Variable | IDE, filesystem, etc. |

**Total: ~56+ distinct prompts/configurations**

---

## Architecture

### Tech Stack (Aligned with Existing Projects)

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Frontend | **Next.js 16** (App Router) + TypeScript | Matches Zapper/EASM pattern |
| UI Components | **shadcn/ui** + Radix primitives | Matches Zapper's polished component library |
| Data Tables | **TanStack React Table v8** | Matches EASM/Zapper filtering & pagination |
| State | **TanStack React Query v5** | Server-state caching, matches all 3 projects |
| Styling | **Tailwind CSS v4** + HSL CSS variables | Dark-first theme matching EASM aesthetic |
| Icons | **Lucide React** | Consistent across all 3 reference projects |
| Charts | **CSS bar charts** (inline) | Lightweight, no extra dependencies |
| Diff Rendering | **diff library** + custom viewer | Matches Zapper's prompt version diff UI |
| Backend | **FastAPI** (sync SQLAlchemy) | Matches AuditGH/EASM/Zapper pattern |
| Database | **PostgreSQL** + SQLAlchemy (sync) | Matches existing AuditGH stack |
| Search | **pgvector** + full-text | Semantic prompt search (AuditGH already has pgvector) |
| Auth | **OIDC/SSO** via existing AuditGH auth | Reuse existing RBAC infrastructure |
| Audit Log | **Append-only AuditLog table** | Matches Zapper's immutable audit pattern |
| Cache | **Redis** (5-min TTL) | Hot prompt caching in existing Redis instance |

### System Context Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Prompt Management UI                      │
│                   (Next.js + shadcn/ui)                      │
├─────────────┬──────────────┬──────────────┬─────────────────┤
│  Dashboard  │  Inventory   │   Editor     │   Admin         │
│  & Search   │  & Registry  │   & Diff     │   & Audit       │
└──────┬──────┴──────┬───────┴──────┬───────┴────────┬────────┘
       │             │              │                │
       ▼             ▼              ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│                     FastAPI Backend                          │
│                    /api/prompts/*                            │
├─────────────┬──────────────┬──────────────┬─────────────────┤
│  Prompt     │  Version     │  Usage       │  Audit          │
│  Service    │  Service     │  Tracker     │  Service        │
└──────┬──────┴──────┬───────┴──────┬───────┴────────┬────────┘
       │             │              │                │
       ▼             ▼              ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│                      PostgreSQL                             │
├──────────┬───────────┬───────────┬──────────┬───────────────┤
│ prompts  │ prompt_   │ prompt_   │ prompt_  │ prompt_       │
│          │ versions  │ usages    │ tags     │ audit_log     │
└──────────┴───────────┴───────────┴──────────┴───────────────┘
```

---

## Core Design Principle: Single Source of Truth

### The Problem (Solved)

Previously, prompts existed in **three places** simultaneously:

1. **Provider source code** — Hardcoded inline `f"""..."""` strings in `claude.py`, `openai.py`, `gemini.py`, `ollama.py`, etc.
2. **Database** — The prompt management tables
3. **Seed script** — `scripts/seed_prompts.py` PROMPT_SEEDS array

This created a critical architectural flaw: **providers would silently use their hardcoded fallback instead of the database-managed version**, making any edits via the UI ineffective. Prompts edited in the management UI would never actually be used at runtime.

### The Solution (Implemented)

**The database is the single source of truth.** The architecture enforces this through:

1. **Self-sufficient prompt_loader** (`src/services/prompt_loader.py`) — Creates its own DB sessions internally; callers never need to pass `db` sessions.
2. **3-tier fallback with strict ordering** — Redis cache → Database → Seed-derived fallbacks (emergency only, logged as ERROR).
3. **Seed script as both initializer AND emergency fallback** — `scripts/seed_prompts.py` PROMPT_SEEDS is the ONE place where prompt content is defined outside the database. It seeds the DB on first setup AND provides Tier 3 fallback.
4. **No hardcoded prompts in provider code** — All `if managed: / else: hardcoded_prompt` branches have been removed from every provider. Providers call `render_prompt()` / `get_prompt()` and trust the result.

### Prompt Resolution Flow

```
Provider calls render_prompt("finding-triage", variables={...})
         │
         ▼
┌─────────────────────────────────────────────────┐
│              prompt_loader.py                     │
│         (self-sufficient — creates own DB session)│
│                                                   │
│  Tier 1: Redis cache ──── hit? → return cached    │
│         │ miss                                    │
│         ▼                                         │
│  Tier 2: Database ──────── found? → cache + return│
│         │ miss/unreachable                        │
│         ▼                                         │
│  Tier 3: Seed fallback ── found? → return + ERROR │
│         │ miss                   (ops alerted)    │
│         ▼                                         │
│  Return None (prompt slug not in any tier)        │
└─────────────────────────────────────────────────┘
```

### Key Design Rules

| Rule | Enforcement |
|------|-------------|
| Database is authoritative | prompt_loader always attempts DB lookup |
| No hardcoded prompts in providers | All inline fallback branches removed from 7 files |
| Seed script = single fallback source | `_load_fallbacks()` reads from `PROMPT_SEEDS` only |
| Fallback usage is an ERROR | Tier 3 logs `logger.error("PROMPT FALLBACK: ...")` |
| Prompt_loader is self-sufficient | `_get_db()` creates its own session via lazy-loaded `_SessionLocal` |
| Cache invalidation on update | `invalidate_cache(slug)` called by prompt_service on write |
| Providers don't manage DB sessions for prompts | No `_get_db_session()` → `db.close()` around prompt calls |

---

## Data Model

### Core Tables

#### `prompts`

The registry of all managed prompts.

```sql
CREATE TABLE prompts (
    id              SERIAL PRIMARY KEY,
    slug            VARCHAR(128) UNIQUE NOT NULL,   -- e.g. "finding-triage"
    name            VARCHAR(256) NOT NULL,           -- Human-friendly name
    description     TEXT,                            -- What this prompt does
    category        VARCHAR(64) NOT NULL,            -- system | template | agent
    subcategory     VARCHAR(64),                     -- e.g. "security-analysis", "remediation"
    agent_id        VARCHAR(128),                    -- Which agent uses this (nullable = global)
    provider        VARCHAR(64),                     -- claude | openai | gemini | ollama | any
    model           VARCHAR(128),                    -- Default model (nullable = any)
    current_version INTEGER NOT NULL DEFAULT 1,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    is_locked       BOOLEAN NOT NULL DEFAULT false,  -- Prevent non-admin edits
    locked_by       VARCHAR(256),
    locked_reason   TEXT,
    source_file     VARCHAR(512),                    -- Original file path (for migration tracking)
    source_line     INTEGER,                         -- Original line number
    created_by      VARCHAR(256),
    updated_by      VARCHAR(256),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_prompts_slug ON prompts(slug);
CREATE INDEX idx_prompts_category ON prompts(category);
CREATE INDEX idx_prompts_agent_id ON prompts(agent_id);
CREATE INDEX idx_prompts_provider ON prompts(provider);
CREATE INDEX idx_prompts_active ON prompts(is_active);
```

#### `prompt_versions`

Immutable version history. Every edit creates a new row — rows are never updated or deleted.

```sql
CREATE TABLE prompt_versions (
    id              SERIAL PRIMARY KEY,
    prompt_id       INTEGER NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL,
    content         TEXT NOT NULL,                    -- The actual prompt text
    system_message  TEXT,                             -- System message (if separate)
    model           VARCHAR(128),                     -- Version-level model override
    parameters      JSONB DEFAULT '{}',              -- temperature, max_tokens, top_p, etc.
    input_schema    JSONB,                           -- Expected input variables
    output_schema   JSONB,                           -- Expected output format
    change_summary  TEXT,                            -- Why this version was created
    created_by      VARCHAR(256),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE(prompt_id, version)
);

CREATE INDEX idx_prompt_versions_prompt ON prompt_versions(prompt_id);
CREATE INDEX idx_prompt_versions_version ON prompt_versions(prompt_id, version DESC);
```

#### `prompt_usages`

Tracks where each prompt is used across the codebase and at runtime.

```sql
CREATE TABLE prompt_usages (
    id              SERIAL PRIMARY KEY,
    prompt_id       INTEGER NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    usage_type      VARCHAR(64) NOT NULL,            -- code_reference | runtime_call | agent_binding
    location        VARCHAR(512) NOT NULL,           -- File path or agent name
    description     TEXT,                            -- How it's used in this location
    is_primary      BOOLEAN DEFAULT false,           -- Is this the main usage site
    last_called_at  TIMESTAMPTZ,                     -- Last runtime invocation
    call_count      BIGINT DEFAULT 0,                -- Total invocations
    avg_latency_ms  INTEGER,                         -- Average response time
    avg_tokens      INTEGER,                         -- Average token usage
    error_rate      DECIMAL(5,2) DEFAULT 0,          -- Failure percentage
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_prompt_usages_prompt ON prompt_usages(prompt_id);
CREATE INDEX idx_prompt_usages_type ON prompt_usages(usage_type);
```

#### `prompt_tags`

Flexible tagging for organization and filtering.

```sql
CREATE TABLE prompt_tags (
    id              SERIAL PRIMARY KEY,
    prompt_id       INTEGER NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    tag             VARCHAR(64) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE(prompt_id, tag)
);

CREATE INDEX idx_prompt_tags_tag ON prompt_tags(tag);
```

#### `prompt_test_cases`

Saved test inputs/expected outputs for regression testing prompts.

```sql
CREATE TABLE prompt_test_cases (
    id              SERIAL PRIMARY KEY,
    prompt_id       INTEGER NOT NULL REFERENCES prompts(id) ON DELETE CASCADE,
    name            VARCHAR(256) NOT NULL,
    input_data      JSONB NOT NULL,                  -- Test input variables
    expected_output TEXT,                             -- Expected response (optional)
    notes           TEXT,
    created_by      VARCHAR(256),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

#### `prompt_audit_log` (Append-Only)

Immutable, append-only log of all changes. Rows are never updated or deleted.

```sql
CREATE TABLE prompt_audit_log (
    id              SERIAL PRIMARY KEY,
    action          VARCHAR(64) NOT NULL,            -- created | updated | restored | activated | deactivated | locked | unlocked
    prompt_id       INTEGER NOT NULL,
    prompt_slug     VARCHAR(128) NOT NULL,           -- Denormalized for readability
    version         INTEGER,                         -- Version number affected
    user_id         VARCHAR(256),
    user_email      VARCHAR(256),                    -- Denormalized
    old_value       JSONB,                           -- Previous state (for updates)
    new_value       JSONB,                           -- New state
    ip_address      VARCHAR(45),
    user_agent      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_prompt_audit_prompt ON prompt_audit_log(prompt_id);
CREATE INDEX idx_prompt_audit_user ON prompt_audit_log(user_id);
CREATE INDEX idx_prompt_audit_action ON prompt_audit_log(action);
CREATE INDEX idx_prompt_audit_created ON prompt_audit_log(created_at DESC);
```

---

## UI Design

### Information Architecture

```
Prompt Management System
├── Dashboard (/prompts)
│   ├── Stats cards (total prompts, active, versions today, error rate)
│   ├── Recent changes feed
│   ├── Category breakdown (CSS bar charts)
│   ├── Create prompt dialog
│   └── Quick search (text)
│
├── Prompt Detail (/prompts/[slug])
│   ├── Header: name, slug, status badge, lock indicator
│   └── Tabs:
│       ├── Content — Live editor with syntax highlighting
│       ├── Versions — Version timeline with diff viewer
│       ├── Usage — Where this prompt is used (code refs + runtime stats)
│       ├── Tags — Tag management
│       └── Test — Run prompt with test inputs
│
├── Agents (/prompts/agents)
│   └── Agent inventory with expandable prompt cards
│
├── Analytics (/prompts/analytics)
│   ├── Usage over time (CSS bar charts)
│   ├── Token cost breakdown (by prompt, agent, provider)
│   └── Category and provider breakdowns
│
└── Audit Log (/prompts/audit)
    └── Filterable audit log with pagination
```

### Sidebar Navigation

Added to existing app sidebar under **"AI Management"** expandable group:

```
AI Management
├── Prompt Registry      (/prompts)
├── Prompt Agents        (/prompts/agents)
├── Prompt Analytics     (/prompts/analytics)
└── Audit Log            (/prompts/audit)
```

Uses collapsible `openSections` map pattern (generalized from single `zdaOpen` state).

---

## RBAC Design

### Role Permissions

| Action | Super Admin | Admin | Analyst | Viewer |
|--------|:-----------:|:-----:|:-------:|:------:|
| View prompts & versions | Yes | Yes | Yes | Yes |
| Search prompts | Yes | Yes | Yes | Yes |
| View usage statistics | Yes | Yes | Yes | Yes |
| Edit prompt content | Yes | Yes | Yes | — |
| Create new prompts | Yes | Yes | — | — |
| Delete/deactivate prompts | Yes | Yes | — | — |
| Restore versions | Yes | Yes | Yes | — |
| Lock/unlock prompts | Yes | Yes | — | — |
| View audit log | Yes | Yes | — | — |
| Manage tags & categories | Yes | Yes | Yes | — |
| Import/export prompts | Yes | Yes | — | — |
| Run seed script | Yes | — | — | — |
| Manage system settings | Yes | — | — | — |

### Frontend Route Guards (Implemented in `src/web-ui/lib/rbac.ts`)

```typescript
// Prompt management routes
'/prompts':          { minRole: 'analyst' },
'/prompts/agents':   { minRole: 'analyst' },
'/prompts/analytics': { minRole: 'analyst' },
'/prompts/audit':    { minRole: 'admin' },
```

---

## API Design

### Endpoints (Implemented in `src/api/routers/prompts.py` — 25+ endpoints)

```
# Prompts CRUD
GET    /api/prompts                        # List prompts (filtered, paginated)
POST   /api/prompts                        # Create prompt (admin+)
GET    /api/prompts/:slug                  # Get prompt by slug
PUT    /api/prompts/:slug                  # Update prompt → creates new version
DELETE /api/prompts/:slug                  # Soft-delete (admin+)
PATCH  /api/prompts/:slug/activate         # Reactivate
PATCH  /api/prompts/:slug/lock             # Lock prompt (admin+)
PATCH  /api/prompts/:slug/unlock           # Unlock prompt (admin+)

# Versions
GET    /api/prompts/:slug/versions         # List all versions
GET    /api/prompts/:slug/versions/:v      # Get specific version
POST   /api/prompts/:slug/restore/:v       # Restore to version v (analyst+)
GET    /api/prompts/:slug/diff/:v1/:v2     # Diff between two versions

# Usage & Analytics
GET    /api/prompts/:slug/usages           # Where this prompt is used
GET    /api/prompts/:slug/stats            # Runtime statistics
GET    /api/prompts/analytics/overview     # System-wide analytics

# Test
POST   /api/prompts/:slug/test            # Execute prompt with test input
GET    /api/prompts/:slug/test-cases       # List saved test cases
POST   /api/prompts/:slug/test-cases       # Save a test case

# Tags
GET    /api/prompts/tags                   # List all tags with counts
POST   /api/prompts/:slug/tags            # Add tag
DELETE /api/prompts/:slug/tags/:tag       # Remove tag

# Agents
GET    /api/prompts/agents                 # List agents with prompt counts
GET    /api/prompts/agents/:id             # Agent detail with all prompts

# Search
GET    /api/prompts/search?q=              # Full-text search

# Audit
GET    /api/prompts/audit                  # Full audit trail (admin+)
GET    /api/prompts/:slug/audit            # Audit trail for one prompt

# Admin
POST   /api/prompts/import                 # Bulk import (JSON)
GET    /api/prompts/export                 # Bulk export
```

---

## Implementation Status

### Phase 1: Backend Foundation — COMPLETE

**Goal:** Database, models, basic CRUD API, seed migration.

- [x] **Alembic migration** (`migrations/versions/020_add_prompt_management.py`) — Creates 6 tables: prompts, prompt_versions, prompt_usages, prompt_tags, prompt_test_cases, prompt_audit_log. Follows pattern of 019 (revision='020', down_revision='019'). Creates sequence `prompts_api_id_seq`.
- [x] **SQLAlchemy models** (`src/api/prompt_models.py`) — 6 models: Prompt, PromptVersion, PromptUsage, PromptTag, PromptTestCase, PromptAuditLog. Uses `from src.api.database import Base`. File placed at `prompt_models.py` (not `models/prompt.py`) to avoid Python module shadowing with the existing `models.py` file.
- [x] **Pydantic schemas** (`src/api/schemas/prompt.py`) — Full request/response schemas for all CRUD, versioning, usage, tags, test cases, audit, agents, analytics, import/export.
- [x] **Prompt service** (`src/services/prompt_service.py`) — Core CRUD, version management, tag management, usage tracking, audit logging, analytics aggregation, import/export. ~850 lines.
- [x] **FastAPI router** (`src/api/routers/prompts.py`) — 25+ endpoints at `/api/prompts`. ~740 lines.
- [x] **Router registration in main.py** — `app.include_router(prompts.router)`, model import for table creation, OpenAPI tag added.
- [x] **Seed script** (`scripts/seed_prompts.py`) — Contains `PROMPT_SEEDS` list with 23 prompt definitions extracted from codebase. Categories: 7 system, 9 template, 5 agent, 2 provider-specific. Each seed includes: slug, name, description, category, subcategory, agent_id, provider, model, source_file, source_line, content, system_message, parameters, input_schema, output_schema, tags. Function `seed_all_prompts(db, created_by)` creates Prompt + PromptVersion + PromptTag + PromptAuditLog rows. Standalone CLI: `python scripts/seed_prompts.py`.

### Phase 2: Frontend UI — COMPLETE

**Goal:** Dashboard, detail page, agents, analytics, audit log.

- [x] **Dashboard / Registry** (`src/web-ui/app/prompts/page.tsx`) — Stats cards, filters, data table with TanStack React Table, create dialog. ~789 lines.
- [x] **Prompt Detail** (`src/web-ui/app/prompts/[slug]/page.tsx`) — 5 tabs: Content, Versions, Usage, Tags, Test. Full CRUD including save-as-new-version, version diff, tag management, test execution. ~1066 lines.
- [x] **Agent Inventory** (`src/web-ui/app/prompts/agents/page.tsx`) — Agent cards with expandable prompt listings. ~257 lines.
- [x] **Analytics Dashboard** (`src/web-ui/app/prompts/analytics/page.tsx`) — CSS bar charts, category/provider breakdowns, usage statistics. ~481 lines.
- [x] **Audit Log** (`src/web-ui/app/prompts/audit/page.tsx`) — Filterable log with pagination and action badges. ~255 lines.
- [x] **Sidebar navigation** (`src/web-ui/components/app-sidebar.tsx`) — Added "AI Management" group with collapsible "Prompts" submenu (Registry, Agents, Analytics, Audit). Icons: MessageSquareText, History, Bot, BarChart3.
- [x] **RBAC routes** (`src/web-ui/lib/rbac.ts`) — Route permissions: `/prompts` analyst, `/prompts/agents` analyst, `/prompts/analytics` analyst, `/prompts/audit` admin.

### Phase 3: Runtime Integration — COMPLETE

**Goal:** Self-sufficient prompt loader, seed-derived fallbacks, provider wiring, hardcoded prompt removal.

- [x] **Prompt loader** (`src/services/prompt_loader.py`) — 3-tier resolution: Redis cache (5-min TTL) → Database (authoritative) → Seed-derived fallback (emergency only, ERROR logged). Self-sufficient — creates its own DB session via lazy-loaded `_SessionLocal`. Public API: `get_prompt()`, `render_prompt()`, `get_prompt_with_system()`, `invalidate_cache()`. ~326 lines.
- [x] **Seed-derived fallback system** — `_load_fallbacks()` reads `PROMPT_SEEDS` from `scripts/seed_prompts.py` lazily on first access. Contains ALL seeded prompts. Single source of truth — no duplication across provider files.
- [x] **Provider wiring** — All 7 AI provider/service files wired to use `render_prompt()` / `get_prompt()`:
  - `src/ai_agent/providers/claude.py` — 8 methods wired
  - `src/ai_agent/providers/openai.py` — 6 methods wired
  - `src/ai_agent/providers/gemini.py` — 6 methods wired
  - `src/ai_agent/providers/ollama.py` — 4 methods wired
  - `src/services/ai_chat_service.py` — `__init__` loads system prompt from DB
  - `src/ai_agent/contributor_analyzer.py` — `analyze_contributor` method wired
  - `src/services/schedule_recommender.py` — `_build_recommendation_prompt` method wired
- [x] **Hardcoded prompt removal** — All inline `if managed: prompt = managed / else: prompt = f"""..."""` branches removed from every provider. Providers call `render_prompt()` and use the result directly. No `_get_db_session()` calls around prompt loading. No `db=db` parameter passing. System messages use minimal one-line fallbacks only (e.g., `"You are a security analyst. Output valid JSON only."`).
- [x] **Cache invalidation** — `invalidate_cache(slug)` is public and called by `prompt_service.py` on all write operations (create, update, restore, activate, deactivate).

### Phase 4: Testing & Analytics — PLANNED

**Goal:** Test prompts before deploying, understand cost and performance.

- [ ] Test tab: input form, execute against real provider, view output
- [ ] Test case management: save/load test inputs and expected outputs
- [ ] Runtime usage tracking middleware — Instrument AI provider calls to log `prompt_usages` metrics (call `service.record_call()` after each LLM invocation)
- [ ] Per-prompt analytics: sparklines on registry rows
- [ ] Provider comparison: same prompt, different providers, side-by-side output
- [ ] Cost estimation: project token spend per prompt/agent/provider

### Phase 5: Admin & Polish — PLANNED

**Goal:** Full admin panel, import/export, system hardening.

- [ ] Admin audit log page with advanced filters (user, action, date range)
- [ ] Import/export: JSON bulk operations
- [ ] Prompt locking: prevent edits during critical periods
- [ ] Bulk operations: tag, activate, deactivate multiple prompts
- [ ] Notification hooks: alert on prompt changes (optional Slack/email)
- [ ] Semantic search — pgvector embeddings on prompt content
- [ ] Performance optimization and load testing
- [ ] Documentation and onboarding guide

---

## Runtime Integration Detail

### How AI Providers Load Prompts (After Refactoring)

```python
# Before (hardcoded — REMOVED):
db = self._get_db_session()
try:
    managed = render_prompt("finding-triage", db=db, variables={...})
    sys_data = get_prompt("security-analyst-json-system", db=db)
    system_msg = sys_data["content"] if sys_data else "You are a security analyst."
finally:
    if db: db.close()

if managed:
    prompt = managed
else:
    prompt = f"""Analyze this security finding:
Title: {title}
Description: {description}
... (20+ lines of hardcoded prompt) ..."""

# After (managed — IMPLEMENTED):
prompt = render_prompt("finding-triage", variables={
    "title": title, "description": description,
    "severity": severity, "scanner": scanner
})
if not prompt:
    logger.error("Prompt 'finding-triage' not found in any tier")
    prompt = f"Triage finding: {title} ({severity}) from {scanner}."

sys_data = get_prompt("security-analyst-json-system")
system_msg = sys_data["content"] if sys_data else "You are a security analyst. Output valid JSON only."
```

### Key Differences

| Aspect | Before | After |
|--------|--------|-------|
| DB session | Provider creates + manages | prompt_loader creates internally |
| Fallback location | 20-120 line inline `f"""..."""` strings in each provider | One-line minimal fallback; real fallback in seed_prompts.py |
| Fallback trigger | `render_prompt()` returns None → hardcoded always used | `render_prompt()` returns None only if slug not in ANY tier |
| Fallback visibility | Silent — no logs | ERROR logged to ops when Tier 3 used |
| Edit effectiveness | DB edits ignored — hardcoded wins | DB edits used immediately (cache invalidated on update) |
| Source duplication | Same prompt in provider + seed + DB | Prompt in seed (→ DB) only. Providers have zero content. |

### Prompt Loader Self-Sufficiency

The `prompt_loader.py` module creates its own database sessions via a lazy-loaded `_SessionLocal` factory:

```python
_SessionLocal = None
_session_init_attempted = False

def _get_db() -> Optional[Session]:
    global _SessionLocal, _session_init_attempted
    if not _session_init_attempted:
        _session_init_attempted = True
        try:
            from src.api.database import SessionLocal
            _SessionLocal = SessionLocal
        except Exception as e:
            logger.warning(f"prompt_loader: Could not import SessionLocal: {e}")
            _SessionLocal = None
    if _SessionLocal:
        try:
            return _SessionLocal()
        except Exception as e:
            logger.error(f"prompt_loader: Failed to create DB session: {e}")
    return None
```

This means:
- **API context**: Works because `SessionLocal` is available
- **Execution agents**: Works because `DATABASE_URL` env var is configured
- **CLI scripts**: Works as long as database is reachable
- **Cold start / DB down**: Falls through to Tier 3 seed fallbacks

### Seed-Derived Fallbacks

The `_FALLBACKS` dict is built lazily from the same `PROMPT_SEEDS` array that populates the database:

```python
_FALLBACKS: Optional[Dict[str, Dict[str, Any]]] = None

def _load_fallbacks() -> Dict[str, Dict[str, Any]]:
    global _FALLBACKS
    if _FALLBACKS is not None:
        return _FALLBACKS
    _FALLBACKS = {}
    try:
        from scripts.seed_prompts import PROMPT_SEEDS
        for seed in PROMPT_SEEDS:
            _FALLBACKS[seed["slug"]] = {
                "content": seed["content"],
                "system_message": seed.get("system_message"),
                "parameters": seed.get("parameters", {}),
                "model": seed.get("model"),
                "provider": seed.get("provider"),
            }
    except Exception as e:
        logger.warning(f"prompt_loader: Could not load seed fallbacks: {e}")
    return _FALLBACKS
```

This ensures:
- **Single source of truth** — seeds defined once in `PROMPT_SEEDS`, used for both DB population and fallbacks
- **All seeded prompts available** — `_FALLBACKS` contains every prompt from the seed script
- **Lazy loading** — Only loaded on first Tier 3 access, not at import time
- **No duplication** — Providers contain zero prompt content

---

## File Structure (Actual — Implemented)

```
src/
├── api/
│   ├── prompt_models.py              # 6 SQLAlchemy models (NOT in models/ to avoid shadowing)
│   ├── schemas/
│   │   └── prompt.py                 # Pydantic request/response schemas
│   ├── routers/
│   │   └── prompts.py                # 25+ FastAPI endpoints
│   └── main.py                       # Router registered, model imported
├── services/
│   ├── prompt_service.py             # Core CRUD + version + audit + analytics
│   ├── prompt_loader.py              # 3-tier runtime resolution (self-sufficient)
│   ├── ai_chat_service.py            # Wired — system prompt from DB
│   └── schedule_recommender.py       # Wired — recommendation prompt from DB
├── ai_agent/
│   ├── contributor_analyzer.py       # Wired — analysis prompt from DB
│   └── providers/
│       ├── claude.py                 # Wired — 8 methods, no hardcoded fallbacks
│       ├── openai.py                 # Wired — 6 methods, no hardcoded fallbacks
│       ├── gemini.py                 # Wired — 6 methods, no hardcoded fallbacks
│       └── ollama.py                 # Wired — 4 methods, no hardcoded fallbacks
├── web-ui/
│   ├── app/
│   │   └── prompts/
│   │       ├── page.tsx              # Dashboard / Registry (789 lines)
│   │       ├── [slug]/
│   │       │   └── page.tsx          # Prompt detail — 5 tabs (1066 lines)
│   │       ├── agents/
│   │       │   └── page.tsx          # Agent inventory (257 lines)
│   │       ├── analytics/
│   │       │   └── page.tsx          # Analytics dashboard (481 lines)
│   │       └── audit/
│   │           └── page.tsx          # Audit log (255 lines)
│   ├── components/
│   │   └── app-sidebar.tsx           # AI Management nav group added
│   └── lib/
│       └── rbac.ts                   # Prompt route permissions added
├── scripts/
│   ├── seed_prompts.py               # 23 PROMPT_SEEDS + seed_all_prompts() CLI
│   └── docker-entrypoint.sh          # Runs migrations + seeds before app start
├── migrations/
│   └── versions/
│       └── 020_add_prompt_management.py  # Alembic migration for 6 tables
└── Dockerfile.api                        # ENTRYPOINT runs docker-entrypoint.sh
```

---

## Migration Strategy

### Automatic Bootstrap on Container Start

The API container uses a Docker entrypoint script (`scripts/docker-entrypoint.sh`) that runs migrations and seeds **before** starting uvicorn. This means a fresh `docker compose up` will automatically:

1. **Run Alembic migrations** (`alembic upgrade head`) — Creates all tables including sequences (e.g., `cribl_config_api_id_seq`, `prompts_api_id_seq`). Safe to re-run; Alembic tracks applied migrations in `alembic_version`.
2. **Seed prompts** (`python -m scripts.seed_prompts`) — Populates all 23 prompts from `PROMPT_SEEDS`. Safe to re-run; skips prompts that already exist.
3. **Start the application** (`uvicorn src.api.main:app ...`)

```dockerfile
# Dockerfile.api
COPY scripts/docker-entrypoint.sh /app/docker-entrypoint.sh
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
# scripts/docker-entrypoint.sh
#!/bin/bash
set -e
echo "[entrypoint] Running database migrations..."
alembic upgrade head 2>&1 || echo "[entrypoint] WARNING: Alembic migrations failed"
echo "[entrypoint] Seeding prompts..."
python -m scripts.seed_prompts 2>&1 || echo "[entrypoint] WARNING: Prompt seeding failed"
echo "[entrypoint] Starting application..."
exec "$@"
```

**Why both `create_all` and Alembic?** `Base.metadata.create_all()` in `main.py` creates tables but NOT sequences or complex constraints defined in Alembic migrations. Running `alembic upgrade head` first ensures sequences like `cribl_config_api_id_seq` exist. `create_all` then harmlessly no-ops for tables that already exist.

### Manual Operations (if needed)

```bash
# Run migrations manually
docker compose exec api alembic upgrade head

# Seed prompts manually
docker compose exec api python -m scripts.seed_prompts

# Re-seed after adding new prompts to PROMPT_SEEDS
docker compose exec api python -m scripts.seed_prompts  # safe — skips existing
```

### Step 1: Seed Database (Automated)

The seed script (`scripts/seed_prompts.py`) populates the database from `PROMPT_SEEDS`:

For each seed, the script:
1. Creates a `Prompt` record with `source_file` and `source_line`
2. Creates `PromptVersion` v1 with the extracted content
3. Creates `PromptTag` entries for all tags
4. Creates `PromptAuditLog` "created" entry
5. Skips prompts that already exist (safe to re-run)

### Step 2: Verify (Manual)

Admin reviews each seeded prompt in the UI:
- Confirms name, description, category, tags
- Validates the extracted content matches expectations
- Edits content as needed (creates v2 automatically)

### Step 3: Runtime (Complete)

All AI providers now load prompts from the database at runtime:
- Providers call `render_prompt("slug", variables={...})` directly
- No DB session management in provider code
- No hardcoded fallback branches
- prompt_loader handles all resolution and caching internally

---

## Technical Decisions & Rationale

### Why `prompt_models.py` instead of `models/prompt.py`

The existing `src/api/models.py` (66KB file) shadows the `src/api/models/` directory in Python's module resolution. Placing models at `src/api/models/prompt.py` made them unimportable via `from src.api.models.prompt import ...`. Solution: `src/api/prompt_models.py` at the package root level.

### Why SERIAL instead of UUID for primary keys

The existing AuditGH database uses SERIAL (auto-incrementing integer) primary keys throughout. The prompt management tables follow this convention for consistency. The `prompts` table also has a separate `prompts_api_id_seq` sequence for API-visible IDs.

### Why sync SQLAlchemy instead of async

The existing AuditGH codebase uses synchronous SQLAlchemy ORM throughout (`from sqlalchemy.orm import Session`). The prompt management system follows this convention. The prompt_loader's lazy DB session creation uses the same `SessionLocal` factory.

### Why `model` field on both Prompt and PromptVersion

The `Prompt.model` field sets the default model for that prompt. `PromptVersion.model` allows a version-level override — useful when testing a prompt on a different model without changing the global default. Resolution: `pv.model or prompt.model`.

### Why CSS bar charts instead of Recharts

The analytics page uses inline CSS `<div>` bars instead of adding Recharts as a dependency. This keeps the bundle smaller and avoids adding dependencies for a single page. If richer charting is needed later, Recharts can be added.

---

## Success Metrics

| Metric | Target | How Measured |
|--------|--------|-------------|
| Prompt coverage | 100% of prompts in system | Count managed vs. hardcoded |
| Version adoption | All edits via UI, not source code | Audit log vs. git commits |
| Search time | < 3 seconds to find any prompt | User testing |
| Rollback time | < 30 seconds to restore a version | Time from click to active |
| Audit completeness | 100% of changes logged | Audit entries vs. version count |
| Zero downtime | No service interruption from prompt changes | Error rate monitoring |
| Fallback rate | 0% in steady state | Monitor ERROR logs for "PROMPT FALLBACK" |
| Cache hit rate | > 80% for hot prompts | Redis metrics |

---

## Risk Mitigation

| Risk | Impact | Mitigation |
|------|--------|------------|
| Prompt DB unavailable | AI providers can't load prompts | 3-tier fallback: Redis → DB → seed-derived (ERROR logged) |
| Bad prompt deployed | Incorrect AI responses | Version restore in < 30 seconds, test before publish |
| Seed data out of sync | Fallback prompts stale | Single source of truth — seeds populate DB AND serve as fallback |
| Performance overhead | Latency added by DB lookup | Redis caching with 5-min TTL, <1ms for hot prompts |
| Permission escalation | Analyst edits locked prompt | RBAC enforced at API layer, lock mechanism |
| Provider ignores DB prompt | Hardcoded wins over managed | All hardcoded fallbacks removed — providers have zero inline content |
| Module import shadowing | Models can't be imported | `prompt_models.py` at package root avoids `models.py` conflict |
| Fresh deploy has no prompts | Empty prompt management UI, Tier 3 fallbacks only | `docker-entrypoint.sh` runs `alembic upgrade head` + `seed_prompts` before uvicorn starts |
| Missing DB sequences | `cribl_config_api_id_seq` etc. errors on insert | Entrypoint runs Alembic first; `create_all` alone doesn't create sequences |

---

## Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| PostgreSQL | Existing | Already in AuditGH stack |
| pgvector extension | Existing | Already configured (semantic search planned Phase 5) |
| Redis | Existing | Already used by AuditGH; prompt caching uses same instance |
| FastAPI | Existing | New router module added |
| Next.js 16 frontend | Existing | New route group `/prompts` added |
| OIDC/SSO auth | Existing | Reuse AuditGH auth system |
| shadcn/ui | Existing | Already in web-ui |
| TanStack React Table | Existing | Already in web-ui |
| Tailwind CSS v4 | Existing | Already in web-ui |
| Lucide React | Existing | Already in web-ui |

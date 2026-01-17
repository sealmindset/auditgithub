# Codebase Structure

**Analysis Date:** 2026-01-17

## Directory Layout

```
auditgithub/
├── src/                    # Main application code
│   ├── api/               # FastAPI application
│   │   ├── routers/       # API endpoint handlers (23 routers)
│   │   ├── middleware/    # FastAPI middleware
│   │   ├── utils/         # Utility functions
│   │   └── integrations/  # External integrations (Jira)
│   ├── web-ui/            # Next.js React application
│   │   ├── app/           # App Router pages
│   │   ├── components/    # React components
│   │   ├── contexts/      # React contexts
│   │   └── hooks/         # Custom React hooks
│   ├── ai_agent/          # AI orchestration
│   │   ├── providers/     # AI provider implementations
│   │   └── tools/         # AI tools/plugins
│   ├── auth/              # Authentication & RBAC
│   ├── rbac/              # Role-Based Access Control
│   ├── scanners/          # Scanner modules
│   │   └── python/        # Python-specific scanners
│   ├── github/            # GitHub API integration
│   └── reporting/         # Report generation
├── execution/              # Background scanning engines
├── scripts/                # Utility scripts
├── tests/                  # Test suite
├── migrations/             # Alembic DB migrations
├── docs/                   # Documentation
├── data/                   # Data storage
└── vulnerability_reports/  # Scan output reports
```

## Directory Purposes

**src/api/**
- Purpose: FastAPI REST API application
- Contains: Main app, routers, middleware, utilities
- Key files: `main.py` (app entry), `models.py` (ORM), `database.py` (connections)
- Subdirectories: `routers/` (23 endpoint modules), `middleware/`, `utils/`, `integrations/`

**src/api/routers/**
- Purpose: API endpoint handlers
- Contains: One file per domain (repositories, findings, scans, ai, etc.)
- Key files: `api_audit.py` (4,227 lines), `ai.py`, `findings.py`, `repositories.py`
- Pattern: Each router exports FastAPI `APIRouter`

**src/web-ui/**
- Purpose: Next.js React frontend application
- Contains: App Router pages, components, contexts, hooks
- Key files: `app/layout.tsx` (root layout), `package.json`
- Subdirectories: `app/` (pages), `components/` (React), `contexts/` (state)

**src/ai_agent/**
- Purpose: AI orchestration and multi-provider support
- Contains: Agent core, reasoning engine, remediation engine, providers
- Key files: `agent.py` (main), `reasoning.py`, `remediation.py`, `learning.py`
- Subdirectories: `providers/` (Claude, OpenAI, Gemini, Ollama)

**src/ai_agent/providers/**
- Purpose: AI provider implementations
- Contains: Base class and concrete implementations
- Key files: `base.py`, `claude.py`, `openai.py`, `ollama.py`, `gemini.py`, `anthropic_foundry.py`, `failover.py`

**src/auth/**
- Purpose: Authentication and session management
- Contains: OAuth config, JWT handling, middleware, rate limiting
- Key files: `config.py`, `providers.py`, `middleware.py`, `tokens.py`, `session.py`

**src/rbac/**
- Purpose: Role-Based Access Control
- Contains: Permission models, checking, caching, auditing
- Key files: `models.py`, `permissions.py`, `dependencies.py`, `cache.py`, `audit.py`

**execution/**
- Purpose: Background scanning engines and CLI tools
- Contains: Scanner scripts, credential testing, AI agents
- Key files: `scan_api.py`, `scan_secrets.py`, `scan_sast.py`, `scan_deps.py`, `scan_iac.py`, `credential_tester.py`, `ai_org_agent.py`

**scripts/**
- Purpose: Utility and maintenance scripts
- Contains: Database management, testing, backup tools
- Key files: `manage_default_org.py`, `test_ai_providers.py`, `backup_organization.py`

**tests/**
- Purpose: pytest test suite
- Contains: Unit and integration tests
- Key files: `conftest.py`, `test_rbac_enforcement.py`, `test_tenant_isolation.py`, `test_ingestion_pipeline.py`

## Key File Locations

**Entry Points:**
- `src/__main__.py` - CLI entry point
- `src/api/main.py` - FastAPI app initialization
- `src/web-ui/app/layout.tsx` - Next.js root layout
- `scan_repos.py` - Main scanning orchestrator

**Configuration:**
- `.env` / `.env.sample` - Environment variables
- `docker-compose.yml` - Container orchestration
- `alembic.ini` - Database migration config
- `src/web-ui/tsconfig.json` - TypeScript config
- `src/web-ui/eslint.config.mjs` - ESLint config
- `pytest.ini` - Test configuration

**Core Logic:**
- `src/api/models.py` - SQLAlchemy ORM models
- `src/api/database.py` - Database connections
- `src/ai_agent/agent.py` - AI agent core
- `src/github/api.py` - GitHub API wrapper

**Testing:**
- `tests/conftest.py` - pytest fixtures
- `tests/test_*.py` - Test files

**Documentation:**
- `README.md` - Project overview
- `docs/` - Detailed documentation
- `CHEATSHEET.md` - Quick reference

## Naming Conventions

**Files:**
- Python: `snake_case.py` (e.g., `credential_tester.py`, `risk_scoring.py`)
- TypeScript: `PascalCase.tsx` for components (e.g., `AskAIDialog.tsx`)
- TypeScript: `kebab-case.ts` for utilities (e.g., `use-mobile.ts`)
- Config: `kebab-case` (e.g., `eslint.config.mjs`)

**Directories:**
- `snake_case` for Python (e.g., `ai_agent/`, `web-ui/`)
- `kebab-case` for TypeScript (e.g., `api-audit/`, `zero-day/`)
- Plural for collections (e.g., `routers/`, `providers/`, `scanners/`)

**Special Patterns:**
- `test_*.py` for test files
- `*.test.ts` for TypeScript tests (none found)
- `__init__.py` for Python packages

## Where to Add New Code

**New API Endpoint:**
- Primary code: `src/api/routers/{domain}.py`
- Models: `src/api/models.py`
- Tests: `tests/test_{domain}.py`

**New AI Provider:**
- Implementation: `src/ai_agent/providers/{provider}.py`
- Base class: Extend `src/ai_agent/providers/base.py`
- Registration: Update `src/ai_agent/agent.py`

**New Scanner:**
- Implementation: `src/scanners/{language}/{scanner}.py`
- Base class: Extend `src/scanners/base.py`
- Execution script: `execution/scan_{type}.py`

**New React Component:**
- Implementation: `src/web-ui/components/{ComponentName}.tsx`
- UI primitives: `src/web-ui/components/ui/`

**New Background Job:**
- Implementation: `execution/{job_name}.py`
- Scheduling: `src/api/scheduler.py`

**Utilities:**
- Python shared: `src/api/utils/`
- TypeScript shared: `src/web-ui/lib/`

## Special Directories

**vulnerability_reports/**
- Purpose: Generated scan reports
- Source: Output from scanning operations
- Committed: No (in .gitignore)

**.backup/**
- Purpose: Backup files and temporary storage
- Source: Backup scripts
- Committed: No (in .gitignore)

**migrations/**
- Purpose: Alembic database migrations
- Source: Auto-generated via `alembic revision`
- Committed: Yes

**src/web-ui/.next/**
- Purpose: Next.js build output
- Source: Generated by `npm build`
- Committed: No (in .gitignore)

---

*Structure analysis: 2026-01-17*
*Update when directory structure changes*

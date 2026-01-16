# Codebase Structure

**Analysis Date:** 2026-01-12

## Directory Layout

```
auditgithub/
├── src/                      # Main source code
│   ├── api/                  # FastAPI backend
│   ├── ai_agent/             # AI/ML components
│   ├── github/               # GitHub integration
│   ├── scanners/             # Security scanner plugins
│   ├── reports/              # Report generation
│   ├── reporting/            # PDF/document generation
│   └── web-ui/               # Next.js React frontend
├── execution/                # Execution scripts and utilities
├── scripts/                  # Utility and maintenance scripts
├── migrations/               # Database migrations
├── docs/                     # Documentation
├── setup/                    # Setup helpers
├── directives/               # Policy directives
├── semgrep-rules/            # Custom Semgrep rules
├── docker-compose.yml        # Container orchestration
├── Dockerfile*               # Multiple Dockerfiles for services
├── requirements.txt          # Python dependencies
├── .env.example              # Environment template
└── *.py                      # Root-level CLI scripts
```

## Directory Purposes

**src/**
- Purpose: Main application source code
- Contains: API, AI agents, GitHub client, scanners, UI
- Key files: `__main__.py` (CLI entry point), `__init__.py`

**src/api/**
- Purpose: FastAPI backend application
- Contains: Routers, models, database, middleware, utilities
- Key files:
  - `main.py` - FastAPI app and middleware setup
  - `models.py` - SQLAlchemy ORM models (25+ entities)
  - `database.py` - Database connection and sessions
  - `config.py` - Environment configuration
  - `database_router.py` - Multi-tenant routing
- Subdirectories:
  - `routers/` - 22+ API endpoint handlers
  - `middleware/` - Request middleware (tenant context)
  - `utils/` - Shared utilities (risk scoring, code extraction, logging)
  - `integrations/` - Third-party integrations (Jira)

**src/api/routers/**
- Purpose: API endpoint handlers by domain
- Contains: FastAPI router definitions
- Key files:
  - `findings.py` (1,553 lines) - Security findings CRUD
  - `ai.py` (2,195 lines) - AI analysis endpoints
  - `projects.py` (1,405 lines) - Project management
  - `organizations.py` - Organization/tenant management
  - `scans.py` - Scan orchestration
  - `attack_surface.py` (1,533 lines) - Attack surface analysis
  - `contributor_profiles.py` (1,533 lines) - Developer intelligence
  - `api_audit.py` (4,218 lines) - API security auditing
  - Plus 14 more domain routers

**src/ai_agent/**
- Purpose: AI/ML components for analysis and remediation
- Contains: AI orchestration, provider implementations, tools
- Key files:
  - `agent.py` - Main AIAgent class (provider orchestration)
  - `remediation.py` - Remediation generation logic
  - `reasoning.py` - Reasoning chain implementation
  - `contributor_analyzer.py` - Developer profile analysis
  - `learning.py` - Model learning and feedback
  - `diagnostics.py` - Diagnostic mode
- Subdirectories:
  - `providers/` - LLM provider implementations (Claude, OpenAI, Gemini, Ollama, Foundry, failover)
  - `tools/` - Agent tools (database access)

**src/github/**
- Purpose: GitHub API integration
- Contains: GitHub API client, data models
- Key files:
  - `api.py` - GitHub API client wrapper
  - `github_client.py` - Extended client implementation
  - `models.py` - Repository and contributor models

**src/scanners/**
- Purpose: Security scanner plugin system
- Contains: Base scanner interface, language-specific implementations
- Key files:
  - `base.py` - Abstract scanner interface
- Subdirectories:
  - `python/` - Python security scanners (safety.py, pip_audit.py)

**src/reports/** & **src/reporting/**
- Purpose: Report generation (multiple formats)
- Contains: Report generators for PDF, DOCX, JSON
- Key files:
  - `src/reports/generator.py` - Report orchestration
  - `src/reporting/pdf_generator.py` - PDF generation with ReportLab

**src/web-ui/**
- Purpose: Next.js React frontend application
- Contains: Pages, components, hooks, contexts, configuration
- Key subdirectories:
  - `app/` - Next.js App Router (pages and layouts)
  - `components/` - React components (30+ components)
  - `contexts/` - React Context providers (TenantContext)
  - `hooks/` - Custom React hooks (use-mobile)
  - `public/` - Static assets
- Key files:
  - `app/layout.tsx` - Root layout with providers
  - `app/page.tsx` - Home/dashboard page
  - `next.config.ts` - Next.js configuration
  - `tsconfig.json` - TypeScript configuration
  - `eslint.config.mjs` - ESLint configuration
  - `package.json` - Frontend dependencies

**src/web-ui/app/**
- Purpose: Next.js App Router pages
- Contains: Page components organized by route
- Key pages:
  - `findings/page.tsx`, `findings/[id]/page.tsx` - Findings list and detail
  - `projects/[id]/page.tsx` - Project detail
  - `repositories/page.tsx` - Repository list
  - `attack-surface/page.tsx` - Attack surface visualization
  - `zero-day/page.tsx` - Zero-day assessment
  - `settings/page.tsx` - Settings
  - `api-audit/settings/page.tsx` - API audit configuration
  - `api/log/route.ts` - Server-side logging endpoint

**src/web-ui/components/**
- Purpose: React UI components
- Contains: 30+ reusable components
- Key components:
  - `data-table.tsx`, `data-table-enhanced.tsx` - Data tables
  - `AskAIDialog.tsx` - AI query dialog
  - `SecurityReportModal.tsx` - Report modal
  - `APIAuditView.tsx` - API audit visualization
  - `ArchitectureView.tsx` - Architecture diagrams
  - `ContributorsView.tsx` - Developer profiles
  - `ZeroDayView.tsx`, `ZDAReportsView.tsx` - Zero-day views
  - `OrganizationSelector.tsx` - Org switcher
  - `theme-provider.tsx` - Theme context

**execution/**
- Purpose: Execution scripts and workflow orchestration
- Contains: Security scanning execution, data processing, automation
- Key files:
  - `scan_deps.py` - Dependency scanning
  - `scan_secrets.py` - Secret detection
  - `scan_sast.py` - Static analysis
  - `scan_api.py` - API scanning
  - `ai_credential_matcher.py` (2,744 lines) - Credential matching
  - `ai_credential_url_agent.py` - URL credential validation
  - `secrets_manager.py` - Secret management
  - `init_db.py` - Database initialization
  - `kotlin_parser.py` - Kotlin AST parsing

**scripts/**
- Purpose: Utility and maintenance scripts
- Contains: Operational scripts for backup, migration, testing

**migrations/**
- Purpose: Database schema migrations
- Contains: Database migration files

**docs/**
- Purpose: Project documentation
- Subdirectories: `specs/` - Specifications

**directives/**
- Purpose: Policy and compliance directives
- Contains: 22+ directive files for security policies

**semgrep-rules/**
- Purpose: Custom Semgrep security rules
- Contains: YAML rule definitions

**Root-level Python scripts:**
- Purpose: CLI utilities and batch operations
- Key files:
  - `scan_repos.py` (8,653 lines) - Monolithic repository scanner
  - `scan_gitleaks.py` - Secret scanning
  - `scan_engagement.py` - Engagement workflow
  - `ingest_scans.py` - Scan result ingestion
  - `update_db_schema.py` - Schema updates
  - `test_*.py` - Ad-hoc test scripts

## Key File Locations

**Entry Points:**
- `src/api/main.py` - FastAPI application
- `src/__main__.py` - CLI entry point
- `src/web-ui/app/layout.tsx` - Frontend root
- `docker-compose.yml` - Container orchestration

**Configuration:**
- `src/api/config.py` - Backend configuration
- `src/web-ui/next.config.ts` - Frontend build config
- `src/web-ui/tsconfig.json` - TypeScript config
- `src/web-ui/eslint.config.mjs` - Linting config
- `.env.example`, `.env.sample` - Environment templates
- `requirements.txt` - Python dependencies
- `src/web-ui/package.json` - Frontend dependencies

**Core Logic:**
- `src/api/models.py` - Database models
- `src/api/database.py` - Database connection
- `src/ai_agent/agent.py` - AI orchestration
- `src/github/api.py` - GitHub client
- `scan_repos.py` - Main scanning logic

**Testing:**
- `test_ai_providers.py` - AI provider connectivity tests
- `test_script.py`, `test_zda_enhancements.py` - Ad-hoc tests

**Documentation:**
- `README.md` - Project overview
- `CONTRIBUTING.md` - Contribution guidelines
- `docs/` - Additional documentation

## Naming Conventions

**Files:**
- Python: snake_case (e.g., `risk_scoring.py`, `github_client.py`)
- TypeScript/React: kebab-case for utilities (e.g., `data-table.tsx`, `use-mobile.ts`)
- TypeScript/React: PascalCase for components (e.g., `AskAIDialog.tsx`, `OrganizationSelector.tsx`)
- Config files: kebab-case or standard names (e.g., `next.config.ts`, `eslint.config.mjs`)

**Directories:**
- snake_case for Python (e.g., `ai_agent/`, `api/routers/`)
- kebab-case for frontend (e.g., `web-ui/`, `attack-surface/`)
- Plural for collections (e.g., `routers/`, `components/`, `providers/`)

**Special Patterns:**
- `*.test.py` - Python test files (root level only)
- `[id]/page.tsx` - Next.js dynamic route pages
- `*.config.*` - Configuration files

## Where to Add New Code

**New API Endpoint:**
- Primary code: `src/api/routers/{domain}.py` (create new or extend existing)
- Model updates: `src/api/models.py` (add/modify ORM models)
- Tests: Root-level `test_{domain}.py` (manual testing pattern)

**New Security Scanner:**
- Implementation: `src/scanners/{language}/{scanner_name}.py`
- Base class: Extend `src/scanners/base.py`
- Integration: Update `scan_repos.py` to invoke scanner

**New AI Provider:**
- Implementation: `src/ai_agent/providers/{provider_name}.py`
- Base class: Extend `src/ai_agent/providers/base.py`
- Configuration: Add env vars to `src/api/config.py`, `.env.example`

**New Frontend Page:**
- Page: `src/web-ui/app/{route}/page.tsx`
- Components: `src/web-ui/components/{ComponentName}.tsx`
- Hooks: `src/web-ui/hooks/use-{feature}.ts`
- Context: `src/web-ui/contexts/{Feature}Context.tsx`

**New Utility:**
- Backend: `src/api/utils/{utility_name}.py`
- Frontend: `src/web-ui/lib/{utility_name}.ts` (create lib/ if needed)

## Special Directories

**execution/**
- Purpose: Workflow orchestration and batch processing
- Source: Core execution logic
- Committed: Yes

**directives/**
- Purpose: Policy directives for compliance
- Source: Security policies and requirements
- Committed: Yes

**migrations/**
- Purpose: Database schema migrations
- Source: Migration scripts (Alembic pattern, not formalized)
- Committed: Yes

---

*Structure analysis: 2026-01-12*
*Update when directory structure changes*

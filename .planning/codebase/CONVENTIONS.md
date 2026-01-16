# Coding Conventions

**Analysis Date:** 2026-01-12

## Naming Patterns

**Files:**
- Python modules: snake_case (e.g., `risk_scoring.py`, `github_client.py`, `cribl_logger.py`)
- TypeScript/React components: PascalCase (e.g., `AskAIDialog.tsx`, `OrganizationSelector.tsx`)
- TypeScript utilities: kebab-case (e.g., `data-table.tsx`, `theme-provider.tsx`, `use-mobile.ts`)
- Next.js pages: `page.tsx` in route folders (e.g., `app/findings/page.tsx`)
- Next.js dynamic routes: `[id]/page.tsx` pattern

**Functions:**
- Python: snake_case (e.g., `calculate_risk_score()`, `get_findings()`, `process_repo()`)
- TypeScript/React: camelCase (e.g., `fetchData()`, `handleClose()`, `isDescriptionRevisionRequest()`)
- Async operations: No special prefix (async keyword sufficient)
- Handlers: `handle<Action>` prefix (e.g., `handleAnalyze()`, `handleClose()`)

**Variables:**
- Python: snake_case (e.g., `repo_path`, `finding_id`, `organization_name`)
- TypeScript: camelCase (e.g., `isLoading`, `apiUrl`, `selectedOrg`)
- Constants (Python): UPPER_SNAKE_CASE (e.g., `SEVERITY_WEIGHTS`, `MAX_RETRIES`, `API_BASE_URL`)
- Constants (TypeScript): UPPER_SNAKE_CASE or camelCase depending on context
- Boolean predicates: `is_<condition>`, `has_<property>` (e.g., `is_applicable`, `has_findings`)

**Types:**
- Python classes: PascalCase (e.g., `Organization`, `Finding`, `AIAgent`, `BaseScanner`)
- TypeScript interfaces: PascalCase, no `I` prefix (e.g., `ConversationMessage`, `AskAIDialogProps`)
- TypeScript types: PascalCase (e.g., `ResponseData`, `UserConfig`)
- Database models: PascalCase singular (e.g., `Repository`, `Finding`, `Contributor`)

## Code Style

**Formatting:**
- Python: 4-space indentation (standard PEP 8)
- TypeScript/React: 2-space indentation
- Line length: ~100-120 characters (not strictly enforced)
- Quotes: Double quotes for strings in TypeScript/React, single quotes in Python
- Semicolons: Omitted in TypeScript/React (modern style)

**Linting:**
- TypeScript: ESLint with flat config - `src/web-ui/eslint.config.mjs`
  - Extends: `eslint-config-next/core-web-vitals`, `eslint-config-next/typescript`
  - Ignores: `.next/**`, `out/**`, `build/**`, `next-env.d.ts`
- Python: No formal linting configuration (no .flake8, pyproject.toml linting section)
- Run: `npm run lint` for frontend

**Type Checking:**
- TypeScript: Strict mode enabled - `src/web-ui/tsconfig.json`
- Python: Type hints used throughout (Python 3.11+ style)

## Import Organization

**Python Order:**
1. Standard library imports
2. Third-party packages
3. Local application imports
4. Relative imports

**TypeScript Order:**
1. React and Next.js imports
2. Third-party packages
3. Local components and utilities
4. Type imports
5. Styles (if any)

**Grouping:**
- Blank lines between import groups
- Alphabetical within groups (not strictly enforced)

**Path Aliases:**
- TypeScript: `@/` maps to `src/web-ui/` (configured in `tsconfig.json`)
- Python: Absolute imports from `src/` root

## Error Handling

**Patterns (Intended):**
- Python: Throw exceptions, catch at router/boundary level
- TypeScript: Try/catch with error state management
- HTTP errors: FastAPI HTTPException for client errors

**Reality - Critical Issue:**
- **50+ bare `except: pass` blocks** that silently swallow all exceptions
- Primary offender: `scan_repos.py` (8,653 lines) with 12+ consecutive bare excepts
- Impact: Errors hidden, debugging extremely difficult
- See [CONCERNS.md](CONCERNS.md) for detailed analysis

**Error Types:**
- Router level: Return HTTP error responses (400, 404, 500)
- Service level: Raise descriptive exceptions
- Logging: Use Loguru with context for debugging

## Logging

**Framework:**
- Loguru - Structured logging with custom Cribl integration - `src/api/utils/cribl_logger.py`
- Levels: debug, info, warning, error, critical

**Patterns:**
- Structured logging with context objects
- HTTP streaming to Cribl endpoint (optional)
- Console output for development
- Format: `logger.info({"context": "value"}, "Message")`

**When:**
- Log state transitions (scan started, completed)
- External API calls (GitHub, AI providers)
- Errors with full context
- Security events (findings, credential detection)

**Where:**
- Routers: Log request/response at info level
- Services: Log business logic at debug level
- Utilities: Minimal logging unless errors

## Comments

**When to Comment:**
- Explain "why" not "what" (code should be self-explanatory)
- Document business logic and security considerations
- Explain non-obvious algorithms or workarounds
- Mark incomplete implementations (TODO)

**Python Docstrings:**
- Required for public APIs and complex functions
- Format: Google style (Args, Returns, Raises sections)
- Example from `src/api/routers/findings.py`:
  ```python
  def get_findings(organization_id: str, db: Session):
      """
      Retrieve all findings for an organization.

      Args:
          organization_id: Organization UUID
          db: Database session

      Returns:
          List of Finding objects
      """
  ```

**TypeScript/JSDoc:**
- Used for component props and complex functions
- Type annotations preferred over JSDoc where possible
- Inline comments for complex logic

**TODO Comments:**
- Format: `# TODO: description` or `// TODO: description`
- Many TODOs present in codebase (e.g., `src/api/routers/secrets.py:327`, `src/api/routers/sla.py:303`)
- No issue linking convention

## Function Design

**Size:**
- Target: Under 50 lines
- Reality: Many functions exceed 100+ lines (especially in `scan_repos.py`)
- Extract helpers for complex logic (not consistently followed)

**Parameters:**
- Python: Explicit parameters, use `**kwargs` sparingly
- TypeScript: Use object destructuring for 3+ parameters
- Dependency injection: Database sessions injected via FastAPI dependencies

**Return Values:**
- Explicit return types in Python (type hints)
- TypeScript: Inferred types or explicit annotations
- Return early for guard clauses

## Module Design

**Exports:**
- Python: Explicit imports, avoid `from module import *` (violated in `update_db_schema.py`)
- TypeScript: Named exports preferred
- React components: Default export for pages, named for reusable components

**Organization:**
- Python: One class per file for major entities
- Routers: Grouped by domain (findings, projects, organizations)
- Components: Atomic design pattern (components, pages, contexts, hooks)

**Circular Dependencies:**
- Avoided through layered architecture
- Models at bottom, routers at top
- Utilities and services in middle

## Database Patterns

**ORM Usage:**
- SQLAlchemy 2.0+ style with declarative models
- Session management via FastAPI dependency injection
- Organization-scoped filtering at query level

**Queries:**
- Use ORM methods, not raw SQL
- **Critical Issue:** F-string SQL in `src/api/database_router.py:153,159` (SQL injection risk)
- Parameterized queries via SQLAlchemy expressions

**Transactions:**
- Implicit via session context
- Commit/rollback at router level

## Multi-Tenancy Patterns

**Organization Context:**
- Extracted from request headers by middleware - `src/api/middleware/tenant.py`
- Stored in request state
- Applied to all queries automatically

**Data Isolation:**
- All models include `organization_id` foreign key
- Queries filtered by organization context
- Per-organization database option via `src/api/database_router.py`

---

*Convention analysis: 2026-01-12*
*Update when patterns change*

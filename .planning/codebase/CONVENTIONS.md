# Coding Conventions

**Analysis Date:** 2026-01-17

## Naming Patterns

**Files:**
- Python: `snake_case.py` (e.g., `credential_matcher.py`, `risk_scoring.py`)
- TypeScript components: `PascalCase.tsx` (e.g., `AskAIDialog.tsx`, `DataTable.tsx`)
- TypeScript utilities: `kebab-case.ts` (e.g., `use-mobile.ts`, `theme-provider.tsx`)
- Test files: `test_*.py` alongside source in `tests/`

**Functions:**
- Python: `snake_case` (e.g., `_run_git()`, `_analyze_contributors()`, `seed_rbac_data()`)
- TypeScript: `camelCase` (e.g., `handleClick`, `setPrompt`, `scrollRef`)
- Handlers: `handle{EventName}` pattern in React

**Variables:**
- Python: `snake_case` for variables
- TypeScript: `camelCase` for variables
- Constants: `UPPER_SNAKE_CASE` (e.g., `TEST_DATABASE_URL`, `MOBILE_BREAKPOINT`)
- No underscore prefix for private members in TypeScript

**Types:**
- Python classes: `PascalCase` (e.g., `RepoIntel`, `SafeProcessResult`, `SubprocessTimeout`)
- TypeScript interfaces: `PascalCase`, no `I` prefix (e.g., `User`, `Config`)
- Pydantic models: `PascalCase` with descriptive names (e.g., `FindingResponse`, `RepositoryCreate`)

## Code Style

**Formatting:**
- Python: 4-space indentation (PEP 8)
- TypeScript: 2-space indentation
- Line length: Not strictly enforced
- Quotes: Double quotes for Python strings and TypeScript JSX attributes
- Semicolons: Required in TypeScript

**Linting:**
- TypeScript: ESLint 9 with flat config (`src/web-ui/eslint.config.mjs`)
- Extends: `eslint-config-next/core-web-vitals`, `eslint-config-next/typescript`
- Ignores: `.next/`, `out/`, `build/`, `next-env.d.ts`
- Python: No explicit linting config (follows PEP 8 implicitly)

## Import Organization

**Python Order:**
1. Standard library imports
2. Third-party packages
3. Local application imports

**TypeScript Order:**
1. React and framework imports
2. External packages (`@radix-ui/*`, `lucide-react`)
3. Internal modules (`@/components/*`, `@/lib/*`)
4. Relative imports (`./`, `../`)

**Path Aliases:**
- TypeScript: `@/` maps to `src/web-ui/` (e.g., `@/components/ui/dialog`)

## Error Handling

**Patterns:**
- Python: try/except with specific exceptions where possible
- FastAPI: HTTPException for client errors
- Broad `except Exception` used in 162 places (area for improvement)

**Error Types:**
- Throw on invalid input, missing dependencies
- Log error with context before re-raising
- Background jobs: catch all, log to Cribl, update status

**Logging:**
- Framework: loguru for structured logging
- Pattern: `logger.info(f"Message with {context}")` or `logger.error(f"Error: {e}")`
- No `print()` in production code (8 violations found)

## Logging

**Framework:**
- Python: loguru 0.7.0+ with HTTP transport to Cribl
- Fallback: MinIO object storage

**Patterns:**
- Structured logging with context objects
- Log at service boundaries
- Log state transitions, external API calls, errors
- Cribl integration: `src/api/utils/cribl_logger.py`

## Comments

**When to Comment:**
- Explain "why" not "what"
- Document business logic and edge cases
- Mark incomplete implementations with `TODO`

**Docstrings:**
- Python: Module-level docstrings with triple quotes
- Class docstrings: Include purpose, fields, usage
- Method docstrings: Args, Returns, Yields sections
- Example: `"""Safe Subprocess Execution - Enhanced subprocess handling with strict timeouts."""`

**TODO Comments:**
- Pattern: `TODO(Phase N):` or `TODO:` with description
- Examples found:
  - `TODO(Phase 5): Add additional tenant filtering`
  - `TODO: Implement actual secret validation`

## Function Design

**Size:**
- Keep functions focused (SRP principle per CONTRIBUTING.md)
- Extract helpers for complex logic
- Large files exist: `api_audit.py` at 4,227 lines (needs refactoring)

**Parameters:**
- Use type hints for all parameters
- Pydantic models for complex request bodies
- Default values for optional parameters

**Return Values:**
- Explicit return types via type hints
- Use Pydantic models for API responses
- Return early for guard clauses

## Module Design

**Exports:**
- Python: No barrel files, direct imports
- TypeScript: Named exports preferred
- Default exports for React components

**FastAPI Routers:**
- One router per domain
- Export `router = APIRouter(prefix="/path", tags=["tag"])`
- Import and include in `main.py`

**Dependency Injection:**
- FastAPI `Depends()` for database sessions
- `get_db()`, `get_tenant_db()` providers
- `get_current_user()` for authentication
- `require_permissions()` for RBAC

---

*Convention analysis: 2026-01-17*
*Update when patterns change*

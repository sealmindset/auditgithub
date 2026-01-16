# Codebase Concerns

**Analysis Date:** 2026-01-12

## Tech Debt

**Monolithic scan_repos.py file:**
- Issue: Single file with 8,653 lines and 127 function definitions
- Files: `scan_repos.py`
- Why: Organic growth without refactoring during rapid development
- Impact: Extremely difficult to navigate, test, maintain, and debug
- Fix approach: Extract into modules by responsibility (scanners/, orchestration/, reporting/)

**Oversized API router files:**
- Issue: Multiple routers exceeding 1,500-4,000 lines
- Files: `src/api/routers/api_audit.py` (4,218 lines), `src/api/routers/ai.py` (2,195 lines), `src/api/routers/findings.py` (1,553 lines), `src/api/routers/attack_surface.py` (1,533 lines), `src/api/routers/projects.py` (1,405 lines)
- Why: Business logic mixed with routing, insufficient service layer extraction
- Impact: Violates single responsibility principle, hard to test, slow development velocity
- Fix approach: Extract business logic to service classes in `src/api/services/`, keep routers thin

**Loose dependency version constraints:**
- Issue: No upper bounds on critical dependencies
- Files: `requirements.txt` (`requests>=2.31.0`, `fastapi>=0.100.0`, `sqlalchemy>=2.0.0`, `anthropic>=0.18.0` with no max versions)
- Why: Likely to accept latest versions without testing
- Impact: Breaking changes can appear in production unexpectedly
- Fix approach: Pin exact versions or use `~=` for minor version locking

**Duplicate code in scan result parsing:**
- Issue: Similar parsing logic repeated across 12+ scanner invocations
- Files: `scan_repos.py:8478-8578` (Semgrep, Bandit, Gitleaks, Trivy, Horusec, Whispers, Bearer, Terrascan, gosec, GolangCI-Lint)
- Why: Copy-paste development without abstraction
- Impact: Bug fixes must be applied to multiple locations, inconsistency risk
- Fix approach: Create `ScanResultParser` base class with language-specific implementations

**Incomplete feature implementations:**
- Issue: TODO comments marking unfinished features
- Files:
  - `src/api/routers/secrets.py:327` - "Implement actual secret validation via secret_validators.py"
  - `src/api/routers/sla.py:303` - "Add assignee resolution"
  - `execution/secrets_manager.py:292` - "Initialize hvac client"
  - `scan_engagement.py:128` - "Implement get_all_repos if needed"
- Why: MVP phase left features incomplete
- Impact: Features advertised but not functional, potential runtime errors
- Fix approach: Complete implementations or remove incomplete features

## Known Bugs

**Silent bare exception handlers:**
- Symptoms: Errors swallowed without logging, operations appear successful when they failed
- Trigger: Any exception during scan result parsing, file reading, subprocess execution
- Files with multiple bare excepts:
  - `scan_repos.py:8478-8578` - 12 consecutive bare `except: pass` blocks
  - `execution/ai_credential_matcher.py:337, 590, 766, 1036, 1314, 1462, 1614, 1858` - 8 bare except blocks
  - `execution/ai_credential_url_agent.py` - Multiple bare excepts throughout
  - `src/safe_subprocess.py:204, 212, 220` - Process termination failures hidden
  - `src/api/routers/api_audit.py:363` - YAML parsing failures hidden
  - `src/api/routers/analytics.py:441, 646` - Analytics calculation failures hidden
  - `src/api/routers/projects.py:1063` - Project operation failures hidden
  - `src/api/routers/feedback.py:32` - User feedback processing failures hidden
- Workaround: None - errors are completely hidden
- Root cause: Defensive programming taken to extreme, lack of proper error handling
- Fix: Replace all bare `except:` with specific exceptions and logging

## Security Considerations

**SQL Injection via f-string formatting:**
- Risk: Database commands constructed with unvalidated input via f-strings
- Files:
  - `src/api/database_router.py:153` - `text(f"SELECT 1 FROM pg_database WHERE datname = '{tenant.database_name}'")`
  - `src/api/database_router.py:159` - `text(f'CREATE DATABASE "{tenant.database_name}"')`
  - `execution/init_db.py:51` - `cur.execute(f"SELECT 1 FROM pg_database WHERE datname = '{target_db}'")`
- Current mitigation: None - direct SQL injection vulnerability
- Recommendations: Use parameterized queries with `%s` placeholders or SQLAlchemy bindparams

**Hardcoded secrets in .env file:**
- Risk: Real API keys and tokens committed to repository
- Files: `.env` (contains actual GitHub token, Azure AI Foundry key, Jira token, etc.)
- Current mitigation: `.gitignore` excludes `.env` but file already exists in repo
- Recommendations:
  - Rotate all exposed credentials immediately
  - Remove `.env` from repository history (git filter-branch or BFG Repo-Cleaner)
  - Use secrets manager (AWS Secrets Manager, HashiCorp Vault) for production
  - Add pre-commit hook to detect secrets (gitleaks, detect-secrets)

**No input validation for database provisioning:**
- Risk: Special characters in tenant database names could cause SQL errors or injection
- Files: `src/api/database_router.py:145-159`
- Current mitigation: None
- Recommendations: Validate database names against `^[a-z0-9_]+$` regex before use

**Subprocess execution without input validation:**
- Risk: Command injection via unsanitized repository paths or arguments
- Files: `src/safe_subprocess.py`, multiple calls in `scan_repos.py`
- Current mitigation: `safe_subprocess.py` implements timeout/killing but not input sanitization
- Recommendations: Validate all paths, use subprocess with list arguments (not shell=True), sanitize inputs

## Performance Bottlenecks

**N+1 query patterns in complex routers:**
- Problem: Potential database queries in loops without eager loading
- Files: `src/api/routers/findings.py`, `src/api/routers/projects.py`, `src/api/routers/attack_surface.py`
- Measurement: Not measured - no performance profiling
- Cause: ORM usage without relationship loading optimization
- Improvement path: Use SQLAlchemy `joinedload()` or `selectinload()` for relationships

**No database connection pooling configuration:**
- Problem: Default SQLAlchemy pooling may not be optimized for production load
- Files: `src/api/database.py`
- Measurement: Not measured
- Cause: Development configuration used in production
- Improvement path: Configure pool size, overflow, timeout based on load testing

**Large file operations in memory:**
- Problem: Repository cloning and scanning may load large files into memory
- Files: `src/api/utils/repo_context.py`, `scan_repos.py`
- Measurement: Not measured
- Cause: No streaming or chunking for large files
- Improvement path: Implement streaming parsers for large results, limit file sizes

## Fragile Areas

**Multi-tenant database provisioning:**
- Why fragile: Dynamic database creation with SQL injection risk, no rollback on failure
- Files: `src/api/database_router.py:145-159`
- Common failures: Special characters in names, insufficient permissions, database already exists
- Safe modification: Add comprehensive validation, transaction wrapping, rollback on error
- Test coverage: None

**AI provider failover chain:**
- Why fragile: Sequential provider attempts without timeout management
- Files: `src/ai_agent/providers/failover.py`, `src/ai_agent/agent.py`
- Common failures: Timeout exhaustion, all providers failing, inconsistent response formats
- Safe modification: Add per-provider timeouts, circuit breaker pattern, fallback responses
- Test coverage: Basic connectivity tests only in `test_ai_providers.py`

**Repository cloning and cleanup:**
- Why fragile: Temporary directory management, process cleanup, disk space management
- Files: `src/api/utils/repo_context.py`, `scan_repos.py`
- Common failures: Disk full, permission errors, orphaned temp directories, long-running clones
- Safe modification: Add disk space checks, timeout on clone, robust cleanup in finally blocks
- Test coverage: None

## Scaling Limits

**Synchronous repository scanning:**
- Current capacity: One repository at a time (sequential processing)
- Limit: Throughput limited by longest scan time (potentially hours for large repos)
- Symptoms at limit: Queue buildup, slow response times, users waiting
- Scaling path: Implement asynchronous task queue (Celery, RQ, or cloud task services)

**In-memory scan results:**
- Current capacity: Limited by container memory (default 2GB typically)
- Limit: Large repositories with 1000+ findings may exhaust memory
- Symptoms at limit: Out of memory errors, container restarts
- Scaling path: Stream results to database incrementally, don't accumulate in memory

**Single PostgreSQL database:**
- Current capacity: Development/small production workload
- Limit: Write contention on `findings` table with high scan frequency
- Symptoms at limit: Slow writes, lock contention, query timeouts
- Scaling path: Read replicas for queries, partitioning for `findings` table by date

## Dependencies at Risk

**setuptools version constraint:**
- Risk: Upper bound `setuptools<81.0.0` indicates known breaking change
- Files: `requirements.txt`
- Impact: Can't upgrade to latest setuptools
- Migration plan: Update dependencies to be compatible with setuptools 81.0+

**No dependency vulnerability scanning:**
- Risk: Using packages with known vulnerabilities
- Files: `requirements.txt` (no safety, pip-audit in CI)
- Impact: Security vulnerabilities in production
- Migration plan: Add `safety check` or `pip-audit` to CI/CD pipeline

## Missing Critical Features

**Automated test suite:**
- Problem: No unit tests, no integration test framework
- Current workaround: Manual testing with ad-hoc scripts
- Blocks: Confident refactoring, regression detection, CI/CD quality gates
- Implementation complexity: Medium (Pytest setup, write tests for critical paths)

**Database migrations framework:**
- Problem: No Alembic or similar migration tool configured
- Current workaround: `update_db_schema.py` script for ad-hoc updates
- Blocks: Controlled schema evolution, rollback capability, multi-environment deployments
- Implementation complexity: Low (Alembic setup, generate initial migration)

**API authentication and authorization:**
- Problem: No authentication on API endpoints, organization context from headers only
- Current workaround: Trust client to provide correct organization context
- Blocks: Production deployment, multi-user access control, security compliance
- Implementation complexity: High (OAuth2/JWT implementation, user model, permissions)

**Centralized logging and monitoring:**
- Problem: Cribl integration optional, no error tracking service (Sentry)
- Current workaround: Local logs only
- Blocks: Production debugging, performance monitoring, alerting
- Implementation complexity: Low (Sentry SDK integration, structured logging)

## Test Coverage Gaps

**Router endpoint testing:**
- What's not tested: All 22+ API routers lack automated tests
- Files: `src/api/routers/*.py`
- Risk: Breaking changes in API contracts undetected
- Priority: High
- Difficulty to test: Medium (requires test database, fixtures)

**Scanner plugin system:**
- What's not tested: Scanner implementations, plugin loading, result parsing
- Files: `src/scanners/*.py`, `scan_repos.py`
- Risk: Scanner failures silently swallowed (due to bare except blocks)
- Priority: High
- Difficulty to test: Medium (requires mock subprocess, fixture scan results)

**AI provider integration:**
- What's not tested: Beyond basic connectivity tests
- Files: `src/ai_agent/providers/*.py`
- Risk: Prompt changes break analysis quality, API changes cause runtime errors
- Priority: Medium
- Difficulty to test: High (requires mock LLM responses, expensive to test with real APIs)

**Database operations:**
- What's not tested: ORM models, migrations, multi-tenant filtering
- Files: `src/api/models.py`, `src/api/database.py`
- Risk: Data corruption, organization data leakage, schema drift
- Priority: Critical
- Difficulty to test: Low (unit tests with SQLite in-memory database)

**Frontend components:**
- What's not tested: All React components lack tests
- Files: `src/web-ui/components/*.tsx`, `src/web-ui/app/*/page.tsx`
- Risk: UI regressions, broken user flows
- Priority: Medium
- Difficulty to test: Medium (requires React Testing Library, mock API calls)

---

*Concerns audit: 2026-01-12*
*Update as issues are fixed or new ones discovered*

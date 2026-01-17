# Codebase Concerns

**Analysis Date:** 2026-01-17

## Tech Debt

**Incomplete Tenant Isolation:**
- Issue: Relying on `SET search_path` for tenant isolation instead of explicit `WHERE tenant_id=` filters
- Files: `src/api/routers/repositories.py`, `src/api/routers/findings.py`, `src/api/routers/scans.py`
- Why: Phase-based implementation - tenant filtering marked as TODO(Phase 5)
- Impact: Potential cross-tenant data access if database-level isolation fails
- Fix approach: Add explicit `organization_id` filters to all queries

**RBAC Resource Query Not Implemented:**
- Issue: `require_tenant_access()` function has TODO comment, passes through without verification
- File: `src/rbac/dependencies.py:312-320`
- Why: Placeholder during initial RBAC implementation
- Impact: Security checkpoint bypassed, allows any resource access
- Fix approach: Implement actual resource query to verify tenant ownership

**Large Monolithic Files:**
- Issue: Several router files exceed 1,000+ lines
- Files:
  - `src/api/routers/api_audit.py` - **4,227 lines** (CRITICAL)
  - `src/api/routers/ai.py` - 2,196 lines
  - `src/api/routers/findings.py` - 1,563 lines
  - `src/api/routers/contributor_profiles.py` - 1,541 lines
  - `src/api/routers/attack_surface.py` - 1,541 lines
  - `src/api/routers/projects.py` - 1,406 lines
  - `src/api/routers/analytics.py` - 1,019 lines
- Why: Organic growth without refactoring
- Impact: Hard to maintain, test, and understand
- Fix approach: Break into smaller, focused modules; extract shared logic

**Missing Secret Validation:**
- Issue: Endpoint marks secrets for "manual validation" but actual validation not implemented
- File: `src/api/routers/secrets.py:328`
- Why: TODO left during feature implementation
- Impact: False sense of security validation without actual implementation
- Fix approach: Implement validation via `secret_validators.py`

## Known Bugs

**None documented at this time.**

Potential issues identified through code analysis but not confirmed as bugs.

## Security Considerations

**AUTH_DISABLED Bypass in Production Code:**
- Risk: Environment variable can disable all authentication
- Files: `src/rbac/dependencies.py:65,114` and others
- Current mitigation: Only enabled via explicit env var
- Recommendations: Move to development-only code path or remove entirely

**Hardcoded Default Credentials:**
- Risk: Default PostgreSQL password in code
- File: `src/knowledge_base.py:29`
- Code: `password = os.environ.get("POSTGRES_PASSWORD", "auditgh_secret")`
- Current mitigation: Only used as fallback when env var not set
- Recommendations: Remove default, require explicit configuration

**Direct Subprocess Execution in API Router:**
- Risk: Executing `scan_repos.py` via subprocess with user-supplied `repo_name`
- File: `src/api/routers/scans.py:46-57`
- Current mitigation: List-based command (no shell=True), repo_name sanitized
- Recommendations: Use task queue instead of direct subprocess execution

**Multiple Print Statements Instead of Logger:**
- Risk: Inconsistent logging, potential information exposure
- Files: `src/api/routers/api_audit.py:596,2503,2537,2557`, `src/api/routers/settings.py:58`, `src/api/utils/redaction.py:63-65`, `src/api/utils/cribl_logger.py:100,209`
- Current mitigation: None
- Recommendations: Replace all `print()` with structured logger calls

## Performance Bottlenecks

**N+1 Query Pattern in SLA Router:**
- Problem: Fetching all findings, then iterating in Python for MTTR calculations
- File: `src/api/routers/sla.py:130-203`
- Measurement: Not measured, but scales poorly with finding count
- Cause: Python-side filtering instead of database aggregation
- Improvement path: Use SQLAlchemy grouping/aggregation in queries

**Large Query Result Sets Without Streaming:**
- Problem: Loading `.all()` results for large datasets
- File: `src/api/routers/sla.py:275` (`get_overdue_findings()`)
- Measurement: Memory usage scales with finding count
- Cause: No pagination or streaming for large result sets
- Improvement path: Add pagination, use streaming cursors

## Fragile Areas

**Broad Exception Handlers:**
- Files: 162 instances of `except Exception:` across API routers
- Why fragile: Catches all errors, may hide specific issues
- Common failures: Silent failures, incorrect error responses
- Safe modification: Replace with specific exception types
- Test coverage: Limited exception-specific testing

**Direct subprocess Module Usage:**
- Files: 11 files import `subprocess` directly
  - `src/safe_subprocess.py`, `src/progress_wrapper.py`, `src/scanners/python/pip_audit.py`, `src/scanners/python/safety.py`, `src/scanners/base.py`, `src/api/routers/ai.py`, `src/api/routers/scans.py`, `src/api/utils/repo_context.py`, `src/api/utils/diagram_executor.py`, `src/api/scheduler.py`, `src/repo_intel.py`
- Why fragile: Inconsistent timeout handling, process cleanup
- Safe modification: Route through `src/safe_subprocess.py` for consistent handling

## Scaling Limits

**Database Connection Pool:**
- Current capacity: Not explicitly configured
- Limit: Default SQLAlchemy pool size
- Symptoms at limit: Connection timeouts, request failures
- Scaling path: Configure pool size via `create_engine()` parameters

**Redis Session Storage:**
- Current capacity: Single Redis instance
- Limit: Memory-bound, single-node
- Symptoms at limit: Session failures, permission cache misses
- Scaling path: Redis cluster for high availability

## Dependencies at Risk

**No Pinned Versions in requirements.txt:**
- Risk: Using loose version constraints (`>=X.Y.Z` only)
- Impact: Builds may break with dependency updates
- Examples: `fastapi>=0.100.0`, `sqlalchemy>=2.0.0`, `pydantic>=2.0.0`
- Migration plan: Add upper bounds or pin specific versions

## Missing Critical Features

**No Frontend Testing:**
- Problem: No Jest/Vitest setup for React components
- Current workaround: Manual testing only
- Blocks: Automated regression testing for UI
- Implementation complexity: Medium (add Vitest, configure for Next.js)

**No E2E Testing:**
- Problem: No Playwright/Cypress for end-to-end flows
- Current workaround: Manual testing
- Blocks: Automated verification of user workflows
- Implementation complexity: Medium (add Playwright, write critical path tests)

## Test Coverage Gaps

**API Router Endpoints:**
- What's not tested: Individual router endpoint unit tests
- Risk: Regression in endpoint-specific logic
- Priority: Medium
- Difficulty to test: Low (use FastAPI TestClient)

**Stripe Webhook Event Types:**
- What's not tested: 9 of 12 webhook event types
- Risk: Silent failures on unhandled events
- Priority: High (payment processing)
- Difficulty to test: Medium (requires Stripe test fixtures)

**TypeScript/React Components:**
- What's not tested: All frontend components
- Risk: UI regressions undetected
- Priority: Medium
- Difficulty to test: Medium (add testing framework)

---

## Summary Statistics

| Category | Count | Severity |
|----------|-------|----------|
| TODO/FIXME comments | 7 | MEDIUM |
| Large files (>1000 lines) | 7 | MEDIUM |
| Broad exception handlers | 162 | LOW |
| Incomplete implementations | 2 | HIGH |
| Security gaps (tenant isolation) | 4 | MEDIUM |
| Print statements instead of logger | 8 | LOW |

## Priority Recommendations

### CRITICAL (Fix First):
1. Implement `require_tenant_access()` actual verification in `src/rbac/dependencies.py:312`
2. Add explicit `organization_id` filters to all queries in repositories, findings, and scans routers

### HIGH (Fix Soon):
3. Implement actual secret validation in `src/api/routers/secrets.py:328`
4. Refactor `api_audit.py` (4,227 lines) - break into sub-modules
5. Remove AUTH_DISABLED bypass or move to tests-only code

### MEDIUM (Address):
6. Replace `print()` with logger in 8 locations
7. Convert N+1 patterns to aggregation queries in SLA router
8. Pin dependency versions in requirements.txt
9. Add frontend testing framework

### LOW (Nice to Have):
10. Add docstrings to complex API endpoints
11. Document database schema
12. Consolidate duplicate query patterns

---

*Concerns audit: 2026-01-17*
*Update as issues are fixed or new ones discovered*

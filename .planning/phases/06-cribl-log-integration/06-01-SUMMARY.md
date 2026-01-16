---
phase: 06-cribl-log-integration
plan: 01
subsystem: logging, middleware
tags: [cribl, loguru, correlation-ids, request-lifecycle, context-propagation]

# Dependency graph
requires:
  - phase: 03-03
    provides: Cribl logger with log_context() and audit event integration
  - phase: 05-03
    provides: SessionActivityMiddleware, SecurityHeadersMiddleware patterns
provides:
  - Request correlation IDs (UUID per request)
  - REQUEST_START, REQUEST_END, REQUEST_ERROR events in Cribl
  - Automatic context propagation (request_id, org_id, user_id) to all logs
  - X-Request-ID response header for client correlation
affects: [06-02, 06-03, 06-04]

# Tech tracking
tech-stack:
  added: []
  patterns: [Request logging middleware, Correlation ID generation, Automatic context propagation via contextvars]

key-files:
  created: [src/api/middleware/logging.py]
  modified: [src/api/main.py, src/api/middleware/tenant.py]

key-decisions: []
patterns-established: []
issues-created: []

# Metrics
duration: 45 minutes
completed: 2026-01-14T17:30:00Z
---

# Phase 6 Plan 1: Request Lifecycle Logging Summary

**Implemented comprehensive request lifecycle logging with automatic correlation IDs and context propagation for forensic analysis.**

## Accomplishments

- Created RequestLoggingMiddleware with REQUEST_START, REQUEST_END, REQUEST_ERROR events
- Implemented automatic UUID request_id generation for correlation
- Integrated set_log_context() and clear_log_context() for automatic context propagation
- Converted TenantMiddleware to Loguru for Cribl integration
- Added structured logging to OrganizationContextMiddleware
- Mounted middleware in correct order for full request lifecycle coverage
- Added X-Request-ID response header for client-side correlation
- All logs now automatically include request_id, org_id, user_id, session_id context
- Middleware failures and validations now centrally logged to Cribl

## Files Created/Modified

**Created:**
- `src/api/middleware/logging.py` - RequestLoggingMiddleware with lifecycle events (171 lines)
  - UUID request_id generation
  - REQUEST_START event with method, path, client IP, user agent
  - REQUEST_END event with status code, duration, bytes sent
  - REQUEST_ERROR event with exception type, message, traceback
  - X-Request-ID header injection for client correlation
  - Client IP extraction from X-Forwarded-For
  - Automatic context propagation via set_log_context()

**Modified:**
- `src/api/main.py` - Mounted RequestLoggingMiddleware, added logging to OrganizationContextMiddleware (30 insertions, 6 deletions)
  - Added Loguru import
  - Mounted RequestLoggingMiddleware after TenantMiddleware (runs first in execution order)
  - Enhanced OrganizationContextMiddleware with structured Loguru logging
  - Store org_id and org_name in request.state for downstream access
  - Log organization context extraction and validation events

- `src/api/middleware/tenant.py` - Converted from logging to Loguru, added structured context (42 insertions, 17 deletions)
  - Replaced standard logging with Loguru
  - Added middleware="TenantMiddleware" context to all log events
  - Log tenant validation success with tenant_slug and tenant_id
  - Log tenant validation failures (not found, inactive, not provisioned)
  - Log JWT extraction and validation events
  - Include structured context in all log entries

## Commit History

1. **33dabda** - `feat(06-01): create request logging middleware with correlation IDs`
   - Created RequestLoggingMiddleware with UUID generation
   - Implemented REQUEST_START, REQUEST_END, REQUEST_ERROR events
   - Added X-Request-ID header injection

2. **c68f68a** - `feat(06-01): integrate request context propagation`
   - Mounted RequestLoggingMiddleware in main.py
   - Enhanced OrganizationContextMiddleware with Loguru logging
   - Implemented automatic context propagation

3. **6e18257** - `feat(06-01): add logging to tenant and organization middleware`
   - Converted TenantMiddleware to Loguru
   - Added structured logging with middleware context
   - Enhanced forensic audit trail

## Decisions Made

- **Middleware ordering**: RequestLoggingMiddleware mounted last (runs first) to wrap all other middleware for complete lifecycle logging
- **Context storage**: Store org_id and org_name in request.state to make available to RequestLoggingMiddleware for context propagation
- **Client IP extraction**: Check X-Forwarded-For header first (proxy/load balancer support), fallback to request.client.host
- **Exception handling**: Log REQUEST_ERROR with full traceback, then re-raise to let FastAPI handle error response
- **Log levels**: INFO for request start/end and successful validations, WARNING for validation failures, DEBUG for organization context extraction

## Issues Encountered

None - all tasks completed successfully without issues.

## Verification Results

All verification checks passed:
- ✓ `src/api/middleware/logging.py` - Python syntax valid
- ✓ `src/api/middleware/tenant.py` - Python syntax valid
- ✓ `src/api/main.py` - Python syntax valid
- ✓ RequestLoggingMiddleware mounted in main.py
- ✓ set_log_context() and clear_log_context() implemented
- ✓ TenantMiddleware uses Loguru

## Next Step

Ready for 06-02-PLAN.md (Application Logger Migration) - Convert 108 logger calls in routers from standard logging to Loguru.

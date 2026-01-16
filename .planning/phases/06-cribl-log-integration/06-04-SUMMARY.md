---
phase: 06-cribl-log-integration
plan: 04
subsystem: logging, monitoring, health
tags: [cribl, performance, instrumentation, health-check, metrics, monitoring]

# Dependency graph
requires:
  - phase: 06-01
    provides: RequestLoggingMiddleware with duration tracking
  - phase: 06-02
    provides: Loguru integration across all routers
  - phase: 06-03
    provides: Redaction for sensitive data in logs
provides:
  - Performance categorization (FAST/NORMAL/SLOW/CRITICAL) for all API requests
  - Slow request alerting (WARNING level for >500ms)
  - Health check event logging (database, Redis status)
  - External service call instrumentation pattern (EXTERNAL_CALL_* events)
affects: [07-test-infrastructure]

# Tech tracking
tech-stack:
  added: []
  patterns: [Performance categorization, Health check logging, External service instrumentation context manager, Slow request alerting]

key-files:
  created: [src/api/utils/instrumentation.py]
  modified: [src/api/middleware/logging.py, src/api/main.py]

key-decisions: []
patterns-established: []
issues-created: []

# Metrics
duration: 25 minutes
completed: 2026-01-14T19:55:00Z
---

# Phase 6 Plan 4: Performance & Health Instrumentation Summary

**Implemented performance monitoring and health check observability for operational visibility in Cribl dashboards**

## Accomplishments

- Enhanced RequestLoggingMiddleware with performance categorization (FAST/NORMAL/SLOW/CRITICAL)
- Added slow request WARNING logs for requests >500ms (alerting in SIEM)
- Implemented /health endpoint with HEALTH_CHECK event logging
- Created health checks for database and Redis dependencies
- Built external service call instrumentation helper (instrument_external_call)
- Established EXTERNAL_CALL_* event types for future use
- Performance monitoring foundation for identifying bottlenecks
- Structured health status with timestamp and individual check results

## Files Created/Modified

**Created:**
- `src/api/utils/instrumentation.py` - External service call instrumentation context manager (69 lines)
  - instrument_external_call() context manager for timing external API calls
  - EXTERNAL_CALL_START, EXTERNAL_CALL_END, EXTERNAL_CALL_ERROR event types
  - Performance categorization: FAST (<200ms), NORMAL (200-1000ms), SLOW (1-5s), CRITICAL (>5s)
  - SLOW_EXTERNAL_CALL WARNING for calls >1000ms
  - Automatic duration calculation and structured logging
  - Error handling with duration tracking on failures
  - Reusable pattern for GitHub, Jira, AI provider instrumentation in Phase 7+

**Modified:**
- `src/api/middleware/logging.py` - Added performance categorization and slow request alerting (10 insertions)
  - Performance thresholds: FAST (<100ms), NORMAL (100-500ms), SLOW (500-2000ms), CRITICAL (>2000ms)
  - Enhanced REQUEST_END event with perf_category field
  - SLOW_REQUEST WARNING event for requests >500ms
  - Updated log message format to include performance category
  - Method and path added to REQUEST_END binding for better filtering

- `src/api/main.py` - Enhanced /health endpoint with dependency checks and logging (38 insertions, 1 deletion)
  - Database connectivity check using SELECT 1
  - Redis connectivity check using ping()
  - Structured health_status with timestamp, checks, and overall status
  - HEALTH_CHECK INFO event when all systems healthy
  - HEALTH_CHECK WARNING event when any system unhealthy
  - Detailed check results (healthy/unhealthy with error message)
  - Multi-tenant status included in health response

## Commit History

1. **a8bf499** - `feat(06-04): add performance categorization to request logging`
   - Enhanced RequestLoggingMiddleware with 4-tier performance categorization
   - Added slow request WARNING logs for SLOW and CRITICAL requests
   - Performance metrics now visible in Cribl dashboards

2. **9bfd8c5** - `feat(06-04): enhance health endpoint with dependency checks and logging`
   - Implemented database and Redis health checks
   - Added HEALTH_CHECK event logging with structured status
   - Enables operational monitoring and alerting on dependency failures

3. **207e183** - `feat(06-04): add external service call instrumentation helper`
   - Created instrument_external_call() context manager
   - Established reusable pattern for external service monitoring
   - Foundation for Phase 7+ GitHub, Jira, AI provider instrumentation

## Decisions Made

**Performance Thresholds**: Different thresholds for API requests vs external calls
- API requests: FAST (<100ms), NORMAL (100-500ms), SLOW (500-2000ms), CRITICAL (>2000ms)
- External calls: FAST (<200ms), NORMAL (200-1000ms), SLOW (1-5s), CRITICAL (>5s)
- Rationale: External calls naturally have higher latency due to network/service delays

**Health Check Scope**: Database and Redis only (no Cribl check)
- Avoid circular dependency (Cribl logger checking Cribl health)
- Database and Redis are critical dependencies sufficient for health signal
- Future expansion possible for GitHub/Jira API connectivity checks

**Instrumentation Pattern**: Context manager for external calls
- Provides clean API: `with instrument_external_call("service", "operation"):`
- Automatic timing and error handling
- Future adoption in routers can be gradual (not required in this phase)

## Issues Encountered

None - all tasks completed successfully with no syntax errors or breaking changes.

## Phase 6 Complete

**All 4 plans finished:**
- **06-01**: Request Lifecycle Logging (correlation IDs, context propagation) - 45 minutes
- **06-02**: Application Logger Migration (108 logger calls to Loguru) - 45 minutes
- **06-03**: Sensitive Data Redaction (GDPR/SOC2 compliance) - 15 minutes
- **06-04**: Performance & Health Instrumentation (monitoring foundation) - 25 minutes

**Total Phase 6 Duration**: 2 hours 10 minutes

**Total Phase 6 Deliverables:**
- Unified logging through Cribl for all application events
- Automatic request correlation and context injection (request_id, org_id, user_id)
- GDPR/SOC2 compliant log forwarding with sensitive data redaction
- Performance monitoring with categorization and alerting
- Health check observability for system dependencies
- 171 lines of middleware code for request lifecycle logging
- 108 logger calls migrated from logging to Loguru across 13 routers
- 7 sensitive data redaction patterns (passwords, tokens, secrets, JWTs, emails)
- External service instrumentation helper for Phase 7+ adoption

**Event Types Established:**
- REQUEST_START, REQUEST_END, REQUEST_ERROR (lifecycle)
- SLOW_REQUEST (performance alerting)
- HEALTH_CHECK (operational monitoring)
- EXTERNAL_CALL_START, EXTERNAL_CALL_END, EXTERNAL_CALL_ERROR (external service timing)
- SLOW_EXTERNAL_CALL (external service alerting)

**Compliance & Security:**
- GDPR Article 32: Technical measures for log data protection (redaction)
- SOC2 CC6.1: Logging of security-relevant events (audit trail)
- SOC2 CC7.2: System monitoring and incident response (health checks, performance alerting)

## Next Step

Ready for Phase 7: Test Infrastructure - Implement unit/integration tests with pytest, test coverage for authentication, RBAC, and critical API endpoints.

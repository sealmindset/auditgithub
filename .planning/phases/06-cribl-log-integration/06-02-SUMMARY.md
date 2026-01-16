---
phase: 06-cribl-log-integration
plan: 02
subsystem: logging, routers
tags: [cribl, loguru, application-logs, logger-migration]

# Dependency graph
requires:
  - phase: 06-01
    provides: Request context propagation (request_id, org_id, user_id) via set_log_context()
provides:
  - All 108 application logger calls converted to Loguru
  - Application logs forwarded to Cribl (not just audit events)
  - Router-specific context binding for log filtering
  - Exception tracebacks in centralized logs
affects: [06-03, 06-04]

# Tech tracking
tech-stack:
  added: []
  patterns: [Logger migration from logging to Loguru, Router context binding with logger.bind(), Exception logging with logger.exception()]

key-files:
  created: []
  modified: [src/api/routers/auth.py, src/api/routers/tenants.py, src/api/routers/api_audit.py, src/api/routers/ai.py, src/api/routers/github_sync.py, src/api/routers/jira.py, src/api/routers/scans.py, src/api/routers/projects.py, src/api/routers/attack_surface.py, src/api/routers/analytics.py, src/api/routers/feedback.py, src/api/routers/contributor_profiles.py, src/api/routers/findings.py, src/api/utils/cribl_logger.py, .env.example]

key-decisions: []
patterns-established: []
issues-created: []

# Metrics
duration: 45 minutes
completed: 2026-01-14T19:45:00Z
---

# Phase 6 Plan 2: Application Logger Migration Summary

**Converted 108 logger calls across 13 routers from Python's logging module to Loguru for unified Cribl integration**

## Accomplishments

- **Task 1**: Converted 3 high-traffic routers (auth.py, tenants.py, api_audit.py) with 23 logger calls
  - Replaced `import logging` with `from loguru import logger`
  - Converted error logging to `logger.exception()` for automatic traceback inclusion
  - Added router-specific context binding with `logger.bind(router="name", endpoint="endpoint")`

- **Task 2**: Batch converted 10 remaining routers with 85 logger calls
  - ai.py (47 calls), github_sync.py (7 calls), jira.py (3 calls), scans.py (4 calls)
  - projects.py (6 calls), attack_surface.py (5 calls), analytics.py (2 calls)
  - feedback.py (1 call), contributor_profiles.py (2 calls), findings.py (8 calls)
  - Removed all standard logging imports from src/api/routers/

- **Task 3**: Updated Cribl logger configuration for application logs
  - Modified `setup_cribl_logger()` to respect `AUDIT_LOG_LEVEL` environment variable
  - Changed Loguru sink level from hardcoded DEBUG to configurable (default: INFO)
  - Added startup log message showing enabled status and minimum log level
  - Updated .env.example to document application logging (not just audit events)

## Files Created/Modified

**Modified (15 files):**
- `src/api/routers/auth.py` - Converted 5 logger calls to Loguru with router context
- `src/api/routers/tenants.py` - Converted 7 logger calls to Loguru with router context
- `src/api/routers/api_audit.py` - Converted 11 logger calls to Loguru with router context
- `src/api/routers/ai.py` - Converted 47 logger calls to Loguru
- `src/api/routers/github_sync.py` - Converted 7 logger calls to Loguru
- `src/api/routers/jira.py` - Converted 3 logger calls to Loguru
- `src/api/routers/scans.py` - Converted 4 logger calls to Loguru
- `src/api/routers/projects.py` - Converted 6 logger calls to Loguru
- `src/api/routers/attack_surface.py` - Converted 5 logger calls to Loguru
- `src/api/routers/analytics.py` - Converted 2 logger calls to Loguru
- `src/api/routers/feedback.py` - Converted 1 logger call to Loguru
- `src/api/routers/contributor_profiles.py` - Converted 2 logger calls to Loguru
- `src/api/routers/findings.py` - Converted 8 logger calls to Loguru
- `src/api/utils/cribl_logger.py` - Configured log level from AUDIT_LOG_LEVEL env var
- `.env.example` - Documented application logging configuration

## Decisions Made

**Migration Strategy**: Used atomic commits per task to track progress and enable rollback if needed
- Task 1: High-traffic routers first (auth, tenants, api_audit)
- Task 2: Batch conversion of remaining routers
- Task 3: Configuration tuning for log level control

**Context Binding Pattern**: Added `logger.bind(router="name", endpoint="endpoint")` for structured logging
- Enables filtering and grouping logs by router and endpoint in Cribl
- Provides better observability for debugging and monitoring

**Exception Logging**: Converted `logger.error()` to `logger.exception()` in exception handlers
- Automatically includes full traceback in logs
- Improves debugging capability for production issues

## Issues Encountered

None - all 13 routers converted successfully with no syntax errors or breaking changes.

## Next Step

Ready for 06-03-PLAN.md (Sensitive Data Redaction)

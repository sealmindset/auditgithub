---
phase: 05-api-security-sessions
plan: 02
subsystem: auth
tags: [sessions, expiry, timeout, activity-tracking, redis, middleware]

# Dependency graph
requires:
  - phase: 05-01
    provides: Redis with AOF persistence for session storage
  - phase: 02-02
    provides: Session-based authentication with cookies
provides:
  - Session expiry enforcement (absolute + idle timeout)
  - Session metadata storage in Redis
  - Activity tracking middleware
  - Periodic session cleanup job
  - SessionMetadata model with expiry checking
affects: [05-03, 06-cribl-log-integration]

# Tech tracking
tech-stack:
  added: [schedule]
  patterns: [Session metadata, dual timeout model, activity tracking, periodic cleanup, SCAN cursor]

key-files:
  created: [src/auth/session.py, src/auth/cleanup.py]
  modified: [src/auth/config.py, src/auth/dependencies.py, src/auth/middleware.py, src/api/main.py, requirements.txt, docker-compose.yml]

key-decisions:
  - "Dual timeout model (8h absolute, 30m idle) - Balance between security and user experience"
  - "Redis metadata storage - Store session metadata separately from session cookie (reduces cookie size)"
  - "TTL = absolute timeout - Redis auto-cleanup for memory management"
  - "SCAN not KEYS - Use cursor-based iteration to avoid blocking Redis"
  - "Separate cleanup container - Isolate cleanup job from API for reliability"
  - "Non-blocking activity updates - Log warnings on failure, don't block requests"
  - "SessionActivityMiddleware - Update last_activity on every authenticated request"

patterns-established:
  - "Session expiry: Check metadata → is_expired() → clear session + delete metadata"
  - "Activity tracking: Middleware updates last_activity after request processing"
  - "Periodic cleanup: SCAN cursor → check expiry → delete expired sessions"
  - "Clear error messages: Return 'absolute timeout' vs 'idle timeout' in 401 response"

issues-created: []

# Metrics
duration: 7min
completed: 2026-01-13
---

# Phase 5 Plan 2: Session Management Summary

**Session expiry with activity tracking, idle timeout enforcement, and periodic cleanup**

## Performance

- **Duration:** 7 min
- **Started:** 2026-01-13T13:12:21Z
- **Completed:** 2026-01-13T13:19:23Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Implemented SessionMetadata model with created_at and last_activity tracking
- Built dual timeout enforcement (8-hour absolute, 30-minute idle)
- Added SessionActivityMiddleware for automatic activity tracking
- Created periodic cleanup job with Redis SCAN (non-blocking)
- Integrated expiry enforcement into get_current_user_from_session()
- Configured Docker Compose to run cleanup job in separate container
- Clear 401 error messages for expired sessions (absolute vs idle)

## Task Commits

1. **Task 1: Session expiry implementation** - `b6d7fd7` (feat)
   - Created src/auth/session.py with SessionMetadata and expiry logic
   - Updated src/auth/config.py with timeout settings
   - Updated src/auth/dependencies.py with expiry enforcement

2. **Task 2: Activity tracking and cleanup** - `de5082e` (feat)
   - Added SessionActivityMiddleware to src/auth/middleware.py
   - Created src/auth/cleanup.py with periodic job
   - Updated requirements.txt, docker-compose.yml, src/api/main.py

## Files Created/Modified

**Created:**
- `src/auth/session.py` - Session metadata storage and expiry logic (214 lines)
- `src/auth/cleanup.py` - Periodic cleanup job with Redis SCAN (117 lines)

**Modified:**
- `src/auth/config.py` - Added session_absolute_timeout_hours (8h), session_idle_timeout_minutes (30m)
- `src/auth/dependencies.py` - Added expiry enforcement to get_current_user_from_session()
- `src/auth/middleware.py` - Added SessionActivityMiddleware class
- `src/api/main.py` - Mounted SessionActivityMiddleware
- `requirements.txt` - Added schedule>=1.2.0
- `docker-compose.yml` - Added session-cleanup service

## Decisions Made

1. **Dual timeout model** - Both absolute (8h) and idle (30m) timeouts for balanced security and UX
2. **Redis metadata storage** - Store session metadata separately from session cookie (reduces cookie size)
3. **TTL on Redis keys** - Set TTL = absolute timeout for automatic memory cleanup
4. **SCAN not KEYS** - Use cursor-based SCAN to avoid blocking Redis on large datasets
5. **Separate cleanup container** - Run cleanup job in dedicated container to avoid blocking API
6. **Non-blocking activity updates** - Log warnings on failure, don't block requests
7. **Clear error messages** - Return "absolute timeout" vs "idle timeout" in 401 response

## Security & Performance Improvements

- **Dual timeout enforcement:** Sessions expire after 8 hours regardless of activity (absolute timeout)
- **Idle timeout:** Sessions expire after 30 minutes of inactivity (prevents abandoned sessions)
- **Activity tracking:** Every authenticated request updates last_activity timestamp
- **Periodic cleanup:** Runs every 5 minutes to prevent Redis memory leaks
- **Non-blocking SCAN:** Uses cursor-based iteration to avoid blocking Redis
- **Clear expiry messages:** Users understand why their session expired

## Issues Encountered

None - execution completed smoothly.

## Verification Results

All verification checks passed:
- ✓ Python syntax validation (py_compile)
- ✓ SessionMetadata.is_expired() method present
- ✓ Redis storage functions (get_session_metadata, set_session_metadata)
- ✓ Expiry enforcement in dependencies.py
- ✓ Activity tracking (update_last_activity)
- ✓ Timeout settings in config.py (8h absolute, 30m idle)
- ✓ Session cleanup function (delete_session)
- ✓ SessionActivityMiddleware class exists
- ✓ Activity update in middleware
- ✓ Cleanup function uses SCAN (not KEYS)
- ✓ Schedule library added to requirements.txt
- ✓ Cleanup service in docker-compose.yml
- ✓ Middleware added to main.py

## Next Step

Ready for 05-03-PLAN.md (API Security Hardening)

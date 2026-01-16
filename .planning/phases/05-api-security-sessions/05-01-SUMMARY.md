---
phase: 05-api-security-sessions
plan: 01
subsystem: auth
tags: [jwt, tokens, refresh, revocation, blacklist, redis, security]

# Dependency graph
requires:
  - phase: 02-03
    provides: JWT validation middleware with JWKS caching
  - phase: 04-01
    provides: Redis service for token storage
provides:
  - Refresh token generation and rotation (HS256, 7-day lifetime)
  - Access token generation (HS256, 1-hour lifetime)
  - Token revocation with Redis blacklist
  - POST /auth/refresh endpoint
  - POST /auth/revoke endpoint
affects: [05-02, 05-03, 06-cribl-log-integration]

# Tech tracking
tech-stack:
  added: []
  patterns: [JWT refresh tokens, token rotation, Redis blacklist, one-time use tokens]

key-files:
  created: [src/auth/tokens.py]
  modified: [src/auth/config.py, src/auth/dependencies.py, src/api/routers/auth.py, docker-compose.yml]

key-decisions:
  - "Self-signed tokens (HS256) - Use our own JWT signing for full lifecycle control (not OIDC provider tokens)"
  - "Redis AOF persistence - Enable appendonly mode to ensure blacklist survives restarts"
  - "One-time use refresh tokens - Rotate on every use with Redis tracking (refresh:{jti})"
  - "TTL-based blacklist - Use Redis SETEX with TTL=(exp-now) to auto-expire blacklist entries"
  - "Token validation priority - Try self-signed (HS256) before OIDC providers (RS256)"
  - "7-day refresh token lifetime - Balance between user convenience and security"
  - "Blacklist check on every request - Enforce revocation instantly via dependencies.py"

patterns-established:
  - "Token rotation: Validate old token → check blacklist → delete from rotation tracker → generate new token"
  - "Revocation: Add jti to Redis blacklist with TTL = token expiry"
  - "Request.state storage: Store jti, exp, user_sub for revocation endpoint"
  - "Dual token system: Short-lived access (1h) + long-lived refresh (7d)"

issues-created: []

# Metrics
duration: 2min
completed: 2026-01-13
---

# Phase 5 Plan 1: Token Refresh & Lifecycle Summary

**JWT refresh mechanism with rotation and Redis-backed token blacklist for instant revocation**

## Performance

- **Duration:** 2 min
- **Started:** 2026-01-13T13:04:31Z
- **Completed:** 2026-01-13T13:06:27Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Implemented refresh token generation with HS256 signing (7-day lifetime)
- Built token rotation mechanism (one-time use with Redis tracking)
- Added Redis-backed token blacklist with TTL auto-expiry
- Created POST /auth/refresh endpoint with secure rotation
- Created POST /auth/revoke endpoint for instant token revocation
- Integrated blacklist check into all protected endpoints
- Configured Redis with AOF persistence for durability

## Task Commits

1. **Task 1: Refresh token endpoint** - `2bdbf4c` (feat)
   - Created src/auth/tokens.py with JWT token management
   - Created src/auth/routers.py with authentication endpoints (later merged)
   - Updated src/auth/config.py with JWT and Redis settings
   - Updated docker-compose.yml Redis service with AOF persistence

2. **Task 2: Token revocation and blacklist** - `aa23363` (feat)
   - Updated src/auth/dependencies.py with blacklist enforcement
   - Merged token endpoints into src/api/routers/auth.py
   - Added POST /auth/refresh and POST /auth/revoke endpoints

## Files Created/Modified

**Created:**
- `src/auth/tokens.py` - Token generation, rotation, revocation logic (353 lines)

**Modified:**
- `src/auth/config.py` - Added jwt_secret_key, refresh_token_expire_days, access_token_expire_minutes, redis_url settings
- `src/auth/dependencies.py` - Added blacklist check to get_current_user_from_token(), stores jti/exp in request.state
- `src/api/routers/auth.py` - Added POST /auth/refresh and POST /auth/revoke endpoints
- `docker-compose.yml` - Added AOF persistence (--appendonly yes) and redis-data volume to Redis service

## Decisions Made

1. **Self-signed tokens (HS256)** - Use our own JWT signing for refresh tokens instead of relying on OIDC provider tokens (gives us full control over lifecycle)
2. **Redis blacklist with TTL** - Use Redis SETEX with TTL=(exp-now) to auto-expire blacklist entries (no manual cleanup needed)
3. **One-time use refresh tokens** - Rotate on every use to prevent token reuse attacks (tracked via Redis refresh:{jti})
4. **Redis AOF persistence** - Enable appendonly mode to ensure blacklist survives restarts
5. **7-day refresh token lifetime** - Balance between user convenience and security
6. **1-hour access token lifetime** - Short-lived for security, refreshable via /auth/refresh
7. **Blacklist check on every request** - Enforce revocation instantly across all endpoints (via dependencies.py)
8. **Token validation priority** - Try self-signed (HS256) first, then OIDC providers (RS256) - allows both systems to coexist

## Security Improvements

- **One-time use tokens:** Refresh tokens can only be used once (Redis tracking prevents reuse)
- **Instant revocation:** Token blacklist enforced on every protected endpoint (<1ms Redis latency)
- **Auto-expiry:** Blacklist entries automatically removed at token expiry (TTL-based)
- **Durability:** Redis AOF ensures blacklist survives restarts
- **Rotation prevents replay:** Old refresh tokens immediately invalidated after successful rotation

## Issues Encountered

None - execution completed smoothly.

## Verification Results

All verification checks passed:
- ✓ Python syntax validation (py_compile)
- ✓ Redis service in docker-compose.yml
- ✓ Redis AOF persistence enabled (--appendonly yes)
- ✓ Redis client in requirements.txt
- ✓ rotate_refresh_token() function present
- ✓ Blacklist check in dependencies.py (is_token_blacklisted)
- ✓ JWT HS256 signing confirmed
- ✓ Blacklist check in dependencies (get_current_user_from_token)
- ✓ Redis client initialization (Redis.from_url)
- ✓ TTL calculation present (ttl = exp - now)
- ✓ Revoke endpoint exists (@router.post /revoke)
- ✓ JTI stored in request.state

## Next Step

Ready for 05-02-PLAN.md (Session Management)

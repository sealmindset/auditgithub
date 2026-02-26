# API-First Architecture — Gap Analysis and Remediation Plan

**Version:** 1.0
**Date:** 2026-02-26
**Audience:** Solution Architects, Platform Engineers
**Companion Document:** [API_First.md](API_First.md)

---

## Table of Contents

1. [Assessment Methodology](#1-assessment-methodology)
2. [Gap Summary Matrix](#2-gap-summary-matrix)
3. [Critical Gaps (Priority 1)](#3-critical-gaps-priority-1)
4. [High Gaps (Priority 2)](#4-high-gaps-priority-2)
5. [Medium Gaps (Priority 3)](#5-medium-gaps-priority-3)
6. [Low Gaps (Priority 4)](#6-low-gaps-priority-4)
7. [Strengths — What AuditGitHub Does Well](#7-strengths--what-auditgithub-does-well)
8. [Remediation Roadmap](#8-remediation-roadmap)

---

## 1. Assessment Methodology

This gap analysis evaluates AuditGitHub against industry-standard API-first maturity criteria across 8 dimensions:

1. **Contract Management** — Is the API contract the source of truth?
2. **Versioning & Compatibility** — How are breaking changes managed?
3. **Client Decoupling** — Are all clients truly equal API consumers?
4. **Security Boundary** — Is the API the sole security enforcement point?
5. **Observability** — Can API behavior be monitored and debugged?
6. **Developer Experience** — How easy is it for new consumers to integrate?
7. **Governance Process** — How are API changes reviewed and approved?
8. **Testing & Validation** — Is the contract tested against implementation?

Each gap is rated:
- **Critical** — Architectural risk; could cause incidents or block scaling
- **High** — Significant deficiency; should be addressed in next quarter
- **Medium** — Improvement opportunity; plan for next 6 months
- **Low** — Nice-to-have; backlog candidate

---

## 2. Gap Summary Matrix

| # | Gap | Dimension | Priority | Effort | Impact |
|---|-----|-----------|----------|--------|--------|
| G-01 | No API versioning strategy | Versioning | Critical | Medium | Breaking changes cannot be managed safely |
| G-02 | Hardcoded API_BASE in frontend | Client Decoupling | Critical | Low | Cannot deploy UI against different API without code change |
| G-03 | No contract testing (spec vs implementation drift) | Testing | Critical | Medium | OpenAPI spec can silently diverge from actual API |
| G-04 | Scanner has partial direct DB access | Client Decoupling | High | High | Bypasses API security controls for some operations |
| G-05 | No API deprecation policy | Versioning | High | Low | No mechanism to sunset endpoints safely |
| G-06 | No generated API client SDKs | Developer Experience | High | Medium | Every consumer writes its own HTTP client |
| G-07 | Dual OpenAPI specs (hand-written + auto-generated) | Contract Management | High | Medium | Two sources of truth for the same API |
| G-08 | No breaking change definition | Governance | High | Low | Teams cannot assess impact of changes |
| G-09 | Inconsistent error response format | Developer Experience | Medium | Medium | Some endpoints return different error shapes |
| G-10 | No API changelog | Governance | Medium | Low | Consumers cannot track what changed between releases |
| G-11 | Missing request/response validation tests | Testing | Medium | Medium | Pydantic validates input but response schemas untested |
| G-12 | No API latency SLA definition | Observability | Medium | Low | No baseline for acceptable response times |
| G-13 | No API review process for new endpoints | Governance | Medium | Low | Endpoints added without spec-first review |
| G-14 | Rate limit configuration not externalized | Security | Medium | Low | Limits hardcoded in Python, not configurable at runtime |
| G-15 | No API key authentication (in progress) | Security | Low | High | Programmatic access requires JWT token management |
| G-16 | No pagination envelope standard | Developer Experience | Low | Medium | Some endpoints return arrays, others paginated objects |
| G-17 | No idempotency keys for POST operations | Developer Experience | Low | Medium | Retry-safe POSTs not guaranteed |

---

## 3. Critical Gaps (Priority 1)

### G-01: No API Versioning Strategy

**Current State:** All endpoints are unversioned. Paths are `/findings`, `/scans`, etc. — no `/v1/` prefix.

**Risk:** Any breaking change (field rename, response shape change, endpoint removal) will break all existing clients simultaneously. There is no mechanism to run old and new versions side-by-side.

**Impact:** As the platform matures and the number of API consumers grows (CLI, CI/CD pipelines, external integrations, partner systems), the inability to make breaking changes without coordinated deployments becomes a scaling bottleneck.

**Remediation:**

```
Option A: URL Prefix Versioning (Recommended)
  Current:  GET /findings
  Proposed: GET /v1/findings

  - Add /v1/ prefix to all existing endpoints
  - Maintain backward compatibility with unversioned paths (redirect or alias)
  - New breaking changes go to /v2/
  - Minimum 2 versions supported concurrently

Option B: Header Versioning
  Accept: application/vnd.auditgh.v1+json

  - More RESTful but harder for developers to discover
  - Not recommended for this project due to existing client patterns

Implementation Steps:
  1. Create APIRouter with prefix="/v1" in main.py
  2. Register all existing routers under /v1/ prefix
  3. Add redirect middleware: /findings → /v1/findings (301)
  4. Update OpenAPI spec servers to include /v1 base path
  5. Update frontend API_BASE to include /v1
  6. Document version lifecycle policy
```

**Effort:** Medium (2-3 days for migration, ongoing for policy)

---

### G-02: Hardcoded API_BASE in Frontend

**Current State:** Multiple frontend files contain:

```typescript
const API_BASE = "http://localhost:8000"  // Hardcoded in 15+ files
```

The `TenantContext.tsx` correctly uses `process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"` but this pattern is not used consistently.

**Risk:** The web UI cannot be deployed against a different API server (staging, production, canary) without a code change and rebuild.

**Affected Files:**
- `src/web-ui/app/page.tsx`
- `src/web-ui/app/findings/page.tsx`
- `src/web-ui/app/findings/[id]/page.tsx`
- `src/web-ui/app/repositories/page.tsx`
- `src/web-ui/app/attack-surface/page.tsx`
- `src/web-ui/app/login/page.tsx`
- `src/web-ui/app/scheduler/page.tsx`
- `src/web-ui/hooks/useWidgetData.ts`
- `src/web-ui/components/SeverityEditor.tsx`
- `src/web-ui/components/SecurityReportModal.tsx`
- `src/web-ui/components/SbomView.tsx`
- `src/web-ui/components/AskAIModal.tsx`
- `src/web-ui/components/contributor-profile-modal.tsx`

**Remediation:**

```
1. Create src/web-ui/lib/config.ts:
   export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"

2. Replace all hardcoded API_BASE constants with import from config.ts

3. Add NEXT_PUBLIC_API_URL to:
   - .env.sample
   - docker-compose.yml (web-ui environment)
   - Dockerfile.ui build args
   - ECS task definition environment

4. Optionally create an API client wrapper:
   src/web-ui/lib/api-client.ts
   - Centralizes fetch() with credentials, error handling, tenant headers
   - Single place to add auth token, retry logic, logging
```

**Effort:** Low (1 day — find-and-replace with import, add env var)

---

### G-03: No Contract Testing (Spec vs Implementation Drift)

**Current State:** The hand-written OpenAPI spec in `swagger/openapi.yaml` and the auto-generated FastAPI spec at `/openapi.json` are maintained independently. There is no automated check that they agree.

**Risk:** The hand-written spec can silently drift from the actual API behavior. External consumers relying on the published spec will encounter unexpected responses or missing fields.

**Evidence of potential drift:**
- The hand-written spec lists `v2.0.0` while `main.py` sets `version="1.0.0"`
- The hand-written spec has ~50 paths; the actual API has 80+ endpoints across 28 routers
- No CI step validates spec accuracy

**Remediation:**

```
Option A: Schemathesis (Recommended)
  - Property-based testing tool that generates requests from OpenAPI spec
  - Detects response schema violations, undocumented status codes, crashes
  - Add to CI pipeline:
    schemathesis run http://localhost:8000/openapi.json --checks all

Option B: Dredd
  - API contract testing that validates actual responses against spec
  - dredd swagger/openapi.yaml http://localhost:8000

Option C: Spectral Linting + Response Validation
  - spectral lint swagger/openapi.yaml (style/completeness checking)
  - Custom pytest fixtures that validate response against Pydantic schemas

Implementation Steps:
  1. Choose single source of truth: either FastAPI-generated OR hand-written (not both)
  2. If hand-written: Add Schemathesis to CI with --base-url http://localhost:8000
  3. If FastAPI-generated: Remove swagger/ directory, generate static spec from /openapi.json
  4. Add CI step that fails build on contract violations
  5. Require spec update in same PR as endpoint changes
```

**Effort:** Medium (2-3 days for tooling setup, ongoing for CI integration)

---

## 4. High Gaps (Priority 2)

### G-04: Scanner Has Partial Direct DB Access

**Current State:** The scanner engine writes scan results directly to PostgreSQL via psycopg2/SQLAlchemy rather than exclusively through the API.

**Risk:** Database writes from the scanner bypass the API middleware stack — no authentication, no RBAC check, no rate limiting, no audit logging, no tenant isolation middleware.

**Remediation:**

```
Short-term (mitigate):
  - Scanner runs as a trusted internal service on the same Docker network
  - Document this as a known architectural exception
  - Ensure scanner uses organization_id in all queries

Long-term (eliminate):
  - Create internal scan result ingestion API endpoint:
    POST /api/internal/scan-results (service-to-service auth token)
  - Scanner pushes results through API instead of direct DB writes
  - API endpoint handles tenant isolation, audit logging, deduplication
  - Estimated effort: 1-2 weeks for migration
```

---

### G-05: No API Deprecation Policy

**Current State:** There is no defined process for deprecating or removing API endpoints.

**Remediation:**

```
Recommended Policy:
  1. Deprecation announcement: Sunset header + API changelog entry
     Sunset: Sat, 01 Nov 2026 00:00:00 GMT
     Deprecation: true

  2. Minimum notice period: 90 days before removal

  3. Deprecation stages:
     a. Announce: Add Sunset header, log usage of deprecated endpoints
     b. Warn: Return Warning header with deprecation message
     c. Monitor: Track call volume to deprecated endpoints
     d. Remove: After 90 days with <1% traffic, remove endpoint

  4. Document in: docs/API_DEPRECATION_POLICY.md
```

---

### G-06: No Generated API Client SDKs

**Current State:** Every consumer (Web UI, CLI, scripts) writes its own HTTP client code using raw `fetch()` or `requests`.

**Risk:** Inconsistent error handling, duplicated auth logic, and manual serialization across clients.

**Remediation:**

```
1. Use OpenAPI Generator to produce typed clients:
   openapi-generator generate -i openapi.json -g python -o sdk/python/
   openapi-generator generate -i openapi.json -g typescript-fetch -o sdk/typescript/

2. Publish as internal packages:
   - PyPI (private): auditgh-sdk
   - npm (private): @auditgh/api-client

3. Adopt in CLI and Web UI first, then scanner and scripts

4. Auto-generate on every API spec change (CI step)
```

---

### G-07: Dual OpenAPI Specs

**Current State:** Two sources of truth exist:
1. `swagger/openapi.yaml` — Hand-written, modular, 50 paths, version 2.0.0
2. `http://localhost:8000/openapi.json` — Auto-generated by FastAPI, 80+ endpoints, version 1.0.0

**Remediation:**

```
Recommended: Single source of truth — FastAPI auto-generated spec

1. Use FastAPI's built-in OpenAPI generation as canonical spec
2. Enhance FastAPI routes with rich metadata:
   - response_model_exclude_unset=True
   - responses={404: {"description": "Not found"}}
   - tags, summary, description on every endpoint
3. Export static spec on build: python -c "import json; from src.api.main import app; print(json.dumps(app.openapi()))" > openapi.json
4. Archive swagger/ directory contents as reference
5. Add CI step to detect spec changes and update static file
```

---

### G-08: No Breaking Change Definition

**Current State:** There is no documented definition of what constitutes a breaking change.

**Remediation:**

```
Document in API governance policy:

BREAKING CHANGES (require version bump):
  - Removing an endpoint
  - Removing or renaming a response field
  - Changing a field's type (string → integer)
  - Adding a required request field
  - Changing authentication requirements
  - Changing error response format
  - Reducing rate limits

NON-BREAKING CHANGES (safe without version bump):
  - Adding a new endpoint
  - Adding an optional request field
  - Adding a response field
  - Increasing rate limits
  - Adding a new enum value to an existing field
  - Performance improvements with same contract
```

---

## 5. Medium Gaps (Priority 3)

### G-09: Inconsistent Error Response Format

**Current State:** Most endpoints use FastAPI's default HTTPException format:
```json
{"detail": "Error message"}
```

But some endpoints return different shapes:
```json
{"error": "message", "status": 400}
{"message": "Not found"}
```

**Remediation:**

```
Standardize all errors to RFC 7807 Problem Details:
{
    "type": "https://auditgh.local/errors/not-found",
    "title": "Resource Not Found",
    "status": 404,
    "detail": "Finding with ID abc123 was not found",
    "instance": "/findings/abc123"
}

Implementation:
1. Create custom exception handler in main.py
2. Map HTTPException to RFC 7807 format
3. Map ValidationError to RFC 7807 with field-level details
4. Document error format in OpenAPI spec components/responses
```

---

### G-10: No API Changelog

**Current State:** Product changelog exists (`CHANGELOG.md`) but it mixes UI, backend, and infrastructure changes. No API-specific changelog documents endpoint additions, removals, or behavior changes.

**Remediation:**

```
Create docs/API_CHANGELOG.md:

## [2.1.0] - 2026-03-15
### Added
- POST /api/api-keys — Create API key (see API_Key_PLAN.md)
- GET /api/api-keys — List API keys
- GET /api/api-keys/tool-categories — Tool category reference

### Changed
- GET /findings — Added `risk_level` field to response

### Deprecated
- None

### Removed
- None
```

---

### G-11: Missing Response Validation Tests

**Current State:** Pydantic validates request input (deserialization), but response schemas are not systematically tested. A route handler could return unexpected fields or missing fields without detection.

**Remediation:**

```
1. Enable FastAPI response_model validation in development:
   @router.get("/findings", response_model=list[FindingResponse])

2. Add pytest fixtures that assert response structure:
   def test_findings_response_schema(client):
       res = client.get("/findings")
       for finding in res.json():
           FindingResponse(**finding)  # Raises if schema mismatch

3. Use Schemathesis (see G-03) for automated response validation
```

---

### G-12: No API Latency SLA Definition

**Current State:** The `RequestLoggingMiddleware` categorizes performance (FAST <100ms, NORMAL, SLOW, CRITICAL >2000ms) but there are no defined SLA targets.

**Remediation:**

```
Recommended SLA Targets:
  - p50 latency: < 100ms (list endpoints), < 200ms (detail endpoints)
  - p95 latency: < 300ms (list), < 500ms (detail)
  - p99 latency: < 1000ms (all endpoints)
  - Error rate: < 0.1% (5xx responses)
  - Availability: 99.9% (measured monthly)

Implementation:
  1. Add Prometheus metrics endpoint (/metrics)
  2. Track histogram of response times per endpoint
  3. Set up alerting on SLA breaches (p99 > 1000ms)
  4. Dashboard in Cribl/Grafana showing SLA compliance
```

---

### G-13: No API Review Process for New Endpoints

**Current State:** New endpoints are added by creating a router file and registering it in `main.py`. There is no requirement to update the OpenAPI spec first or get architectural review.

**Remediation:**

```
Recommended Process:
  1. Open spec PR first: Add endpoint to OpenAPI spec with schemas
  2. Architecture review: Verify naming conventions, auth requirements, pagination
  3. Implementation PR: Build endpoint matching the approved spec
  4. Contract test: CI validates implementation matches spec
  5. Documentation: Update API changelog

Checklist for new endpoints:
  □ Path follows RESTful naming (plural nouns, no verbs)
  □ Auth requirement defined (public or require_permissions)
  □ Rate limit configured (or inherits global default)
  □ Response model defined with Pydantic
  □ Error responses documented
  □ Pagination if returning lists
  □ Organization scoping applied
  □ Audit logging for write operations
```

---

### G-14: Rate Limit Configuration Not Externalized

**Current State:** Rate limits are defined in Python code (`src/auth/rate_limit.py`):
```python
default_limits=["100/minute"]
```

Endpoint-specific limits are also hardcoded in the same file.

**Remediation:**

```
1. Move rate limit configuration to environment variables or database:
   RATE_LIMIT_DEFAULT=100/minute
   RATE_LIMIT_AUTH_LOGIN=5/minute
   RATE_LIMIT_AUTH_REFRESH=10/minute

2. Or store in SystemConfig table (already exists):
   Key: rate_limit.default, Value: "100/minute"
   Key: rate_limit.auth.login, Value: "5/minute"

3. Allow runtime changes without redeployment
```

---

## 6. Low Gaps (Priority 4)

### G-15: No API Key Authentication (In Progress)

**Current State:** API key management is planned and documented in `docs/API_Key_PLAN.md`. Implementation has not started.

**Status:** Tracked separately. See [API_Key_PLAN.md](API_Key_PLAN.md) for the 4-phase implementation plan.

---

### G-16: No Pagination Envelope Standard

**Current State:** Pagination is inconsistent across endpoints:

```json
// Pattern A (findings — paginated envelope):
{
    "items": [...],
    "total": 1000,
    "page": 1,
    "page_size": 100,
    "total_pages": 10,
    "has_next": true,
    "has_prev": false
}

// Pattern B (repositories — bare array):
[
    {"id": "...", "name": "..."},
    ...
]
```

**Remediation:**

```
Standardize all list endpoints to return paginated envelope:
{
    "data": [...],
    "pagination": {
        "total": 1000,
        "page": 1,
        "page_size": 100,
        "total_pages": 10,
        "has_next": true,
        "has_prev": false
    }
}

This is a breaking change — implement with API versioning (G-01).
```

---

### G-17: No Idempotency Keys for POST Operations

**Current State:** POST requests (create scan, create organization, send invitation) have no idempotency key mechanism. Retrying a failed POST could create duplicate resources.

**Remediation:**

```
1. Accept optional Idempotency-Key header on POST endpoints
2. Store key + response in Redis with 24h TTL
3. If same key seen again, return cached response (no re-execution)
4. Document in API spec:
   headers:
     Idempotency-Key:
       schema: {type: string, format: uuid}
       description: "Unique key for safe retries"
```

---

## 7. Strengths — What AuditGitHub Does Well

Before remediation, it is important to recognize the strong API-first foundations already in place:

| Area | Strength |
|------|----------|
| **Architecture** | Clean separation: API is the sole entry point for all clients. Web UI has zero DB access. |
| **Auth stack** | Four auth methods (OIDC, JWT, Device Flow, Break Glass) all resolved at the API layer |
| **RBAC** | 5-tier role hierarchy with 13 permissions, tenant-scoped, Redis-cached, wildcard support |
| **Middleware** | 8-layer pipeline enforcing security, logging, and tenant isolation uniformly |
| **Multi-tenancy** | Schema-per-tenant isolation with organization-scoped queries and middleware extraction |
| **Observability** | Structured JSON logging via Cribl with request correlation IDs and performance categorization |
| **Documentation** | Both hand-written OpenAPI spec and auto-generated Swagger/ReDoc |
| **Rate limiting** | Per-user/IP rate limiting with Redis backend and endpoint-specific overrides |
| **Health monitoring** | `/health` endpoint with dependency checks, Docker Compose health probes |
| **Deployment flexibility** | Runs on Docker Compose (dev) and AWS ECS Fargate (prod) with IaC (Terraform) |
| **Multi-client support** | 6 client types consuming the same API surface with appropriate auth per client |
| **Audit trail** | Auth events, authorization decisions, and data access logged with tenant context |

---

## 8. Remediation Roadmap

### Phase 1 — Critical Fixes (Weeks 1-4)

| Gap | Action | Owner | Estimated Effort |
|-----|--------|-------|-----------------|
| G-02 | Centralize API_BASE into `lib/config.ts` and env var | Frontend | 1 day |
| G-01 | Add `/v1/` prefix to all endpoints with backward-compatible redirects | Backend | 3 days |
| G-03 | Add Schemathesis contract testing to CI pipeline | DevOps | 2 days |
| G-07 | Choose single spec source of truth (recommend: FastAPI-generated) | Architecture | 1 day decision + 2 days migration |

### Phase 2 — High Priority (Weeks 5-10)

| Gap | Action | Owner | Estimated Effort |
|-----|--------|-------|-----------------|
| G-05 | Write and publish API deprecation policy | Architecture | 1 day |
| G-08 | Document breaking change definition in governance policy | Architecture | 0.5 days |
| G-06 | Set up OpenAPI Generator for Python and TypeScript SDKs | Backend + Frontend | 3 days |
| G-04 | Design internal scan ingestion endpoint; begin scanner migration | Backend | 1-2 weeks |

### Phase 3 — Medium Priority (Weeks 11-20)

| Gap | Action | Owner | Estimated Effort |
|-----|--------|-------|-----------------|
| G-09 | Standardize error responses to RFC 7807 | Backend | 2 days |
| G-10 | Create API changelog and add to release process | All | 0.5 days + ongoing |
| G-11 | Add response schema validation tests | QA | 2 days |
| G-12 | Define and publish API latency SLAs | SRE | 1 day |
| G-13 | Implement API review process for new endpoints | Architecture | 1 day |
| G-14 | Externalize rate limit configuration | Backend | 1 day |

### Phase 4 — Low Priority (Backlog)

| Gap | Action | Owner | Estimated Effort |
|-----|--------|-------|-----------------|
| G-15 | Implement API key authentication (separate plan) | Backend + Frontend | 4-6 weeks |
| G-16 | Standardize pagination envelope (breaking change, needs v2) | Backend | 2 days |
| G-17 | Add idempotency key support for POST endpoints | Backend | 2 days |

---

### Success Criteria

The gaps are considered resolved when:

1. **G-01 resolved:** All endpoints accessible under `/v1/` prefix; version documented in spec
2. **G-02 resolved:** Zero hardcoded `http://localhost:8000` strings in frontend source
3. **G-03 resolved:** CI pipeline fails on contract violations; green for current codebase
4. **G-04 resolved:** Scanner writes findings exclusively through the API
5. **G-05–G-08 resolved:** Governance documents published and linked from README
6. **G-09 resolved:** All error responses conform to RFC 7807 format
7. **G-10 resolved:** API changelog updated with every release
8. **G-11 resolved:** Response schema tests cover all list and detail endpoints
9. **G-12 resolved:** SLA targets published; monitoring dashboards active
10. **G-13 resolved:** New endpoint PRs require spec-first review approval

---

*This gap analysis is a living document. Reassess quarterly as gaps are remediated and new patterns emerge.*

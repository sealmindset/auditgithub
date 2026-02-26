# API Governance — Current State and Recommendations

**Source:** [API_First.md](API_First.md) - Section 12

---

## 12.1 What Exists Today

| Governance Area | Current State |
|----------------|---------------|
| **API Specification** | OpenAPI 3.0.3 in `swagger/openapi.yaml` (hand-maintained, modular) |
| **Auto-generated docs** | FastAPI `/docs` (Swagger UI) and `/redoc` at runtime |
| **Authentication** | JWT Bearer, OIDC, Device Flow, Session — enforced at middleware |
| **Authorization** | RBAC with 5 roles, 13 permissions, wildcard support, Redis-cached |
| **Rate limiting** | Per-user/IP, endpoint-specific overrides, Redis-backed |
| **Audit logging** | Structured JSON via Cribl logger, auth audit table, authorization audit |
| **Health checks** | `/health` endpoint with dependency status |
| **Error responses** | Consistent HTTPException with status codes and detail messages |
| **Pagination** | `skip`/`limit` pattern (default 100, max 1000) |
| **CORS** | Configurable origins, credentials, methods, headers |

## 12.2 Recommended Governance Additions

The following governance practices are recommended for long-term API health. A detailed gap analysis with prioritized remediation is available in [API_First_GAP.md](API_First_GAP.md).

| Practice | Recommendation | Priority |
|----------|---------------|----------|
| **API Versioning** | Adopt URL-prefix versioning (`/v1/`, `/v2/`) for breaking changes | High |
| **Deprecation Policy** | Define sunset headers, minimum notice periods (90 days), and migration guides | High |
| **Contract Testing** | Add Schemathesis or Dredd for spec-vs-implementation drift detection | High |
| **Changelog** | Maintain a per-version API changelog separate from product changelog | Medium |
| **SDK Generation** | Use OpenAPI Generator to produce typed Python/TypeScript clients | Medium |
| **API Review Process** | Require spec-level PR review before implementation for new endpoints | Medium |
| **SLA Definitions** | Define latency (p99 < 500ms), availability (99.9%), and error rate targets | Medium |
| **Breaking Change Policy** | Define what constitutes a breaking change; require version bump | High |

# The API Contract

**Source:** [API_First.md](API_First.md) - Section 4

---

## OpenAPI 3.0.3 Specification

The API contract is defined in `swagger/openapi.yaml` with a modular structure:

```
swagger/
├── openapi.yaml                 ← Root specification (version, servers, security, paths)
├── components/
│   ├── schemas.yaml             ← Reusable data models (Organization, Repository, Finding, etc.)
│   ├── responses.yaml           ← Standard error responses (400, 401, 403, 404, 500)
│   └── parameters.yaml          ← Reusable query parameters (skip, limit, org filter)
├── paths/
│   ├── organizations/           ← 10 path definitions
│   ├── repositories/            ← 4 path definitions
│   ├── findings/                ← 4 path definitions
│   ├── scans/                   ← 3 path definitions
│   ├── github/                  ← 4 path definitions
│   ├── auth/                    ← 4 path definitions
│   ├── tenants/                 ← 2 path definitions
│   ├── analytics/               ← 2 path definitions
│   ├── ai/                      ← 1 path definition
│   └── ... (15+ more domains)
└── README.md                    ← Specification maintenance guide
```

## Contract Characteristics

| Property | Value |
|----------|-------|
| Spec version | OpenAPI 3.0.3 |
| API version | 2.0.0 |
| Authentication | JWT Bearer token (global security scheme) |
| Pagination | `skip` / `limit` (default 100, max 1000) |
| Rate limiting | Per-user, exposed via `X-RateLimit-*` headers |
| Content type | `application/json` (all endpoints) |
| Server environments | `http://localhost:8000/api` (dev), `https://api.auditgh.local/api` (prod) |

## Auto-Generated Documentation

FastAPI generates interactive API documentation at runtime:

- **Swagger UI**: `http://localhost:8000/docs` — Interactive endpoint testing
- **ReDoc**: `http://localhost:8000/redoc` — Clean reference documentation
- **OpenAPI JSON**: `http://localhost:8000/openapi.json` — Machine-readable spec

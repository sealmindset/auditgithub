# Gemini 3 Diagram Generation Prompt

**Source:** [API_First.md](API_First.md) - Appendix B

Use the following prompt with Google Gemini 3 to generate a complete set of architecture diagrams for AuditGitHub. The prompt is designed to produce 7 diagrams that together explain the API-first architecture visually.

---

## Prompt

```
You are a technical diagram designer creating architecture documentation for AuditGitHub,
an enterprise API-first security scanning platform. Generate 7 professional diagrams
using clean, modern styling with a dark blue (#1e3a5f) and teal (#2dd4bf) color palette
on white backgrounds. Use standard UML/C4 notation where applicable.

All diagrams should include a title, a brief caption, and a legend.

=== DIAGRAM 1: System Context (C4 Level 1) ===

Show AuditGitHub as a central system box with these external actors/systems around it:

USERS:
- Security Analyst (uses Web Dashboard and CLI)
- Platform Admin (manages organizations, users, API keys)
- CI/CD Pipeline (automated scan triggers)

EXTERNAL SYSTEMS:
- GitHub (repository source, metadata, Actions workflows)
- Jira (ticket creation for findings)
- Cribl Stream (log forwarding to SIEM)
- Identity Providers (Microsoft Entra ID, Okta — OIDC authentication)
- AI Providers (Anthropic Claude, OpenAI GPT-4, Google Gemini, Ollama local)
- MinIO / S3 (log and report storage)

Draw arrows showing data flow direction with labels.
AuditGitHub should be shown as containing: "FastAPI Backend (API Layer)", with the tagline
"All clients access capabilities exclusively through REST API endpoints."

=== DIAGRAM 2: Container Diagram (C4 Level 2) ===

Show the internal containers of the AuditGitHub platform:

CONTAINERS:
1. Web UI (Next.js, port 3000) — "Pure API consumer, zero DB access"
2. FastAPI Backend (Python, port 8000) — "API layer: 28 routers, 80+ endpoints"
3. CLI Tool (Python) — "OAuth 2.0 Device Flow (RFC 8628)"
4. Scanner Engine (Docker, on-demand) — "20+ security tools"
5. PostgreSQL (port 5432) — "Multi-org with schema-per-tenant isolation"
6. Redis (port 6379) — "Sessions, RBAC cache, rate limits, token blacklist"
7. MinIO (port 9009) — "S3-compatible log and report storage"

Draw all client containers (Web UI, CLI, Scanner) connecting ONLY to the FastAPI Backend.
Draw the FastAPI Backend connecting to PostgreSQL, Redis, and MinIO.
Add a note: "No client has direct database access — the API is the single entry point."

=== DIAGRAM 3: API Request Flow Sequence Diagram ===

Show a sequence diagram for a typical authenticated API request:

PARTICIPANTS: Browser, Next.js UI, FastAPI API, Middleware Pipeline, RBAC Engine,
  Redis Cache, PostgreSQL

SEQUENCE:
1. Browser → Next.js UI: Navigate to /findings
2. Next.js UI → FastAPI API: GET /findings (credentials: include, cookie)
3. FastAPI API → Middleware Pipeline: Request enters pipeline
4. Middleware Pipeline: 1. RequestLogging (generate request_id)
5. Middleware Pipeline: 2. SecurityHeaders (CSP, HSTS)
6. Middleware Pipeline: 3. Authentication (validate session cookie)
7. Middleware Pipeline: 4. OrganizationContext (extract org_id)
8. Middleware Pipeline → RBAC Engine: Check "findings:read" permission
9. RBAC Engine → Redis Cache: Check cached permissions
10. Redis Cache → RBAC Engine: Cache hit (permissions list)
11. RBAC Engine → Middleware Pipeline: Permission granted
12. Middleware Pipeline → PostgreSQL: SELECT findings WHERE org_id = ?
13. PostgreSQL → Middleware Pipeline: Results
14. Middleware Pipeline → FastAPI API: Attach X-Request-ID, rate limit headers
15. FastAPI API → Next.js UI: 200 OK {findings: [...]}
16. Next.js UI → Browser: Render findings table

=== DIAGRAM 4: Authentication Methods Topology ===

Show a diagram with the FastAPI Backend in the center and four authentication
paths converging on it:

PATH 1 - Web UI (OIDC):
  Browser → /auth/login/entra → Entra ID (PKCE + S256) → /auth/callback → Session Cookie

PATH 2 - CLI (Device Flow):
  CLI → POST /auth/device/code → Display user_code → Browser verifies →
  CLI polls /auth/device/token → JWT access + refresh tokens

PATH 3 - API Client (Bearer Token):
  Script → Authorization: Bearer {jwt} → Token validation →
  Check blacklist (Redis) → Resolve user

PATH 4 - Emergency (Break Glass):
  Admin → POST /auth/break-glass/login → Local password (bcrypt) →
  Session cookie → Full audit logging

Show all four paths merging into a single box:
"Unified Identity → RBAC Permission Check → Route Handler"

=== DIAGRAM 5: Multi-Tenant Data Flow ===

Show how data is isolated per organization:

TOP: Three API requests arrive with different org headers:
  - Request A: X-Organization-ID: org-uuid-example-org
  - Request B: X-Organization-ID: org-uuid-example-org
  - Request C: No organization header

MIDDLE: OrganizationContextMiddleware resolves org_id for each request

BOTTOM: PostgreSQL database with:
  - public schema (shared): organizations, roles, permissions, users
  - tenant_example-org schema (isolated): repositories, findings, scans
  - tenant_example-org schema (isolated): repositories, findings, scans

Show Request A routed to tenant_example-org, Request B to tenant_example-org,
Request C rejected with 400 "Missing organization context."

=== DIAGRAM 6: Middleware Pipeline (Layered) ===

Show a vertical layered diagram with 8 horizontal bands, one per middleware layer.
Each band should show:
- Layer number and name
- What it does (2-3 words)
- What it sets on request.state

Layer stack (top to bottom, matching request flow):
1. RequestLoggingMiddleware — Correlation ID, performance tracking
2. TenantMiddleware — Schema routing, tenant validation
3. SecurityHeadersMiddleware — CSP, HSTS, X-Frame-Options
4. AuthenticationMiddleware — Session/JWT/API Key validation
5. SessionActivityMiddleware — Idle timeout tracking (Redis)
6. OrganizationContextMiddleware — Org extraction from headers/params
7. CORSMiddleware — Cross-origin policy enforcement
8. SessionMiddleware — Encrypted cookie management

Show a REQUEST arrow entering at the top and a RESPONSE arrow exiting at the bottom.
Between layers, show the request.state accumulating context:
  After layer 2: request.state.tenant_id
  After layer 4: request.state.user
  After layer 6: request.state.org_id

=== DIAGRAM 7: Deployment Topology ===

Show two deployment environments side by side:

LEFT: Local Development (Docker Compose)
  - 7 containers in a single Docker network
  - api (FastAPI :8000), web-ui (Next.js :3000), scanner (on-demand)
  - db (PostgreSQL :5432), redis (:6379), minio (:9009), mailhog (:1025)
  - Show docker-compose.yml as the orchestrator

RIGHT: Production (AWS ECS Fargate)
  - VPC with public and private subnets
  - ALB in public subnet (HTTPS :443, path-based routing)
  - ECS Fargate tasks in private subnet: API (2 tasks), WebUI (2 tasks)
  - RDS PostgreSQL (Multi-AZ) in private subnet
  - ElastiCache Redis (failover) in private subnet
  - S3 buckets for reports and logs
  - ECR for container images
  - GitHub Actions CI/CD pipeline deploying to ECS

Show that in BOTH environments, the API layer is the single entry point.
No client connects directly to databases in either environment.

=== STYLE GUIDELINES ===
- Use Mermaid, PlantUML, or draw.io XML format (specify which you're using)
- Primary color: #1e3a5f (dark blue)
- Accent color: #2dd4bf (teal)
- Background: white
- Font: Inter or system sans-serif
- Line style: solid for data flow, dashed for async/optional
- Arrow labels should be concise (verb + noun, e.g., "fetch findings")
- Each diagram should be self-contained and printable on A4/letter paper
- Include a brief 1-sentence caption below each diagram title
```

# Executive Summary

**Source:** [API_First.md](API_First.md) - Section 1

---

## For Directors and Executive Leadership

**API-First architecture** is a design philosophy where every capability in a software system is exposed through a well-defined programmatic interface (API) *before* any user interface is built. The API is the product. The web dashboard, the command-line tool, the CI/CD integration, and every future client are all equal consumers of that same API.

**Why this matters to the business:**

- **Faster integration development.** When a new tool (Jira, Cribl, a SIEM, a compliance platform) needs to connect to AuditGitHub, the integration surface already exists. There is no custom backend work required — only an API client. This reduces integration timelines from weeks to days.

- **Parallel team velocity.** Frontend, backend, scanner, and AI teams can work independently against the API contract. A change to the dashboard does not require a backend deployment. A new scanner does not require a UI change. This eliminates cross-team blocking and accelerates delivery.

- **Reduced vendor lock-in.** Because every capability is accessible via standard HTTP/REST, AuditGitHub is not locked to any single UI framework, deployment model, or client technology. The Next.js frontend could be replaced with a mobile app, a Slack bot, or a Power BI dashboard — all consuming the same API.

- **Breach cost avoidance.** The API layer enforces authentication, authorization, rate limiting, and audit logging uniformly across every client. There is no "back door" through a direct database connection. Every action — whether from a human analyst, an automated scanner, or an AI agent — passes through the same security controls.

- **Engineering hour savings.** API-first eliminates the class of bugs where "the UI does X but the API does Y." There is one source of truth for business logic. Testing is centralized. Documentation is auto-generated from the contract.

## How AuditGitHub Implements API-First

AuditGitHub is a security scanning platform for GitHub organizations. Its architecture follows API-first as a core design principle:

1. **The API is the single entry point.** The FastAPI backend on port 8000 serves 80+ endpoints across 28 routers. No client — including the web dashboard — has direct database access.

2. **Six distinct clients** consume the same API: the Next.js web dashboard, a CLI tool (OAuth 2.0 Device Flow), the scanner engine, AI agents (Claude, GPT-4, Gemini, Ollama), external integrations (Jira, Cribl, GitHub), and programmatic scripts/CI pipelines.

3. **The contract is documented.** A hand-maintained OpenAPI 3.0.3 specification in `swagger/openapi.yaml` defines every endpoint, schema, and response. FastAPI also auto-generates interactive documentation at `/docs`.

4. **Security is enforced at the API layer.** JWT authentication, OIDC (Entra ID, Okta), RBAC with 5 role tiers, per-endpoint rate limiting, tenant isolation, and structured audit logging are all implemented in the API middleware stack — not in any individual client.

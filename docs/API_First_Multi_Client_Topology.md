# Multi-Client Topology

**Source:** [API_First.md](API_First.md) - Section 5

---

AuditGitHub serves **six distinct client types**, all consuming the same API:

## Client Inventory

```
┌────────────────────────────────────────────────────────────────────┐
│                     API CLIENT TOPOLOGY                            │
├───────────────┬──────────────┬──────────────┬─────────────────────┤
│   Client      │  Auth Method │  Transport   │  Primary Endpoints  │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ Web UI        │ Session      │ fetch() +    │ /analytics/*        │
│ (Next.js)     │ (OIDC)       │ credentials  │ /findings/*         │
│ :3000         │              │ :include     │ /repositories/*     │
│               │              │              │ /settings/*         │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ CLI Tool      │ Device Flow  │ HTTP client  │ /auth/device/*      │
│ (Python)      │ (RFC 8628)   │ (requests)   │ /repositories/*     │
│               │              │              │ /scans/*            │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ Scanner       │ Internal     │ Direct DB +  │ /scans/*            │
│ (Docker)      │ (service)    │ API calls    │ /findings/*         │
│ On-demand     │              │              │ /repositories/*     │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ AI Agents     │ Internal     │ Service-to-  │ /ai/*               │
│ (Multi-LLM)   │ (service)    │ service      │ /ai/chat/*          │
│               │              │              │ /findings/*         │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ Integrations  │ JWT Bearer   │ REST/Webhook │ /jira/*             │
│ (Jira, Cribl) │              │              │ /cribl/*            │
│               │              │              │ /github/*           │
├───────────────┼──────────────┼──────────────┼─────────────────────┤
│ CI/CD &       │ JWT Bearer / │ HTTP client  │ /scans/*            │
│ Scripts       │ API Key      │              │ /organizations/*    │
│               │ (planned)    │              │ /findings/*         │
└───────────────┴──────────────┴──────────────┴─────────────────────┘
```

## Frontend as Pure API Consumer

The Next.js web dashboard has **zero database connectivity**. Every piece of data displayed in the UI flows through the API:

```
Browser → Next.js (:3000) → fetch("http://localhost:8000/...") → FastAPI (:8000) → PostgreSQL
                                                                                 → Redis
                                                                                 → MinIO
```

**Evidence of decoupling:**

- `Dockerfile.ui` installs only Node.js — no database drivers
- `docker-compose.yml` web-ui service has `depends_on: api` — not `db`
- Every page component uses `fetch()` with `credentials: 'include'` against `API_BASE`
- The `useWidgetData` hook centralizes API consumption with auto-refresh and org-scoping

## CLI as Device Flow Client

The CLI (`cli/auditgh-cli.py`) authenticates using OAuth 2.0 Device Authorization Grant (RFC 8628):

```
CLI                    API                     Browser              OIDC Provider
 │                      │                        │                       │
 │ POST /auth/device/   │                        │                       │
 │      code            │                        │                       │
 │─────────────────────>│                        │                       │
 │                      │                        │                       │
 │ { device_code,       │                        │                       │
 │   user_code,         │                        │                       │
 │   verification_uri } │                        │                       │
 │<─────────────────────│                        │                       │
 │                      │                        │                       │
 │ Display: "Go to      │                        │                       │
 │ {url} and enter      │                        │                       │
 │ code {user_code}"    │                        │                       │
 │                      │                        │                       │
 │                      │  GET /auth/device/     │                       │
 │                      │      verify            │                       │
 │                      │<───────────────────────│                       │
 │                      │                        │                       │
 │                      │  Redirect to OIDC      │                       │
 │                      │───────────────────────>│──────────────────────>│
 │                      │                        │  Authenticate         │
 │                      │                        │<─────────────────────│
 │                      │  POST /auth/device/    │                       │
 │                      │       approve          │                       │
 │                      │<───────────────────────│                       │
 │                      │                        │                       │
 │ POST /auth/device/   │                        │                       │
 │      token (polling) │                        │                       │
 │─────────────────────>│                        │                       │
 │                      │                        │                       │
 │ { access_token,      │                        │                       │
 │   refresh_token }    │                        │                       │
 │<─────────────────────│                        │                       │
 │                      │                        │                       │
 │ GET /repositories    │                        │                       │
 │ Authorization:       │                        │                       │
 │   Bearer {token}     │                        │                       │
 │─────────────────────>│                        │                       │
```

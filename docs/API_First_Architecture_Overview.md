# AuditGitHub Architecture Overview

**Source:** [API_First.md](API_First.md) - Section 3

---

## Textual Architecture Diagram

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                          AuditGitHub Platform                                  ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║   CLIENTS (All equal API consumers — no direct DB access)                      ║
║   ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐  ║
║   │  Web UI      │ │  CLI Tool    │ │  Scanner     │ │  AI Agents           │  ║
║   │  (Next.js)   │ │  (Python)    │ │  (Docker)    │ │  (Claude/GPT/Gemini) │  ║
║   │  :3000       │ │  Device Flow │ │  On-demand   │ │  Multi-provider      │  ║
║   └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────────┬───────────┘  ║
║          │                │                │                     │              ║
║   ┌──────┴────────┐ ┌────┴────────┐ ┌─────┴─────────┐  ┌───────┴───────┐      ║
║   │  External     │ │  CI/CD      │ │  Jira         │  │  Cribl        │      ║
║   │  Scripts      │ │  Pipelines  │ │  Integration  │  │  Stream       │      ║
║   └──────┬────────┘ └────┬────────┘ └─────┬─────────┘  └───────┬───────┘      ║
║          │               │                │                     │              ║
║  ════════╪═══════════════╪════════════════╪═════════════════════╪══════════     ║
║          │               │                │                     │              ║
║          └───────────────┴────────┬───────┴─────────────────────┘              ║
║                                   │                                            ║
║                                   ▼                                            ║
║   ╔══════════════════════════════════════════════════════════════════════╗      ║
║   ║              FastAPI Backend — The API Layer (:8000)                ║      ║
║   ╠══════════════════════════════════════════════════════════════════════╣      ║
║   ║                                                                    ║      ║
║   ║   MIDDLEWARE PIPELINE (executes top-to-bottom for every request)   ║      ║
║   ║   ┌────────────────────────────────────────────────────────────┐   ║      ║
║   ║   │  1. Request Logging    — UUID correlation, performance     │   ║      ║
║   ║   │  2. Tenant Isolation   — Schema routing (multi-tenant)     │   ║      ║
║   ║   │  3. Security Headers   — CSP, HSTS, X-Frame-Options       │   ║      ║
║   ║   │  4. Authentication     — JWT / OIDC / Session / API Key    │   ║      ║
║   ║   │  5. Session Activity   — Idle timeout tracking (Redis)     │   ║      ║
║   ║   │  6. Organization Ctx   — Multi-org context extraction      │   ║      ║
║   ║   │  7. CORS               — Cross-origin policy enforcement   │   ║      ║
║   ║   │  8. Rate Limiting      — Per-user/IP with Redis counters   │   ║      ║
║   ║   └────────────────────────────────────────────────────────────┘   ║      ║
║   ║                                                                    ║      ║
║   ║   API ROUTERS (28 modules, 80+ endpoints)                         ║      ║
║   ║   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐  ║      ║
║   ║   │ Findings    │ │ Scans       │ │ Repos       │ │ Analytics │  ║      ║
║   ║   │ Secrets     │ │ Attack Sfc  │ │ Attack Path │ │ SLA       │  ║      ║
║   ║   │ Auth        │ │ Device Flow │ │ Users       │ │ Invites   │  ║      ║
║   ║   │ AI / Chat   │ │ Orgs        │ │ Tenants     │ │ Scheduler │  ║      ║
║   ║   │ Jira        │ │ Cribl       │ │ GitHub Sync │ │ Git Sync  │  ║      ║
║   ║   │ CI/CD       │ │ Projects    │ │ Settings    │ │ Feedback  │  ║      ║
║   ║   │ API Audit   │ │ Schedules   │ │ Contributors│ │ Secrets   │  ║      ║
║   ║   └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘  ║      ║
║   ║                                                                    ║      ║
║   ║   SERVICE LAYER                                                    ║      ║
║   ║   ┌────────────────────────────────────────────────────────────┐   ║      ║
║   ║   │  CommitAnalyzer · ScheduleRecommender · ScheduleExecutor  │   ║      ║
║   ║   │  RiskScoring · ArchitecturePreprocessor · CodeExtractors  │   ║      ║
║   ║   │  Redaction · Instrumentation · TenantProvisioning         │   ║      ║
║   ║   └────────────────────────────────────────────────────────────┘   ║      ║
║   ║                                                                    ║      ║
║   ╚══════════════════════════════════════════════════════════════════════╝      ║
║                          │              │              │                        ║
║                  ┌───────┴──────┐ ┌─────┴──────┐ ┌────┴───────┐               ║
║                  │ PostgreSQL   │ │   Redis    │ │   MinIO    │               ║
║                  │ (Multi-org)  │ │ (Cache,    │ │ (Logs, S3) │               ║
║                  │ :5432        │ │  Sessions, │ │ :9009      │               ║
║                  │              │ │  Tokens)   │ │            │               ║
║                  │              │ │ :6379      │ │            │               ║
║                  └──────────────┘ └────────────┘ └────────────┘               ║
║                                                                                ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

## Key Architectural Invariants

1. **Every arrow passes through the API layer.** No client connects directly to PostgreSQL, Redis, or MinIO.
2. **The middleware pipeline is the security perimeter.** Every request — regardless of client type — traverses the same 8-layer middleware stack.
3. **Data stores are internal.** PostgreSQL, Redis, and MinIO are private services with no exposed ports in production.

# External Integrations

**Analysis Date:** 2026-01-12

## APIs & External Services

**GitHub Integration:**
- GitHub REST API - Repository scanning and analysis
  - SDK/Client: requests library with custom client - `src/github/api.py`, `src/github/github_client.py`
  - Auth: Personal Access Token in `GITHUB_TOKEN` env var - `.env.example`
  - Endpoints used: repos, contents, commits, contributors
  - Multi-organization support: `GITHUB_ORGANIZATION` env var - `src/api/config.py`

**AI/LLM Providers:**
- Anthropic Claude - AI-powered security analysis and remediation
  - SDK/Client: anthropic package v0.18.0+ - `src/ai_agent/providers/claude.py`
  - Auth: API key in `ANTHROPIC_API_KEY` env var - `.env.example`
  - Models: Claude 3 (Opus, Sonnet, Haiku) - `src/api/config.py`

- OpenAI GPT-4 - Alternative AI provider
  - SDK/Client: openai package v1.0.0+ - `src/ai_agent/providers/openai.py`
  - Auth: API key in `OPENAI_API_KEY` env var - `.env.example`
  - Models: GPT-4, GPT-4 Turbo - `src/api/config.py`

- Google Gemini - Third AI provider option
  - SDK/Client: google-generativeai package v0.5.0+ - `src/ai_agent/providers/gemini.py`
  - Auth: API key in `GEMINI_API_KEY` env var - `.env.example`
  - Models: Gemini Pro - `src/api/config.py`

- Ollama - Self-hosted LLM option
  - SDK/Client: Custom HTTP client - `src/ai_agent/providers/ollama.py`
  - Connection: `OLLAMA_BASE_URL` env var - `.env.example`
  - Models: Any Ollama-compatible model - `src/api/config.py`

- Azure AI Foundry - Enterprise AI service
  - SDK/Client: anthropic package with custom endpoint - `src/ai_agent/providers/anthropic_foundry.py`
  - Auth: API key in `ANTHROPIC_FOUNDRY_API_KEY`, `AZURE_AI_FOUNDRY_API_KEY` - `.env.example`
  - Endpoint: `ANTHROPIC_FOUNDRY_BASE_URL`, `AZURE_AI_FOUNDRY_ENDPOINT` - `src/api/config.py`

**Project Management:**
- Jira - Issue tracking integration
  - SDK/Client: requests with Jira REST API - `src/api/integrations/jira.py`
  - Auth: Token in `JIRA_TOKEN` env var - `.env.example`
  - Endpoints: `JIRA_URL`, `JIRA_PROJECT_KEY` - `src/api/config.py`
  - Features: Create issues from findings, sync status - `src/api/routers/jira.py`

**Logging & Observability:**
- Cribl Stream - Log aggregation and processing
  - Integration: HTTP ingest endpoint - `src/api/utils/cribl_logger.py`
  - Config: `CRIBL_ENDPOINT`, `CRIBL_TOKEN` - `.env.example`
  - Features: Structured logging, event streaming - `src/api/routers/cribl.py`

## Data Storage

**Databases:**
- PostgreSQL 15 - Primary relational database
  - Connection: `DATABASE_URL` env var - `.env.example`, `src/api/config.py`
  - Client: SQLAlchemy ORM v2.0.0+ - `src/api/database.py`
  - Migrations: Alembic (implied, not configured) - `migrations/` directory
  - Multi-tenant: Organization-scoped with database router - `src/api/database_router.py`

**File Storage:**
- MinIO (S3-compatible) - Object storage for logs
  - SDK/Client: minio package v7.2.0+ - `requirements.txt`
  - Connection: `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY` - `.env.example`
  - Usage: Backup storage for Cribl logs - `src/api/utils/cribl_logger.py`
  - Buckets: Configured via Docker Compose - `docker-compose.yml`

**Caching:**
- Not detected - No Redis or similar caching layer configured

## Authentication & Identity

**Auth Provider:**
- Custom JWT - Token-based authentication (implied from FastAPI patterns)
  - Implementation: Organization context middleware - `src/api/middleware/tenant.py`
  - Token storage: Request headers (`X-Organization-ID`, `X-Organization-Name`)
  - Session management: Database-backed with `Organization` model - `src/api/models.py`

**OAuth Integrations:**
- GitHub OAuth - For GitHub API access
  - Credentials: `GITHUB_TOKEN` (personal access token pattern) - `.env.example`
  - Scopes: repo, read:org (inferred from API usage)

## Monitoring & Observability

**Error Tracking:**
- Loguru - Structured logging
  - Integration: Custom Cribl logger wrapper - `src/api/utils/cribl_logger.py`
  - Config: `LOG_LEVEL` env var - `src/api/config.py`

**Analytics:**
- Custom analytics endpoints - Built-in analytics system
  - Implementation: `src/api/routers/analytics.py`
  - Storage: PostgreSQL with aggregation queries

**Logs:**
- Stdout/stderr - Standard container logging
- Cribl Stream - Optional centralized logging - `src/api/utils/cribl_logger.py`
- MinIO - Log archive storage - `docker-compose.yml`

## CI/CD & Deployment

**Hosting:**
- Docker Containers - Multi-container architecture
  - Deployment: Docker Compose for development - `docker-compose.yml`
  - Containers: API, Scanner, Web UI, PostgreSQL, MinIO
  - Production: Adaptable to any container platform (ECS, Kubernetes, etc.)

**CI Pipeline:**
- Not configured - No `.github/workflows/`, `.gitlab-ci.yml`, or similar detected

## Environment Configuration

**Development:**
- Required env vars: `DATABASE_URL`, `GITHUB_TOKEN`, at least one AI provider key
- Secrets location: `.env` file (gitignored) - `.env.example` template
- Mock/stub services: Local PostgreSQL and MinIO via Docker Compose - `docker-compose.yml`

**Staging:**
- Not applicable - No separate staging configuration detected

**Production:**
- Secrets management: Environment variables (container platform-dependent)
- Database: External PostgreSQL recommended
- Scaling: Horizontal scaling supported via stateless API design

## Webhooks & Callbacks

**Incoming:**
- GitHub Webhooks - Not currently implemented (potential future integration)

**Outgoing:**
- Cribl Stream - HTTP POST for log events
  - Endpoint: `CRIBL_ENDPOINT` - `.env.example`
  - Verification: Bearer token in `CRIBL_TOKEN` - `src/api/utils/cribl_logger.py`
  - Events: Log entries, security findings

---

*Integration audit: 2026-01-12*
*Update when adding/removing external services*

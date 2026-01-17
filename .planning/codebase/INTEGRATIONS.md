# External Integrations

**Analysis Date:** 2026-01-17

## APIs & External Services

**AI/LLM Providers:**

- **OpenAI (GPT-4)** - AI-powered analysis and remediation
  - SDK/Client: `openai` npm package v4.x (AsyncOpenAI)
  - Auth: API key in `OPENAI_API_KEY` env var
  - Models: GPT-4-turbo, GPT-4, GPT-4o, GPT-5
  - Implementation: `src/ai_agent/providers/openai.py`

- **Anthropic Claude** - AI-powered analysis with DOE self-annealing
  - SDK/Client: `anthropic` package (AsyncAnthropic)
  - Auth: API key in `ANTHROPIC_API_KEY` env var
  - Models: Claude 3 Opus/Sonnet/Haiku, Claude Sonnet 4
  - Implementation: `src/ai_agent/providers/claude.py`

- **Google Gemini** - AI analysis
  - SDK/Client: `google.genai` (new SDK)
  - Auth: API key in `GEMINI_API_KEY` env var
  - Model: `gemini-1.5-pro-latest` (default)
  - Implementation: `src/ai_agent/providers/gemini.py`

- **Azure AI Foundry** - Enterprise Claude deployment
  - SDK/Client: Anthropic SDK with Foundry deployment
  - Auth: `AZURE_AI_FOUNDRY_ENDPOINT`, `AZURE_AI_FOUNDRY_API_KEY` env vars
  - Deployment: `cogdep-aifoundry` prefix
  - Implementation: `src/ai_agent/providers/anthropic_foundry.py`

- **Ollama (Local LLM)** - On-premise inference
  - SDK/Client: AsyncOpenAI (OpenAI-compatible API)
  - Auth: None (local)
  - URL: `OLLAMA_BASE_URL` (default: `http://localhost:11434`)
  - Implementation: `src/ai_agent/providers/ollama.py`

**GitHub Integration:**
- GitHub API - Repository scanning and metadata
  - SDK/Client: `requests.Session` with retry logic
  - Auth: Personal Access Token in `GITHUB_TOKEN` env var
  - Base URL: `https://api.github.com`
  - Implementation: `src/github/api.py`
  - Multi-org: `ORG_{NAME}_TOKEN`, `ORG_{NAME}_GITHUB` env vars

**Project Management:**
- Jira - Ticket creation from security findings
  - SDK/Client: `requests` with HTTPBasicAuth
  - Auth: `JIRA_URL`, `JIRA_USERNAME`, `JIRA_API_TOKEN`, `JIRA_PROJECT_KEY` env vars
  - API: `{JIRA_URL}/rest/api/3/`
  - Implementation: `src/api/integrations/jira.py`
  - Router: `src/api/routers/jira.py`

## Data Storage

**Databases:**
- PostgreSQL - Primary data store
  - Connection: `DATABASE_URL` or `POSTGRES_*` env vars
  - Client: SQLAlchemy 2.0.0+ with async support
  - Migrations: Alembic (`alembic.ini`, `migrations/`)
  - Implementation: `src/api/database.py`

**Caching:**
- Redis - Session storage, permission caching, token blacklist
  - Connection: `REDIS_URL` (default: `redis://redis:6379/0`)
  - Client: redis 5.0.0+ with hiredis parser
  - TTL: 5 minutes for permission cache
  - Implementation: `src/rbac/cache.py`

**File Storage:**
- MinIO (S3-Compatible) - Log archival and fallback storage
  - SDK/Client: `minio` 7.2.0+
  - Auth: `minio_access_key`, `minio_secret_key`
  - Implementation: `src/api/utils/cribl_logger.py`

## Authentication & Identity

**Auth Provider:**
- Custom OAuth2 + JWT implementation
  - SDK: authlib 1.3.0, python-jose[cryptography] 3.3.0+
  - Token storage: Redis-backed with httpOnly cookies
  - Session management: JWT refresh tokens
  - Implementation: `src/auth/`

**OAuth Integrations:**
- Configurable OAuth providers
  - Setup: `src/auth/providers.py`
  - Credentials: Provider-specific env vars

## Monitoring & Observability

**Log Management:**
- Cribl Stream - Centralized log collection
  - SDK/Client: `httpx` async HTTP
  - Auth: Bearer token
  - Config: `ingest_url`, `auth_token`, `verify_ssl`
  - Implementation: `src/api/utils/cribl_logger.py`
  - Router: `src/api/routers/cribl.py`

**Error Tracking:**
- Not configured (potential addition)

**Analytics:**
- Built-in analytics via `src/api/routers/analytics.py`

**Logs:**
- loguru with HTTP transport to Cribl
- MinIO fallback when Cribl unavailable
- Retention: Configurable

## CI/CD & Deployment

**Hosting:**
- Docker containers via Docker Compose
  - Deployment: `docker-compose up`
  - Services: `api`, `web-ui`, `scanner`, `db`, `redis`

**Container Images:**
- `Dockerfile` - Main image
- `Dockerfile.api` - API service
- `Dockerfile.scanner` - Scanner service
- `Dockerfile.ui` - Web UI service

## Environment Configuration

**Development:**
- Required env vars: `GITHUB_TOKEN`, `POSTGRES_*`, `REDIS_*`
- Secrets location: `.env` (gitignored), `.env.sample` for template
- Mock services: Local PostgreSQL/Redis via Docker

**Production:**
- Secrets management: Environment variables
- Database: PostgreSQL with connection pooling
- Cache: Redis cluster

## Webhooks & Callbacks

**Incoming:**
- Jira - `/api/webhooks/jira`
  - Verification: Via RBAC permissions
  - Events: Issue updates, comments

**Outgoing:**
- GitHub API calls for repository metadata
- AI provider API calls for analysis
- Cribl for log forwarding

## Security Scanning Tools

**Secret Detection:**
- Gitleaks - Git secret scanning
- TruffleHog - Entropy-based secret detection
- Whispers - Python secret scanner

**Dependency Scanning:**
- Grype - Container and artifact scanning
- Trivy - Vulnerabilities, misconfigurations, secrets
- OSV - Open Source Vulnerabilities database
- OWASP Dependency-Check - Multi-language scanning

**Static Analysis:**
- Semgrep 1.0.0+ - AST-based pattern matching
- CodeQL - Semantic code analysis
- Bandit - Python security linter

**Infrastructure Scanning:**
- Checkov - Terraform, CloudFormation, Kubernetes
- Terrascan - IaC security scanner

**Container Security:**
- Dockle - Docker image linting
- Trivy - Container image scanning

**Go Security:**
- gosec - Go security analyzer
- govulncheck - Go vulnerability checker

---

*Integration audit: 2026-01-17*
*Update when adding/removing external services*

# Technology Stack

**Analysis Date:** 2026-01-12

## Languages

**Primary:**
- Python 3.11 - Backend API and security scanning - `Dockerfile.scanner`, `Dockerfile.api`, `src/api/main.py`
- TypeScript 5.x - Frontend UI - `src/web-ui/tsconfig.json`, `src/web-ui/package.json`

**Secondary:**
- JavaScript/Node.js 20 - Web UI runtime and build tools - `src/web-ui/package.json`, `Dockerfile.ui`
- Java 21 (OpenJDK) - Scanning Java projects - `Dockerfile.scanner`
- Go 1.21.5 - Go project scanning and security tools - `Dockerfile.scanner`
- Ruby - Ruby gem vulnerability auditing - `Dockerfile.scanner`
- .NET 8.0 - For OSS Gadget security tool - `Dockerfile.scanner`

## Runtime

**Environment:**
- Python 3.11-slim - Backend containers - `Dockerfile.scanner`, `Dockerfile.api`
- Node.js 20-alpine - Frontend container - `Dockerfile.ui`
- PostgreSQL 15 - Primary database - `docker-compose.yml`
- Docker & Docker Compose - Container orchestration - `docker-compose.yml`

**Package Manager:**
- pip - Python packages - `requirements.txt`
- npm - Node.js packages - `src/web-ui/package.json`, `src/web-ui/package-lock.json`

## Frameworks

**Core:**
- FastAPI 0.100.0+ - Backend web framework - `src/api/main.py`, `requirements.txt`
- Next.js 16.0.6 - React framework with SSR - `src/web-ui/package.json`, `src/web-ui/next.config.ts`
- React 19.2.0 - UI library - `src/web-ui/package.json`

**Testing:**
- No formal test framework configured - Manual testing only
- ESLint - Code quality linting - `src/web-ui/eslint.config.mjs`

**Build/Dev:**
- TypeScript 5.x - Type checking - `src/web-ui/tsconfig.json`
- Uvicorn 0.23.0+ - ASGI server - `docker-compose.yml`, `requirements.txt`
- Next.js built-in bundler - Frontend builds - `src/web-ui/next.config.ts`
- Tailwind CSS 4 - Styling framework - `src/web-ui/package.json`

## Key Dependencies

**Critical:**
- anthropic 0.18.0+ - Claude AI integration - `requirements.txt`, `src/ai_agent/providers/claude.py`
- openai 1.0.0+ - GPT-4 AI integration - `requirements.txt`, `src/ai_agent/providers/openai.py`
- google-generativeai 0.5.0+ - Gemini AI integration - `requirements.txt`, `src/ai_agent/providers/gemini.py`
- SQLAlchemy 2.0.0+ - Database ORM - `src/api/database.py`, `requirements.txt`
- Pydantic 2.0.0+ - Data validation - `requirements.txt`, `src/api/models.py`
- @radix-ui/* - React component library - `src/web-ui/package.json`
- Recharts 3.5.1 - Data visualization - `src/web-ui/package.json`

**Infrastructure:**
- psycopg2-binary 2.9.0+ - PostgreSQL adapter - `requirements.txt`
- requests 2.31.0+ - HTTP client - `requirements.txt`, `src/github/api.py`
- httpx 0.24.0+ - Async HTTP client - `requirements.txt`
- minio 7.2.0+ - S3-compatible storage - `requirements.txt`, `src/api/utils/cribl_logger.py`
- APScheduler 3.10.0+ - Task scheduling - `requirements.txt`, `src/api/scheduler.py`

**Security Scanning Tools (Docker-installed):**
- Gitleaks 8.18.2 - Secret detection - `Dockerfile.scanner`
- Grype - Vulnerability scanning - `Dockerfile.scanner`, `requirements.txt`
- Syft - SBOM generation - `Dockerfile.scanner`, `Dockerfile.api`
- Semgrep 1.0.0+ - SAST analysis - `Dockerfile.scanner`, `requirements.txt`
- CodeQL 2.15.3 - Code analysis - `Dockerfile.scanner`
- Trivy - Multi-purpose security scanner - `Dockerfile.scanner`
- OWASP Dependency-Check 12.1.0 - Dependency vulnerabilities - `Dockerfile.scanner`
- Bandit - Python security linting - `Dockerfile.scanner`
- Nuclei 3 - Template-based scanning - `Dockerfile.scanner`

## Configuration

**Environment:**
- `.env` files - Environment-based configuration - `.env.example`, `.env.sample`
- Pydantic Settings - Configuration loading - `src/api/config.py`
- Docker Compose environment variables - Service configuration - `docker-compose.yml`

**Build:**
- `next.config.ts` - Next.js configuration - `src/web-ui/next.config.ts`
- `tsconfig.json` - TypeScript compilation - `src/web-ui/tsconfig.json`
- `eslint.config.mjs` - ESLint flat config - `src/web-ui/eslint.config.mjs`
- `requirements.txt` - Python dependencies - `requirements.txt`

## Platform Requirements

**Development:**
- macOS/Linux/Windows with Docker support
- Docker Desktop or Docker Engine
- Node.js 20+ for frontend development
- Python 3.11+ for backend development

**Production:**
- Docker container platform (AWS ECS, Kubernetes, Docker Compose)
- PostgreSQL 15+ database
- Persistent volumes for scan data and logs
- Network access for GitHub API, AI providers (Claude/OpenAI/Gemini)

---

*Stack analysis: 2026-01-12*
*Update after major dependency changes*

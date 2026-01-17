# Technology Stack

**Analysis Date:** 2026-01-17

## Languages

**Primary:**
- Python 3.x - Backend API, scanning orchestration, AI integration, CLI tools
- TypeScript 5.x - Frontend development (`src/web-ui/`)

**Secondary:**
- JavaScript - Build scripts, config files
- Shell/Bash - Setup scripts, Docker orchestration

## Runtime

**Environment:**
- Python 3.x - Backend runtime via Docker
- Node.js 20+ - Web UI runtime (inferred from TypeScript config and Next.js 16)
- Docker - Containerization for all services (`Dockerfile`, `Dockerfile.api`, `Dockerfile.scanner`, `Dockerfile.ui`)

**Package Manager:**
- pip - Python package manager (`requirements.txt`, `src/api/requirements.txt`)
- npm - JavaScript package manager (`src/web-ui/package.json`)
- Lockfile: No lockfiles detected (no pip.freeze or package-lock.json)

## Frameworks

**Core:**
- FastAPI 0.100.0+ - REST API backend (`src/api/main.py`)
- Next.js 16.0.6 - React-based web UI with App Router (`src/web-ui/`)
- React 19.2.0 - Frontend UI library

**Testing:**
- pytest 7.4.0+ - Python testing framework
- pytest-asyncio 0.21.0+ - Async test support
- pytest-cov 4.1.0+ - Code coverage reporting

**Build/Dev:**
- TypeScript 5.x - TypeScript compiler and type checking
- Tailwind CSS 4 - Utility-first CSS framework
- Docker Compose - Container orchestration (`docker-compose.yml`)

## Key Dependencies

**Critical:**
- SQLAlchemy 2.0.0+ - Python ORM for database access (`src/api/models.py`)
- psycopg2-binary 2.9.0+ - PostgreSQL adapter for Python
- Redis 5.0.0+ - In-memory caching and session storage
- Anthropic SDK - Claude AI integration (`src/ai_agent/providers/claude.py`)
- OpenAI SDK - GPT-4 integration (`src/ai_agent/providers/openai.py`)

**Infrastructure:**
- Alembic 1.13.0 - Database migrations (`alembic.ini`)
- APScheduler 3.10.0+ - Background job scheduling
- loguru 0.7.0+ - Structured logging with HTTP transport
- slowapi 0.1.9+ - Rate limiting for FastAPI

**Frontend:**
- Radix UI primitives - 11 headless UI components for accessibility
- TanStack React Table 8.21.3 - Data table component
- Recharts 3.5.1 - Data visualization/charting
- Mermaid 10.9.0 - Diagram and flowchart rendering
- Lucide React 0.555.0 - Icon library

## Configuration

**Environment:**
- `.env` files - Environment configuration
- `.env.sample` - Template configuration with all required variables
- Key configs: `GITHUB_TOKEN`, `POSTGRES_*`, `REDIS_*`, `AI_PROVIDER`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`

**Build:**
- `docker-compose.yml` - Container orchestration
- `tsconfig.json` - TypeScript configuration (`src/web-ui/`)
- `next.config.ts` - Next.js configuration
- `eslint.config.mjs` - ESLint 9 flat config format

## Platform Requirements

**Development:**
- macOS/Linux (Docker required)
- Docker and Docker Compose
- PostgreSQL (via Docker service `db`)
- Redis (via Docker service `redis`)

**Production:**
- Docker container deployment
- PostgreSQL database
- Redis for caching/sessions
- Environment variables for secrets

---

*Stack analysis: 2026-01-17*
*Update after major dependency changes*

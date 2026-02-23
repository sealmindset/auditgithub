# AuditGH: GitHub Repository Security Scanner

AuditGitHub ensures that the applications we build and the third-party dependencies we leverage are secure by design, preventing hackers from disrupting services or stealing from our openly accessible customer platforms. By automating our security scanning and using AI agents to instantly validate only real threats, it removes the friction of manual security checks—saving costly engineering hours while safeguarding our revenue from devastating breaches


A modular, AI-powered security scanning platform for GitHub organizations. Scan repositories for secrets, vulnerabilities, and misconfigurations with multi-tenant support.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## What is AuditGH?

AuditGH is an enterprise-grade security scanning tool that:

- **Scans GitHub repositories** for secrets, vulnerabilities, and security issues
- **Supports multiple organizations** with isolated data and credentials
- **Uses AI agents** for intelligent analysis and remediation recommendations
- **Provides a web dashboard** for viewing and managing findings
- **Runs anywhere** - Docker, local CLI, or CI/CD pipelines

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/sealmindset/auditgithub.git
cd auditgithub

# Configure environment
cp .env.sample .env
# Edit .env with your GitHub token and settings

# Start the stack (API, Web UI, Database, Redis)
docker-compose up -d

# Initialize database schema
docker exec auditgh_api python init_db.py

# Run your first scan (preview mode)
docker-compose run --rm scanner --target myorg --dry-run

# Run actual scan
docker-compose run --rm scanner --target myorg

# Ingest scan results into database
docker exec auditgh_api python ingest_reports.py
```

**Access the dashboard:** http://localhost:3000

→ [Full Getting Started Guide](docs/GETTING_STARTED.md) | **[Command Cheatsheet](CHEATSHEET.md)**

---

## Features

### Security Scanning
| Category | Tools | Detects |
|----------|-------|--------|
| **Secrets** | Gitleaks, TruffleHog, Whispers | API keys, tokens, passwords |
| **Vulnerabilities** | Grype, Trivy, OSV | CVEs in dependencies |
| **Static Analysis** | Semgrep, CodeQL, Bandit | Code vulnerabilities |
| **Infrastructure** | Checkov, Trivy, Terrascan | IaC misconfigurations |
| **Container Security** | Dockle, Trivy | Docker image issues |
| **Go Security** | gosec, govulncheck | Go-specific vulnerabilities |

### Multi-Organization Support
- Scan multiple GitHub organizations from one installation
- Isolated data per organization (same database, securely segmented)
- Separate credentials per organization
- Persistent organization selection across UI navigation
- Schema synchronization and drift detection

### AI-Powered Analysis
- **Zero Day Analysis** - AI-powered vulnerability impact assessment
- **Credential-to-URL correlation** and automated testing
- **API path discovery** and fuzzing
- **Executive summaries** and risk assessments
- Supports **Claude (Anthropic), GPT-4 (OpenAI), and local Ollama**

### Self-Healing Operations
- Automatic timeout recovery for stuck scans
- Schema drift detection and auto-sync
- Backup and restore with 30-day retention
- Session-based authentication with Redis caching
- CORS preflight handling for cross-origin requests
- **Automatic repository metadata validation** after every scan

---

## Documentation

### Getting Started
| Guide | Description |
|-------|-------------|
| **[Cheatsheet](CHEATSHEET.md)** | **Quick reference for all commands** |
| [Getting Started](docs/GETTING_STARTED.md) | Installation and first scan |
| [Running Modes](docs/RUNNING_MODES.md) | Docker vs CLI, when to use each |
| [Configuration](docs/CONFIGURATION.md) | All environment variables and options |

### Operations
| Guide | Description |
|-------|-------------|
| [Multi-Tenant Setup](docs/MULTI_TENANT.md) | Add and manage multiple organizations |
| [Scan Validation](SCAN_VALIDATION.md) | Automatic metadata validation system |
| [Database Reset](docs/DATABASE_RESET.md) | Backup, reset, and restore data |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |

### Advanced
| Guide | Description |
|-------|-------------|
| [Security Tools](docs/SECURITY_TOOLS.md) | All scanning tools and future roadmap |
| [AI Agents](docs/AI_AGENTS.md) | AI capabilities, LLM configuration |
| [Dependencies](docs/DEPENDENCIES.md) | System requirements, external services |

---

## Common Commands

See **[CHEATSHEET.md](CHEATSHEET.md)** for complete command reference with detailed explanations.

### Quick Reference

```bash
# Scanning
docker-compose run --rm scanner --target myorg --dry-run        # Preview
docker-compose run --rm scanner --target myorg                  # Basic scan
docker-compose run --rm scanner --target myorg --rescan-days 7  # Incremental
docker-compose run --rm scanner --target myorg --overridescan   # Force rescan
docker-compose run --rm scanner --target myorg --ai-agent       # With AI

# Data ingestion
docker exec auditgh_api python ingest_reports.py

# Services
docker-compose up -d          # Start all services
docker-compose logs -f api    # View API logs
docker-compose restart api    # Restart API
docker-compose down           # Stop all services
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AuditGH Stack                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Web UI    │  │   FastAPI   │  │      Scanner Engine     │ │
│  │  (Next.js)  │  │   Backend   │  │  (Python + AI Agents)   │ │
│  │  :3000      │  │   :8000     │  │   (on-demand)           │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│         │                │                      │               │
│         └────────────────┼──────────────────────┘               │
│                          │                                      │
│         ┌────────────────┼────────────────┐                     │
│         │                │                │                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │  PostgreSQL  │ │    Redis     │ │    MinIO     │            │
│  │  (Multi-org) │ │   (Cache)    │ │  (Logs/S3)   │            │
│  │    :5432     │ │    :6379     │ │    :9009     │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Docker | 20.10+ | 24.0+ |
| Docker Compose | 1.29+ | 2.0+ |
| RAM | 4GB | 8GB |
| Disk | 20GB | 50GB |
| GitHub PAT | `repo`, `read:org` scopes | Classic token with full permissions |

**Optional:** AI provider API key (Anthropic, OpenAI, or Ollama)

---

## License

GNU General Public License v3.0

---

## Support

- **Issues:** [GitHub Issues](https://github.com/sealmindset/auditgithub/issues)
- **Documentation:** [docs/](docs/)
- **Cheatsheet:** [CHEATSHEET.md](CHEATSHEET.md)
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)

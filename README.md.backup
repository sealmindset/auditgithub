# AuditGH: GitHub Repository Security Scanner

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

# Start the stack (API, Web UI, Database)
docker-compose up -d

# Run your first scan (uses dedicated scanner container)
docker-compose run --rm scanner --dry-run
```

**Access the dashboard:** http://localhost:3000

→ [Full Getting Started Guide](docs/GETTING_STARTED.md)

---

## Features

### Security Scanning
| Category | Tools | Detects |
|----------|-------|--------|
| **Secrets** | Gitleaks, TruffleHog | API keys, tokens, passwords |
| **Vulnerabilities** | Grype, Trivy, OSV | CVEs in dependencies |
| **Static Analysis** | Semgrep, CodeQL | Code vulnerabilities |
| **Infrastructure** | Checkov, Trivy | IaC misconfigurations |
| **AI Tokens** | Custom scanner | OpenAI, Anthropic keys |

### Multi-Organization Support
- Scan multiple GitHub organizations from one installation
- Isolated data per organization (same database, securely segmented)
- Separate credentials per organization
- Schema synchronization and drift detection

### AI-Powered Analysis
- **4 AI agents** for intelligent security analysis
- Credential-to-URL correlation and testing
- API path discovery and fuzzing
- Executive summaries and risk assessments
- Supports Claude, GPT-4, and local Ollama

### Self-Healing Operations
- Automatic timeout recovery for stuck scans
- Schema drift detection and auto-sync
- Backup and restore with 30-day retention

---

## Documentation

### Getting Started
| Guide | Description |
|-------|-------------|
| [Getting Started](docs/GETTING_STARTED.md) | Installation and first scan |
| [Running Modes](docs/RUNNING_MODES.md) | Docker vs CLI, when to use each |
| [Configuration](docs/CONFIGURATION.md) | All environment variables and options |

### Operations
| Guide | Description |
|-------|-------------|
| [Cheatsheet](docs/CHEATSHEET.md) | Quick reference for common commands |
| [Multi-Tenant Setup](docs/MULTI_TENANT.md) | Add and manage multiple organizations |
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

### Scanning

The scanner runs in a dedicated container, separate from the API, for better resource isolation.

```bash
# Scan default organization (from GITHUB_ORG in .env)
docker-compose run --rm scanner

# Scan specific organization
docker-compose run --rm scanner --target myorg

# Incremental scan: new repos + repos not scanned in 14 days (recommended for regular use)
docker-compose run --rm scanner --target myorg --rescan-days 14

# Scan a single repository
docker-compose run --rm scanner --target myorg --repo specific-repo-name

# Dry run (preview without scanning)
docker-compose run --rm scanner --target myorg --dry-run

# With AI analysis (disabled by default, requires API key)
docker-compose run --rm scanner --target myorg --ai-agent

# Run with custom options
docker-compose run --rm scanner --target myorg --max-workers 8 --loglevel DEBUG
```

### Organization Management

```bash
# List organizations
docker-compose run --rm scanner --list-orgs

# Reset organization data (creates backup first)
docker-compose run --rm scanner python scripts/reset_organization_data.py --target myorg --force

# Check schema drift
docker-compose run --rm scanner --check-drift
```

### Services

```bash
# Start all services (API, Web UI, Database)
docker-compose up -d

# Start only API and database
docker-compose up -d api db

# View logs
docker-compose logs -f api

# Stop services
docker-compose down

# Rebuild containers after code changes
docker-compose build api
docker-compose build scanner
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         AuditGH Stack                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │   Web UI    │  │   FastAPI   │  │      Scanner Engine     │ │
│  │  (React)    │  │   Backend   │  │  (Python + AI Agents)   │ │
│  │  :3000      │  │   :8000     │  │                         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
│         │                │                      │               │
│         └────────────────┼──────────────────────┘               │
│                          │                                      │
│                 ┌────────────────┐                              │
│                 │   PostgreSQL   │                              │
│                 │   (Multi-org)  │                              │
│                 │     :5432      │                              │
│                 └────────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Purpose | Location |
|-----------|---------|----------|
| Scanner Engine | Security scanning orchestration | `scan_repos.py`, `execution/` |
| AI Agents | Intelligent analysis | `execution/ai_*.py` |
| FastAPI Backend | REST API | `src/api/` |
| React Frontend | Web dashboard | `src/web-ui/` |
| Migrations | Database schema | `migrations/` |

---

## AI Agents

AuditGH includes 4 AI agents for enhanced security analysis:

| Agent | Purpose | LLM Required |
|-------|---------|-------------|
| **Organization Agent** | Multi-org orchestration | No |
| **Credential Matcher** | Credential-to-URL correlation | Optional |
| **API Discovery** | API path reverse engineering | Optional |
| **Credential URL Tester** | Security testing & analysis | Yes |

**Recommended LLM:** Claude 3 (lowest hallucination for security analysis)

→ [Full AI Agents Guide](docs/AI_AGENTS.md)

---

## Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Docker | 20.10+ | 24.0+ |
| RAM | 4GB | 8GB |
| Disk | 20GB | 50GB |
| GitHub PAT | `repo`, `read:org` scopes | - |

**Optional:** AI provider API key (Anthropic, OpenAI, or Ollama)

→ [Full Dependencies Guide](docs/DEPENDENCIES.md)

---

## License

GNU General Public License v3.0

---

## Support

- **Issues:** [GitHub Issues](https://github.com/sealmindset/auditgithub/issues)
- **Docs:** [docs/](docs/)
- **Changelog:** [CHANGELOG.md](CHANGELOG.md)

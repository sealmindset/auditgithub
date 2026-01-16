# Dependencies & Requirements

This guide covers all external dependencies, services, and requirements for running AuditGH.

## Core Dependencies

### Required Services

| Service | Purpose | Required | Default |
|---------|---------|----------|---------|
| **PostgreSQL** | Data storage | Yes | Included in Docker |
| **Docker** | Container runtime | Recommended | - |
| **GitHub API** | Repository access | Yes | api.github.com |

### Optional Services

| Service | Purpose | Required For |
|---------|---------|--------------|
| **Anthropic Claude** | AI analysis | AI-powered features |
| **OpenAI GPT-4** | AI analysis | AI-powered features |
| **Ollama** | Local AI | Air-gapped AI features |

---

## GitHub Requirements

### Personal Access Token (PAT)

**Required Scopes:**
| Scope | Purpose |
|-------|---------|
| `repo` | Full access to private repositories |
| `read:org` | Read organization membership |

**Optional Scopes:**
| Scope | Purpose |
|-------|---------|
| `admin:org` | Organization admin (for webhooks) |
| `write:packages` | Package registry access |

### Creating a PAT

1. Go to GitHub → Settings → Developer settings → Personal access tokens
2. Click "Generate new token (classic)"
3. Select scopes: `repo`, `read:org`
4. Set expiration (90 days recommended)
5. Copy token to `.env` file

### Rate Limits

| Tier | Requests/Hour | Notes |
|------|---------------|-------|
| Unauthenticated | 60 | Not usable for scanning |
| Authenticated | 5,000 | Standard PAT |
| GitHub App | 15,000 | For high-volume scanning |

---

## AI Provider Requirements

### Anthropic Claude

**Best for:** Security analysis, low hallucination

```bash
# .env configuration
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-api03-...
```

**Supported Models:**
| Model | Context | Best For |
|-------|---------|----------|
| claude-3-opus-20240229 | 200K | Complex security analysis |
| claude-3-sonnet-20240229 | 200K | Balanced cost/quality |
| claude-3-haiku-20240307 | 200K | Fast, cost-effective |

**API Key:** https://console.anthropic.com/

### OpenAI GPT-4

**Best for:** General purpose, fast responses

```bash
# .env configuration
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o  # or gpt-4-turbo
```

**Supported Models:**
| Model | Context | Best For |
|-------|---------|----------|
| gpt-4o | 128K | Best overall |
| gpt-4-turbo | 128K | Faster, slightly cheaper |
| gpt-4 | 8K | Original, most tested |

**API Key:** https://platform.openai.com/api-keys

### Ollama (Local)

**Best for:** Air-gapped environments, cost-sensitive

```bash
# .env configuration
AI_PROVIDER=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3
```

**Setup:**
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull model
ollama pull llama3

# Start server
ollama serve
```

**Recommended Models:**
| Model | Size | Best For |
|-------|------|----------|
| llama3:70b | 40GB | Best quality |
| llama3:8b | 4.7GB | Good balance |
| codellama:34b | 19GB | Code analysis |
| mistral:7b | 4.1GB | Fast, lightweight |

---

## Database Requirements

### PostgreSQL

**Minimum Version:** 14.0

**Required Extensions:**
| Extension | Purpose | Included |
|-----------|---------|----------|
| `uuid-ossp` | UUID generation | Yes (default) |
| `pgcrypto` | Encryption functions | Yes (default) |

**Configuration:**
```bash
# .env
POSTGRES_HOST=db          # 'localhost' for local
POSTGRES_PORT=5432
POSTGRES_USER=auditgh
POSTGRES_PASSWORD=postgres
POSTGRES_DB=auditgh_kb
```

**Resource Requirements:**
| Metric | Minimum | Recommended |
|--------|---------|-------------|
| RAM | 512MB | 2GB |
| Disk | 1GB | 10GB+ |
| CPU | 1 core | 2+ cores |

---

## Python Dependencies

### Core Packages

```
# requirements.txt (key packages)
fastapi>=0.104.0
uvicorn>=0.24.0
sqlalchemy>=2.0.0
asyncpg>=0.29.0
psycopg2-binary>=2.9.9
pydantic>=2.5.0
httpx>=0.25.0
python-dotenv>=1.0.0
cryptography>=41.0.0
```

### Scanner Dependencies

| Scanner | Package | System Dependency |
|---------|---------|-------------------|
| Gitleaks | - | `gitleaks` binary |
| TruffleHog | `truffleHog3` | - |
| Semgrep | `semgrep` | - |
| Grype | - | `grype` binary |
| Trivy | - | `trivy` binary |
| Syft | - | `syft` binary |

### AI Packages

```
# AI provider SDKs
anthropic>=0.7.0      # For Claude
openai>=1.3.0         # For GPT-4
ollama>=0.1.0         # For local LLMs
```

---

## System Dependencies

### Docker Environment

All system dependencies are included in the Docker image:

```dockerfile
# From Dockerfile
FROM python:3.11-slim

# System tools
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    jq \
    postgresql-client

# Security scanners
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

### Local Environment

If running without Docker:

```bash
# macOS
brew install gitleaks grype syft trivy postgresql@14

# Ubuntu/Debian
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Python
pip install -r requirements.txt
```

---

## Network Requirements

### Outbound Connections

| Destination | Port | Purpose |
|-------------|------|---------|
| api.github.com | 443 | GitHub API |
| github.com | 443 | Git clone |
| api.anthropic.com | 443 | Claude API |
| api.openai.com | 443 | OpenAI API |
| pypi.org | 443 | Python packages |
| ghcr.io | 443 | Container images |

### Internal Ports

| Service | Port | Purpose |
|---------|------|---------|
| API | 8000 | FastAPI backend |
| Web UI | 3000 | React frontend |
| Database | 5432 | PostgreSQL |
| Ollama | 11434 | Local LLM (optional) |

### Firewall Rules

```bash
# Required outbound
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Internal services
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT  # API
iptables -A INPUT -p tcp --dport 3000 -j ACCEPT  # UI
```

---

## Resource Requirements

### Minimum (Small Org, <50 repos)

| Resource | Requirement |
|----------|-------------|
| CPU | 2 cores |
| RAM | 4GB |
| Disk | 20GB |
| Network | 10 Mbps |

### Recommended (Medium Org, 50-200 repos)

| Resource | Requirement |
|----------|-------------|
| CPU | 4 cores |
| RAM | 8GB |
| Disk | 50GB |
| Network | 100 Mbps |

### Production (Large Org, 200+ repos)

| Resource | Requirement |
|----------|-------------|
| CPU | 8+ cores |
| RAM | 16GB+ |
| Disk | 100GB+ SSD |
| Network | 1 Gbps |

---

## Version Compatibility

### Tested Versions

| Component | Minimum | Tested | Latest |
|-----------|---------|--------|--------|
| Python | 3.10 | 3.11 | 3.12 |
| PostgreSQL | 14 | 15 | 16 |
| Docker | 20.10 | 24.0 | 25.0 |
| Node.js | 18 | 20 | 21 |

### Breaking Changes

| Version | Change | Migration |
|---------|--------|-----------|
| 2.0.0 | Multi-tenant schema | Run migration 004 |
| 1.5.0 | New secrets manager | Set SECRETS_MASTER_KEY |
| 1.0.0 | Initial release | - |

---

## Dependency Updates

### Checking for Updates

```bash
# Python packages
pip list --outdated

# Docker images
docker-compose pull

# System tools
brew outdated  # macOS
```

### Security Updates

```bash
# Check for vulnerabilities in dependencies
pip-audit

# Update all packages
pip install --upgrade -r requirements.txt
```

---

## Offline/Air-Gapped Installation

For environments without internet access:

### 1. Download Dependencies

```bash
# On connected machine
pip download -r requirements.txt -d ./packages/
docker save auditgh:latest > auditgh-image.tar
```

### 2. Transfer to Air-Gapped System

```bash
# Copy packages/ directory and tar file
scp -r packages/ user@airgapped:/path/to/auditgh/
scp auditgh-image.tar user@airgapped:/path/to/
```

### 3. Install Offline

```bash
# On air-gapped machine
pip install --no-index --find-links=./packages/ -r requirements.txt
docker load < auditgh-image.tar
```

### 4. Use Local LLM

```bash
# Configure Ollama for AI features
AI_PROVIDER=ollama
OLLAMA_HOST=http://localhost:11434
```

---

[← Back to README](../README.md) | [Configuration →](CONFIGURATION.md)
